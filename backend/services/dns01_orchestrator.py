"""Issue #35 — ACME DNS-01 (v1.8.0): non-blocking per-cycle orchestration.

Driven by the existing `complete_pending_acme_orders` background task (which already claims
in-progress orders with `FOR UPDATE SKIP LOCKED`). For a dns-01 order this module advances AT MOST
ONE step per 60s cycle — publish TXT, then (after a short min-age) respond — so the serial claim
loop is never blocked by a multi-minute wait, and NO DNS library is needed (the CA is the source of
truth; a propagation-lag `invalid` is recovered by a bounded fresh-order chain).

Design invariants (from the hardening review):
- Additive at the RRset level: publish/cleanup operate on a single (name, value), so wildcard+apex
  (two values at one name) coexist.
- No new order-status value: a failed order stays `invalid`; a boolean `dns01_retry_claimed` does the
  winner-only CAS + claim exclusion, so existing `status` consumers are untouched.
- Secrets (provider API tokens) are NEVER logged or written to error_detail/events.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

from database.connection import get_database_connection, close_database_connection
from services.acme_service import acme_service as acme_svc, ACMEService
from services.dns_providers import get_provider, is_supported, DnsProviderError
from utils.dns_credentials import decrypt_dns_credentials
from utils.activity_log import record_event

logger = logging.getLogger(__name__)

# Tunables (kept conservative vs Let's Encrypt rate limits: 5 failed-validations/host/hour,
# 300 new-orders/account/3h).
PROPAGATION_GRACE_SECONDS = 25          # min age before we tell the CA to validate
MANUAL_CONFIRM_TTL = timedelta(hours=48)
MAX_RETRIES = 3                          # bounded fresh-order chain (1 original + 3 retries = 4 orders)
# Retry backoff floor (minutes) indexed by the order's current dns01_attempts: [15, 30, 60].
# The AUTHORITATIVE implementation is the SQL CASE in main.py's claim query
# (complete_pending_acme_orders), so the backoff is evaluated atomically with the
# FOR UPDATE SKIP LOCKED claim. Documented here only — do not reintroduce a second copy.


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt) -> Optional[datetime]:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


async def _load_credentials(conn, account_id: int) -> Tuple[Optional[Dict[str, str]], bool]:
    """Return (credentials_dict_or_None, row_exists). credentials None + row_exists True means the
    stored token could not be decrypted (e.g. SECRET_KEY rotated)."""
    row = await conn.fetchrow(
        "SELECT credentials_encrypted FROM letsencrypt_account_dns_credentials WHERE account_id = $1",
        account_id,
    )
    if not row:
        return None, False
    return decrypt_dns_credentials(row["credentials_encrypted"]), True


async def _fail_order(conn, order_id: int, reason: str) -> None:
    """Mark an order invalid with a sanitized reason (no secrets) + event."""
    import json
    payload = json.dumps({"stage": "dns01", "reason": reason, "timestamp": _now().isoformat()})
    await conn.execute(
        "UPDATE letsencrypt_orders SET status = 'invalid', error_detail = $1, updated_at = NOW() WHERE id = $2",
        payload, order_id,
    )
    await record_event(order_id, "acme.dns01.validation", severity="ERROR", message=reason, conn=conn)


async def advance_dns01_order(order_id: int) -> None:
    """One non-blocking step for a claimed pending/processing dns-01 order. No-op for http-01 or
    orders not in a publishable state. Safe to call every cycle (idempotent via CAS flags)."""
    conn = await get_database_connection()
    try:
        order = await conn.fetchrow(
            """SELECT o.id, o.status, o.challenge_type, o.account_id, a.dns_provider
               FROM letsencrypt_orders o JOIN letsencrypt_accounts a ON o.account_id = a.id
               WHERE o.id = $1""",
            order_id,
        )
        if not order or order["challenge_type"] != "dns-01":
            return
        if order["status"] not in ("pending", "processing"):
            return

        challenges = await conn.fetch(
            "SELECT * FROM acme_challenges WHERE order_id = $1 AND challenge_type = 'dns-01'", order_id
        )
        if not challenges:
            return

        provider_name = (order["dns_provider"] or "manual").strip()

        # --- Manual provider: the user publishes + confirms; we only enforce the deadline. ---
        if provider_name == "manual" or not is_supported(provider_name):
            deadline = _aware(challenges[0]["manual_confirm_deadline"])
            if deadline is None:
                new_deadline = _now() + MANUAL_CONFIRM_TTL
                await conn.execute(
                    "UPDATE acme_challenges SET manual_confirm_deadline = $1 WHERE order_id = $2 AND manual_confirm_deadline IS NULL",
                    new_deadline, order_id,
                )
            elif _now() > deadline:
                await _fail_order(conn, order_id,
                                  "Manual DNS-01 confirmation deadline passed without confirmation.")
            return  # respond happens via the dns-confirm endpoint

        # --- Automated provider (e.g. Cloudflare). ---
        creds, row_exists = await _load_credentials(conn, order["account_id"])
        if not row_exists:
            await _fail_order(conn, order_id,
                              f"No DNS provider credentials configured for provider '{provider_name}'.")
            return
        if creds is None:
            await _fail_order(conn, order_id,
                              "DNS provider credentials could not be decrypted; re-enter them in Settings.")
            return

        provider = get_provider(provider_name, creds)

        # Publish any not-yet-published challenge (CAS so two replicas can't double-publish).
        for ch in challenges:
            if ch["dns_record_published"]:
                continue
            flipped = await conn.fetchval(
                """UPDATE acme_challenges SET dns_record_published = TRUE, dns_published_at = NOW()
                   WHERE id = $1 AND dns_record_published = FALSE RETURNING id""",
                ch["id"],
            )
            if not flipped:
                continue
            name = ACMEService._challenge_dns_name(ch["domain"])
            try:
                await provider.add_txt_record(name, ch["dns_txt_value"])
                await record_event(order_id, "acme.dns01.publish",
                                   message=f"Published TXT {name}; waiting for DNS propagation before asking the CA to validate.",
                                   details={"name": name, "provider": provider_name}, conn=conn)
            except DnsProviderError as exc:
                # Revert so the next cycle retries the publish; keep the order pending. exc is sanitized.
                await conn.execute(
                    "UPDATE acme_challenges SET dns_record_published = FALSE, dns_published_at = NULL WHERE id = $1",
                    ch["id"],
                )
                await record_event(order_id, "acme.dns01.publish", severity="WARNING",
                                   message=f"Publish failed for {name}: {exc}",
                                   details={"name": name, "provider": provider_name}, conn=conn)
                return

        # All published? Then respond once the min-age gate has elapsed (across cycles, no sleep).
        rows = await conn.fetch(
            "SELECT dns_record_published, dns_published_at FROM acme_challenges WHERE order_id = $1 AND challenge_type = 'dns-01'",
            order_id,
        )
        if any(not r["dns_record_published"] for r in rows):
            return
        published_ats = [_aware(r["dns_published_at"]) for r in rows if r["dns_published_at"]]
        if not published_ats:
            return
        if (_now() - min(published_ats)).total_seconds() < PROPAGATION_GRACE_SECONDS:
            return  # wait one more cycle

        # Only POST the challenge response if something still needs validating — avoids re-POSTing
        # every cycle (and bumping dns01_last_attempt_at) once the CA already has them processing.
        still_pending = await conn.fetchval(
            """SELECT 1 FROM acme_challenges WHERE order_id = $1 AND challenge_type = 'dns-01'
               AND (status IN ('pending', 'failed') OR status IS NULL) LIMIT 1""",
            order_id,
        )
        if not still_pending:
            return

        await acme_svc.respond_to_challenges(order_id)
        await conn.execute("UPDATE letsencrypt_orders SET dns01_last_attempt_at = NOW() WHERE id = $1", order_id)
        await record_event(order_id, "acme.dns01.responded",
                           message="Told the CA to validate the DNS-01 challenge(s).", conn=conn)
    finally:
        await close_database_connection(conn)


async def confirm_manual_dns01(order_id: int) -> Dict:
    """Called by POST /orders/{id}/dns-confirm for the manual provider: mark the TXT published and
    tell the CA to validate. Returns a small status dict."""
    conn = await get_database_connection()
    try:
        await conn.execute(
            """UPDATE acme_challenges SET dns_record_published = TRUE, dns_published_at = COALESCE(dns_published_at, NOW())
               WHERE order_id = $1 AND challenge_type = 'dns-01'""",
            order_id,
        )
        await acme_svc.respond_to_challenges(order_id)
        await conn.execute("UPDATE letsencrypt_orders SET dns01_last_attempt_at = NOW() WHERE id = $1", order_id)
        await record_event(order_id, "acme.dns01.responded",
                           message="Manual DNS-01 confirmed; told the CA to validate.", conn=conn)
        return {"ok": True}
    finally:
        await close_database_connection(conn)


async def retry_invalid_dns01(order_id: int) -> None:
    """Bounded fresh-order recovery for a dns-01 order that went `invalid` (e.g. propagation lag).
    Winner-only CAS on `dns01_retry_claimed`; cleans the old TXT, mints a child order. No-op for
    http-01 or when the budget is exhausted."""
    conn = await get_database_connection()
    child_created = False
    try:
        order = await conn.fetchrow(
            """SELECT o.*, a.dns_provider FROM letsencrypt_orders o
               JOIN letsencrypt_accounts a ON o.account_id = a.id WHERE o.id = $1""",
            order_id,
        )
        if not order or order["challenge_type"] != "dns-01":
            return
        if (order["dns01_attempts"] or 0) >= MAX_RETRIES:
            return  # budget exhausted; stays terminal invalid

        # Winner-only claim (closes the cross-replica double-mint race).
        claimed = await conn.fetchval(
            """UPDATE letsencrypt_orders SET dns01_retry_claimed = TRUE, updated_at = NOW()
               WHERE id = $1 AND status = 'invalid' AND dns01_retry_claimed = FALSE RETURNING id""",
            order_id,
        )
        if not claimed:
            return

        provider_name = (order["dns_provider"] or "manual").strip()
        # Best-effort cleanup of this order's TXT before minting the replacement.
        if provider_name != "manual" and is_supported(provider_name):
            creds, _exists = await _load_credentials(conn, order["account_id"])
            if creds:
                provider = get_provider(provider_name, creds)
                chs = await conn.fetch(
                    "SELECT domain, dns_txt_value FROM acme_challenges WHERE order_id = $1 AND challenge_type = 'dns-01'",
                    order_id,
                )
                for ch in chs:
                    try:
                        await provider.remove_txt_record(ACMEService._challenge_dns_name(ch["domain"]), ch["dns_txt_value"])
                    except DnsProviderError:
                        pass  # tolerate; the reconcile sweep will retry
        await conn.execute(
            "UPDATE acme_challenges SET dns_record_cleaned = TRUE WHERE order_id = $1 AND dns_record_published = TRUE",
            order_id,
        )

        import json
        domains = json.loads(order["domains"]) if isinstance(order["domains"], str) else (order["domains"] or [])
        cluster_ids = json.loads(order["cluster_ids"]) if isinstance(order["cluster_ids"], str) else (order["cluster_ids"] or [])
        next_attempts = (order["dns01_attempts"] or 0) + 1
        child = await acme_svc.create_order(
            order["account_id"], domains, cluster_ids, challenge_type="dns-01",
            created_by=order["created_by"],
        )
        child_created = True
        await conn.execute(
            """UPDATE letsencrypt_orders
               SET dns01_attempts = $1, dns01_parent_order_id = $2, dns01_last_attempt_at = NOW()
               WHERE id = $3""",
            next_attempts, order_id, child["order_id"],
        )
        await record_event(order_id, "acme.dns01.validation", severity="WARNING",
                           message=f"DNS-01 order invalid; minted retry #{next_attempts} (order {child['order_id']}).",
                           details={"child_order_id": child["order_id"], "attempt": next_attempts}, conn=conn)
    except Exception as exc:  # noqa: BLE001
        logger.error(f"[DNS01-RETRY] order {order_id}: {exc}")
        # A transient failure (e.g. CA rate limit) BEFORE the child was minted must NOT permanently
        # burn the retry slot — reset the claim so the next cycle can retry. If the child was already
        # created, leave the claim set (resetting would double-mint).
        if not child_created:
            try:
                await conn.execute(
                    "UPDATE letsencrypt_orders SET dns01_retry_claimed = FALSE WHERE id = $1 AND status = 'invalid'",
                    order_id,
                )
            except Exception:
                pass
    finally:
        await close_database_connection(conn)


async def reconcile_dns01_cleanup() -> None:
    """Best-effort sweep that removes any TXT records left published for terminal orders (covers a
    cleanup that failed, or the kill-switch being flipped off mid-flight). NOT gated by the
    kill-switch. Runs once per completion cycle."""
    conn = await get_database_connection()
    try:
        rows = await conn.fetch(
            """SELECT c.id AS chal_id, c.order_id, c.domain, c.dns_txt_value, o.account_id, a.dns_provider
               FROM acme_challenges c
               JOIN letsencrypt_orders o ON c.order_id = o.id
               JOIN letsencrypt_accounts a ON o.account_id = a.id
               WHERE c.challenge_type = 'dns-01'
                 AND c.dns_record_published = TRUE
                 AND COALESCE(c.dns_record_cleaned, FALSE) = FALSE
                 AND o.status IN ('valid', 'invalid', 'cancelled')
               LIMIT 50""",
        )
        for r in rows:
            provider_name = (r["dns_provider"] or "manual").strip()
            if provider_name == "manual" or not is_supported(provider_name):
                # Manual: nothing to call; mark cleaned so we stop revisiting.
                await conn.execute("UPDATE acme_challenges SET dns_record_cleaned = TRUE WHERE id = $1", r["chal_id"])
                continue
            creds, _exists = await _load_credentials(conn, r["account_id"])
            if creds is None:
                continue  # can't clean without creds; leave for a later pass
            provider = get_provider(provider_name, creds)
            try:
                await provider.remove_txt_record(ACMEService._challenge_dns_name(r["domain"]), r["dns_txt_value"])
                await conn.execute("UPDATE acme_challenges SET dns_record_cleaned = TRUE WHERE id = $1", r["chal_id"])
                await record_event(r["order_id"], "acme.dns01.cleanup",
                                   message=f"Cleaned up TXT for {r['domain']}", conn=conn)
            except DnsProviderError:
                pass  # retry next sweep
    except Exception as exc:  # noqa: BLE001
        logger.debug(f"[DNS01-RECONCILE] skipped: {exc}")
    finally:
        await close_database_connection(conn)
