"""MFA router — Issue #18, v1.6.0.

All endpoints are additive; nothing here breaks existing JWT or apply_service flows.
Authentication is JWT-based (Bearer). Admin endpoints additionally require
``users.is_admin == True`` (canonical super-admin flag).
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Header, HTTPException, Request

from auth_middleware import get_current_user_from_token
from database.connection import close_database_connection, get_database_connection
from middleware.mfa_rate_limit_key import mfa_rate_limit_key
from middleware.mfa_rate_limits import MFA_LIMITS
from middleware.rate_limiter import limiter
from models.mfa import (
    MfaAdminResetAllRequest,
    MfaAdminResetRequest,
    MfaDisableRequest,
    MfaEnrollConfirmRequest,
    MfaEnrollConfirmResponse,
    MfaEnrollStartResponse,
    MfaRegenerateBackupRequest,
    MfaRegenerateBackupResponse,
    MfaStatusResponse,
)
from services import mfa_service
from utils.activity_log import log_user_activity

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/mfa", tags=["MFA"])

# Lifecycle constants (Plan section 5)
PENDING_ENROLLMENT_TTL_SECONDS = 600  # 10 minutes — QR scan + verify window
PENDING_ENROLLMENT_MAX_ATTEMPTS = 5


# ---------------------------------------------------------------------------
# Authentication helpers
# ---------------------------------------------------------------------------


async def _require_user(authorization: Optional[str]) -> dict:
    user = await get_current_user_from_token(authorization)
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


async def _require_admin(authorization: Optional[str]) -> dict:
    user = await _require_user(authorization)
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="Admin privileges required")
    return user


async def _cleanup_expired_pending_enrollments(conn) -> None:
    try:
        await conn.execute(
            "DELETE FROM mfa_pending_enrollments WHERE expires_at < NOW()"
        )
    except Exception as exc:
        logger.debug(f"Pending-enrollment cleanup skipped: {exc}")


# ---------------------------------------------------------------------------
# Self status
# ---------------------------------------------------------------------------


@router.get(
    "/status",
    summary="MFA status for the authenticated user",
    response_model=MfaStatusResponse,
)
async def mfa_status(authorization: str = Header(None)):
    current = await _require_user(authorization)
    conn = await get_database_connection()
    try:
        row = await conn.fetchrow(
            """
            SELECT mfa_enabled, mfa_method, mfa_enrolled_at, mfa_last_used_at
              FROM users
             WHERE id = $1
            """,
            current["id"],
        )
        remaining = await conn.fetchval(
            """
            SELECT COUNT(*) FROM mfa_backup_codes
             WHERE user_id = $1 AND used_at IS NULL
            """,
            current["id"],
        )
    finally:
        await close_database_connection(conn)

    if not row:
        raise HTTPException(status_code=404, detail="User not found")

    return MfaStatusResponse(
        enabled=bool(row["mfa_enabled"]),
        method=row["mfa_method"],
        enrolled_at=row["mfa_enrolled_at"].isoformat() if row["mfa_enrolled_at"] else None,
        last_used_at=row["mfa_last_used_at"].isoformat() if row["mfa_last_used_at"] else None,
        backup_codes_remaining=int(remaining or 0),
    )


@router.get(
    "/admin/status/{user_id}",
    summary="Admin: MFA status of any user",
    response_model=MfaStatusResponse,
)
async def mfa_admin_status(user_id: int, authorization: str = Header(None)):
    await _require_admin(authorization)
    conn = await get_database_connection()
    try:
        row = await conn.fetchrow(
            """
            SELECT mfa_enabled, mfa_method, mfa_enrolled_at, mfa_last_used_at
              FROM users
             WHERE id = $1
            """,
            user_id,
        )
        remaining = await conn.fetchval(
            """
            SELECT COUNT(*) FROM mfa_backup_codes
             WHERE user_id = $1 AND used_at IS NULL
            """,
            user_id,
        )
    finally:
        await close_database_connection(conn)

    if not row:
        raise HTTPException(status_code=404, detail="User not found")

    return MfaStatusResponse(
        enabled=bool(row["mfa_enabled"]),
        method=row["mfa_method"],
        enrolled_at=row["mfa_enrolled_at"].isoformat() if row["mfa_enrolled_at"] else None,
        last_used_at=row["mfa_last_used_at"].isoformat() if row["mfa_last_used_at"] else None,
        backup_codes_remaining=int(remaining or 0),
    )


# ---------------------------------------------------------------------------
# Enrollment
# ---------------------------------------------------------------------------


@router.post(
    "/enroll/start",
    summary="Begin TOTP enrollment (returns secret + otpauth URI)",
    response_model=MfaEnrollStartResponse,
)
@limiter.limit(MFA_LIMITS.enroll_start, key_func=mfa_rate_limit_key)
async def mfa_enroll_start(request: Request, authorization: str = Header(None)):
    current = await _require_user(authorization)

    # Round 7 audit fix — REFUSE re-enrollment if the user is already MFA-on.
    # Without this guard a stolen JWT could silently rotate the victim's TOTP
    # secret + invalidate all their backup codes via /enroll/start ->
    # /enroll/confirm (overwriting `users.mfa_secret_encrypted` and replacing
    # `mfa_backup_codes`). To re-enroll, the user must first call /api/mfa/disable
    # (which requires a fresh TOTP) or an admin must run /api/mfa/admin-reset.
    secret_plain = mfa_service.generate_totp_secret()
    secret_encrypted = mfa_service.encrypt_secret(secret_plain)

    conn = await get_database_connection()
    blocked = False
    try:
        # Single transaction with SELECT FOR UPDATE closes the TOCTOU window
        # between the mfa_enabled check and the pending_enrollment upsert.
        async with conn.transaction():
            row = await conn.fetchrow(
                "SELECT mfa_enabled FROM users WHERE id = $1 FOR UPDATE",
                current["id"],
            )
            if row and row["mfa_enabled"]:
                blocked = True
            else:
                await _cleanup_expired_pending_enrollments(conn)
                await conn.execute(
                    """
                    INSERT INTO mfa_pending_enrollments
                        (user_id, secret_encrypted, attempts, expires_at)
                    VALUES ($1, $2, 0, NOW() + ($3 || ' seconds')::interval)
                    ON CONFLICT (user_id) DO UPDATE
                      SET secret_encrypted = EXCLUDED.secret_encrypted,
                          attempts = 0,
                          expires_at = EXCLUDED.expires_at,
                          created_at = CURRENT_TIMESTAMP
                    """,
                    current["id"],
                    secret_encrypted,
                    str(PENDING_ENROLLMENT_TTL_SECONDS),
                )
    finally:
        await close_database_connection(conn)

    if blocked:
        raise HTTPException(
            status_code=400,
            detail="MFA is already enabled. Disable it first (via /api/mfa/disable or admin reset) to re-enroll.",
        )

    hostname_hint = request.url.hostname if request.url else None
    label = mfa_service.build_account_label(current["username"], hostname_hint)
    otpauth_uri = mfa_service.build_otpauth_uri(label, secret_plain)

    await log_user_activity(
        user_id=current["id"],
        action="mfa.enrollment.started",
        resource_type="mfa",
        resource_id=str(current["id"]),
        details={"secret_len": len(secret_plain)},  # NEVER log the secret itself
        ip_address=str(request.client.host) if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )

    return MfaEnrollStartResponse(
        secret=secret_plain,
        otpauth_uri=otpauth_uri,
        expires_in=PENDING_ENROLLMENT_TTL_SECONDS,
    )


@router.post(
    "/enroll/confirm",
    summary="Confirm enrollment with a TOTP code; returns 10 backup codes once",
    response_model=MfaEnrollConfirmResponse,
)
@limiter.limit(MFA_LIMITS.enroll_confirm, key_func=mfa_rate_limit_key)
async def mfa_enroll_confirm(
    payload: MfaEnrollConfirmRequest,
    request: Request,
    authorization: str = Header(None),
):
    current = await _require_user(authorization)
    # Pre-generate plain codes & hashes outside the DB transaction so we
    # never hold a row lock for ~2-3s of bcrypt work.
    plain_codes = mfa_service.generate_backup_codes()
    hashes = await mfa_service.hash_backup_codes(plain_codes)

    ip = str(request.client.host) if request.client else None
    ua = request.headers.get("user-agent")

    # failure: { reason, attempts, http_status, detail }; success when None.
    failure: Optional[dict] = None
    conn = await get_database_connection()
    try:
        async with conn.transaction():
            # Lock the pending row so concurrent /enroll/confirm calls for the
            # same user can't both consume the same pending enrollment.
            pending = await conn.fetchrow(
                """
                SELECT secret_encrypted, attempts, expires_at
                  FROM mfa_pending_enrollments
                 WHERE user_id = $1
                 FOR UPDATE
                """,
                current["id"],
            )

            if not pending:
                failure = {
                    "reason": "no_pending",
                    "http_status": 410,
                    "detail": "No pending enrollment; start again",
                }
            else:
                from datetime import datetime as _dt
                if pending["expires_at"] and pending["expires_at"] < _dt.utcnow():
                    await conn.execute(
                        "DELETE FROM mfa_pending_enrollments WHERE user_id = $1",
                        current["id"],
                    )
                    failure = {
                        "reason": "expired",
                        "http_status": 410,
                        "detail": "Enrollment expired; start again",
                    }
                else:
                    secret_plain = mfa_service.decrypt_secret(pending["secret_encrypted"])
                    if not secret_plain:
                        await conn.execute(
                            "DELETE FROM mfa_pending_enrollments WHERE user_id = $1",
                            current["id"],
                        )
                        failure = {
                            "reason": "unreadable",
                            "http_status": 500,
                            "detail": "Pending enrollment unreadable; start again",
                        }
                    else:
                        ok, _step = mfa_service.verify_totp_with_replay_guard(
                            secret_plain, payload.code, None
                        )
                        if not ok:
                            new_attempts = (pending["attempts"] or 0) + 1
                            if new_attempts >= PENDING_ENROLLMENT_MAX_ATTEMPTS:
                                await conn.execute(
                                    "DELETE FROM mfa_pending_enrollments WHERE user_id = $1",
                                    current["id"],
                                )
                                failure = {
                                    "reason": "too_many_attempts",
                                    "attempts": new_attempts,
                                    "http_status": 410,
                                    "detail": "Enrollment invalidated; start again",
                                }
                            else:
                                await conn.execute(
                                    "UPDATE mfa_pending_enrollments SET attempts = $1 WHERE user_id = $2",
                                    new_attempts,
                                    current["id"],
                                )
                                failure = {
                                    "reason": "invalid_code",
                                    "attempts": new_attempts,
                                    "http_status": 401,
                                    "detail": "Invalid code",
                                }
                        else:
                            # Verified — finalize state inside the transaction.
                            await conn.execute(
                                """
                                UPDATE users
                                   SET mfa_enabled = TRUE,
                                       mfa_method = 'totp',
                                       mfa_secret_encrypted = $1,
                                       mfa_enrolled_at = NOW(),
                                       mfa_last_used_totp_step = NULL,
                                       mfa_last_used_at = NULL
                                 WHERE id = $2
                                """,
                                pending["secret_encrypted"],
                                current["id"],
                            )
                            await conn.execute(
                                "DELETE FROM mfa_backup_codes WHERE user_id = $1",
                                current["id"],
                            )
                            await conn.executemany(
                                "INSERT INTO mfa_backup_codes (user_id, code_hash) VALUES ($1, $2)",
                                [(current["id"], h) for h in hashes],
                            )
                            await conn.execute(
                                "DELETE FROM mfa_pending_enrollments WHERE user_id = $1",
                                current["id"],
                            )
    finally:
        await close_database_connection(conn)

    if failure is not None:
        # Log AFTER commit so the audit row reflects what actually persisted.
        await log_user_activity(
            user_id=current["id"],
            action="mfa.enrollment.failed",
            resource_type="mfa",
            resource_id=str(current["id"]),
            details={
                "reason": failure["reason"],
                "attempts": failure.get("attempts"),
            },
            ip_address=ip,
            user_agent=ua,
        )
        raise HTTPException(status_code=failure["http_status"], detail=failure["detail"])

    await log_user_activity(
        user_id=current["id"],
        action="mfa.enrollment.confirmed",
        resource_type="mfa",
        resource_id=str(current["id"]),
        details={"method": "totp"},
        ip_address=ip,
        user_agent=ua,
    )

    return MfaEnrollConfirmResponse(enabled=True, backup_codes=plain_codes, method="totp")


# ---------------------------------------------------------------------------
# Disable + regenerate
# ---------------------------------------------------------------------------


async def _verify_user_code(conn, user_row: dict, code: str) -> Optional[str]:
    """Verify a TOTP-or-backup code against the user's stored secret.

    Returns the method used ('totp' / 'backup') on success, None on failure.

    On TOTP success the step counter is bumped *atomically* — the UPDATE
    only succeeds if no other request consumed the same (or a newer) step
    in between. On backup success the consumed row's used_at is set with
    an atomic ``WHERE used_at IS NULL RETURNING id`` pattern.
    """
    secret_plain = mfa_service.decrypt_secret(user_row["mfa_secret_encrypted"])
    if secret_plain:
        ok, step = mfa_service.verify_totp_with_replay_guard(
            secret_plain, code, user_row["mfa_last_used_totp_step"]
        )
        if ok:
            bumped = await conn.fetchval(
                """
                UPDATE users
                   SET mfa_last_used_totp_step = $1, mfa_last_used_at = NOW()
                 WHERE id = $2
                   AND (mfa_last_used_totp_step IS NULL
                        OR mfa_last_used_totp_step < $1)
                 RETURNING id
                """,
                step,
                user_row["id"],
            )
            if bumped:
                return "totp"

    rows = await conn.fetch(
        """
        SELECT id, code_hash FROM mfa_backup_codes
         WHERE user_id = $1 AND used_at IS NULL
        """,
        user_row["id"],
    )
    for row in rows:
        if await mfa_service.check_backup_code(code, row["code_hash"]):
            consumed = await conn.fetchval(
                """
                UPDATE mfa_backup_codes
                   SET used_at = NOW()
                 WHERE id = $1 AND used_at IS NULL
                 RETURNING id
                """,
                row["id"],
            )
            if consumed:
                return "backup"
    return None


@router.post("/disable", summary="Disable MFA (requires current TOTP or backup)")
@limiter.limit(MFA_LIMITS.disable, key_func=mfa_rate_limit_key)
async def mfa_disable(
    payload: MfaDisableRequest,
    request: Request,
    authorization: str = Header(None),
):
    current = await _require_user(authorization)
    conn = await get_database_connection()
    try:
        user_row = await conn.fetchrow(
            """
            SELECT id, mfa_enabled, mfa_secret_encrypted, mfa_last_used_totp_step
              FROM users WHERE id = $1
            """,
            current["id"],
        )
        if not user_row or not user_row["mfa_enabled"]:
            raise HTTPException(status_code=400, detail="MFA is not enabled")

        method_used = await _verify_user_code(conn, dict(user_row), payload.code)
        if not method_used:
            await log_user_activity(
                user_id=current["id"],
                action="mfa.disable.failed",
                resource_type="mfa",
                resource_id=str(current["id"]),
                details={"reason": "invalid_code"},
                ip_address=str(request.client.host) if request.client else None,
                user_agent=request.headers.get("user-agent"),
            )
            raise HTTPException(status_code=401, detail="Invalid code")

        async with conn.transaction():
            await conn.execute(
                """
                UPDATE users
                   SET mfa_enabled = FALSE,
                       mfa_method = NULL,
                       mfa_secret_encrypted = NULL,
                       mfa_enrolled_at = NULL,
                       mfa_last_used_at = NULL,
                       mfa_last_used_totp_step = NULL
                 WHERE id = $1
                """,
                current["id"],
            )
            await conn.execute(
                "DELETE FROM mfa_backup_codes WHERE user_id = $1", current["id"]
            )
            await conn.execute(
                "DELETE FROM mfa_pending_logins WHERE user_id = $1", current["id"]
            )
            await conn.execute(
                "DELETE FROM mfa_pending_enrollments WHERE user_id = $1", current["id"]
            )
    finally:
        await close_database_connection(conn)

    await log_user_activity(
        user_id=current["id"],
        action="mfa.disabled.self",
        resource_type="mfa",
        resource_id=str(current["id"]),
        details={"verified_via": method_used},
        ip_address=str(request.client.host) if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    return {"enabled": False}


@router.post(
    "/backup-codes/regenerate",
    summary="Issue 10 fresh backup codes (TOTP required)",
    response_model=MfaRegenerateBackupResponse,
)
@limiter.limit(MFA_LIMITS.regenerate_backup_codes, key_func=mfa_rate_limit_key)
async def mfa_regenerate_backup_codes(
    payload: MfaRegenerateBackupRequest,
    request: Request,
    authorization: str = Header(None),
):
    current = await _require_user(authorization)
    # bcrypt-hash the new codes outside the DB transaction (~2-3s of CPU work).
    plain_codes = mfa_service.generate_backup_codes()
    hashes = await mfa_service.hash_backup_codes(plain_codes)

    ip = str(request.client.host) if request.client else None
    ua = request.headers.get("user-agent")

    failure: Optional[dict] = None
    conn = await get_database_connection()
    try:
        async with conn.transaction():
            user_row = await conn.fetchrow(
                """
                SELECT id, mfa_enabled, mfa_secret_encrypted, mfa_last_used_totp_step
                  FROM users WHERE id = $1
                 FOR UPDATE
                """,
                current["id"],
            )
            if not user_row or not user_row["mfa_enabled"]:
                failure = {"http_status": 400, "detail": "MFA is not enabled"}
            else:
                secret_plain = mfa_service.decrypt_secret(user_row["mfa_secret_encrypted"])
                if not secret_plain:
                    failure = {"http_status": 500, "detail": "MFA secret unreadable"}
                else:
                    ok, step = mfa_service.verify_totp_with_replay_guard(
                        secret_plain, payload.code, user_row["mfa_last_used_totp_step"]
                    )
                    if not ok:
                        failure = {"http_status": 401, "detail": "Invalid TOTP code"}
                    else:
                        bumped = await conn.fetchval(
                            """
                            UPDATE users
                               SET mfa_last_used_totp_step = $1, mfa_last_used_at = NOW()
                             WHERE id = $2
                               AND (mfa_last_used_totp_step IS NULL
                                    OR mfa_last_used_totp_step < $1)
                             RETURNING id
                            """,
                            step,
                            current["id"],
                        )
                        if not bumped:
                            failure = {"http_status": 401, "detail": "Invalid TOTP code"}
                        else:
                            await conn.execute(
                                "DELETE FROM mfa_backup_codes WHERE user_id = $1",
                                current["id"],
                            )
                            await conn.executemany(
                                "INSERT INTO mfa_backup_codes (user_id, code_hash) VALUES ($1, $2)",
                                [(current["id"], h) for h in hashes],
                            )
    finally:
        await close_database_connection(conn)

    if failure is not None:
        raise HTTPException(status_code=failure["http_status"], detail=failure["detail"])

    await log_user_activity(
        user_id=current["id"],
        action="mfa.backup_codes.regenerated",
        resource_type="mfa",
        resource_id=str(current["id"]),
        details={"codes_count": len(plain_codes)},
        ip_address=ip,
        user_agent=ua,
    )

    return MfaRegenerateBackupResponse(backup_codes=plain_codes)


# ---------------------------------------------------------------------------
# Admin operations
# ---------------------------------------------------------------------------


@router.post("/admin-reset/{user_id}", summary="Admin: reset a single user's MFA")
@limiter.limit(MFA_LIMITS.admin_reset, key_func=mfa_rate_limit_key)
async def mfa_admin_reset(
    user_id: int,
    payload: MfaAdminResetRequest,
    request: Request,
    authorization: str = Header(None),
):
    admin = await _require_admin(authorization)
    if user_id == admin["id"]:
        raise HTTPException(status_code=400, detail="Use /api/mfa/disable for self-reset")

    conn = await get_database_connection()
    try:
        target = await conn.fetchrow(
            "SELECT id, username, mfa_enabled FROM users WHERE id = $1", user_id
        )
        if not target:
            raise HTTPException(status_code=404, detail="User not found")

        async with conn.transaction():
            await conn.execute(
                """
                UPDATE users
                   SET mfa_enabled = FALSE,
                       mfa_method = NULL,
                       mfa_secret_encrypted = NULL,
                       mfa_enrolled_at = NULL,
                       mfa_last_used_at = NULL,
                       mfa_last_used_totp_step = NULL
                 WHERE id = $1
                """,
                user_id,
            )
            await conn.execute(
                "DELETE FROM mfa_backup_codes WHERE user_id = $1", user_id
            )
            await conn.execute(
                "DELETE FROM mfa_pending_logins WHERE user_id = $1", user_id
            )
            await conn.execute(
                "DELETE FROM mfa_pending_enrollments WHERE user_id = $1", user_id
            )
    finally:
        await close_database_connection(conn)

    await log_user_activity(
        user_id=admin["id"],
        action="mfa.disabled.admin_reset",
        resource_type="mfa",
        resource_id=str(user_id),
        details={
            "target_user_id": user_id,
            "target_username": target["username"],
            "admin_user_id": admin["id"],
            "reason": payload.reason,
        },
        ip_address=str(request.client.host) if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    return {"reset": True, "user_id": user_id}


@router.post(
    "/admin-reset-all",
    summary="Admin: emergency reset of MFA for all users (double confirm)",
)
@limiter.limit(MFA_LIMITS.admin_reset_all, key_func=mfa_rate_limit_key)
async def mfa_admin_reset_all(
    payload: MfaAdminResetAllRequest,
    request: Request,
    authorization: str = Header(None),
):
    admin = await _require_admin(authorization)
    # Pydantic's Literal already enforces the magic string, but check defensively too.
    if payload.confirm != "RESET ALL MFA":
        raise HTTPException(status_code=400, detail="Invalid confirmation string")

    conn = await get_database_connection()
    try:
        async with conn.transaction():
            reset_count = await conn.fetchval(
                """
                WITH affected AS (
                    UPDATE users
                       SET mfa_enabled = FALSE,
                           mfa_method = NULL,
                           mfa_secret_encrypted = NULL,
                           mfa_enrolled_at = NULL,
                           mfa_last_used_at = NULL,
                           mfa_last_used_totp_step = NULL
                     WHERE mfa_enabled = TRUE
                     RETURNING id
                )
                SELECT COUNT(*) FROM affected
                """
            )
            await conn.execute("DELETE FROM mfa_backup_codes")
            await conn.execute("DELETE FROM mfa_pending_logins")
            await conn.execute("DELETE FROM mfa_pending_enrollments")
    finally:
        await close_database_connection(conn)

    await log_user_activity(
        user_id=admin["id"],
        action="mfa.disabled.admin_bulk_reset",
        resource_type="mfa",
        resource_id=str(admin["id"]),
        details={
            "reset_count": int(reset_count or 0),
            "reason": payload.reason,
            "admin_user_id": admin["id"],
        },
        ip_address=str(request.client.host) if request.client else None,
        user_agent=request.headers.get("user-agent"),
    )
    return {"reset_count": int(reset_count or 0)}
