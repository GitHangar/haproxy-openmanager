"""MFA rate-limit key extraction (user-aware + ingress-aware).

Problem with the default ``slowapi.util.get_remote_address``:

  * Behind an ingress / reverse proxy / load balancer, every request looks
    like it originates from the same upstream IP (the proxy itself). A
    5/minute IP-bucket therefore becomes a 5/minute *whole-organization*
    bucket. In a 500-user enterprise rolling out MFA, this stalls the
    rollout to a trickle.

Strategy (combined B + C from the design review):

  1. **User-aware key (preferred):** if the request carries a valid Bearer
     JWT, derive the bucket from ``user:<id>``. Each authenticated user
     gets an isolated bucket, regardless of source IP. A malicious user
     burning their own quota cannot starve the other 499.

  2. **Trusted-proxy XFF fallback:** if the request is unauthenticated
     (e.g. ``/login`` flow, future endpoints) and the TCP peer is in
     ``MFA_TRUSTED_PROXY_CIDRS``, peel the first hop off ``X-Forwarded-For``.
     This preserves real-IP buckets behind a known ingress without
     accepting spoofed headers from the public internet.

  3. **Default fallback:** plain ``request.client.host`` (slowapi default).

JWT decode is intentionally signature-verified (replay/spoof protection)
and *sync* — slowapi's decorator hook is sync, and our JWT library
(python-jose) is sync as well. Failed verification silently downgrades
to IP-based bucketing — never crashes the decorator.

Env vars:
  * ``MFA_TRUSTED_PROXY_CIDRS`` — comma-separated CIDR list of trusted
    upstream proxies. Empty (default) disables XFF parsing entirely,
    which is the safe choice when the deployment topology is unknown.
    Examples:
        ``MFA_TRUSTED_PROXY_CIDRS=10.0.0.0/8,172.16.0.0/12``
        ``MFA_TRUSTED_PROXY_CIDRS=192.168.0.0/16``
"""
from __future__ import annotations

import logging
import os
from ipaddress import ip_address, ip_network
from typing import List

from fastapi import Request
from jose import jwt

logger = logging.getLogger(__name__)


def _parse_trusted_cidrs() -> List:
    """Parse the trusted-proxy CIDR list at import time.

    A malformed entry is logged and skipped — we never crash the process
    over a typo in operational config.
    """
    raw = os.getenv("MFA_TRUSTED_PROXY_CIDRS", "").strip()
    if not raw:
        return []
    nets = []
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            nets.append(ip_network(entry, strict=False))
        except ValueError:
            logger.warning(
                "MFA_TRUSTED_PROXY_CIDRS: ignoring invalid CIDR %r", entry
            )
    return nets


_TRUSTED_NETS = _parse_trusted_cidrs()


def _peer_ip(request: Request) -> str:
    """The TCP peer IP — never raises; falls back to ``0.0.0.0``."""
    return request.client.host if request.client else "0.0.0.0"


def _is_trusted_peer(peer: str) -> bool:
    if not _TRUSTED_NETS:
        return False
    try:
        peer_ip = ip_address(peer)
    except ValueError:
        return False
    return any(peer_ip in net for net in _TRUSTED_NETS)


def _real_ip(request: Request) -> str:
    """If TCP peer is in a trusted proxy CIDR, peel off the first
    ``X-Forwarded-For`` IP; otherwise return the peer.

    ``X-Forwarded-For`` from an *untrusted* peer is intentionally ignored —
    accepting it would let any client spoof their bucket.
    """
    peer = _peer_ip(request)
    if not _is_trusted_peer(peer):
        return peer
    xff = request.headers.get("X-Forwarded-For")
    if not xff:
        return peer
    first = xff.split(",")[0].strip()
    return first or peer


def _user_id_from_jwt(request: Request) -> str | None:
    """Sync JWT decode → ``user_id`` (or ``sub``) claim. None on failure.

    Uses the same secret + algorithm as ``auth_middleware`` so a token that
    is valid for the API surface is also valid for the rate-limit key.
    Bad / missing / expired tokens silently return None — slowapi falls
    back to IP bucketing.
    """
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[7:].strip()
    if not token or token in {"null", "undefined"}:
        return None
    # Late import to avoid pulling jose into module-load when not needed.
    try:
        from config import JWT_ALGORITHM, JWT_SECRET_KEY
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
    except Exception:
        return None
    uid = payload.get("user_id") or payload.get("sub")
    if uid is None:
        return None
    return str(uid)


def mfa_rate_limit_key(request: Request) -> str:
    """slowapi ``key_func`` for MFA endpoints.

    Order:
      1. Authenticated → ``user:<id>``
      2. Trusted-proxy XFF → ``ip:<first hop>``
      3. TCP peer → ``ip:<peer>``
    """
    uid = _user_id_from_jwt(request)
    if uid is not None:
        return f"user:{uid}"
    return f"ip:{_real_ip(request)}"
