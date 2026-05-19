"""MFA rate-limit configuration (env-overridable).

Best-practice pattern:
  - Secure-by-default values live in code (kept in sync with the threat model).
  - Operations can override per-environment via env vars (ConfigMap on K8s)
    WITHOUT a code change / re-release.
  - All limits funnel through a single named constant so the decorator stays
    declarative (``@limiter.limit(MFA_LIMITS.enroll_start)``).

Env-var precedence::

    MFA_RATE_LIMIT_<NAME>  >  default in code

slowapi limit string syntax: ``<count>/<period>`` where period is
``second|minute|hour|day``. Example: ``"5/minute"``.

NOTE: slowapi binds limits at import time. A change to an env var requires a
backend restart (rolling restart on K8s, ``docker compose restart backend``
locally). This is consistent with how ``SECRET_KEY`` / ``MFA_ENCRYPTION_KEY``
behave.
"""
from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# slowapi limit-string format guard. Keeps a typo from silently disabling
# rate-limiting at process start.
_LIMIT_RE = re.compile(r"^\d+/(second|minute|hour|day)$")


def _env(name: str, default: str) -> str:
    """Read ``MFA_RATE_LIMIT_<NAME>``; fall back to ``default``.

    Validates the limit string. On bad input, logs a warning and returns the
    secure default instead of crashing the process.
    """
    value = os.getenv(f"MFA_RATE_LIMIT_{name}", default).strip()
    if not _LIMIT_RE.match(value):
        logger.warning(
            "MFA_RATE_LIMIT_%s='%s' is not a valid slowapi limit string "
            "(expected '<n>/<second|minute|hour|day>'); using default '%s'.",
            name, value, default,
        )
        return default
    return value


@dataclass(frozen=True)
class MfaRateLimits:
    """Aggregate of MFA endpoint rate-limit strings (slowapi format).

    Defaults assume the rate-limit ``key_func`` is ``mfa_rate_limit_key``
    (user-aware + ingress-aware), NOT raw IP. Per-user buckets are safe to
    keep generous because a misbehaving user only burns their own quota and
    cannot starve the rest of the org. If you re-key on raw IP, retighten
    these values (see README + ``MFA_RATE_LIMIT_<NAME>`` env overrides).
    """

    # Enrollment lifecycle — per-user buckets, large enough for org-wide rollout
    enroll_start: str = _env("ENROLL_START", "10/minute")
    enroll_confirm: str = _env("ENROLL_CONFIRM", "10/minute")

    # Self-service maintenance
    disable: str = _env("DISABLE", "10/minute")
    regenerate_backup_codes: str = _env("REGENERATE_BACKUP_CODES", "5/hour")

    # Admin operations (per-admin bucket; bulk reset stays tight because
    # it is an emergency-only flow).
    admin_reset: str = _env("ADMIN_RESET", "60/hour")
    admin_reset_all: str = _env("ADMIN_RESET_ALL", "1/day")


# Module-level singleton — import this from routers/mfa.py.
MFA_LIMITS = MfaRateLimits()
