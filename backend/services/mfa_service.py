"""MFA (TOTP + backup codes) service layer — Issue #18, v1.6.0.

Owns the cryptographic and persistence-shape concerns of multi-factor auth:
  - TOTP secret generation / verification with replay protection (RFC 6238)
  - Backup code generation, hashing (bcrypt) and atomic single-use consumption
  - Fernet-based encryption of TOTP secrets at rest

Strictly no logging of secrets — only metadata (lengths, counts) is logged.
"""
from __future__ import annotations

import asyncio
import base64
import logging
import os
import secrets as _secrets
import time
from typing import List, Optional, Tuple
from urllib.parse import quote

import bcrypt
import pyotp
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from config import SECRET_KEY

logger = logging.getLogger(__name__)

# RFC 6238 parameters — kept conservative for widest authenticator app compatibility.
TOTP_DIGITS = 6
TOTP_PERIOD = 30
TOTP_DIGEST = "sha1"
TOTP_VALID_WINDOW_STEPS = 1  # ±1 step (±30s) tolerance

# Backup code spec (Plan section 5).
# Alphabet drops the confusing pairs: 0/O, 1/I, L. Resulting size is 31, which
# still yields 31**8 ≈ 8.5×10^11 combinations per half — far beyond brute-force.
BACKUP_CODE_COUNT = 10
BACKUP_CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
BACKUP_CODE_HALF_LEN = 4  # XXXX-YYYY

# OTP URI defaults.
DEFAULT_ISSUER = "HAProxy OpenManager"
ACCOUNT_LABEL_DOMAIN_FALLBACK = "haproxy-openmanager"


# ---------------------------------------------------------------------------
# Fernet key resolution
# ---------------------------------------------------------------------------


_fernet_instance: Optional[Fernet] = None


def _resolve_fernet_key() -> bytes:
    """Resolve the Fernet key, preferring the explicit env var.

    Falls back to HKDF over SECRET_KEY with a versioned info string so a future
    rotation can be expressed by bumping the version suffix.
    """
    explicit = os.getenv("MFA_ENCRYPTION_KEY", "").strip()
    if explicit:
        try:
            Fernet(explicit.encode())
            return explicit.encode()
        except Exception as exc:
            logger.error("MFA_ENCRYPTION_KEY env var present but invalid: %s", exc)
            # fall through to HKDF derivation rather than crashing the app

    logger.warning(
        "MFA_ENCRYPTION_KEY env var not set or invalid; deriving from SECRET_KEY (v1). "
        "Set an explicit MFA_ENCRYPTION_KEY in production to enable key rotation."
    )
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"mfa-totp-secret-v1",
    )
    derived = hkdf.derive(SECRET_KEY.encode("utf-8"))
    return base64.urlsafe_b64encode(derived)


def _get_fernet() -> Fernet:
    global _fernet_instance
    if _fernet_instance is None:
        _fernet_instance = Fernet(_resolve_fernet_key())
    return _fernet_instance


def reset_fernet_for_tests() -> None:
    """Test-only hook to force re-resolution of the Fernet key after env mutation."""
    global _fernet_instance
    _fernet_instance = None


# ---------------------------------------------------------------------------
# TOTP secrets
# ---------------------------------------------------------------------------


def generate_totp_secret() -> str:
    """Return a fresh base32 TOTP secret (32 chars)."""
    return pyotp.random_base32()


def encrypt_secret(secret_plain: str) -> str:
    """Fernet-encrypt the base32 secret. Returns str for direct DB storage."""
    token = _get_fernet().encrypt(secret_plain.encode("utf-8"))
    return token.decode("utf-8")


def decrypt_secret(secret_encrypted: str) -> Optional[str]:
    """Decrypt a previously stored secret. Returns None when the token can't be
    decrypted (e.g. key rotated without re-enroll). Never raises to the caller.
    """
    try:
        return _get_fernet().decrypt(secret_encrypted.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        logger.warning("Failed to decrypt MFA secret (invalid Fernet token)")
        return None
    except Exception as exc:
        logger.error("Unexpected error decrypting MFA secret: %s", exc)
        return None


def build_otpauth_uri(account_label: str, secret_plain: str, issuer: str = DEFAULT_ISSUER) -> str:
    """Build an otpauth:// URI that all major authenticator apps accept.

    Format: otpauth://totp/<issuer>:<account>?secret=<b32>&issuer=<issuer>&algorithm=SHA1&digits=6&period=30
    """
    issuer_q = quote(issuer, safe="")
    label = f"{issuer}:{account_label}"
    label_q = quote(label, safe=":@")
    return (
        f"otpauth://totp/{label_q}?secret={secret_plain}"
        f"&issuer={issuer_q}&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_PERIOD}"
    )


def build_account_label(username: str, hostname_hint: Optional[str] = None) -> str:
    """Compose the per-user otpauth label, respecting env > hostname > fallback."""
    domain = (
        os.getenv("MFA_ACCOUNT_LABEL_DOMAIN", "").strip()
        or (hostname_hint or "").strip()
        or ACCOUNT_LABEL_DOMAIN_FALLBACK
    )
    return f"{username}@{domain}"


def verify_totp_with_replay_guard(
    secret_plain: str,
    code: str,
    last_used_step: Optional[int],
) -> Tuple[bool, Optional[int]]:
    """Verify a 6-digit TOTP code with explicit per-step replay protection.

    Returns (success, step_consumed). Caller persists the consumed step on success.

    Implementation notes:
      - pyotp.TOTP.at(seconds_since_epoch) — to target step N we pass step*PERIOD.
      - secrets.compare_digest is used for constant-time comparison.
      - Replay guard rejects codes whose step is <= the previously consumed step.
    """
    if not secret_plain or not code:
        return (False, None)
    code = code.strip()
    if len(code) != TOTP_DIGITS or not code.isdigit():
        return (False, None)

    totp = pyotp.TOTP(secret_plain, digits=TOTP_DIGITS, interval=TOTP_PERIOD, digest=TOTP_DIGEST)
    now = int(time.time())
    current_step = now // TOTP_PERIOD

    for offset in (0, -1, 1):
        step = current_step + offset
        expected = totp.at(step * TOTP_PERIOD)
        if len(expected) == len(code) and _secrets.compare_digest(expected, code):
            if last_used_step is not None and step <= last_used_step:
                return (False, None)
            return (True, step)
    return (False, None)


# ---------------------------------------------------------------------------
# Backup codes
# ---------------------------------------------------------------------------


def generate_backup_codes(count: int = BACKUP_CODE_COUNT) -> List[str]:
    """Return ``count`` plain-text backup codes formatted as ``XXXX-YYYY``."""
    codes: List[str] = []
    for _ in range(count):
        left = "".join(_secrets.choice(BACKUP_CODE_ALPHABET) for _ in range(BACKUP_CODE_HALF_LEN))
        right = "".join(_secrets.choice(BACKUP_CODE_ALPHABET) for _ in range(BACKUP_CODE_HALF_LEN))
        codes.append(f"{left}-{right}")
    return codes


def normalize_backup_code(user_input: str) -> str:
    """Canonical form for comparison: uppercase, strip dashes/spaces."""
    if not user_input:
        return ""
    return user_input.strip().upper().replace("-", "").replace(" ", "")


async def _hash_one_backup_code(code_plain: str) -> str:
    """Bcrypt-hash a single backup code on a worker thread."""
    normalized = normalize_backup_code(code_plain)
    hashed = await asyncio.to_thread(bcrypt.hashpw, normalized.encode("utf-8"), bcrypt.gensalt())
    return hashed.decode("utf-8")


async def hash_backup_codes(codes_plain: List[str]) -> List[str]:
    """Hash backup codes in parallel (each bcrypt op runs in its own thread)."""
    return await asyncio.gather(*(_hash_one_backup_code(c) for c in codes_plain))


async def check_backup_code(user_input: str, code_hash: str) -> bool:
    """Run a single bcrypt verify on the worker pool."""
    normalized = normalize_backup_code(user_input)
    if not normalized:
        return False
    return await asyncio.to_thread(
        bcrypt.checkpw, normalized.encode("utf-8"), code_hash.encode("utf-8")
    )


# ---------------------------------------------------------------------------
# Misc helpers
# ---------------------------------------------------------------------------


def generate_challenge_token() -> str:
    """64-char hex challenge token for /api/auth/login → /mfa-verify hand-off."""
    return _secrets.token_hex(32)
