"""Issue #35 — ACME DNS-01 (v1.8.0): at-rest encryption for per-account DNS provider credentials.

Mirrors the established Fernet + HKDF(SECRET_KEY) pattern used for the VRRP secret
(backend/services/keepalived_config.py) and TOTP secrets (backend/services/mfa_service.py):
prefer an explicit DNS_PROVIDER_ENCRYPTION_KEY env var (enables key rotation), else derive a
stable key from SECRET_KEY via HKDF with a versioned info string.

DNS provider credentials are a small dict (e.g. {"api_token": "..."}). They are JSON-serialized,
encrypted to a Fernet token string for storage, and only ever decrypted in-process when a DNS-01
order needs to talk to the provider. Plaintext credentials are NEVER logged or returned by the API.

NOTE on key rotation: if SECRET_KEY rotates and DNS_PROVIDER_ENCRYPTION_KEY is not set, previously
stored credentials become undecryptable (decrypt returns None). Callers MUST treat a None result as
"credentials unavailable — re-enter in Settings" and surface a clear error, never a silent hang.
"""
from __future__ import annotations

import base64
import json
import logging
import os
from typing import Dict, Optional

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from config import SECRET_KEY

logger = logging.getLogger(__name__)

_fernet_instance: Optional[Fernet] = None


def _resolve_fernet_key() -> bytes:
    """Prefer an explicit DNS_PROVIDER_ENCRYPTION_KEY; else derive from SECRET_KEY via HKDF
    with a versioned info string (so credentials survive restarts)."""
    explicit = os.getenv("DNS_PROVIDER_ENCRYPTION_KEY", "").strip()
    if explicit:
        try:
            Fernet(explicit.encode())
            return explicit.encode()
        except Exception as exc:  # noqa: BLE001
            logger.error("DNS_PROVIDER_ENCRYPTION_KEY env var present but invalid: %s", exc)
    logger.warning(
        "DNS_PROVIDER_ENCRYPTION_KEY not set; deriving the DNS-credentials encryption key from "
        "SECRET_KEY. Set DNS_PROVIDER_ENCRYPTION_KEY to a Fernet key to enable key rotation."
    )
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"dns-provider-creds-v1")
    derived = hkdf.derive(SECRET_KEY.encode("utf-8"))
    return base64.urlsafe_b64encode(derived)


def _get_fernet() -> Fernet:
    global _fernet_instance
    if _fernet_instance is None:
        _fernet_instance = Fernet(_resolve_fernet_key())
    return _fernet_instance


def reset_fernet_for_tests() -> None:
    """Test-only hook to force re-resolution after env mutation."""
    global _fernet_instance
    _fernet_instance = None


def encrypt_dns_credentials(credentials: Dict[str, str]) -> str:
    """JSON-serialize and Fernet-encrypt a credentials dict to a storable token string."""
    payload = json.dumps(credentials, separators=(",", ":")).encode("utf-8")
    return _get_fernet().encrypt(payload).decode("utf-8")


def decrypt_dns_credentials(token: str) -> Optional[Dict[str, str]]:
    """Decrypt a stored token back to the credentials dict. Returns None if the token can't be
    decrypted (e.g. key rotated) — callers must surface a clear 're-enter credentials' error."""
    try:
        plain = _get_fernet().decrypt(token.encode("utf-8")).decode("utf-8")
        data = json.loads(plain)
        if not isinstance(data, dict):
            logger.error("Decrypted DNS credentials are not a JSON object")
            return None
        return data
    except InvalidToken:
        logger.warning("Failed to decrypt DNS provider credentials (invalid Fernet token)")
        return None
    except Exception as exc:  # noqa: BLE001
        logger.error("Unexpected error decrypting DNS provider credentials: %s", exc)
        return None
