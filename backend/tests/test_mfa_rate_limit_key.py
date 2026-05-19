"""Tests for middleware.mfa_rate_limit_key — user-aware + ingress-aware key."""
import importlib
from datetime import datetime, timedelta
from typing import Dict, Optional

import pytest
from fastapi import Request
from jose import jwt


def _make_request(
    headers: Optional[Dict[str, str]] = None,
    peer: str = "127.0.0.1",
) -> Request:
    """Tiny ASGI scope shim — enough for the key_func surface."""
    raw_headers = []
    if headers:
        raw_headers = [
            (k.encode("latin-1"), v.encode("latin-1")) for k, v in headers.items()
        ]
    scope = {
        "type": "http",
        "headers": raw_headers,
        "client": (peer, 12345),
        "method": "POST",
        "path": "/api/mfa/enroll/start",
        "query_string": b"",
    }
    return Request(scope)


@pytest.fixture
def reload_key(monkeypatch):
    """Reload the key module so MFA_TRUSTED_PROXY_CIDRS is re-parsed."""

    def _reload(**env):
        for var in ("MFA_TRUSTED_PROXY_CIDRS",):
            monkeypatch.delenv(var, raising=False)
        for k, v in env.items():
            monkeypatch.setenv(k, v)
        from middleware import mfa_rate_limit_key as m
        return importlib.reload(m)

    return _reload


# ---------------------------------------------------------------------------
# User-aware key extraction
# ---------------------------------------------------------------------------


def _mint_jwt(user_id, claim: str = "user_id") -> str:
    """Mint a test JWT. Note: RFC 7519 says ``sub`` is a StringOrURI,
    and python-jose validates that type when decoding, so callers that use
    ``claim='sub'`` must pass a string user_id (matches production behavior
    where auth_middleware also accepts string ``sub``)."""
    from config import JWT_ALGORITHM, JWT_SECRET_KEY
    payload = {
        claim: user_id,
        "exp": datetime.utcnow() + timedelta(minutes=10),
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)


def test_user_aware_via_user_id_claim(reload_key):
    m = reload_key()
    token = _mint_jwt(42, claim="user_id")
    req = _make_request(headers={"authorization": f"Bearer {token}"})
    assert m.mfa_rate_limit_key(req) == "user:42"


def test_user_aware_via_sub_claim(reload_key):
    m = reload_key()
    token = _mint_jwt("7", claim="sub")  # JWT spec: sub is a string
    req = _make_request(headers={"authorization": f"Bearer {token}"})
    assert m.mfa_rate_limit_key(req) == "user:7"


def test_no_auth_header_falls_back_to_ip(reload_key):
    m = reload_key()
    req = _make_request(peer="203.0.113.5")
    assert m.mfa_rate_limit_key(req) == "ip:203.0.113.5"


def test_missing_bearer_prefix_falls_back_to_ip(reload_key):
    m = reload_key()
    req = _make_request(headers={"authorization": "abc.def.ghi"}, peer="203.0.113.5")
    assert m.mfa_rate_limit_key(req) == "ip:203.0.113.5"


def test_bearer_null_or_undefined_falls_back_to_ip(reload_key):
    m = reload_key()
    for bogus in ("null", "undefined", "", "   "):
        req = _make_request(
            headers={"authorization": f"Bearer {bogus}"}, peer="198.51.100.9"
        )
        assert m.mfa_rate_limit_key(req) == "ip:198.51.100.9"


def test_tampered_jwt_falls_back_to_ip(reload_key):
    """A token with a forged signature must NOT be honored — fallback to IP."""
    m = reload_key()
    bad = "eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjogMTIzfQ.NOT_A_VALID_SIGNATURE"
    req = _make_request(headers={"authorization": f"Bearer {bad}"}, peer="10.1.2.3")
    assert m.mfa_rate_limit_key(req) == "ip:10.1.2.3"


def test_expired_jwt_falls_back_to_ip(reload_key):
    m = reload_key()
    from config import JWT_ALGORITHM, JWT_SECRET_KEY
    payload = {
        "user_id": 9,
        "exp": datetime.utcnow() - timedelta(minutes=5),
    }
    expired = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)
    req = _make_request(headers={"authorization": f"Bearer {expired}"}, peer="10.0.0.7")
    assert m.mfa_rate_limit_key(req) == "ip:10.0.0.7"


# ---------------------------------------------------------------------------
# Trusted-proxy X-Forwarded-For handling
# ---------------------------------------------------------------------------


def test_untrusted_peer_xff_is_ignored(reload_key):
    """X-Forwarded-For from an untrusted client cannot move buckets."""
    m = reload_key()  # no trusted CIDRs
    req = _make_request(
        headers={"x-forwarded-for": "1.2.3.4"},
        peer="203.0.113.5",
    )
    assert m.mfa_rate_limit_key(req) == "ip:203.0.113.5"


def test_trusted_peer_xff_is_honored(reload_key):
    """Peer in trusted CIDR → first XFF hop becomes the bucket."""
    m = reload_key(MFA_TRUSTED_PROXY_CIDRS="10.0.0.0/8")
    req = _make_request(
        headers={"x-forwarded-for": "203.0.113.42, 10.0.0.99"},
        peer="10.0.0.99",
    )
    assert m.mfa_rate_limit_key(req) == "ip:203.0.113.42"


def test_trusted_cidr_multiple_ranges(reload_key):
    m = reload_key(MFA_TRUSTED_PROXY_CIDRS="10.0.0.0/8, 172.16.0.0/12")
    req = _make_request(
        headers={"x-forwarded-for": "198.51.100.4"},
        peer="172.16.5.5",
    )
    assert m.mfa_rate_limit_key(req) == "ip:198.51.100.4"


def test_trusted_peer_no_xff_falls_back_to_peer(reload_key):
    m = reload_key(MFA_TRUSTED_PROXY_CIDRS="10.0.0.0/8")
    req = _make_request(peer="10.0.0.99")
    assert m.mfa_rate_limit_key(req) == "ip:10.0.0.99"


def test_invalid_cidr_in_env_is_logged_and_ignored(reload_key, caplog):
    import logging
    with caplog.at_level(logging.WARNING, logger="middleware.mfa_rate_limit_key"):
        m = reload_key(MFA_TRUSTED_PROXY_CIDRS="not-a-cidr, 10.0.0.0/8")
    assert any("ignoring invalid CIDR" in r.message for r in caplog.records)
    # The valid one is still effective.
    req = _make_request(
        headers={"x-forwarded-for": "9.9.9.9"},
        peer="10.0.0.1",
    )
    assert m.mfa_rate_limit_key(req) == "ip:9.9.9.9"


def test_user_bucket_wins_over_xff(reload_key):
    """Auth always wins, even from a trusted proxy."""
    m = reload_key(MFA_TRUSTED_PROXY_CIDRS="10.0.0.0/8")
    token = _mint_jwt(99)  # integer user_id claim
    req = _make_request(
        headers={
            "authorization": f"Bearer {token}",
            "x-forwarded-for": "1.1.1.1",
        },
        peer="10.0.0.1",
    )
    assert m.mfa_rate_limit_key(req) == "user:99"


def test_no_client_in_scope_does_not_crash(reload_key):
    m = reload_key()
    scope = {
        "type": "http",
        "headers": [],
        "client": None,
        "method": "POST",
        "path": "/api/mfa/enroll/start",
        "query_string": b"",
    }
    req = Request(scope)
    # Whatever it returns, it must be deterministic and not raise.
    out = m.mfa_rate_limit_key(req)
    assert out.startswith("ip:")
