"""Unit tests for the MFA service layer (Issue #18, v1.6.0).

These tests cover the pure-Python side of MFA — no DB, no FastAPI.
"""
from __future__ import annotations

import asyncio
import os
import re
import sys
import time

import pytest

# Repo path setup (mirrors other tests in this folder).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pyotp  # noqa: E402

from services import mfa_service  # noqa: E402


# ---------------------------------------------------------------------------
# TOTP
# ---------------------------------------------------------------------------


class TestTotpSecret:
    def test_secret_is_base32(self):
        secret = mfa_service.generate_totp_secret()
        # pyotp.random_base32() returns 32-character base32 strings.
        assert len(secret) == 32
        assert re.fullmatch(r"[A-Z2-7]+", secret), "secret must be valid base32"

    def test_secrets_are_unique(self):
        secrets = {mfa_service.generate_totp_secret() for _ in range(50)}
        assert len(secrets) == 50


class TestVerifyTotp:
    def setup_method(self):
        self.secret = mfa_service.generate_totp_secret()
        self.totp = pyotp.TOTP(self.secret, digits=6, interval=30, digest="sha1")

    def test_happy_path(self):
        code = self.totp.now()
        ok, step = mfa_service.verify_totp_with_replay_guard(self.secret, code, None)
        assert ok is True
        assert step == int(time.time()) // 30

    def test_invalid_code_format_rejected(self):
        ok, step = mfa_service.verify_totp_with_replay_guard(self.secret, "abc", None)
        assert ok is False and step is None
        ok, step = mfa_service.verify_totp_with_replay_guard(self.secret, "12345", None)
        assert ok is False and step is None

    def test_tolerance_minus_30s(self):
        now = int(time.time())
        previous_step = (now // 30) - 1
        prev_code = self.totp.at(previous_step * 30)
        ok, step = mfa_service.verify_totp_with_replay_guard(self.secret, prev_code, None)
        assert ok is True
        assert step == previous_step

    def test_tolerance_plus_30s(self):
        now = int(time.time())
        next_step = (now // 30) + 1
        next_code = self.totp.at(next_step * 30)
        ok, step = mfa_service.verify_totp_with_replay_guard(self.secret, next_code, None)
        assert ok is True
        assert step == next_step

    def test_replay_rejected(self):
        code = self.totp.now()
        ok, step = mfa_service.verify_totp_with_replay_guard(self.secret, code, None)
        assert ok is True
        # Submit again with the previously-consumed step: must be rejected.
        ok2, step2 = mfa_service.verify_totp_with_replay_guard(self.secret, code, step)
        assert ok2 is False
        assert step2 is None

    def test_wrong_code_rejected(self):
        ok, step = mfa_service.verify_totp_with_replay_guard(self.secret, "000000", None)
        assert ok is False
        assert step is None


# ---------------------------------------------------------------------------
# Fernet + key resolution
# ---------------------------------------------------------------------------


class TestFernet:
    def setup_method(self):
        mfa_service.reset_fernet_for_tests()

    def teardown_method(self):
        mfa_service.reset_fernet_for_tests()

    def test_encrypt_decrypt_roundtrip_with_env_key(self, monkeypatch):
        from cryptography.fernet import Fernet
        key = Fernet.generate_key().decode()
        monkeypatch.setenv("MFA_ENCRYPTION_KEY", key)
        mfa_service.reset_fernet_for_tests()

        secret = "JBSWY3DPEHPK3PXP" * 2
        token = mfa_service.encrypt_secret(secret)
        assert token and token != secret
        recovered = mfa_service.decrypt_secret(token)
        assert recovered == secret

    def test_decrypt_invalid_token_returns_none(self, monkeypatch):
        from cryptography.fernet import Fernet
        monkeypatch.setenv("MFA_ENCRYPTION_KEY", Fernet.generate_key().decode())
        mfa_service.reset_fernet_for_tests()

        assert mfa_service.decrypt_secret("not-a-valid-fernet-token") is None

    def test_hkdf_fallback_when_env_unset(self, monkeypatch, caplog):
        monkeypatch.delenv("MFA_ENCRYPTION_KEY", raising=False)
        mfa_service.reset_fernet_for_tests()

        with caplog.at_level("WARNING"):
            secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
            token = mfa_service.encrypt_secret(secret)
            recovered = mfa_service.decrypt_secret(token)
        assert recovered == secret
        assert any("MFA_ENCRYPTION_KEY" in r.message for r in caplog.records), (
            "expected a WARN log when falling back to SECRET_KEY derivation"
        )


# ---------------------------------------------------------------------------
# Backup codes
# ---------------------------------------------------------------------------


class TestBackupCodes:
    def test_generate_count_and_format(self):
        codes = mfa_service.generate_backup_codes()
        assert len(codes) == 10
        # 31-char alphabet: A-H J K M N P-Z 2-9 (excludes I, L, O, 0, 1).
        for code in codes:
            assert re.fullmatch(r"[A-HJKM-NP-Z2-9]{4}-[A-HJKM-NP-Z2-9]{4}", code), code

    def test_alphabet_excludes_confusing_characters(self):
        # Generate enough codes to virtually guarantee any forbidden char would surface.
        for _ in range(20):
            codes = mfa_service.generate_backup_codes()
            for code in codes:
                for ch in code.replace("-", ""):
                    assert ch not in "0O1IL", f"forbidden char {ch!r} in {code!r}"

    def test_codes_are_unique(self):
        codes = mfa_service.generate_backup_codes()
        assert len(set(codes)) == len(codes)

    def test_normalize_strips_case_dash_space(self):
        assert mfa_service.normalize_backup_code("abcd-efgh") == "ABCDEFGH"
        assert mfa_service.normalize_backup_code(" ab cd-ef gh ") == "ABCDEFGH"
        assert mfa_service.normalize_backup_code("") == ""
        assert mfa_service.normalize_backup_code(None) == ""  # type: ignore[arg-type]

    def test_hash_and_check_async(self):
        async def _run():
            plain = mfa_service.generate_backup_codes()[:1]
            hashes = await mfa_service.hash_backup_codes(plain)
            assert len(hashes) == 1
            assert await mfa_service.check_backup_code(plain[0], hashes[0]) is True
            assert await mfa_service.check_backup_code("WRONG-CODE", hashes[0]) is False
            # Case + dash normalization
            assert await mfa_service.check_backup_code(plain[0].lower(), hashes[0]) is True
            assert (
                await mfa_service.check_backup_code(plain[0].replace("-", ""), hashes[0])
                is True
            )

        asyncio.run(_run())


# ---------------------------------------------------------------------------
# otpauth URI
# ---------------------------------------------------------------------------


class TestOtpAuthUri:
    def test_uri_shape(self):
        uri = mfa_service.build_otpauth_uri("alice@example.com", "JBSWY3DPEHPK3PXP")
        assert uri.startswith("otpauth://totp/")
        assert "secret=JBSWY3DPEHPK3PXP" in uri
        assert "issuer=" in uri
        assert "algorithm=SHA1" in uri
        assert "digits=6" in uri
        assert "period=30" in uri

    def test_account_label_env_override(self, monkeypatch):
        monkeypatch.setenv("MFA_ACCOUNT_LABEL_DOMAIN", "ops.example.com")
        label = mfa_service.build_account_label("alice", hostname_hint="ignored.com")
        assert label == "alice@ops.example.com"

    def test_account_label_hostname_hint(self, monkeypatch):
        monkeypatch.delenv("MFA_ACCOUNT_LABEL_DOMAIN", raising=False)
        label = mfa_service.build_account_label("alice", hostname_hint="api.local")
        assert label == "alice@api.local"

    def test_account_label_fallback(self, monkeypatch):
        monkeypatch.delenv("MFA_ACCOUNT_LABEL_DOMAIN", raising=False)
        label = mfa_service.build_account_label("alice", hostname_hint=None)
        assert label == "alice@haproxy-openmanager"


# ---------------------------------------------------------------------------
# Challenge token
# ---------------------------------------------------------------------------


class TestChallengeToken:
    def test_length_and_uniqueness(self):
        tokens = {mfa_service.generate_challenge_token() for _ in range(50)}
        assert len(tokens) == 50
        for t in tokens:
            assert len(t) == 64
            assert re.fullmatch(r"[0-9a-f]{64}", t)
