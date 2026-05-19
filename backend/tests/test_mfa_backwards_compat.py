"""Backwards-compatibility regression tests for the MFA rollout (Issue #18).

These tests don't hit a real database — they exercise the authoritative
contract surfaces (login response shape, auth_middleware behaviour) using
mocks where needed so the suite stays fast and deterministic.
"""
from __future__ import annotations

import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestAuthMiddlewareUnchanged:
    """auth_middleware MUST NOT look for MFA claims — Madde 2 of the plan."""

    def test_decoder_imports_without_mfa_dependencies(self):
        import auth_middleware
        # The middleware's verification function exists and is callable.
        assert callable(getattr(auth_middleware, "get_current_user_from_token", None))

    def test_middleware_source_has_no_mfa_claim_check(self):
        """The middleware source must not reference ``mfa`` claims directly."""
        with open(
            os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "auth_middleware.py",
            ),
            "r",
            encoding="utf-8",
        ) as fh:
            source = fh.read()
        # Allow incidental occurrences (e.g. comments); but never a claim lookup.
        assert "payload.get('mfa'" not in source
        assert 'payload.get("mfa"' not in source
        assert "claims['mfa'" not in source
        assert 'claims["mfa"' not in source


class TestMfaModelsCoexistWithUserModels:
    def test_models_user_module_unchanged_pydantic_shape(self):
        from models import user as user_mod
        # Ensure that User / UserUpdate / LoginRequest still load and still
        # don't expose mfa-related fields (kept in models.mfa).
        for cls in (user_mod.User, user_mod.UserUpdate, user_mod.LoginRequest):
            fields = set(cls.model_fields.keys())
            assert not {"mfa_enabled", "mfa_required", "mfa_token"} & fields, (
                f"{cls.__name__} unexpectedly exposes MFA field; should stay byte-identical."
            )

    def test_models_mfa_module_exposes_expected_models(self):
        from models import mfa as mfa_mod
        for name in (
            "MfaVerifyRequest",
            "MfaEnrollStartResponse",
            "MfaEnrollConfirmRequest",
            "MfaEnrollConfirmResponse",
            "MfaDisableRequest",
            "MfaRegenerateBackupRequest",
            "MfaRegenerateBackupResponse",
            "MfaAdminResetRequest",
            "MfaAdminResetAllRequest",
            "MfaStatusResponse",
        ):
            assert hasattr(mfa_mod, name), f"Missing model: {name}"


class TestRouterIncluded:
    def test_main_includes_mfa_router(self):
        with open(
            os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "main.py",
            ),
            "r",
            encoding="utf-8",
        ) as fh:
            source = fh.read()
        assert "from routers.mfa import router as mfa_router" in source
        assert "app.include_router(mfa_router)" in source


class TestLoginResponseShapeForNonMfaUser:
    """When MFA columns are missing or mfa_enabled=FALSE, /login returns the
    pre-MFA response shape — no ``mfa_required`` / ``mfa_token`` keys leak through.
    """

    def test_login_without_mfa_returns_legacy_shape(self):
        from fastapi.testclient import TestClient
        from main import app

        client = TestClient(app)

        async def _fetch_mfa_state_none(conn, user_id):
            return None

        async def _no_log(*args, **kwargs):
            return None

        fake_user = {
            "id": 1,
            "username": "admin",
            "email": "admin@example.com",
            "password_hash": "$2b$12$placeholder",
            "is_active": True,
            "role": "admin",
            "created_at": None,
            "updated_at": None,
            "last_login_at": None,
        }

        mock_conn = MagicMock()
        mock_conn.fetchrow = AsyncMock(return_value=fake_user)
        mock_conn.fetch = AsyncMock(return_value=[])
        mock_conn.execute = AsyncMock(return_value=None)

        async def _get_conn():
            return mock_conn

        async def _close(conn):
            return None

        with patch(
            "routers.auth.get_database_connection", _get_conn
        ), patch("routers.auth.close_database_connection", _close), patch(
            "routers.auth._fetch_mfa_state", _fetch_mfa_state_none
        ), patch("routers.auth.log_user_activity", _no_log), patch(
            "bcrypt.checkpw", return_value=True
        ):
            resp = client.post(
                "/api/auth/login",
                json={"username": "admin", "password": "anything"},
            )

        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert "access_token" in body
        assert "token_type" in body
        assert "expires_in" in body
        assert "user" in body
        assert "roles" in body
        assert "permissions" in body
        # CRITICAL — pre-MFA contract must not be polluted with MFA fields.
        assert "mfa_required" not in body
        assert "mfa_token" not in body
        assert "methods" not in body
