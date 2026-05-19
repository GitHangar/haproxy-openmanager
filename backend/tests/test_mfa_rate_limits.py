"""Tests for middleware.mfa_rate_limits — env-driven MFA rate-limit config."""
import importlib
import logging

import pytest


@pytest.fixture
def reload_module(monkeypatch):
    """Helper: reload the module after env mutation so dataclass defaults
    pick up the new values."""

    def _reload(**env):
        for key in list(globals().get('_OVERRIDDEN_ENVS', set())):
            monkeypatch.delenv(key, raising=False)
        for key, value in env.items():
            monkeypatch.setenv(key, value)
        from middleware import mfa_rate_limits as m
        return importlib.reload(m)

    return _reload


def test_defaults_when_no_env(reload_module, monkeypatch):
    """No env var set → secure defaults applied (user-aware key assumption)."""
    for key in (
        "MFA_RATE_LIMIT_ENROLL_START",
        "MFA_RATE_LIMIT_ENROLL_CONFIRM",
        "MFA_RATE_LIMIT_DISABLE",
        "MFA_RATE_LIMIT_REGENERATE_BACKUP_CODES",
        "MFA_RATE_LIMIT_ADMIN_RESET",
        "MFA_RATE_LIMIT_ADMIN_RESET_ALL",
    ):
        monkeypatch.delenv(key, raising=False)
    m = reload_module()
    assert m.MFA_LIMITS.enroll_start == "10/minute"
    assert m.MFA_LIMITS.enroll_confirm == "10/minute"
    assert m.MFA_LIMITS.disable == "10/minute"
    assert m.MFA_LIMITS.regenerate_backup_codes == "5/hour"
    assert m.MFA_LIMITS.admin_reset == "60/hour"
    assert m.MFA_LIMITS.admin_reset_all == "1/day"


def test_env_override_per_endpoint(reload_module):
    m = reload_module(
        MFA_RATE_LIMIT_ENROLL_START="100/hour",
        MFA_RATE_LIMIT_ADMIN_RESET_ALL="3/day",
    )
    assert m.MFA_LIMITS.enroll_start == "100/hour"
    assert m.MFA_LIMITS.admin_reset_all == "3/day"
    # Untouched values still default.
    assert m.MFA_LIMITS.disable == "10/minute"


@pytest.mark.parametrize(
    "bad",
    [
        "totally-bogus",
        "5/lightyear",
        "abc/minute",
        "5",
        "/minute",
        "5//minute",
        "",
    ],
)
def test_invalid_format_falls_back_to_default(reload_module, caplog, bad):
    with caplog.at_level(logging.WARNING, logger="middleware.mfa_rate_limits"):
        m = reload_module(MFA_RATE_LIMIT_ENROLL_START=bad)
    # Falls back to the secure default for enroll_start.
    assert m.MFA_LIMITS.enroll_start == "10/minute"
    assert any("not a valid slowapi limit string" in r.message for r in caplog.records)


def test_whitespace_around_value_is_tolerated(reload_module):
    m = reload_module(MFA_RATE_LIMIT_DISABLE="  30/minute  ")
    assert m.MFA_LIMITS.disable == "30/minute"


@pytest.mark.parametrize(
    "valid",
    ["1/second", "100/minute", "1000/hour", "10/day"],
)
def test_all_valid_periods_accepted(reload_module, valid):
    m = reload_module(MFA_RATE_LIMIT_DISABLE=valid)
    assert m.MFA_LIMITS.disable == valid


def test_dataclass_is_frozen(reload_module):
    """Frozen dataclass guards against accidental mutation after import."""
    m = reload_module()
    with pytest.raises((AttributeError, Exception)):
        m.MFA_LIMITS.disable = "999/second"  # type: ignore[misc]
