"""
Issue #10 regression: ssl_certificates.expiry_date is stored as TIMESTAMP (tz-naive).
ssl_parser.parse_ssl_certificate() returns tz-aware UTC datetime. Without normalization
in _complete_certificate(), asyncpg silently fails the INSERT/UPDATE for tz-aware
values, leaving expiry_date NULL and breaking auto-renewal.

These tests verify the normalization logic before the DB write.
"""
import pytest
from datetime import datetime, timezone, timedelta


def _normalize_expiry(expiry_date):
    """Replicates the inline normalization in routers/letsencrypt.py:_complete_certificate()."""
    if expiry_date is not None and getattr(expiry_date, 'tzinfo', None) is not None:
        return expiry_date.astimezone(timezone.utc).replace(tzinfo=None)
    return expiry_date


class TestExpiryDateNormalization:
    def test_tz_aware_utc_is_made_naive(self):
        tz_aware = datetime(2026, 8, 15, 12, 0, 0, tzinfo=timezone.utc)
        result = _normalize_expiry(tz_aware)
        assert result.tzinfo is None
        assert result.year == 2026 and result.month == 8 and result.day == 15

    def test_tz_aware_non_utc_is_converted_to_utc_then_naive(self):
        # +03:00 timezone, hour 15 local == 12 UTC
        eastern = timezone(timedelta(hours=3))
        tz_aware_local = datetime(2026, 8, 15, 15, 0, 0, tzinfo=eastern)
        result = _normalize_expiry(tz_aware_local)
        assert result.tzinfo is None
        assert result.hour == 12  # converted to UTC

    def test_naive_passes_through_unchanged(self):
        naive = datetime(2026, 8, 15, 12, 0, 0)
        result = _normalize_expiry(naive)
        assert result is naive
        assert result.tzinfo is None

    def test_none_passes_through(self):
        assert _normalize_expiry(None) is None

    def test_real_world_le_expiry_format(self):
        # Let's Encrypt typically issues 90-day certs. Verify a typical value.
        future = datetime.now(timezone.utc) + timedelta(days=89, hours=23)
        result = _normalize_expiry(future)
        assert result.tzinfo is None
        # Should still be ~89-90 days in the future
        diff = result - datetime.utcnow()
        assert 88 <= diff.days <= 91
