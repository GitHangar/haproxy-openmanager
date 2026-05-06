"""
Issue #11 regression: duplicate `_acme_challenge_backend` in generated config.

Tests verify the layered defense:
1. agent.py _should_sync_backend filter
2. haproxy_config_parser.py reserved_backend_names check
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestShouldSyncBackend:
    def test_acme_challenge_backend_is_skipped(self):
        from routers.agent import _should_sync_backend
        assert _should_sync_backend('_acme_challenge_backend') is False

    def test_user_backend_is_synced(self):
        from routers.agent import _should_sync_backend
        assert _should_sync_backend('my-app-backend') is True
        assert _should_sync_backend('api-prod') is True

    def test_underscore_prefixed_names_are_skipped(self):
        from routers.agent import _should_sync_backend
        assert _should_sync_backend('_internal') is False
        assert _should_sync_backend('_anything') is False


class TestParserReservedNames:
    def test_acme_challenge_backend_not_persisted(self):
        from utils.haproxy_config_parser import HAProxyConfigParser
        cfg = """
global
    daemon

defaults
    mode http

frontend test_fe
    bind *:80
    default_backend my-app

backend my-app
    server s1 10.0.0.1:80 check

backend _acme_challenge_backend
    mode http
    server _acme_mgmt 10.0.0.99:8080
"""
        parser = HAProxyConfigParser()
        result = parser.parse(cfg)
        backend_names = [b.name for b in result.backends]
        assert 'my-app' in backend_names
        assert '_acme_challenge_backend' not in backend_names
        # Should have warning
        assert any('_acme_challenge_backend' in w.lower() or 'reserved' in w.lower()
                   for w in result.warnings)
