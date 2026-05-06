"""
Audit Tur 4/5 / Commit 8: ACME endpoints are covered by audit middleware.
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from middleware.activity_logger import RESOURCE_MAPPING, SPECIAL_ACTIONS, extract_resource_info


class TestACMERouteCoverage:
    def test_letsencrypt_in_resource_mapping(self):
        assert '/api/letsencrypt' in RESOURCE_MAPPING
        assert RESOURCE_MAPPING['/api/letsencrypt'] == 'letsencrypt_order'

    def test_revoke_certificate_special_action(self):
        path = '/api/letsencrypt/certificates/{cert_id}/revoke'
        assert path in SPECIAL_ACTIONS
        assert SPECIAL_ACTIONS[path] == 'acme_certificate_revoked'

    def test_import_ca_chain_special_action(self):
        assert '/api/letsencrypt/import-ca-chain' in SPECIAL_ACTIONS

    def test_account_ops_special_actions(self):
        assert '/api/letsencrypt/accounts' in SPECIAL_ACTIONS
        assert '/api/letsencrypt/accounts/{account_id}' in SPECIAL_ACTIONS
        assert '/api/letsencrypt/accounts/{account_id}/permanent' in SPECIAL_ACTIONS


class TestExtractResourceInfo:
    def test_post_certificates_resolves_to_acme(self):
        rt, action, _ = extract_resource_info('/api/letsencrypt/certificates', 'POST')
        # Either matches SPECIAL_ACTIONS (acme_certificate_requested) or generic create.
        assert rt == 'letsencrypt_order'

    def test_post_revoke_resolves_to_revoked_action(self):
        rt, action, rid = extract_resource_info(
            '/api/letsencrypt/certificates/42/revoke', 'POST'
        )
        assert rt == 'letsencrypt_order'
        assert action == 'acme_certificate_revoked'
        assert rid == '42'

    def test_get_request_returns_default_unknown(self):
        # GET on /api/letsencrypt/orders is not in SPECIAL_ACTIONS, and GET is not
        # in LOGGABLE_ACTIONS, so extract_resource_info() falls through to the
        # default ('unknown', 'get', None). The middleware itself skips logging
        # GETs; this test just ensures no crash on the codepath.
        rt, action, _ = extract_resource_info('/api/letsencrypt/orders', 'GET')
        assert rt == 'unknown'
        assert action == 'get'
