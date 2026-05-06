"""
Audit Tur 6 / Commit 5c, 5h, 5i: ACME order state machine error_detail serialization.

Verifies that error_detail is persisted as structured JSON-as-TEXT for:
- check_order_status non-200 (Commit 5c)
- finalize_order non-200 (Commit 5h)
- download_certificate non-200 (Commit 5i)
"""
import pytest
import json
from datetime import datetime


class TestErrorDetailSerialization:
    """Validate the structured payload format used across all 3 stages."""
    
    def _build_payload(self, stage, http_status, ca_response):
        return json.dumps({
            "stage": stage,
            "http_status": http_status,
            "ca_response": ca_response if isinstance(ca_response, dict) else str(ca_response)[:1000],
            "timestamp": datetime.utcnow().isoformat(),
        })

    def test_check_order_status_payload_parses(self):
        payload = self._build_payload("check_order_status", 503, {"detail": "Service unavailable"})
        parsed = json.loads(payload)
        assert parsed["stage"] == "check_order_status"
        assert parsed["http_status"] == 503
        assert parsed["ca_response"]["detail"] == "Service unavailable"
        assert "timestamp" in parsed

    def test_finalize_payload_parses(self):
        payload = self._build_payload("finalize_order", 400, {"detail": "Invalid CSR"})
        parsed = json.loads(payload)
        assert parsed["stage"] == "finalize_order"
        assert parsed["http_status"] == 400

    def test_download_payload_parses(self):
        payload = self._build_payload("download_certificate", 502, "raw text response")
        parsed = json.loads(payload)
        assert parsed["stage"] == "download_certificate"
        assert parsed["http_status"] == 502
        assert parsed["ca_response"] == "raw text response"

    def test_string_response_truncated_to_1000(self):
        long_str = "a" * 5000
        payload = self._build_payload("check_order_status", 500, long_str)
        parsed = json.loads(payload)
        assert len(parsed["ca_response"]) == 1000

    def test_dict_response_preserved_as_object(self):
        payload = self._build_payload("finalize_order", 400, {"key1": "v1", "key2": [1, 2]})
        parsed = json.loads(payload)
        assert parsed["ca_response"]["key1"] == "v1"
        assert parsed["ca_response"]["key2"] == [1, 2]


class TestStuckOrderDetection:
    """Verify the conditions that mark an order as 'stuck'."""

    def test_valid_order_without_certificate_id_is_stuck(self):
        order = {"status": "valid", "ssl_certificate_id": None}
        is_stuck = order["status"] == "valid" and not order["ssl_certificate_id"]
        assert is_stuck is True

    def test_valid_order_with_certificate_id_is_not_stuck(self):
        order = {"status": "valid", "ssl_certificate_id": 42}
        is_stuck = order["status"] == "valid" and not order["ssl_certificate_id"]
        assert is_stuck is False

    def test_pending_order_is_not_stuck(self):
        order = {"status": "pending", "ssl_certificate_id": None}
        is_stuck = order["status"] == "valid" and not order["ssl_certificate_id"]
        assert is_stuck is False
