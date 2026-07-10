"""
Issue #38 regression tests: HAProxy SPOE `filter` + frontend `log-format` support.

Bug: the bulk-config parser recognised only a fixed set of frontend directives,
so `filter spoe engine coraza config ...` and `log-format ...` were silently
dropped on import / manual edit. This regenerated a config missing the SPOE
engine definition, so HAProxy failed with
"unable to find SPOE engine 'coraza' used by the send-spoe-group 'coraza-req'".

These tests verify the end-to-end fix without requiring a database:
1. parser captures `filter` + `log-format` into the new ParsedFrontend fields;
2. `http-request send-spoe-group` is still preserved (regression guard);
3. the generator's directive categoriser + bucket flush order emit `filter`
   BEFORE the `http-request send-spoe-group` rules and keep `log-format`;
4. reject/rollback restores the new columns;
5. a non-SPOE frontend is completely unaffected (zero-impact).
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from utils.haproxy_config_parser import parse_haproxy_config, ParsedFrontend
from services.haproxy_config import _categorize_haproxy_directive
from models.frontend import FrontendConfig


# The exact frontend/backend config reported in Issue #38 (Coraza-SPOA).
ISSUE_38_CONFIG = r"""
frontend web-frontend
    bind *:8073
    mode http
        log-format "%ci:%cp\ [%t]\ %ft\ %b/%s\ %ST\ %B\ %{+Q}r\ %[var(txn.coraza.id)]\ waf-hit:\ %[var(txn.coraza.fail)]"
        filter spoe engine coraza config /etc/haproxy/coraza.cfg
      http-request set-var(txn.coraza.app) str(haproxy_waf)
     http-request send-spoe-group coraza coraza-req
    http-request deny if { var(txn.coraza.fail) -m int eq 1 }
    default_backend web-backend

backend web-backend
    balance roundrobin
    mode http
    server server1 192.168.1.10:443 weight 100 ssl verify none

backend coraza-spoa
    mode tcp
    option spop-check
    server coraza_spoa 192.168.12.21:9000
"""


def _get_frontend(parse_result, name):
    for fe in parse_result.frontends:
        if fe.name == name:
            return fe
    return None


class TestParserCapturesSpoe:
    def test_filter_and_log_format_captured(self):
        result = parse_haproxy_config(ISSUE_38_CONFIG)
        fe = _get_frontend(result, "web-frontend")
        assert fe is not None, "web-frontend should be parsed and kept"
        assert fe.filters is not None
        assert "filter spoe engine coraza config /etc/haproxy/coraza.cfg" in fe.filters
        assert fe.log_format is not None
        assert fe.log_format.startswith("log-format")
        # the escaped/quoted format string must be preserved verbatim
        assert "%[var(txn.coraza.fail)]" in fe.log_format

    def test_send_spoe_group_still_preserved(self):
        # Regression guard: http-request rules (incl. send-spoe-group) must
        # still be collected into request_headers as before.
        result = parse_haproxy_config(ISSUE_38_CONFIG)
        fe = _get_frontend(result, "web-frontend")
        assert fe.request_headers is not None
        assert "send-spoe-group coraza coraza-req" in fe.request_headers

    def test_multiple_filters_preserved_in_order(self):
        cfg = """
frontend f1
    bind *:80
    mode http
    filter compression
    filter spoe engine coraza config /etc/haproxy/coraza.cfg
    default_backend b1

backend b1
    mode http
    server s1 10.0.0.1:80
"""
        fe = _get_frontend(parse_haproxy_config(cfg), "f1")
        lines = fe.filters.split("\n")
        assert lines == [
            "filter compression",
            "filter spoe engine coraza config /etc/haproxy/coraza.cfg",
        ]

    def test_log_format_sd_variant_captured(self):
        cfg = """
frontend f1
    bind *:80
    mode http
    log-format-sd "[exampleSDID@1234 field=value]"
    default_backend b1

backend b1
    mode http
    server s1 10.0.0.1:80
"""
        fe = _get_frontend(parse_haproxy_config(cfg), "f1")
        assert fe.log_format is not None
        assert fe.log_format.startswith("log-format-sd")


class TestGeneratorOrderingContract:
    """The generator routes directives into ordered buckets. Verify SPOE
    correctness at the (pure) categoriser + documented flush-order level."""

    def test_filter_routes_to_filter_bucket(self):
        assert _categorize_haproxy_directive("    filter spoe engine coraza config /x.cfg") == "filter"

    def test_send_spoe_group_routes_to_http_req(self):
        assert _categorize_haproxy_directive("    http-request send-spoe-group coraza coraza-req") == "http_req"

    def test_log_format_routes_to_prelude(self):
        assert _categorize_haproxy_directive('    log-format "%ci:%cp"') == "prelude"
        assert _categorize_haproxy_directive('    log-format-sd "[x]"') == "prelude"

    def test_flush_order_places_filter_before_http_req(self):
        # The bucket flush order is the single source of truth for emission
        # ordering. Assert `filter` is flushed before `http_req` (and after
        # `prelude`), guaranteeing `filter ...` renders before
        # `http-request send-spoe-group ...`.
        src = _read_source("services/haproxy_config.py")
        m = re.search(r"for _bucket_key in \((.*?)\):", src, re.DOTALL)
        assert m, "bucket flush loop not found"
        order = re.findall(r'"(\w+)"', m.group(1))
        assert "filter" in order, "new 'filter' bucket missing from flush order"
        assert order.index("prelude") < order.index("filter") < order.index("http_req")


class TestModelAndRollback:
    def test_model_has_passthrough_fields(self):
        fc = FrontendConfig(
            name="f", bind_port=80,
            filters="filter spoe engine coraza config /etc/haproxy/coraza.cfg",
            log_format='log-format "%ci"',
        )
        assert fc.filters.startswith("filter spoe")
        assert fc.log_format.startswith("log-format")

    def test_dataclass_defaults_none(self):
        fe = ParsedFrontend(name="f")
        assert fe.filters is None
        assert fe.log_format is None

    def test_rollback_restores_new_columns(self):
        # Reject/rollback of a frontend UPDATE must restore the new columns,
        # otherwise the rejected (new) filters/log_format would persist.
        src = _read_source("utils/entity_snapshot.py")
        assert "log_format = $" in src
        assert "filters = $" in src
        assert "old_values.get('log_format')" in src
        assert "old_values.get('filters')" in src


class TestZeroImpact:
    def test_non_spoe_frontend_unaffected(self):
        cfg = """
frontend plain
    bind *:80
    mode http
    option httplog
    default_backend b1

backend b1
    mode http
    server s1 10.0.0.1:80
"""
        fe = _get_frontend(parse_haproxy_config(cfg), "plain")
        # No filter / log-format present → new fields stay None (no behaviour change)
        assert fe.filters is None
        assert fe.log_format is None

    def test_spop_check_backend_roundtrips_without_warning(self):
        result = parse_haproxy_config(ISSUE_38_CONFIG)
        be = next((b for b in result.backends if b.name == "coraza-spoa"), None)
        assert be is not None, "coraza-spoa backend should import"
        assert be.mode == "tcp"
        assert be.options and "option spop-check" in be.options
        # spop-check is now a known option → no spurious 'unknown option' warning
        assert not any(
            "coraza-spoa" in w and "spop-check" in w and "Unknown" in w
            for w in result.warnings
        )


def _read_source(relpath):
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    with open(os.path.join(base, relpath), "r", encoding="utf-8") as fh:
        return fh.read()
