"""v1.7.4 — guard for the stick-table auto-inject in the HAProxy config renderer.

A frontend that uses a stick counter (`track-sc<N>` or an `sc_*_rate(...)` fetch) but declares
no `stick-table` makes HAProxy fatally reject the WHOLE cluster config with "table '<frontend>'
used but not configured". This happens with rate-limit directives baked into a frontend's stored
request_headers/options by an older version or a config import. The renderer now injects a default
stick-table in that case. Pure source guard (the behavioural renderer test needs a DB and is
disabled); this locks the wiring so it can't silently regress."""
from __future__ import annotations

import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _src() -> str:
    with open(os.path.join(ROOT, "services", "haproxy_config.py"), encoding="utf-8") as f:
        return f.read()


def test_renderer_detects_stick_counter_usage():
    s = _src()
    # Detection: any track-sc<N> write OR an sc_*_rate(...) fetch flips _sc_counter_used.
    assert "_sc_counter_used" in s
    assert '"track-sc" in stripped or ("sc_" in stripped and "_rate(" in stripped)' in s


def test_renderer_injects_stick_table_when_missing():
    s = _src()
    # Inject ONLY when a counter is used AND no stick-table was emitted (purely additive).
    assert "if _sc_counter_used and not _stick_table_emitted:" in s
    assert 'stick-table type ip size 100k expire 30s store http_req_rate(10s)' in s
    # The inject must register the table so it is not added twice.
    assert "_stick_table_emitted = True" in s
