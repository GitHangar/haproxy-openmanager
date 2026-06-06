"""v1.7.5 — guard for the HA/VIP "View Change" diff.

Editing a VIP (e.g. priority + virtual IP) must show a REAL line diff (only the changed lines)
against the previous applied vip-* config — not the whole keepalived.conf marked as "added", and
without the doubled "+ +" prefix (the line must be stored WITHOUT a +/- prefix; the UI adds it
from `type`, exactly like the standard haproxy diff). Pure source guard (the behavioural diff
test needs a DB); locks the wiring so it can't regress."""
from __future__ import annotations

import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _cluster_src() -> str:
    with open(os.path.join(ROOT, "routers", "cluster.py"), encoding="utf-8") as f:
        return f.read()


def test_vip_diff_uses_real_difflib_against_previous_applied():
    s = _cluster_src()
    # The previous APPLIED vip-* config for this VIP is fetched as the diff baseline.
    assert "AND status='APPLIED' AND cluster_id=$2 AND id < $3 ORDER BY id DESC LIMIT 1" in s
    # And the diff is a real unified_diff of old vs new (not "everything added").
    assert "difflib.unified_diff(old_content.split('\\n'), new_content.split('\\n')" in s


def test_vip_diff_stores_lines_without_prefix():
    s = _cluster_src()
    # The old vip bug prepended "+ {line}", doubling the UI prefix ("+ +"). The vip diff now
    # stores the stripped diff line (dl[1:]) — the UI adds the +/- from `type`. `dl` is unique
    # to the vip branch (the standard haproxy diff uses `line`), so this targets the vip fix
    # only and does not touch the (separate, out-of-scope) SSL diff branch.
    assert '"line": dl[1:], "line_number": line_number' in s
