"""v1.7.6 — guard: the agent must surface keepalived FAULT state.

A VIP whose interface has no usable IPv4 (or whose track-script fails) puts keepalived into
FAULT — the virtual IP is NOT held. Previously get_keepalive_state only grepped (MASTER|BACKUP),
so a FAULT'd VIP reported as BACKUP — misleading (looks healthy-ish). It must report FAULT so the
UI shows it red. Both get_keepalive_state copies (installer + SKIP_TO_DAEMON daemon) must include
FAULT. Pure source guard."""
from __future__ import annotations

import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_keepalive_state_detects_fault_in_both_copies():
    with open(os.path.join(ROOT, "utils", "agent_scripts", "linux_install.sh"), encoding="utf-8") as f:
        s = f.read()
    # FAULT added to the state grep in both copies (installer + daemon), both detection methods.
    assert s.count("MASTER|BACKUP|FAULT") >= 2
    # and the misleading MASTER|BACKUP-only grep is gone.
    assert 'grep -oE "(MASTER|BACKUP)"' not in s
