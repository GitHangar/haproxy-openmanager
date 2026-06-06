"""Issue #27 follow-up (v1.7.2) — source-level guards for the opt-in keepalived package
uninstall + the "we installed it" marker. Pure (no DB), mirroring the project's other
source-assertion tests: they lock in the *safe defaults* so a future edit can't silently
turn routine VIP deletion into a package purge, or purge a package we didn't install."""
from __future__ import annotations

import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(rel: str) -> str:
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def test_agent_script_purge_is_optin_and_marker_guarded():
    s = _read("utils/agent_scripts/linux_install.sh")
    # The install marker is written only when WE install keepalived, and read by the purge
    # guard — present in BOTH function copies (installer-mode + SKIP_TO_DAEMON).
    assert s.count(".hom_installed") >= 4
    # Multi-distro purge cascade exists, but ONLY inside the opt-in branch.
    assert "apt-get purge -y -qq keepalived" in s
    assert "apk del keepalived" in s
    # Orphan self-heal (not_configured) must NEVER purge — graceful teardown only, both copies.
    assert s.count('_kp_teardown "false"') >= 2
    # Purge is honored only on an explicit teardown, parsed from the delivery response.
    assert s.count(".purge // false") >= 2


def test_agent_delivery_signals_purge_on_teardown():
    s = _read("routers/agent.py")
    assert "v.purge_on_teardown" in s
    assert '"purge"' in s  # teardown response carries the opt-in flag


def test_delete_endpoint_accepts_purge_package_default_off():
    s = _read("routers/vip.py")
    # Query param defaults to False (safe), and it sets the persisted teardown flag.
    assert "purge_package: bool = False" in s
    assert "purge_on_teardown=$2" in s


def test_migration_adds_purge_column_and_bumps_schema():
    s = _read("database/migrations.py")
    assert "purge_on_teardown BOOLEAN NOT NULL DEFAULT FALSE" in s
    assert "SCHEMA_VERSION = 7" in s
