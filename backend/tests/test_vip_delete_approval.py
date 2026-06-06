"""Issue #27 safety (v1.7.2) — source-level guards for APPROVAL-GATED VIP deletion.

The critical invariant: an agent must NEVER tear a VIP down without an explicit human approval.
We enforce that by keeping the VIP is_active=TRUE (so the agent keeps serving it) when a delete
is merely *requested*; only an APPROVE (apply) flips is_active=FALSE. These guards lock in that
wiring so a future edit can't silently make delete immediate again. Pure (no DB)."""
from __future__ import annotations

import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(rel: str) -> str:
    with open(os.path.join(ROOT, rel), encoding="utf-8") as f:
        return f.read()


def test_delete_stages_for_approval_keeps_vip_running():
    s = _read("routers/vip.py")
    # A running (applied) VIP's delete sets pending_delete=TRUE and stages a delete version —
    # it must NOT flip is_active=FALSE in delete_vip (that only happens on approval in apply_vip).
    assert "pending_delete=TRUE" in s
    assert '_stage_vip_version(conn, vip_id, "delete"' in s
    # The staged-delete branch (running VIP) must not contain an is_active=FALSE soft-delete;
    # only the "never applied" branch may remove immediately (guarded by applied_snapshot IS NULL).
    assert 'v["applied_snapshot"] is None' in s


def test_apply_performs_delete_only_on_approval():
    s = _read("routers/vip.py")
    # apply_vip short-circuits on pending_delete and only THEN flips is_active=FALSE.
    assert 'if v["pending_delete"]:' in s
    assert "is_active=FALSE, pending_delete=FALSE" in s


def test_reject_cancels_delete_as_noop():
    s = _read("routers/vip.py")
    # reject_vip clears the staged delete + purge intent; the VIP keeps running (is_active never
    # touched here) — the "nothing happened" path.
    assert "pending_delete=FALSE, purge_on_teardown=FALSE" in s
    assert "Deletion rejected" in s


def test_agent_delivery_teardown_only_on_inactive():
    # The agent is told to tear down ONLY when is_active=FALSE; a pending-delete VIP is still
    # is_active=TRUE, so the delivery returns 'available' and the agent keeps serving it.
    s = _read("routers/agent.py")
    assert "if not row['is_active']:" in s
    assert '"status": "teardown"' in s


def test_migration_adds_pending_delete_and_bumps_schema():
    s = _read("database/migrations.py")
    assert "pending_delete BOOLEAN NOT NULL DEFAULT FALSE" in s
    assert "SCHEMA_VERSION = 7" in s


def test_list_visibility_backward_compat_gates_on_applied():
    # A VIP soft-deleted under the OLD immediate-delete (pre-1.7.2: is_active=FALSE,
    # last_config_status='PENDING') must NOT reappear in the list as DELETING — the
    # teardown-tracking clause is gated on last_config_status='APPLIED' (new-flow approved
    # deletes only). Locks the backward-compat fix.
    s = _read("routers/vip.py")
    assert "v.last_config_status = 'APPLIED' AND EXISTS" in s
