"""Issue #27 (v1.7.0) — unit tests for VIP request-model validation (pure, no DB)."""
from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.vip import VIPCreate, VIPMemberIn  # noqa: E402


def _members(master_prio=150, backup_prio=100, n_backup=1):
    members = [{"agent_id": 1, "network_interface": "eth0", "role": "MASTER", "priority": master_prio}]
    for i in range(n_backup):
        members.append({"agent_id": 2 + i, "network_interface": "eth0", "role": "BACKUP", "priority": backup_prio})
    return members


def _create(**over):
    base = dict(name="web-vip", pool_id=1, virtual_ip="10.0.0.100", members=_members())
    base.update(over)
    return VIPCreate(**base)


class TestField:
    def test_ok(self):
        v = _create()
        assert v.virtual_ip == "10.0.0.100"
        assert v.use_unicast is True  # cloud-safe default

    def test_ipv6_rejected(self):
        with pytest.raises(ValueError):
            _create(virtual_ip="fd00::1")

    def test_bad_ip_rejected(self):
        with pytest.raises(ValueError):
            _create(virtual_ip="not-an-ip")

    def test_auth_pass_max_8(self):
        _create(auth_pass="12345678")
        with pytest.raises(ValueError):
            _create(auth_pass="123456789")

    def test_interface_forbidden_char(self):
        with pytest.raises(ValueError):
            VIPMemberIn(agent_id=1, network_interface="eth0; rm -rf /", role="BACKUP", priority=100)

    def test_priority_range(self):
        with pytest.raises(ValueError):
            VIPMemberIn(agent_id=1, network_interface="eth0", role="BACKUP", priority=255)

    def test_role_normalized(self):
        m = VIPMemberIn(agent_id=1, network_interface="eth0", role="master", priority=150)
        assert m.role == "MASTER"

    def test_vrid_range(self):
        with pytest.raises(ValueError):
            _create(virtual_router_id=300)


class TestMembers:
    def test_single_node_allowed(self):
        # A single-node VIP (one MASTER, no BACKUP) is valid: a keepalived-managed floating
        # IP without failover (Issue #27 follow-up — relaxed from >=2 members to >=1, e.g. a
        # one-box cluster that wants a stable VIP, or before a 2nd node is added for real HA).
        v = VIPCreate(name="x", pool_id=1, virtual_ip="10.0.0.5",
                      members=[{"agent_id": 1, "network_interface": "eth0", "role": "MASTER", "priority": 150}])
        assert len(v.members) == 1 and v.members[0].role == "MASTER"

    def test_needs_at_least_one(self):
        # An empty membership is still rejected — a VIP must have at least one node.
        with pytest.raises(ValueError):
            VIPCreate(name="x", pool_id=1, virtual_ip="10.0.0.5", members=[])

    def test_exactly_one_master(self):
        bad = [{"agent_id": 1, "network_interface": "eth0", "role": "MASTER", "priority": 150},
               {"agent_id": 2, "network_interface": "eth0", "role": "MASTER", "priority": 140}]
        with pytest.raises(ValueError):
            VIPCreate(name="x", pool_id=1, virtual_ip="10.0.0.5", members=bad)

    def test_master_must_be_highest(self):
        with pytest.raises(ValueError):
            _create(members=_members(master_prio=100, backup_prio=120))

    def test_no_duplicate_agent(self):
        dup = [{"agent_id": 1, "network_interface": "eth0", "role": "MASTER", "priority": 150},
               {"agent_id": 1, "network_interface": "eth1", "role": "BACKUP", "priority": 100}]
        with pytest.raises(ValueError):
            VIPCreate(name="x", pool_id=1, virtual_ip="10.0.0.5", members=dup)
