"""Issue #27 (v1.7.0) — unit tests for the keepalived config generator + secret crypto.

Pure-function tests; no DB. Validates the rendered keepalived.conf for MASTER/BACKUP,
unicast peers, the failover weight arithmetic, the script-security requirements, the
ownership marker, and Fernet round-trip.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services import keepalived_config as kc  # noqa: E402


VIP = {
    "id": 3, "name": "web-vip", "virtual_ip": "10.0.0.100", "prefix_length": 24,
    "virtual_router_id": 51, "advert_int": 1, "use_unicast": True, "track_haproxy": True,
}
MEMBERS = [
    {"role": "MASTER", "priority": 150, "network_interface": "eth0", "agent_id": 1, "ip_address": "10.0.0.11"},
    {"role": "BACKUP", "priority": 100, "network_interface": "eth0", "agent_id": 2, "ip_address": "10.0.0.12"},
]


def _render(this_idx, auth="s3cr3t"):
    this_agent = MEMBERS[this_idx]
    peers = [m["ip_address"] for m in MEMBERS if m["agent_id"] != this_agent["agent_id"]]
    return kc.render_keepalived_conf(vip=VIP, members=MEMBERS, this_agent=this_agent,
                                     peer_ips=peers, auth_pass_plain=auth)


class TestRender:
    def test_master_state_priority_iface_vrid(self):
        conf = _render(0)
        assert "state MASTER" in conf
        assert "priority 150" in conf
        assert "interface eth0" in conf
        assert "virtual_router_id 51" in conf
        assert "10.0.0.100/24 dev eth0" in conf

    def test_backup_state(self):
        conf = _render(1)
        assert "state BACKUP" in conf
        assert "priority 100" in conf

    def test_unicast_peers(self):
        # MASTER's config lists the BACKUP as its unicast peer (and its own src ip).
        conf = _render(0)
        assert "unicast_src_ip 10.0.0.11" in conf
        assert "unicast_peer" in conf
        assert "10.0.0.12" in conf

    def test_script_security_block(self):
        conf = _render(0)
        assert "enable_script_security" in conf
        assert "script_user root" in conf

    def test_ownership_marker(self):
        assert kc.OWNERSHIP_MARKER in _render(0)

    def test_weight_makes_failed_master_lose(self):
        # On HAProxy failure the master's effective priority must drop below the backup.
        conf = _render(0)
        weight_line = [l for l in conf.splitlines() if l.strip().startswith("weight ")][0]
        weight = int(weight_line.strip().split()[1])
        assert 150 + weight < 100, "failed master must fall below every backup"
        assert "track_script" in conf and "chk_haproxy" in conf

    def test_track_disabled_omits_script(self):
        vip = {**VIP, "track_haproxy": False}
        conf = kc.render_keepalived_conf(vip=vip, members=MEMBERS, this_agent=MEMBERS[0],
                                         peer_ips=["10.0.0.12"], auth_pass_plain=None)
        assert "vrrp_script" not in conf
        assert "track_script" not in conf

    def test_no_auth_when_secret_absent(self):
        conf = _render(0, auth=None)
        assert "auth_pass" not in conf

    def test_multicast_omits_unicast(self):
        vip = {**VIP, "use_unicast": False}
        conf = kc.render_keepalived_conf(vip=vip, members=MEMBERS, this_agent=MEMBERS[0],
                                         peer_ips=["10.0.0.12"], auth_pass_plain="x")
        assert "unicast_src_ip" not in conf
        assert "unicast_peer" not in conf

    def test_single_node_omits_unicast_block(self):
        # Single-node VIP (no peers): even with use_unicast=True we must NOT emit a bare
        # `unicast_src_ip`/`unicast_peer` — keepalived treats a unicast keyword with no peers
        # as deprecated, warns, and falls back to multicast (and `keepalived -t` flags it).
        # Omitting the block yields a clean multicast config that holds the VIP solo.
        only = [{"role": "MASTER", "priority": 150, "network_interface": "eth0",
                 "agent_id": 1, "ip_address": "10.0.0.11"}]
        conf = kc.render_keepalived_conf(vip=VIP, members=only, this_agent=only[0],
                                         peer_ips=[], auth_pass_plain=None)
        assert "unicast_src_ip" not in conf
        assert "unicast_peer" not in conf
        assert "state MASTER" in conf
        assert "10.0.0.100/24 dev eth0" in conf


class TestCheckScript:
    def test_default_process_name(self):
        s = kc.build_haproxy_check_script()
        assert "pidof haproxy" in s
        assert kc.OWNERSHIP_MARKER in s

    def test_process_name_from_bin_path(self):
        s = kc.build_haproxy_check_script(bin_path="/opt/hap/sbin/haproxy-ent")
        assert "pidof haproxy-ent" in s

    def test_malicious_bin_path_falls_back(self):
        s = kc.build_haproxy_check_script(bin_path="/x/haproxy; rm -rf /")
        assert "rm -rf" not in s
        assert "pidof haproxy" in s


class TestSecretCrypto:
    def test_roundtrip(self):
        kc.reset_fernet_for_tests()
        token = kc.encrypt_vrrp_secret("s3cr3t")
        assert token != "s3cr3t"
        assert kc.decrypt_vrrp_secret(token) == "s3cr3t"

    def test_decrypt_garbage_returns_none(self):
        kc.reset_fernet_for_tests()
        assert kc.decrypt_vrrp_secret("not-a-fernet-token") is None
