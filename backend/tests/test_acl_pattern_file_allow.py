"""Issue #38 follow-up — ACL `-f <file>` pattern-file support (v1.8.9).

The Bulgu #12 hard rejects were removed: pattern files are
operator-managed host files (same policy as the SPOE
`filter ... config <path>` reference preserved since v1.8.8), bulk
import always accepted `-f`, and the agent runs `haproxy -c` before
every reload so a missing file fails safely. These tests pin:

1. ACCEPT — the manual FrontendConfig model and the wizard models
   accept `-f` in every rule field (string + dict shapes).
2. GUARDS KEPT — `$(`/backtick shell-substitution rejects and the
   `X !X` contradiction machinery are unchanged.
3. WARNINGS — `_pattern_file_warnings` emits exactly one advisory
   listing the referenced files, and NOTHING for `-f`-free rules
   (zero-noise: existing users see no new output).
4. ADVISORY — the bulk-import preview advisory block scans
   acl/use_backend rules (and only those fields).
"""

import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from models.frontend import FrontendConfig  # noqa: E402
from routers.frontend import _pattern_file_warnings  # noqa: E402


ACL_F = "blacklisted src -f /etc/haproxy/blacklist.lst"
UB_F = "be-secure if { src -f /etc/haproxy/allowlist.lst }"
REDIR_F = "location /blocked if { src -f /etc/haproxy/blacklist.lst }"


# ──────────────────────────────────────────────────────────────────────
# 1. ACCEPT — manual FrontendConfig model
# ──────────────────────────────────────────────────────────────────────


def test_frontend_config_accepts_acl_file_flag():
    fe = FrontendConfig(name="fe1", bind_port=80, mode="http", acl_rules=[ACL_F])
    assert fe.acl_rules == [ACL_F]


def test_frontend_config_accepts_use_backend_file_flag():
    fe = FrontendConfig(
        name="fe1", bind_port=80, mode="http", use_backend_rules=[UB_F])
    assert fe.use_backend_rules == [UB_F]


def test_frontend_config_accepts_redirect_string_file_flag():
    fe = FrontendConfig(
        name="fe1", bind_port=80, mode="http", redirect_rules=[REDIR_F])
    assert fe.redirect_rules == [REDIR_F]


def test_frontend_config_accepts_redirect_dict_file_flag():
    rule = {"type": "scheme", "scheme": "https",
            "condition": "if { src -f /etc/haproxy/blacklist.lst }"}
    fe = FrontendConfig(
        name="fe1", bind_port=80, mode="http", redirect_rules=[rule])
    assert fe.redirect_rules == [rule]


# ──────────────────────────────────────────────────────────────────────
# 2. GUARDS KEPT — dangerous-content rejects unchanged
# ──────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("bad_rule", [
    "acl1 path $(rm -rf /)",
    "acl1 path `id`",
])
def test_acl_shell_substitution_still_rejected(bad_rule):
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        FrontendConfig(name="fe1", bind_port=80, mode="http", acl_rules=[bad_rule])


@pytest.mark.parametrize("bad_rule", [
    "be1 if $(whoami)",
    "be1 if `id`",
])
def test_use_backend_shell_substitution_still_rejected(bad_rule):
    from pydantic import ValidationError
    with pytest.raises(ValidationError):
        FrontendConfig(
            name="fe1", bind_port=80, mode="http", use_backend_rules=[bad_rule])


def test_contradiction_detection_still_works_on_file_flag_rules():
    """Interaction guard: a `-f` rule with an `X !X` contradiction is
    still caught by the handler-level contradiction machinery — the
    `-f` relaxation must not weaken that gate."""
    from models.frontend import _frontend_has_acl_contradiction
    assert _frontend_has_acl_contradiction(
        "be1 if blacklisted !blacklisted") is True
    # And a normal -f rule is NOT a contradiction.
    assert _frontend_has_acl_contradiction(UB_F) is False


# ──────────────────────────────────────────────────────────────────────
# 3. WARNINGS — _pattern_file_warnings (zero-noise contract)
# ──────────────────────────────────────────────────────────────────────


def test_pattern_file_warnings_lists_unique_paths():
    warnings = _pattern_file_warnings(
        acl_rules=[ACL_F, "other src -f /etc/haproxy/blacklist.lst"],
        use_backend_rules=[UB_F],
        redirect_rules=[{"condition": "if { src -f /etc/haproxy/geo.lst }"}],
    )
    assert len(warnings) == 1
    w = warnings[0]
    assert "/etc/haproxy/blacklist.lst" in w
    assert "/etc/haproxy/allowlist.lst" in w
    assert "/etc/haproxy/geo.lst" in w
    # Duplicate path listed once.
    assert w.count("/etc/haproxy/blacklist.lst") == 1
    # Non-blocking framing: mentions fail-safe haproxy -c.
    assert "haproxy -c" in w


def test_pattern_file_warnings_empty_without_file_flag():
    """Zero-noise: operators who don't use `-f` must see NO warning."""
    assert _pattern_file_warnings(
        acl_rules=["is_api path_beg /api", "is_admin src 10.0.0.0/24"],
        use_backend_rules=["be-api if is_api"],
        redirect_rules=[{"type": "scheme", "scheme": "https",
                         "condition": "if !{ ssl_fc }"}],
    ) == []
    assert _pattern_file_warnings() == []


def test_pattern_file_warnings_ignores_dash_f_substrings():
    """`-file`/`-foo` substrings must not trigger the advisory."""
    assert _pattern_file_warnings(
        acl_rules=["is_self path_beg /self-config-file",
                   "is_foo path_beg /foo -m beg"],
    ) == []


# ──────────────────────────────────────────────────────────────────────
# 4. Wizard models accept `-f` (string + dict) — parity
# ──────────────────────────────────────────────────────────────────────


def test_wizard_models_accept_file_flag():
    from models.site_wizard import FrontendStep

    fe = FrontendStep(
        name="fe1", mode="http", bind_address="*", bind_port=80,
        acl_rules=[ACL_F],
        use_backend_rules=["be-x if blacklisted"],
        redirect_rules=[{"type": "scheme", "target": "https",
                         "condition": "if { src -f /etc/haproxy/x.lst }"}],
    )
    assert fe.acl_rules == [ACL_F]
    assert fe.redirect_rules[0]["condition"] == "if { src -f /etc/haproxy/x.lst }"


# ──────────────────────────────────────────────────────────────────────
# 5. Bulk-import preview advisory — source-level pin
# ──────────────────────────────────────────────────────────────────────


def test_parse_bulk_advisory_scans_only_structured_rule_fields():
    """The preview advisory scans acl_rules/use_backend_rules but NOT
    request_headers/tcp_request_rules (always-free-form fields —
    warning there would add new noise for existing users)."""
    src = Path(__file__).resolve().parents[1] / "routers" / "config.py"
    text = src.read_text()
    block_start = text.index("pattern-file advisory")
    block = text[block_start:block_start + 1200]
    assert 'acl_rules' in block
    assert 'use_backend_rules' in block
    assert 'request_headers' not in block.split("_pattern_paths")[1], (
        "advisory must not scan request_headers")


def test_no_dash_f_reject_left_in_models():
    """No model file may still hard-reject the `-f` flag."""
    for rel in ("models/frontend.py", "models/site_wizard.py"):
        text = (Path(__file__).resolve().parents[1] / rel).read_text()
        for m in re.finditer(r"-f\(\\s\|\$\)", text):
            ctx = text[max(0, m.start() - 400):m.start() + 400]
            assert "raise ValueError" not in ctx, (
                f"{rel}: a `-f` reject regex still sits next to a raise")
