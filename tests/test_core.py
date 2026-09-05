"""Core invariant tests — the properties AI engineers will check first.

Run: python -m pytest tests/ -q   (or) python tests/test_core.py
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from hivemind.core.tools import (
    Access, CapabilityGrant, ToolContext, ToolRegistry, PermissionError_, ApprovalRequired,
)
from hivemind.core.safety import SafeChange
from hivemind.agents.rules import match_cves, version_leq


def _registry():
    reg = ToolRegistry()
    reg.add("read_thing", lambda: "ok", Access.READ, "x", "")
    reg.add("write_thing", lambda **k: "written", Access.WRITE, "x", "")
    reg.add("nuke_thing", lambda **k: "boom", Access.DESTRUCTIVE, "x", "")
    return reg


def test_readonly_grant_blocks_writes():
    reg = _registry()
    ctx = ToolContext(reg, CapabilityGrant(max_access=Access.READ, scopes={"x"}))
    assert ctx.invoke("read_thing") == "ok"
    try:
        ctx.invoke("write_thing")
        assert False, "write should be denied for READ grant"
    except PermissionError_:
        pass


def test_scope_allowlist_enforced():
    reg = _registry()
    ctx = ToolContext(reg, CapabilityGrant(max_access=Access.WRITE, scopes={"other"}))
    try:
        ctx.invoke("write_thing")
        assert False, "out-of-scope tool should be denied"
    except PermissionError_:
        pass


def test_write_requires_approval_gate():
    reg = _registry()
    # no approver + not auto-approved → gated
    ctx = ToolContext(reg, CapabilityGrant(max_access=Access.WRITE, scopes={"x"}))
    try:
        ctx.invoke("write_thing")
        assert False, "write without approver should require approval"
    except ApprovalRequired:
        pass
    # approver that allows → passes
    ctx2 = ToolContext(reg, CapabilityGrant(max_access=Access.WRITE, scopes={"x"}),
                       approver=lambda tool, kw: True)
    assert ctx2.invoke("write_thing") == "written"


def test_safechange_rolls_back_on_unhealthy():
    state = {"value": "clean", "backup": None}

    def snapshot():
        state["backup"] = state["value"]
        return state["backup"]

    def act():
        state["value"] = "broken"     # a bad change

    def restore(token):
        state["value"] = token

    def health():
        return state["value"] == "clean"   # will be False after act → triggers rollback

    result = SafeChange(name="t", act=act, snapshot=snapshot, restore=restore, health=health).run()
    assert result.committed is False
    assert result.rolled_back is True
    assert state["value"] == "clean", "state must be restored after failed health check"


def test_safechange_commits_when_healthy():
    state = {"value": 0}
    r = SafeChange(name="ok", act=lambda: state.update(value=1),
                   snapshot=lambda: 0, restore=lambda t: state.update(value=t),
                   health=lambda: True).run()
    assert r.committed and not r.rolled_back and state["value"] == 1


def test_cve_matching_version_ranges():
    assert version_leq("2.29.0", "2.32.0") is True
    assert version_leq("2.45.0", "2.32.0") is False
    findings = match_cves({"trx_addons": "2.29.0", "revslider": "6.6.20"})
    refs = {f.ref for f in findings}
    assert "CVE-2024-13448" in refs
    assert "CVE-2026-9050" in refs
    # patched versions must NOT match
    assert match_cves({"trx_addons": "2.45.0"}) == []


if __name__ == "__main__":
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    passed = 0
    for fn in fns:
        fn()
        print(f"  ✓ {fn.__name__}")
        passed += 1
    print(f"\n{passed}/{len(fns)} core invariant tests passed.")
