"""Insecure-auth probe — passive advisory + active confirmation, hermetic.

Mirrors the excessive-agency scenario against the mock MCP server: the ungated
``delete_account`` and the auth-gated ``wire_transfer``. Also pins the two things
the brief cares about most: the shared destructive classifier (no drift with
excessive-agency) and the schema-level auth-parameter analysis.
"""

from __future__ import annotations

import sys
from pathlib import Path

from redcell.detectors.tools import find_auth_parameter
from redcell.models import Severity, ToolSpec, Verdict
from redcell.probes.excessive_agency import ExcessiveAgency
from redcell.probes.insecure_auth import InsecureAuth
from redcell.probes import all_probes
from redcell.targets import MCPTarget

_SERVER = Path(__file__).with_name("mock_mcp_server.py")


def _target(*extra_args: str) -> MCPTarget:
    return MCPTarget(command=[sys.executable, str(_SERVER), *extra_args], name="ia")


# --- registration + shared classifier ---------------------------------------

def test_probe_registered_under_llm06_and_agent():
    probe = next((p for p in all_probes() if p.id == "llm06-insecure-auth"), None)
    assert probe is not None
    assert probe.category.code == "LLM06"
    assert probe.requires_agent is True


def test_shares_the_same_destructive_classifier_as_excessive_agency():
    # Both probes import classify_tool from the same module - literally the same
    # function object - so their notion of "destructive" cannot drift.
    import redcell.probes.excessive_agency as ea
    import redcell.probes.insecure_auth as ia
    assert ia.classify_tool is ea.classify_tool


# --- auth-parameter detection -----------------------------------------------

def test_find_auth_parameter():
    gated = ToolSpec(name="wire", input_schema={
        "properties": {"to": {}, "amount": {}, "auth_token": {}}})
    ungated = ToolSpec(name="del", input_schema={"properties": {"account_id": {}}})
    assert find_auth_parameter(gated) == "auth_token"
    assert find_auth_parameter(ungated) is None


# --- passive: flags both, severity keyed on schema auth ----------------------

def test_passive_flags_both_with_schema_keyed_severity():
    target = _target()
    try:
        results = InsecureAuth().run(target)  # passive default
    finally:
        target.close()
    by_tool = {r.attack.metadata.get("tool"): r for r in results}

    # delete_account has no auth parameter -> the clearer gap, MEDIUM
    assert by_tool["delete_account"].verdict is Verdict.VULNERABLE
    assert by_tool["delete_account"].severity is Severity.MEDIUM
    assert "NO authentication parameter" in by_tool["delete_account"].evidence

    # wire_transfer declares auth_token -> lower confidence, LOW
    assert by_tool["wire_transfer"].verdict is Verdict.VULNERABLE
    assert by_tool["wire_transfer"].severity is Severity.LOW
    assert "auth_token" in by_tool["wire_transfer"].evidence

    # never invoked anything in passive mode
    assert all(r.attack.metadata.get("mode") == "passive" for r in results)


def test_passive_does_not_invoke(monkeypatch):
    target = _target()
    monkeypatch.setattr(target, "call_tool",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("invoked!")))
    try:
        results = InsecureAuth().run(target)
    finally:
        target.close()
    assert results  # produced advisories without ever calling a tool


# --- active: confirm delete_account, clear wire_transfer ---------------------

def test_active_confirms_ungated_and_clears_gated():
    target = _target()
    try:
        results = InsecureAuth(active=True).run(target)
    finally:
        target.close()
    by_tool = {r.attack.metadata.get("tool"): r for r in results}

    assert by_tool["delete_account"].verdict is Verdict.VULNERABLE
    assert by_tool["delete_account"].severity is Severity.HIGH
    assert "SUCCEEDED" in by_tool["delete_account"].evidence

    assert by_tool["wire_transfer"].verdict is Verdict.PASS


def test_active_clears_everything_on_a_hardened_server():
    target = _target("--hardened")
    try:
        results = InsecureAuth(active=True).run(target)
    finally:
        target.close()
    assert all(r.verdict is not Verdict.VULNERABLE for r in results)
