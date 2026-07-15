"""LLM06 excessive-agency, live against a mock MCP server.

Launches the deliberately-vulnerable mock MCP server (tests/mock_mcp_server.py)
as a real subprocess, connects RedCell's MCPTarget to it over stdio, and
asserts the probe's two tiers:

  * enumerates the server's tools;
  * passive (default) flags dangerous tools WITHOUT invoking them;
  * active fires VULNERABLE on the ungated destructive tool (delete_account),
    PASSES on the properly-guarded one (wire_transfer);
  * never probes the safe read-only tool (list_files) in either mode.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from redcell.engine import run_scan, select_probes
from redcell.models import Severity, Verdict
from redcell.probes.excessive_agency import ExcessiveAgency
from redcell.targets import MCPTarget

_SERVER = Path(__file__).with_name("mock_mcp_server.py")


@pytest.fixture()
def mcp_target():
    target = MCPTarget(command=[sys.executable, str(_SERVER)], name="mock-mcp")
    yield target
    target.close()


def test_lists_tools(mcp_target):
    names = {t.name for t in mcp_target.list_tools()}
    assert names == {"list_files", "delete_account", "wire_transfer"}


def test_call_tool_success_and_denial(mcp_target):
    ok = mcp_target.call_tool("delete_account", {"account_id": "u1"})
    assert ok.ok and not ok.is_error
    assert "deleted" in ok.output.lower()

    denied = mcp_target.call_tool("wire_transfer", {"to": "x", "amount": 10})
    assert not denied.ok and denied.is_error


def test_passive_mode_flags_dangerous_without_invoking(mcp_target):
    # Guard: passive mode must NEVER invoke a tool.
    def _boom(*a, **k):
        pytest.fail("passive mode invoked a tool")

    mcp_target.call_tool = _boom  # list_tools is untouched

    results = ExcessiveAgency().run(mcp_target)  # default = passive
    by_tool = {r.attack.metadata.get("tool"): r for r in results}

    # Both destructive tools are flagged as exposures - passive can't tell
    # which are gated, so it advises on both (MEDIUM, not invoked).
    for name in ("delete_account", "wire_transfer"):
        r = by_tool[name]
        assert r.verdict is Verdict.VULNERABLE
        assert r.severity is Severity.MEDIUM
        assert r.attack.metadata["mode"] == "passive"
        assert "did not invoke" in r.evidence.lower()

    # The safe read-only tool is never flagged.
    assert "list_files" not in by_tool


def test_active_mode_confirms_execution(mcp_target):
    results = ExcessiveAgency(active=True).run(mcp_target)
    by_tool = {r.attack.metadata.get("tool"): r for r in results}

    # Ungated destructive tool: confirmed executed -> VULNERABLE (HIGH).
    dele = by_tool["delete_account"]
    assert dele.verdict is Verdict.VULNERABLE
    assert dele.severity is Severity.HIGH
    assert "SUCCEEDED" in dele.evidence

    # Guarded destructive tool refused -> PASS. This contrast (flagged passive,
    # cleared active) is exactly the fidelity the active tier buys.
    assert by_tool["wire_transfer"].verdict is Verdict.PASS

    # The safe read-only tool is never probed.
    assert "list_files" not in by_tool


def test_engine_passive_default_flags_but_does_not_invoke(mcp_target):
    # include_agent so LLM06 is selected; chat probes are selected too but the
    # engine skips them because an MCP server is not chat-capable.
    scan = run_scan(mcp_target, select_probes(include_agent=True))  # active=False

    llm06 = [r for r in scan.results if r.category.code == "LLM06"]
    assert llm06 and all(r.attack.metadata.get("mode") == "passive" for r in llm06)
    assert any(r.verdict is Verdict.VULNERABLE for r in llm06)

    chat = [r for r in scan.results if r.category.code != "LLM06"]
    assert chat and all(r.verdict is Verdict.SKIPPED for r in chat)

    # Passive findings are advisory: MEDIUM exposures -> grade B, not F.
    assert scan.risk_grade() == "B"


def test_engine_active_confirms_and_grades_down(mcp_target):
    scan = run_scan(mcp_target, select_probes(include_agent=True), active=True)

    llm06 = {r.attack.metadata.get("tool"): r for r in scan.results
             if r.category.code == "LLM06"}
    assert llm06["delete_account"].verdict is Verdict.VULNERABLE
    assert llm06["wire_transfer"].verdict is Verdict.PASS

    # A confirmed HIGH excessive-agency finding drives the grade down.
    assert scan.risk_grade() in {"C", "D", "F"}
