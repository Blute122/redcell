"""Evaluation-harness tests: the hardened targets must be false-positive-free.

The credibility of the results table rests on the negative controls behaving.
These tests pin that down: a refusing chat model and an auth-gated MCP server
produce zero VULNERABLE verdicts, while the vulnerable targets still fire.
"""

from __future__ import annotations

import sys
from pathlib import Path

from redcell.engine import run_scan, select_probes
from redcell.models import Verdict
from redcell.probes.excessive_agency import ExcessiveAgency
from redcell.targets import HardenedMockTarget, MCPTarget

from evaluation.run_eval import _CHAT_CODES, render_markdown, run_evaluation

_SERVER = Path(__file__).with_name("mock_mcp_server.py")


def test_hardened_chat_target_yields_no_findings():
    scan = run_scan(HardenedMockTarget(), select_probes())
    vulnerable = [r for r in scan.results if r.verdict is Verdict.VULNERABLE]
    assert not vulnerable, f"hardened chat target produced false positives: {vulnerable}"
    assert scan.risk_grade() == "A"


def test_hardened_mcp_server_gates_destructive_tools():
    # Active mode against the --hardened server: every destructive call refused.
    target = MCPTarget(
        command=[sys.executable, str(_SERVER), "--hardened"], name="hardened-mcp"
    )
    try:
        results = ExcessiveAgency(active=True).run(target)
    finally:
        target.close()
    by_tool = {r.attack.metadata.get("tool"): r for r in results}
    assert by_tool["delete_account"].verdict is Verdict.PASS
    assert by_tool["wire_transfer"].verdict is Verdict.PASS
    assert all(r.verdict is not Verdict.VULNERABLE for r in results)


def test_evaluation_harness_zero_false_positives():
    report = run_evaluation(include_real=False)
    # Precision claim: not a single false positive in any category.
    assert report.total_false_positives == 0
    for s in report.stats:
        assert s.false_positives == 0, f"{s.code} false positive"


def test_functional_correctness_every_planted_case_detected():
    # Functional-correctness claim: on the deliberately-vulnerable mock every
    # chat attack is a genuine positive and is detected (N/N per category),
    # and the ungated MCP tool is confirmed.
    report = run_evaluation(include_real=False)
    for s in report.stats:
        if s.code in _CHAT_CODES:
            assert s.detected == s.attempts, f"{s.code} missed a planted case"
    llm06 = next(s for s in report.stats if s.code == "LLM06")
    assert llm06.detected >= 1


def test_evaluation_passive_over_reports_on_hardened():
    # The documented fidelity contrast: passive flags the gated tools, active clears them.
    report = run_evaluation(include_real=False)
    assert report.passive_hardened_flags >= 1
    assert report.active_hardened_flags == 0


def test_live_model_column_skips_when_env_unset(monkeypatch):
    # The real-target section must skip cleanly (no column, no error) when the
    # endpoint env vars are unset - this is what keeps CI green.
    for var in ("REDCELL_EVAL_URL", "REDCELL_EVAL_MODEL", "REDCELL_EVAL_KEY"):
        monkeypatch.delenv(var, raising=False)
    report = run_evaluation(include_real=True)
    assert report.real_label is None
    assert report.real_note is None
    assert "Live model" not in render_markdown(report)
