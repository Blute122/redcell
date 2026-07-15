"""Smoke + behaviour tests.

Runs the full probe set against the deliberately vulnerable mock and asserts
that the known-vulnerable categories actually fire. This is what lets you
say, in a viva, that detection is validated against a controlled baseline.
"""

from redcell.engine import run_scan, select_probes
from redcell.models import Verdict
from redcell.targets import MockVulnerableTarget


def _scan():
    target = MockVulnerableTarget()
    return run_scan(target, select_probes())


def test_scan_runs_and_produces_results():
    scan = _scan()
    assert scan.results, "expected at least one result"


def test_injection_detected_on_vulnerable_mock():
    scan = _scan()
    injection = [r for r in scan.results if r.category.code == "LLM01"]
    assert any(r.verdict is Verdict.VULNERABLE for r in injection)


def test_secret_leak_detected():
    scan = _scan()
    sid = [r for r in scan.results if r.category.code == "LLM02"]
    assert any(r.verdict is Verdict.VULNERABLE for r in sid)


def test_agent_probes_skipped_for_chat_target():
    scan = _scan()
    agent = [r for r in scan.results if r.category.code == "LLM06"]
    # not included by default; when included they should skip on a chat target
    assert all(r.verdict is not Verdict.VULNERABLE for r in agent)


def test_risk_grade_is_failing_for_vulnerable_mock():
    scan = _scan()
    assert scan.risk_grade() in {"C", "D", "F"}
