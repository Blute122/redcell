"""The --fail-on CI gate.

`redcell scan ... --fail-on <severity>` exits non-zero when any finding is at
or above the threshold, so a pipeline can block on it. Absent the flag the exit
code is unchanged (0), which keeps it opt-in.
"""

from __future__ import annotations

import pytest
from typer.testing import CliRunner

from redcell.cli import app
from redcell.models import ScanResult, Severity

runner = CliRunner()


# --- severity parsing / threshold logic --------------------------------------

def test_severity_from_label_is_case_insensitive():
    assert Severity.from_label("HIGH") is Severity.HIGH
    assert Severity.from_label(" critical ") is Severity.CRITICAL


def test_severity_from_label_rejects_unknown():
    with pytest.raises(ValueError, match="unknown severity"):
        Severity.from_label("catastrophic")


def test_exceeds_is_inclusive_of_the_threshold():
    from redcell.models import Attack, OwaspCategory, ProbeResult, Verdict

    def finding(sev: Severity) -> ProbeResult:
        return ProbeResult(
            probe_id="p", probe_name="p", category=OwaspCategory.LLM01,
            attack=Attack(id="a", prompt="x"), verdict=Verdict.VULNERABLE, severity=sev,
        )

    scan = ScanResult(target_name="t", results=[finding(Severity.MEDIUM)])
    assert scan.exceeds(Severity.MEDIUM)   # at the threshold counts
    assert scan.exceeds(Severity.LOW)      # above it counts
    assert not scan.exceeds(Severity.HIGH)  # below it does not
    assert ScanResult(target_name="t").exceeds(Severity.INFO) is False  # no findings


# --- CLI exit codes -----------------------------------------------------------

def test_no_fail_on_flag_exits_zero_despite_findings():
    result = runner.invoke(app, ["scan", "--demo"])
    assert result.exit_code == 0


def test_fail_on_high_exits_nonzero_on_vulnerable_demo():
    result = runner.invoke(app, ["scan", "--demo", "--fail-on", "high"])
    assert result.exit_code == 1


def test_fail_on_above_worst_finding_exits_zero():
    # LLM09 alone yields only a LOW finding, so a HIGH gate must pass.
    result = runner.invoke(app, ["scan", "--demo", "-c", "LLM09", "--fail-on", "high"])
    assert result.exit_code == 0


def test_fail_on_at_the_finding_severity_exits_nonzero():
    result = runner.invoke(app, ["scan", "--demo", "-c", "LLM09", "--fail-on", "low"])
    assert result.exit_code == 1


def test_invalid_fail_on_value_is_a_usage_error():
    result = runner.invoke(app, ["scan", "--demo", "--fail-on", "bogus"])
    assert result.exit_code == 2
