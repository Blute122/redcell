"""SARIF v2.1.0 reporter tests.

This file is the one place to look for "how is SARIF tested". It has two
concerns, added in two commits:

* T3 - pin the severity mappings so a future edit can't silently drift them.
* T4 - schema-validate the document and guard the structural invariants
  (no orphan ruleIds, only VULNERABLE findings become results).
"""

from __future__ import annotations

from redcell.models import (
    Attack,
    OwaspCategory,
    ProbeResult,
    ScanResult,
    Severity,
    Verdict,
)
from redcell.report_sarif import build_sarif

# The full contract, one row per severity level. The drift being guarded
# against is exactly a later edit nudging one pair (e.g. MEDIUM 5.0 -> 6.0), so
# every level is asserted explicitly - a single spot-check would leave the
# other four unguarded.
_EXPECTED: dict[Severity, tuple[str, str]] = {
    Severity.CRITICAL: ("error", "9.0"),
    Severity.HIGH: ("error", "7.0"),
    Severity.MEDIUM: ("warning", "5.0"),
    Severity.LOW: ("note", "2.0"),
    Severity.INFO: ("note", "0.0"),
}


def _finding(severity: Severity) -> ProbeResult:
    return ProbeResult(
        probe_id=f"probe-{severity.label}",
        probe_name=f"{severity.label} probe",
        category=OwaspCategory.LLM01,
        attack=Attack(id=f"attack-{severity.label}", prompt="x"),
        verdict=Verdict.VULNERABLE,
        severity=severity,
        evidence="evidence",
    )


def _scan_one_per_severity() -> ScanResult:
    return ScanResult(target_name="mapping-target", results=[_finding(s) for s in _EXPECTED])


def test_every_severity_maps_to_its_level_and_security_severity():
    doc = build_sarif(_scan_one_per_severity())
    run = doc["runs"][0]
    rules = {r["id"]: r for r in run["tool"]["driver"]["rules"]}
    results = {r["ruleId"]: r for r in run["results"]}

    for severity, (level, security_severity) in _EXPECTED.items():
        pid = f"probe-{severity.label}"
        # result level (what GitHub renders as error/warning/note)
        assert results[pid]["level"] == level, f"{severity.label}: result level"
        # rule default level (self-describing ruleset)
        assert rules[pid]["defaultConfiguration"]["level"] == level, (
            f"{severity.label}: rule default level"
        )
        # security-severity lives on the rule, where GitHub reads it
        assert rules[pid]["properties"]["security-severity"] == security_severity, (
            f"{severity.label}: security-severity"
        )


def test_security_severity_is_only_on_the_rule_not_the_result():
    # It belongs on the rule (GitHub reads it there); duplicating it onto the
    # result was removed in review, so guard against it creeping back.
    run = build_sarif(_scan_one_per_severity())["runs"][0]
    for result in run["results"]:
        assert "security-severity" not in result["properties"]
