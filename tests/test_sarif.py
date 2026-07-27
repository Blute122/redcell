"""SARIF v2.1.0 reporter tests.

This file is the one place to look for "how is SARIF tested". It has two
concerns, added in two commits:

* T3 - pin the severity mappings so a future edit can't silently drift them.
* T4 - schema-validate the document and guard the structural invariants
  (no orphan ruleIds, only VULNERABLE findings become results).
"""

from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from redcell.engine import run_scan, select_probes
from redcell.models import (
    Attack,
    OwaspCategory,
    ProbeResult,
    ScanResult,
    Severity,
    Verdict,
)
from redcell.report_sarif import build_sarif
from redcell.targets import MockVulnerableTarget

# Official SARIF 2.1.0 schema, vendored for hermetic validation. See
# tests/fixtures/README.md for provenance (OASIS errata01, frozen 2.1.0).
_SCHEMA = json.loads(
    (Path(__file__).parent / "fixtures" / "sarif-2.1.0.schema.json").read_text(encoding="utf-8")
)

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


# --- T4: schema validation + structural invariants --------------------------
#
# Schema validation proves the document is well-formed, not correct: the schema
# permits orphan ruleIds and other semantic errors. The invariants below do the
# real work.
#
# Design intent: `rules` is one entry per probe *exercised* in the scan (any
# verdict), and `results` is VULNERABLE findings only. So results reference a
# subset of rules, and rules mirror exactly the distinct probes in the scan.


def _mixed_scan() -> ScanResult:
    """A scan spanning all verdicts, so rules-vs-results can't hide behind a
    demo where every probe happens to fire."""
    def result(pid: str, verdict: Verdict) -> ProbeResult:
        return ProbeResult(
            probe_id=pid, probe_name=f"{pid} probe", category=OwaspCategory.LLM01,
            attack=Attack(id=f"{pid}-a", prompt="x"), verdict=verdict,
            severity=Severity.HIGH, evidence="e",
        )
    return ScanResult(target_name="mixed", results=[
        result("probe-vuln", Verdict.VULNERABLE),
        result("probe-pass", Verdict.PASS),
        result("probe-skip", Verdict.SKIPPED),
        result("probe-error", Verdict.ERROR),
    ])


def test_demo_sarif_validates_against_official_schema():
    doc = build_sarif(run_scan(MockVulnerableTarget(), select_probes()))
    jsonschema.validate(instance=doc, schema=_SCHEMA)  # raises on failure


def test_no_orphan_rule_ids():
    # Every ruleId in results must resolve to a declared rule - the single most
    # common SARIF error, and one the schema does NOT catch.
    for scan in (run_scan(MockVulnerableTarget(), select_probes()), _mixed_scan()):
        run = build_sarif(scan)["runs"][0]
        declared = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
        referenced = {result["ruleId"] for result in run["results"]}
        assert referenced <= declared, f"orphan ruleIds: {referenced - declared}"


def test_only_vulnerable_findings_become_results():
    scan = _mixed_scan()
    run = build_sarif(scan)["runs"][0]
    assert len(run["results"]) == len(scan.findings) == 1
    assert {r["ruleId"] for r in run["results"]} == {"probe-vuln"}


def test_rules_mirror_the_probes_exercised_in_the_scan():
    # rules == distinct probes across ALL results (not just findings), so a
    # probe that only PASSed still gets a rule and the two can't drift apart.
    scan = _mixed_scan()
    run = build_sarif(scan)["runs"][0]
    declared = {rule["id"] for rule in run["tool"]["driver"]["rules"]}
    exercised = {r.probe_id for r in scan.results}
    assert declared == exercised


def test_ruleindex_points_at_the_matching_rule():
    run = build_sarif(run_scan(MockVulnerableTarget(), select_probes()))["runs"][0]
    rules = run["tool"]["driver"]["rules"]
    for result in run["results"]:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]
