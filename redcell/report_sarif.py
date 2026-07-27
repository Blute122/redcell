"""SARIF v2.1.0 output for RedCell scans.

SARIF (Static Analysis Results Interchange Format) is the JSON schema GitHub
ingests to render findings natively under Security -> Code scanning. This module
converts a ``ScanResult`` into a SARIF 2.1.0 document with the stdlib ``json``
only - no runtime dependency. It targets **2.1.0 specifically**, the version
GitHub's ``upload-sarif`` action consumes.

Only VULNERABLE results become SARIF ``results``; PASS / SKIPPED / ERROR are not
findings. Every ``ruleId`` that appears in ``results`` is declared in
``tool.driver.rules`` (orphan ruleIds are the single most common SARIF error).

Two conversions SARIF forces, and how we resolve them:

**Severity -> SARIF level.** SARIF ``level`` has only ``error`` | ``warning`` |
``note``, so the five-level ``Severity`` is collapsed:

    CRITICAL, HIGH -> error
    MEDIUM         -> warning
    LOW, INFO      -> note

That loses granularity, so each *rule* carries
``properties.security-severity`` - a 0-10 numeric string GitHub reads (from the
rule, not the result) to sort, filter, and assign its own Critical/High/Medium/
Low band. The values are chosen to land in GitHub's bands so its severity
matches ours:

    CRITICAL -> "9.0"   (GitHub: >= 9.0  critical)
    HIGH     -> "7.0"   (GitHub: 7.0-8.9 high)
    MEDIUM   -> "5.0"   (GitHub: 4.0-6.9 medium)
    LOW      -> "2.0"   (GitHub: 0.1-3.9 low)
    INFO     -> "0.0"

**Locations.** RedCell is black-box: findings are behavioural, against a running
endpoint, and are not tied to any source file or line. Fabricating a physical
path would be a false claim about where the bug lives. The idiomatic SARIF for a
dynamic tool is therefore a ``logicalLocations`` entry naming the probe and its
OWASP category - that is the *semantic* location of the finding.

GitHub code scanning additionally wants a ``physicalLocation`` to surface an
alert, so each result also carries one whose ``artifactLocation.uri`` is a
stable, deliberately non-source placeholder under ``redcell-findings/`` (the
scan target's name). It is namespaced so it can never be mistaken for a real
source file, and its purpose is spelled out in the artifact ``description``. The
logical location remains the source of truth.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

from . import __version__
from .models import ProbeResult, ScanResult, Severity

_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/"
    "sarif-schema-2.1.0.json"
)
_INFORMATION_URI = "https://github.com/Blute122/redcell"

# Severity -> SARIF level (error | warning | note). See module docstring.
_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}

# Severity -> GitHub security-severity score (0-10, as a string). See docstring.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.0",
    Severity.HIGH: "7.0",
    Severity.MEDIUM: "5.0",
    Severity.LOW: "2.0",
    Severity.INFO: "0.0",
}


def _slug(text: str) -> str:
    """A filesystem-safe slug for use in the placeholder location uri."""
    return re.sub(r"[^a-zA-Z0-9._-]+", "-", text).strip("-") or "target"


def _rule(result: ProbeResult) -> dict[str, Any]:
    """A SARIF reportingDescriptor (rule) derived from a probe's result."""
    code = result.category.code
    return {
        "id": result.probe_id,
        "name": result.probe_name,
        "shortDescription": {"text": result.probe_name},
        "fullDescription": {
            "text": f"{result.probe_name}. Maps to OWASP {code}: {result.category.title}."
        },
        "helpUri": _INFORMATION_URI,
        "defaultConfiguration": {"level": _LEVEL[result.severity]},
        "properties": {
            "tags": [code, "security"],
            "security-severity": _SECURITY_SEVERITY[result.severity],
        },
    }


def _fingerprint(result: ProbeResult) -> str:
    """Stable per-finding hash so GitHub tracks an alert across re-uploads."""
    key = f"{result.probe_id}::{result.attack.id}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _sarif_result(result: ProbeResult, rule_index: int, target_name: str) -> dict[str, Any]:
    """One SARIF result for a single VULNERABLE finding."""
    detail = result.evidence or result.notes or "flagged as vulnerable"
    return {
        "ruleId": result.probe_id,
        "ruleIndex": rule_index,
        "level": _LEVEL[result.severity],
        "message": {"text": f"{result.probe_name}: {detail}"},
        "locations": [
            {
                # Placeholder physical location: NOT a source file (RedCell is
                # black-box). Namespaced + described so it can't be misread.
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": f"redcell-findings/{_slug(target_name)}",
                        "description": {
                            "text": "RedCell scan target - behavioural finding, "
                            "not a source file location."
                        },
                    }
                },
                # The real, semantic location of the finding.
                "logicalLocations": [
                    {
                        "name": result.probe_id,
                        "fullyQualifiedName": f"{result.category.code}/{result.probe_id}",
                    }
                ],
            }
        ],
        "partialFingerprints": {"redcellAttackId/v1": _fingerprint(result)},
        "properties": {
            "owasp": result.category.code,
            "severity": result.severity.label,
            "attackId": result.attack.id,
        },
    }


def build_sarif(scan: ScanResult) -> dict[str, Any]:
    """Build the SARIF 2.1.0 document as a plain dict (for tests / callers)."""
    # One rule per probe that appears in the scan, in first-seen order. Declaring
    # rules for probes that produced no finding is valid and keeps the ruleset
    # self-describing; it also guarantees no result can reference an orphan rule.
    rule_index: dict[str, int] = {}
    rules: list[dict[str, Any]] = []
    for r in scan.results:
        if r.probe_id not in rule_index:
            rule_index[r.probe_id] = len(rules)
            rules.append(_rule(r))

    results = [
        _sarif_result(r, rule_index[r.probe_id], scan.target_name)
        for r in scan.findings
    ]

    return {
        "$schema": _SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "RedCell",
                        "version": __version__,
                        "informationUri": _INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def to_sarif(scan: ScanResult, indent: int = 2) -> str:
    """Render the scan as a SARIF 2.1.0 JSON document."""
    return json.dumps(build_sarif(scan), indent=indent)
