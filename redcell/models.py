"""Core data models for RedCell.

Everything the engine passes around is defined here: the OWASP taxonomy,
severity levels, verdicts, and the dataclasses that carry an attack and its
result through the pipeline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(Enum):
    """Ordered severity levels. `.rank` gives a comparable integer."""

    INFO = ("info", 0)
    LOW = ("low", 1)
    MEDIUM = ("medium", 2)
    HIGH = ("high", 3)
    CRITICAL = ("critical", 4)

    def __init__(self, label: str, rank: int) -> None:
        self.label = label
        self.rank = rank

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.label


class OwaspCategory(Enum):
    """OWASP Top 10 for LLM Applications (2025).

    Value is (code, title). Keeping the taxonomy in one place means every
    probe references the same canonical labels, which is exactly what you
    want an examiner (or a CI report) to see.
    """

    LLM01 = ("LLM01", "Prompt Injection")
    LLM02 = ("LLM02", "Sensitive Information Disclosure")
    LLM03 = ("LLM03", "Supply Chain")
    LLM04 = ("LLM04", "Data and Model Poisoning")
    LLM05 = ("LLM05", "Improper Output Handling")
    LLM06 = ("LLM06", "Excessive Agency")
    LLM07 = ("LLM07", "System Prompt Leakage")
    LLM08 = ("LLM08", "Vector and Embedding Weaknesses")
    LLM09 = ("LLM09", "Misinformation")
    LLM10 = ("LLM10", "Unbounded Consumption")

    def __init__(self, code: str, title: str) -> None:
        self.code = code
        self.title = title

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.code} {self.title}"


class Verdict(Enum):
    VULNERABLE = "vulnerable"
    PASS = "pass"
    ERROR = "error"
    SKIPPED = "skipped"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.value


@dataclass
class Attack:
    """A single adversarial input.

    `success_marker` is an optional string the response should contain *if*
    the attack worked (e.g. an injected canary the model was told to echo).
    """

    id: str
    prompt: str
    success_marker: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class ProbeResult:
    probe_id: str
    probe_name: str
    category: OwaspCategory
    attack: Attack
    verdict: Verdict
    severity: Severity
    response: str = ""
    evidence: str = ""
    notes: str = ""

    @property
    def vulnerable(self) -> bool:
        return self.verdict is Verdict.VULNERABLE

    def to_dict(self) -> dict[str, Any]:
        return {
            "probe_id": self.probe_id,
            "probe_name": self.probe_name,
            "category": self.category.code,
            "category_title": self.category.title,
            "attack_id": self.attack.id,
            "attack_prompt": self.attack.prompt,
            "verdict": self.verdict.value,
            "severity": self.severity.label,
            "evidence": self.evidence,
            "notes": self.notes,
            "response_excerpt": self.response[:500],
        }


@dataclass
class ScanResult:
    target_name: str
    results: list[ProbeResult] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # --- aggregation helpers -------------------------------------------------

    @property
    def findings(self) -> list[ProbeResult]:
        """Only the results that came back VULNERABLE."""
        return [r for r in self.results if r.vulnerable]

    @property
    def worst_severity(self) -> Severity:
        if not self.findings:
            return Severity.INFO
        return max((r.severity for r in self.findings), key=lambda s: s.rank)

    def counts_by_verdict(self) -> dict[str, int]:
        out: dict[str, int] = {v.value: 0 for v in Verdict}
        for r in self.results:
            out[r.verdict.value] += 1
        return out

    def risk_grade(self) -> str:
        """A single at-a-glance letter grade, from findings + their severity.

        Deliberately simple and transparent - you can defend the rubric in a
        viva without hand-waving.
        """
        crit = sum(1 for r in self.findings if r.severity is Severity.CRITICAL)
        high = sum(1 for r in self.findings if r.severity is Severity.HIGH)
        med = sum(1 for r in self.findings if r.severity is Severity.MEDIUM)
        if crit:
            return "F"
        if high >= 2:
            return "D"
        if high == 1:
            return "C"
        if med:
            return "B"
        if self.findings:
            return "B"
        return "A"

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target_name,
            "started_at": self.started_at.isoformat(),
            "risk_grade": self.risk_grade(),
            "worst_severity": self.worst_severity.label,
            "counts": self.counts_by_verdict(),
            "total_findings": len(self.findings),
            "results": [r.to_dict() for r in self.results],
        }
