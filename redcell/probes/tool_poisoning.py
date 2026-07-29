"""LLM01 (via tooling): MCP tool-poisoning.

A malicious MCP server can attack the model through the *tool metadata* it
advertises — descriptions that embed instructions to the model, hidden/unicode
directives, or exfiltration chaining. The tool metadata is the attack surface,
not the model's reply, so this probe inspects what ``list_tools()`` returned and
never invokes a tool. It is therefore passive with no ``--active`` variant
(there is nothing to confirm by calling).

Maps to **LLM01** (prompt injection, delivered via tooling), cross-referenced to
**LLM06** (its aim is to induce unauthorised tool use). Findings carry the
severity of the indicator that fired — unambiguous artifacts (hidden characters,
explicit injection phrasing, filesystem exfiltration) are HIGH; a
context-exfiltration co-occurrence, which a legitimate memory tool can resemble,
is MEDIUM. See ``detectors/metadata.py`` for the indicator design and the clean
cases each one is built to spare.

Boundary: this inspects advertised metadata. Poisoning injected at tool-call
time (a tool returning a malicious result mid-conversation) is the sequence
problem handled by the injection-sequence probe, not here.
"""

from __future__ import annotations

from ..detectors.metadata import ToolPoisoningDetector
from ..detectors.rules import Detector
from ..models import Attack, OwaspCategory, ProbeResult, Severity, Verdict
from ..targets.base import AgentTarget, Target
from .base import Probe, register


@register
class ToolPoisoning(Probe):
    """Flags malicious/deceptive MCP tool metadata (passive; never invokes)."""

    id = "llm01-tool-poisoning"
    name = "Tool poisoning (malicious MCP tool metadata)"
    category = OwaspCategory.LLM01
    severity = Severity.HIGH
    description = (
        "Inspects advertised MCP tool metadata for model-directed instructions, "
        "hidden characters, and exfiltration directives (cross-ref LLM06). Passive."
    )
    requires_agent = True

    def attacks(self) -> list[Attack]:
        """Metadata inspection has no per-attack payloads; kept for the report."""
        return [Attack(id="tp-inspect", prompt="inspect advertised tool metadata")]

    def detector(self) -> Detector:
        """The metadata poisoning detector (used via inspect(), not evaluate())."""
        return ToolPoisoningDetector()

    def run(self, target: Target) -> list[ProbeResult]:
        """Inspect each advertised tool's metadata for poisoning indicators."""
        if not isinstance(target, AgentTarget):  # pragma: no cover - engine gates this
            return super().run(target)

        try:
            tools = target.list_tools()
        except Exception as exc:  # noqa: BLE001 - record, don't crash the scan
            return [self._error(Attack(id="tp-list-tools", prompt="tools/list"), exc)]

        detector = ToolPoisoningDetector()
        results: list[ProbeResult] = []
        for spec in tools:
            signals = detector.inspect(spec)
            if not signals:
                continue
            worst = max(signals, key=lambda s: s.severity.rank).severity
            evidence = f"Poisoned tool '{spec.name}': " + " ".join(s.evidence for s in signals)
            attack = Attack(
                id=f"tp-{spec.name}",
                prompt=f"inspect metadata of tool '{spec.name}'",
                metadata={"tool": spec.name, "indicators": [s.indicator for s in signals]},
            )
            results.append(ProbeResult(
                probe_id=self.id, probe_name=self.name, category=self.category,
                attack=attack, severity=worst, verdict=Verdict.VULNERABLE, evidence=evidence,
            ))

        if not results:
            attack = Attack(id="tp-clean", prompt="inspect advertised tool metadata")
            results.append(ProbeResult(
                probe_id=self.id, probe_name=self.name, category=self.category,
                attack=attack, severity=self.severity, verdict=Verdict.PASS,
                notes=f"{len(tools)} tool(s) inspected; no poisoning indicators.",
            ))
        return results

    def _error(self, attack: Attack, exc: Exception) -> ProbeResult:
        return ProbeResult(
            probe_id=self.id, probe_name=self.name, category=self.category,
            attack=attack, severity=self.severity, verdict=Verdict.ERROR,
            notes=f"transport error: {exc}",
        )
