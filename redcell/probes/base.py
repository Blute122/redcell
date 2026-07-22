"""Probe base class + registry.

A Probe bundles: an OWASP category, a base severity, a set of adversarial
Attacks, and the Detector that scores each response. Adding a new probe is
the extension point of the whole framework - subclass Probe, list your
attacks, pick a detector, decorate with @register. Nothing else needs to
change; the engine and CLI discover it automatically.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from ..detectors.llm_judge import LLMJudgeUnavailable
from ..detectors.rules import Detector
from ..models import Attack, OwaspCategory, ProbeResult, Severity, Verdict
from ..targets.base import Target

# --- registry ----------------------------------------------------------------

_REGISTRY: list[type["Probe"]] = []


def register(cls: type["Probe"]) -> type["Probe"]:
    """Class decorator that adds a probe to the registry."""
    _REGISTRY.append(cls)
    return cls


def all_probes() -> list["Probe"]:
    """Instantiate every registered probe."""
    return [cls() for cls in _REGISTRY]


# --- base --------------------------------------------------------------------


class Probe(ABC):
    """One OWASP category's worth of attacks plus the detector that scores them."""

    #: short stable id, e.g. "pi-instruction-override"
    id: str
    #: human name for reports
    name: str
    category: OwaspCategory
    severity: Severity
    #: one-line description used in --list and in reports
    description: str = ""

    #: set True on probes that only make sense against tool-using agents;
    #: the engine skips them (SKIPPED verdict) for plain chat targets.
    requires_agent: bool = False

    @abstractmethod
    def attacks(self) -> list[Attack]:
        """The adversarial inputs this probe sends."""
        raise NotImplementedError

    @abstractmethod
    def detector(self) -> Detector:
        """The detector that scores this probe's responses."""
        raise NotImplementedError

    def run(self, target: Target) -> list[ProbeResult]:
        """Run every attack against `target` and score each response."""
        detector = self.detector()
        results: list[ProbeResult] = []
        for attack in self.attacks():
            results.append(self._run_one(target, detector, attack))
        return results

    def _run_one(self, target: Target, detector: Detector, attack: Attack) -> ProbeResult:
        base = dict(
            probe_id=self.id,
            probe_name=self.name,
            category=self.category,
            attack=attack,
            severity=self.severity,
        )
        try:
            response = target.send(attack.prompt)
        except Exception as exc:  # noqa: BLE001 - we want to record any failure
            return ProbeResult(**base, verdict=Verdict.ERROR, response="",
                               notes=f"transport error: {exc}")
        try:
            vulnerable, evidence = detector.evaluate(attack, response, target)
        except LLMJudgeUnavailable as exc:
            return ProbeResult(**base, verdict=Verdict.SKIPPED, response=response,
                               notes=f"judge unavailable: {exc}")
        verdict = Verdict.VULNERABLE if vulnerable else Verdict.PASS
        return ProbeResult(**base, verdict=verdict, response=response, evidence=evidence)
