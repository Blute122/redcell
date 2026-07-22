"""The scan engine.

Loads probes from the registry (optionally filtered), runs each against a
target, and returns a ScanResult. Agent-only probes are skipped for chat
targets. A callback lets the CLI show live progress.
"""

from __future__ import annotations

from collections.abc import Callable

from .models import Attack, ProbeResult, ScanResult, Severity, Verdict
from .probes import all_probes
from .probes.base import Probe
from .targets.base import AgentTarget, Target

ProgressCb = Callable[[Probe, list[ProbeResult]], None]


def select_probes(
    categories: list[str] | None = None,
    probe_ids: list[str] | None = None,
    include_agent: bool = False,
) -> list[Probe]:
    """Pick probes from the registry, filtered by category and/or id.

    Agent-only probes are excluded unless `include_agent` is True.
    """
    probes = all_probes()
    if categories:
        wanted = {c.upper() for c in categories}
        probes = [p for p in probes if p.category.code in wanted]
    if probe_ids:
        wanted_ids = set(probe_ids)
        probes = [p for p in probes if p.id in wanted_ids]
    if not include_agent:
        probes = [p for p in probes if not p.requires_agent]
    return probes


def run_scan(
    target: Target,
    probes: list[Probe] | None = None,
    on_probe_done: ProgressCb | None = None,
    active: bool = False,
) -> ScanResult:
    """Run the selected probes against a target.

    `active` opts agent probes into actively invoking the dangerous tools they
    find (confirming exploitability) instead of only flagging them. It is
    off by default so a plain scan never triggers destructive tool calls.
    """
    if probes is None:
        probes = select_probes()

    is_agent = isinstance(target, AgentTarget)
    scan = ScanResult(target_name=target.name)
    for probe in probes:
        # Opt agent probes into active mode; passive is the safe default.
        if hasattr(probe, "active"):
            probe.active = active
        reason = _skip_reason(probe, target, is_agent)
        if reason is not None:
            # Recorded as skipped so the report is explicit about coverage.
            skipped = [_skipped(probe, a, reason) for a in probe.attacks()]
            scan.results.extend(skipped)
            if on_probe_done:
                on_probe_done(probe, skipped)
            continue

        results = probe.run(target)
        scan.results.extend(results)
        if on_probe_done:
            on_probe_done(probe, results)
    return scan


def _skip_reason(probe: Probe, target: Target, is_agent: bool) -> str | None:
    """Why (if at all) a probe cannot run against this target."""
    if probe.requires_agent and not is_agent:
        return "requires an agent/tool-using target"
    if not probe.requires_agent and not target.chat_capable:
        return "target is not chat-capable (no prompt interface)"
    return None


def _skipped(probe: Probe, attack: Attack, reason: str) -> ProbeResult:
    return ProbeResult(
        probe_id=probe.id,
        probe_name=probe.name,
        category=probe.category,
        attack=attack,
        verdict=Verdict.SKIPPED,
        severity=Severity.INFO,
        notes=reason,
    )
