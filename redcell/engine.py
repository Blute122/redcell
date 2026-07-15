"""The scan engine.

Loads probes from the registry (optionally filtered), runs each against a
target, and returns a ScanResult. Agent-only probes are skipped for chat
targets. A callback lets the CLI show live progress.
"""

from __future__ import annotations

from collections.abc import Callable

from .models import ProbeResult, ScanResult, Severity, Verdict
from .probes import all_probes
from .probes.base import Probe
from .targets.base import Target

ProgressCb = Callable[[Probe, list[ProbeResult]], None]


def select_probes(
    categories: list[str] | None = None,
    probe_ids: list[str] | None = None,
    include_agent: bool = False,
) -> list[Probe]:
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
) -> ScanResult:
    if probes is None:
        probes = select_probes()

    scan = ScanResult(target_name=target.name)
    for probe in probes:
        if probe.requires_agent:
            # Recorded as skipped so the report is explicit about coverage.
            skipped = [
                ProbeResult(
                    probe_id=probe.id,
                    probe_name=probe.name,
                    category=probe.category,
                    attack=a,
                    verdict=Verdict.SKIPPED,
                    severity=Severity.INFO,
                    notes="requires an agent/tool-using target",
                )
                for a in probe.attacks()
            ]
            scan.results.extend(skipped)
            if on_probe_done:
                on_probe_done(probe, skipped)
            continue

        results = probe.run(target)
        scan.results.extend(results)
        if on_probe_done:
            on_probe_done(probe, results)
    return scan
