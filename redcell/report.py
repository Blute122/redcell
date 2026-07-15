"""Reporting.

Three outputs from one ScanResult:
- a coloured console summary (rich) for interactive use,
- JSON for CI pipelines and machine consumption,
- Markdown for your write-up / FYP results chapter.
"""

from __future__ import annotations

import json

from rich.console import Console
from rich.table import Table

from .models import ScanResult, Severity, Verdict

_SEV_COLOUR = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}

_VERDICT_COLOUR = {
    Verdict.VULNERABLE: "bold red",
    Verdict.PASS: "green",
    Verdict.ERROR: "magenta",
    Verdict.SKIPPED: "dim",
}


def print_console(scan: ScanResult, console: Console | None = None) -> None:
    console = console or Console()

    grade = scan.risk_grade()
    grade_colour = "green" if grade == "A" else "yellow" if grade in "BC" else "red"
    console.print()
    console.rule(f"[bold]RedCell scan · {scan.target_name}")
    console.print(
        f"Risk grade: [{grade_colour} bold]{grade}[/]   "
        f"Findings: [bold]{len(scan.findings)}[/]   "
        f"Worst: [{_SEV_COLOUR[scan.worst_severity]}]{scan.worst_severity.label}[/]"
    )

    table = Table(show_lines=False, expand=True)
    table.add_column("OWASP", style="bold", no_wrap=True)
    table.add_column("Probe")
    table.add_column("Attack", no_wrap=True)
    table.add_column("Verdict", no_wrap=True)
    table.add_column("Sev", no_wrap=True)
    table.add_column("Evidence")

    for r in scan.results:
        table.add_row(
            r.category.code,
            r.probe_name,
            r.attack.id,
            f"[{_VERDICT_COLOUR[r.verdict]}]{r.verdict.value}[/]",
            f"[{_SEV_COLOUR[r.severity]}]{r.severity.label}[/]",
            (r.evidence or r.notes)[:60],
        )
    console.print(table)
    console.print()


def to_json(scan: ScanResult, indent: int = 2) -> str:
    return json.dumps(scan.to_dict(), indent=indent)


def to_markdown(scan: ScanResult) -> str:
    lines: list[str] = []
    lines.append(f"# RedCell scan report\n")
    lines.append(f"**Target:** {scan.target_name}  ")
    lines.append(f"**Started:** {scan.started_at.isoformat()}  ")
    lines.append(f"**Risk grade:** {scan.risk_grade()}  ")
    lines.append(f"**Worst severity:** {scan.worst_severity.label}  ")
    lines.append(f"**Total findings:** {len(scan.findings)}\n")

    if scan.findings:
        lines.append("## Findings\n")
        lines.append("| OWASP | Probe | Attack | Severity | Evidence |")
        lines.append("|---|---|---|---|---|")
        for r in scan.findings:
            ev = r.evidence.replace("|", "\\|")
            lines.append(
                f"| {r.category.code} | {r.probe_name} | `{r.attack.id}` "
                f"| {r.severity.label} | {ev} |"
            )
        lines.append("")

    lines.append("## Full results\n")
    lines.append("| OWASP | Probe | Attack | Verdict | Severity |")
    lines.append("|---|---|---|---|---|")
    for r in scan.results:
        lines.append(
            f"| {r.category.code} | {r.probe_name} | `{r.attack.id}` "
            f"| {r.verdict.value} | {r.severity.label} |"
        )
    lines.append("")
    return "\n".join(lines)
