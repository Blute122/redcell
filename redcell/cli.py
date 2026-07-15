"""RedCell command-line interface.

    redcell scan --demo                     # offline demo against the mock
    redcell scan --target-url ... --model ...   # scan a real endpoint
    redcell list-probes                     # show the probe catalogue
"""

from __future__ import annotations

from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .engine import run_scan, select_probes
from .probes import all_probes
from .report import print_console, to_json, to_markdown
from .targets import MockVulnerableTarget, OpenAICompatTarget

app = typer.Typer(add_completion=False, help="RedCell - OWASP LLM Top 10 scanner.")
console = Console()


@app.command()
def scan(
    target_url: str = typer.Option(
        None, "--target-url", help="Base URL of an OpenAI-compatible API."
    ),
    model: str = typer.Option(None, "--model", help="Model name to request."),
    api_key: str = typer.Option(None, "--api-key", envvar="REDCELL_API_KEY"),
    system_prompt: str = typer.Option(
        None, "--system-prompt",
        help="System prompt you control; a canary is planted for leak probes.",
    ),
    demo: bool = typer.Option(
        False, "--demo", help="Scan the built-in vulnerable mock (no keys/network)."
    ),
    categories: list[str] = typer.Option(
        None, "--category", "-c", help="Filter by OWASP code, e.g. -c LLM01 -c LLM07."
    ),
    include_agent: bool = typer.Option(
        False, "--include-agent", help="Also run agent-only probes (LLM06)."
    ),
    output: Path = typer.Option(None, "--output", "-o", help="Write report to a file."),
    fmt: str = typer.Option("md", "--format", "-f", help="Output format: md or json."),
) -> None:
    """Run a scan against a target (or the demo mock)."""
    if demo:
        target = MockVulnerableTarget()
    elif target_url and model:
        target = OpenAICompatTarget(
            base_url=target_url, model=model, api_key=api_key,
            system_prompt=system_prompt,
        )
    else:
        console.print(
            "[red]Provide --demo, or both --target-url and --model.[/]"
        )
        raise typer.Exit(code=2)

    probes = select_probes(categories=categories, include_agent=include_agent)
    if not probes:
        console.print("[yellow]No probes matched your filter.[/]")
        raise typer.Exit(code=1)

    with console.status("Running probes..."):
        result = run_scan(target, probes)

    print_console(result, console)

    if output:
        text = to_json(result) if fmt == "json" else to_markdown(result)
        output.write_text(text, encoding="utf-8")
        console.print(f"Report written to [bold]{output}[/] ({fmt}).")


@app.command("list-probes")
def list_probes() -> None:
    """List every registered probe."""
    table = Table(title="RedCell probe catalogue")
    table.add_column("OWASP", style="bold")
    table.add_column("ID")
    table.add_column("Severity")
    table.add_column("Description")
    for p in sorted(all_probes(), key=lambda x: x.category.code):
        tag = " (agent)" if p.requires_agent else ""
        table.add_column
        table.add_row(p.category.code, p.id, p.severity.label, p.description + tag)
    console.print(table)


@app.command()
def version() -> None:
    """Print the RedCell version."""
    console.print(f"RedCell {__version__}")


if __name__ == "__main__":
    app()
