"""RedCell command-line interface.

    redcell scan --demo                     # offline demo against the mock
    redcell scan --target-url ... --model ...   # scan a real endpoint
    redcell list-probes                     # show the probe catalogue
"""

from __future__ import annotations

import shlex
import sys
from contextlib import nullcontext
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .engine import run_scan, select_probes
from .models import Severity
from .probes import all_probes
from .report import print_console, to_json, to_markdown, to_sarif
from .targets import (
    MCPHttpTarget,
    MCPTarget,
    MockVulnerableTarget,
    OpenAICompatTarget,
)

app = typer.Typer(add_completion=False, help="RedCell - OWASP LLM Top 10 scanner.")
console = Console()

#: Report renderers by --format value. sarif emits SARIF 2.1.0 for GitHub
#: code scanning; md/json are unchanged.
_REPORTERS = {"md": to_markdown, "json": to_json, "sarif": to_sarif}


def _parse_headers(raw: list[str] | None) -> dict[str, str]:
    """Parse repeated 'Key: Value' header flags into a dict.

    Values are credentials, so nothing here is logged; a malformed flag is a
    usage error the caller turns into exit 2.
    """
    headers: dict[str, str] = {}
    for item in raw or []:
        key, sep, value = item.partition(":")
        if not sep or not key.strip():
            raise ValueError(f"invalid --mcp-header '{item}'; expected 'Key: Value'")
        headers[key.strip()] = value.strip()
    return headers


def _safe_streams() -> None:
    """Let output survive redirection on legacy Windows code pages.

    The report uses box-drawing and spinner glyphs that cp1252 can't encode, so
    piping or redirecting a scan would otherwise die with UnicodeEncodeError -
    which matters most in exactly the CI setting `--fail-on` is built for.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (ValueError, OSError):  # pragma: no cover - stream can't change
            pass


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
    mcp_url: str = typer.Option(
        None, "--mcp-url",
        help="Scan a hosted MCP server over HTTP/SSE, e.g. --mcp-url https://host/mcp. "
             "Mutually exclusive with --mcp-command.",
    ),
    mcp_header: list[str] = typer.Option(
        None, "--mcp-header",
        help="Auth header 'Key: Value' for --mcp-url (repeatable). Treated as a "
             "credential: never logged or written to reports/SARIF.",
    ),
    mcp_command: str = typer.Option(
        None, "--mcp-command",
        help="Launch and scan an MCP server, e.g. --mcp-command 'python server.py'. "
             "Runs the agent/tool probes (LLM06) live against its tools.",
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
    active: bool = typer.Option(
        False, "--active",
        help="Actively INVOKE the dangerous tools LLM06 flags, to confirm they "
             "execute unauthenticated. Has side effects - authorised/disposable "
             "targets only. Default is passive (flag without invoking).",
    ),
    output: Path = typer.Option(None, "--output", "-o", help="Write report to a file."),
    fmt: str = typer.Option("md", "--format", "-f", help="Output format: md, json, or sarif."),
    fail_on: str = typer.Option(
        None, "--fail-on",
        help="Exit non-zero if any finding is at or above this severity "
             "(info|low|medium|high|critical). For CI gating; off by default.",
    ),
) -> None:
    """Run a scan against a target (or the demo mock)."""
    _safe_streams()
    if fmt not in _REPORTERS:
        console.print(
            f"[red]Unknown --format '{fmt}'. Choose from: {', '.join(_REPORTERS)}.[/]"
        )
        raise typer.Exit(code=2)
    if mcp_command and mcp_url:
        console.print("[red]Give only one of --mcp-command or --mcp-url.[/]")
        raise typer.Exit(code=2)

    if demo:
        target = MockVulnerableTarget()
    elif mcp_command:
        target = MCPTarget(command=shlex.split(mcp_command))
        # An MCP server is a tool target: the agent probes are the point.
        include_agent = True
    elif mcp_url:
        try:
            headers = _parse_headers(mcp_header)
        except ValueError as exc:
            console.print(f"[red]{exc}[/]")
            raise typer.Exit(code=2)
        target = MCPHttpTarget(url=mcp_url, headers=headers)
        include_agent = True
    elif target_url and model:
        target = OpenAICompatTarget(
            base_url=target_url, model=model, api_key=api_key,
            system_prompt=system_prompt,
        )
    else:
        console.print(
            "[red]Provide --demo, --mcp-command, --mcp-url, or both "
            "--target-url and --model.[/]"
        )
        raise typer.Exit(code=2)

    probes = select_probes(categories=categories, include_agent=include_agent)
    if not probes:
        console.print("[yellow]No probes matched your filter.[/]")
        raise typer.Exit(code=1)

    # Only animate when attached to a terminal; a spinner in a redirected CI
    # log is noise at best.
    spinner = console.status("Running probes...") if console.is_terminal else nullcontext()
    try:
        with spinner:
            result = run_scan(target, probes, active=active)
    finally:
        close = getattr(target, "close", None)
        if callable(close):
            close()

    print_console(result, console)

    if output:
        text = _REPORTERS[fmt](result)
        output.write_text(text, encoding="utf-8")
        console.print(f"Report written to [bold]{output}[/] ({fmt}).")

    # CI gate: opt-in, so default behaviour (exit 0) is unchanged.
    if fail_on:
        try:
            threshold = Severity.from_label(fail_on)
        except ValueError as exc:
            console.print(f"[red]{exc}[/]")
            raise typer.Exit(code=2)
        gating = result.findings_at_or_above(threshold)
        if gating:
            console.print(
                f"[red bold]FAIL[/] {len(gating)} finding(s) at or above "
                f"[bold]{threshold.label}[/]."
            )
            raise typer.Exit(code=1)
        console.print(f"[green]PASS[/] no findings at or above {threshold.label}.")


@app.command("list-probes")
def list_probes() -> None:
    """List every registered probe."""
    _safe_streams()
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
