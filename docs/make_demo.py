"""Regenerate the README's terminal images from live scans.

Uses rich's own SVG export (`Console(record=True)` + `save_svg`) rather than an
external recorder. termtosvg and asciinema both record via a Unix pseudo-
terminal (`os.openpty`, `termios`), so neither runs on Windows; this is
cross-platform, needs no extra dependency, and is reproducible - rerun it
whenever the console output changes.

    python docs/make_demo.py

Writes:
    docs/demo.svg      - the offline `--demo` scan (README hero)
    docs/demo-mcp.svg  - an `--active` MCP scan (the excessive-agency finding)
"""

from __future__ import annotations

import sys
from pathlib import Path

from rich.console import Console

from redcell.engine import run_scan, select_probes
from redcell.report import print_console
from redcell.targets import MCPTarget, MockVulnerableTarget

_DOCS = Path(__file__).resolve().parent
_REPO = _DOCS.parent
_MCP_SERVER = _REPO / "tests" / "mock_mcp_server.py"

#: Wide enough that the evidence column mostly fits on one line - at 100 cols
#: the demo table wraps to ~82 rendered lines and scales down to illegible in a
#: README; at 160 it's ~37 and keeps a readable banner shape.
_WIDTH = 160


def _console() -> Console:
    """A recording console wide enough for the findings table."""
    return Console(record=True, width=_WIDTH)


def _save(console: Console, name: str, title: str) -> Path:
    """Export the recorded output to docs/<name>."""
    path = _DOCS / name
    console.save_svg(str(path), title=title, unique_id=name)
    return path


def render_demo() -> Path:
    """Capture the offline demo scan against the built-in vulnerable mock."""
    console = _console()
    scan = run_scan(MockVulnerableTarget(), select_probes())
    print_console(scan, console)
    return _save(console, "demo.svg", "redcell scan --demo")


def render_mcp() -> Path:
    """Capture an active MCP scan, filtered to the LLM06 findings.

    Without the filter the chat probes are selected too and come back SKIPPED
    ("not chat-capable"), which buries the two rows that matter.
    """
    console = _console()
    target = MCPTarget(command=[sys.executable, str(_MCP_SERVER)], name="mcp:my_mcp_server.py")
    try:
        probes = select_probes(categories=["LLM06"], include_agent=True)
        scan = run_scan(target, probes, active=True)
    finally:
        target.close()
    print_console(scan, console)
    return _save(console, "demo-mcp.svg", "redcell scan --mcp-command ... --active")


def main() -> int:
    """Regenerate every documentation image."""
    for path in (render_demo(), render_mcp()):
        print(f"wrote {path.relative_to(_REPO)} ({path.stat().st_size:,} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
