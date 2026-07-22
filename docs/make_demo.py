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
from rich.terminal_theme import TerminalTheme

from redcell.engine import run_scan, select_probes
from redcell.report import print_console
from redcell.targets import MCPTarget, MockVulnerableTarget

_DOCS = Path(__file__).resolve().parent
_REPO = _DOCS.parent
_MCP_SERVER = _REPO / "tests" / "mock_mcp_server.py"

# Column count drives legibility more than anything else: GitHub scales a
# README image into roughly a 900px column, so effective character width is
# ~900/columns px. At 160 columns that is ~5.6px - unreadable, and it reads as
# muddy grey no matter the palette. 96 columns gives ~9.4px.
_HERO_WIDTH = 96      # the compact MCP capture used at the top of the README
_FULL_WIDTH = 110     # the full demo scan; denser, shown further down

#: High-contrast palette. rich's default export theme puts dim reds/greens on
#: dark grey (3.5:1 and 4.1:1 - both under WCAG AA); these clear 4.5:1 against
#: the background and read correctly in GitHub's light and dark modes.
_THEME = TerminalTheme(
    (13, 17, 23),        # background  #0d1117
    (230, 237, 243),     # foreground  #e6edf3  (13.9:1)
    [
        (48, 54, 61),    # black
        (255, 123, 114),  # red      #ff7b72  vulnerable
        (63, 185, 80),   # green    #3fb950  pass
        (210, 153, 34),  # yellow   #d29922  medium
        (88, 166, 255),  # blue     #58a6ff
        (188, 140, 255),  # magenta  #bc8cff
        (57, 197, 207),  # cyan     #39c5cf
        (230, 237, 243),  # white
    ],
    [
        (139, 148, 158),  # bright black - table borders/dim text, 5.6:1
        (255, 166, 158),
        (86, 211, 100),
        (227, 179, 65),
        (121, 192, 255),
        (210, 168, 255),
        (86, 216, 225),
        (255, 255, 255),
    ],
)


def _console(width: int) -> Console:
    """A recording console at a fixed width, with colour forced on."""
    # force_terminal keeps the styling when stdout is redirected.
    return Console(record=True, width=width, force_terminal=True)


def _save(console: Console, name: str, title: str) -> Path:
    """Export the recorded output to docs/<name>, with LF line endings.

    Uses export_svg + an explicit write rather than Console.save_svg, which
    opens the file in default text mode and would emit CRLF on Windows -
    against this repo's .gitattributes (eol=lf).
    """
    path = _DOCS / name
    svg = console.export_svg(title=title, unique_id=name, theme=_THEME)
    path.write_text(svg, encoding="utf-8", newline="\n")
    return path


def render_demo() -> Path:
    """Capture the offline demo scan against the built-in vulnerable mock."""
    console = _console(_FULL_WIDTH)
    scan = run_scan(MockVulnerableTarget(), select_probes())
    print_console(scan, console)
    return _save(console, "demo.svg", "redcell scan --demo")


def render_mcp() -> Path:
    """Capture an active MCP scan, filtered to the LLM06 findings.

    Without the filter the chat probes are selected too and come back SKIPPED
    ("not chat-capable"), which buries the two rows that matter.
    """
    console = _console(_HERO_WIDTH)
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
