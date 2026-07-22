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
_HERO_WIDTH = 80      # the compact MCP capture used at the top (~11.2px/char)
_FULL_WIDTH = 110     # the full demo scan; 20 findings can't also be large

#: Light palette - dark text on white. A dark terminal theme looks natural but
#: is the wrong choice for a README image: thin light strokes on a dark ground
#: bloom and wash out once the image is downscaled into a ~900px column, which
#: reads as "too dark" no matter how high the nominal contrast is. Dark-on-light
#: survives downscaling far better. Colours are GitHub's light-mode semantics.
_THEME = TerminalTheme(
    (255, 255, 255),     # background  white
    (31, 35, 40),        # foreground  #1f2328  (14.7:1)
    [
        (31, 35, 40),    # black
        (207, 34, 46),   # red      #cf222e  vulnerable
        (26, 127, 55),   # green    #1a7f37  pass
        (154, 103, 0),   # yellow   #9a6700  medium
        (9, 105, 218),   # blue     #0969da
        (130, 80, 223),  # magenta  #8250df
        (23, 109, 120),  # cyan     #176d78
        (89, 99, 110),   # white -> used for dim text
    ],
    [
        (89, 99, 110),   # bright black - table borders/dim text, 5.6:1
        (164, 14, 38),
        (17, 99, 41),
        (119, 78, 0),
        (2, 81, 187),
        (104, 44, 191),
        (18, 87, 96),
        (31, 35, 40),
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
