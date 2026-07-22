# docs/

Supporting assets for the top-level `README.md`.

| File | Used in |
|------|---------|
| `demo.svg` | README hero — the offline `redcell scan --demo` findings table |
| `demo-mcp.svg` | "Scanning an MCP server" — an `--active` scan confirming excessive agency |
| `CHANGELOG.md` | Release notes |

## Regenerating the images

Both SVGs are generated from **live scans**, so they never drift from what the
tool actually prints:

```bash
python docs/make_demo.py
```

That's it — no external recorder, no extra dependency. It uses `rich`'s own SVG
export (`Console(record=True)` + `Console.save_svg`), which RedCell already
depends on for console output. Re-running produces byte-identical files, so
regenerating doesn't churn the repo; run it whenever the console output changes.

### Why not termtosvg / asciinema?

Both are **Unix-only**. They record by allocating a pseudo-terminal via
`os.openpty` / `termios` / `fcntl`, none of which exist on Windows, so they
fail there regardless of how they're installed or invoked. `rich`'s exporter is
cross-platform and reproducible, which is the better fit for an image that's
regenerated as part of the build rather than recorded once by hand.

### If you want animation instead

The generated images are static, which for a README hero is arguably better —
the graded findings table is visible instantly, with no waiting for a loop to
reach the interesting part. If you do want a moving capture:

- **[ScreenToGif](https://www.screentogif.com/)** — Windows-native; record the
  terminal window and export a GIF.
- **asciinema inside WSL** — works, since WSL provides a real pty.

## A note on fonts

`rich`'s SVG export references Fira Code from a CDN. GitHub renders README
images in a sandbox that blocks external fetches, so the font falls back to the
viewer's generic monospace. Alignment is unaffected: every `<text>` element
carries an explicit `textLength`, which pins glyph advance regardless of the
font in use.
