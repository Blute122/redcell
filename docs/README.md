# docs/

Supporting assets for the top-level `README.md`.

## `demo.svg`

The terminal capture shown in the README. The committed file is a **hand-drawn
placeholder** — replace it with a real capture of an actual scan.

### Regenerate from a real scan

Any of these produce an SVG you can drop in as `docs/demo.svg`:

**Option A — [`termtosvg`](https://github.com/nbedos/termtosvg)** (records a live
terminal session):

```bash
pip install termtosvg
termtosvg docs/demo.svg -t window_frame -c "redcell scan --demo"
```

**Option B — [`asciinema`](https://asciinema.org) +
[`svg-term`](https://github.com/marionebl/svg-term-cli)**:

```bash
asciinema rec docs/demo.cast -c "redcell scan --demo"
cat docs/demo.cast | svg-term --out docs/demo.svg --window
```

**Option C — [`freeze`](https://github.com/charmbracelet/freeze)** (renders
captured output, no recording):

```bash
redcell scan --demo > docs/demo.txt
freeze docs/demo.txt -o docs/demo.svg
```

Keep the capture short (the demo scan is the clearest one-screen story) and
prefer the MCP scan (`redcell scan --mcp-command "python tests/mock_mcp_server.py" --active`)
if you want to showcase the differentiator instead.
