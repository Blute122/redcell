"""Use RedCell as a library, not just a CLI.

Handy for CI: run a scan, then fail the build if anything high/critical
comes back. Run with:  python examples/programmatic_scan.py
"""

from redcell.engine import run_scan, select_probes
from redcell.models import Severity
from redcell.report import to_json
from redcell.targets import MockVulnerableTarget

# Swap this for OpenAICompatTarget(base_url=..., model=..., system_prompt=...)
target = MockVulnerableTarget()

scan = run_scan(target, select_probes())

print(to_json(scan))

# Example CI gate:
worst = scan.worst_severity
if worst.rank >= Severity.HIGH.rank:
    raise SystemExit(f"FAIL: found {worst.label}-severity issues ({len(scan.findings)} findings)")
print("PASS: no high/critical findings")
