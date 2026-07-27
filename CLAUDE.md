# RedCell — working notes for Claude Code

RedCell is an OWASP LLM Top 10 vulnerability scanner for LLM apps and agents.

## Architecture
Flow: `target → engine → [probe → attacks → detector] → report`
Four independent extension points: targets, probes, detectors, report.

## Core constraints (do not violate)
- **Probes only ever touch the `Target` interface.** Never call HTTP,
  SDKs, or network code directly inside a probe. If a probe needs a new
  way to reach a system, that goes in a new `Target` adapter under
  `redcell/targets/`, not in the probe.
- **Detection is deterministic rule-based by default.** The LLM-judge
  (`detectors/llm_judge.py`) is an *optional* layer, gated behind
  `GROQ_API_KEY`. Never make a probe hard-depend on the judge — it must
  degrade to SKIPPED when no key is present, never crash the scan.

## Conventions
- New probes: subclass `Probe`, list attacks, pick a detector, `@register`.
  Map every probe to an `OwaspCategory` and assign a `Severity`.
- Agent-only probes set `requires_agent = True` and are skipped for chat
  targets.
- Line endings are LF (see `.gitattributes`).

## Validation
- Run `pytest -q` after any change. Tests assert the known-vulnerable
  categories fire against `MockVulnerableTarget` — that's the baseline.
- For manual checks: `redcell scan --demo`.

## Ethics
Defensive, authorised-testing-only tool. Don't add features whose primary
purpose is attacking systems the user doesn't own.
