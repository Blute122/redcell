# Changelog

All notable changes to RedCell are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet. Planned next: broader MCP coverage (tool poisoning, insecure auth,
injection-driven tool *sequences*), an HTTP/SSE MCP transport, and SARIF output
for GitHub code scanning.

## [0.1.0] - 2026-07-22

First release. An OWASP LLM Top 10 scanner that covers both the prompt layer
and the tool layer, with a reproducible evaluation behind its claims.

### Added

**Architecture** — a four-part pipeline (`target → engine → [probe → attack →
detector] → report`) where each part is an independent extension point. Probes
only ever see the `Target` / `AgentTarget` interface, so the same probe runs
against a cloud API, a local model, or an MCP agent unchanged.

**Targets**
- `OpenAICompatTarget` — any OpenAI-compatible `/chat/completions` endpoint
  (OpenAI, Groq, Ollama, LM Studio, custom wrappers), with optional canary
  planting so leak probes score reliably instead of heuristically.
- `MCPTarget` — connects to a Model Context Protocol server over stdio
  (newline-delimited JSON-RPC 2.0: `initialize` → `tools/list` → `tools/call`),
  with a watchdog so a hung server errors instead of blocking a scan.
- `AgentTarget` — capability interface (`list_tools` / `call_tool`) for
  tool-callers, kept separate from the chat-only `Target` contract.
- `MockVulnerableTarget` / `HardenedMockTarget` — offline positive and negative
  controls for the demo, the tests, and the evaluation.

**Probes**
- LLM01 direct prompt injection — instruction override, delimiter break,
  translation smuggling, payload splitting.
- LLM01 indirect / cross-context injection — instructions hidden in "retrieved"
  content, scored by an *out-of-band action* (a computed value, a string
  transform, a closed-domain answer absent from the source) so a model that
  faithfully quotes the malicious document is not mistaken for one that obeyed it.
- LLM02 sensitive information disclosure — canary-scored secret extraction.
- LLM05 improper output handling — raw XSS/SQLi-shaped payload emission.
- LLM06 excessive agency — enumerates an agent's tools, flags the destructive
  ones, and (opt-in) attempts the unauthorised call. Two tiers: **passive**
  (default, never invokes) and **active** (`--active`, confirms exploitability;
  a call that succeeds when it should have been gated is the finding).
- LLM07 system prompt leakage — canary leak, with a heuristic fallback.
- LLM09 misinformation — deterministic known-false-fact seed check.

**Detectors** — rule-based and deterministic by default (`MarkerEcho`,
`OutOfBandAction`, `CanaryLeak`, `SystemLeakHeuristic`, `Markup`, `Contains`,
`ToolCall`), plus an optional Groq-backed LLM judge that degrades to a SKIPPED
verdict when unconfigured rather than failing a scan.

**CLI** — `redcell scan` against `--demo`, an OpenAI-compatible endpoint, or
`--mcp-command`; plus `list-probes` and `version`. Category filters (`-c`),
report export (`-o` / `-f`), and `--fail-on <severity>` for CI gating (exit 1
at or above the threshold, 2 on usage error, 0 otherwise — opt-in, so adding
RedCell to a build never breaks it by surprise).

**Reporting** — coloured console summary, JSON for pipelines, Markdown for
write-ups, each with a transparent letter risk grade.

**Evaluation** (`evaluation/run_eval.py`) — a reproducible harness reporting two
separate claims rather than one blended rate: *functional correctness* (every
genuinely-vulnerable case is detected) and *precision* (zero false positives on
hardened controls). Optionally adds a live-model column from a local Ollama or
Groq endpoint, gated on environment variables and skipping cleanly when unset or
unreachable. It writes its table straight into the README.

**Project** — GitHub Actions CI across Python 3.10–3.12, 35 tests including
hermetic coverage of the MCP and live-model paths, docstring-coverage tests, and
the verbatim Apache-2.0 licence with a `NOTICE`.

[Unreleased]: https://github.com/Blute122/redcell/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Blute122/redcell/releases/tag/v0.1.0
