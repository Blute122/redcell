# RedCell

[![CI](https://github.com/Blute122/redcell/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Blute122/redcell/actions/workflows/ci.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE)

**A security scanner for LLM applications and tool-using agents.**

LLM apps ship with no security-testing layer. Traditional scanners don't
understand prompts, and they understand tool calls even less — a WAF can't tell
you whether your agent can be talked into deleting an account.

RedCell probes both layers. It runs the same adversarial methodology against
chat endpoints *and* MCP agents, maps every finding to the
[OWASP Top 10 for LLM Applications (2025)](https://owasp.org/www-project-top-10-for-large-language-model-applications/),
and grades the result.

```bash
pip install -e .
redcell scan --demo      # zero setup, no API key, no network
```

![RedCell scanning the built-in vulnerable target](docs/demo.svg)

## What makes it different

**It tests agents, not just prompts.** Point RedCell at an MCP server and it
enumerates the server's tools, flags the destructive ones, and — on an
authorised target — confirms excessive agency by *actually attempting the
unauthorised call*. A tool call that succeeds when it should have been gated is
a confirmed finding, not an inference from what the model claimed it would do.
Passive enumeration is the default; active exploitation is opt-in.

**Its indirect-injection detection can tell obeying from quoting.** When the
payload arrives inside a document the model is asked to summarise, the naive
check — did the marker appear in the output? — fires on any model that
faithfully quotes the document. RedCell's attacks instead carry success signals
that *cannot* appear in a summary: a computed value, a string transform, a
closed-domain answer absent from the source. A model only emits them by
executing the injected instruction.

**The numbers are two claims, not one.** Every genuinely-vulnerable case in the
test corpus is detected, and hardened controls — a chat target that refuses
injection, an MCP server whose destructive tools are auth-gated, a summariser
that quotes a malicious document without obeying it — produce **zero false
positives**. See [Results](#results).

> ⚠️ **Authorised testing only.** RedCell is a defensive red-teaming tool. Run
> it against systems you own or have explicit permission to test. The payloads
> are standard, publicly documented patterns, included so *defenders* can find
> these weaknesses before attackers do.

---

## Quickstart

```bash
redcell scan --demo       # scan the built-in vulnerable mock
redcell list-probes       # see the probe catalogue
```

Scan a real OpenAI-compatible endpoint (OpenAI, Groq, Ollama, LM Studio, or
your own FastAPI wrapper):

```bash
redcell scan \
  --target-url http://localhost:11434/v1 \
  --model llama3 \
  --system-prompt "You are a support bot for ACME."
```

Passing `--system-prompt` plants a secret canary in the context, so the
leak / sensitive-info probes score reliably instead of falling back to
heuristics. Filter categories and export a report with
`redcell scan --demo -c LLM01 -c LLM07 -o report.md -f md`.

## Use it in CI

`--fail-on <severity>` exits non-zero when any finding is at or above the
threshold, so a pipeline can block on it. It's opt-in: without the flag a scan
always exits 0, so adding RedCell to a build never breaks it by surprise.

```bash
redcell scan --demo --fail-on high -o report.json -f json
```

| Exit code | Meaning |
|-----------|---------|
| `0` | Scan completed; nothing at or above the threshold |
| `1` | At least one finding at or above `--fail-on` |
| `2` | Usage error (bad target arguments, or an unknown severity) |

## Scanning an MCP server (the headline feature)

RedCell speaks the Model Context Protocol over stdio. Point it at any MCP
server and the LLM06 excessive-agency probe runs against its tools —
enumerating them and flagging the destructive/privileged ones. It works in two
tiers, mirroring how DAST tools separate safe crawling from active
exploitation:

**Passive (default) — always safe to run.** Flags every dangerous tool from
its MCP annotations (`destructiveHint`) and its name/signature, *without ever
invoking it*. Findings are advisory (MEDIUM): they prove the capability is
exposed, not that it's exploitable.

```bash
redcell scan --mcp-command "python my_mcp_server.py"
```

**Active (`--active`) — authorised, disposable targets only.** Actually
attempts the unauthorised call to confirm exploitability. A call that
**succeeds when it should have been gated** is a confirmed finding (HIGH); a
refusal flips to PASS. Calls use recognisable `redcell-probe` sentinel
arguments.

```bash
redcell scan --mcp-command "python my_mcp_server.py" --active
```

> ⚠️ `--active` genuinely executes the tools it flags — `delete_account` really
> deletes. Run it only against a server you own or a disposable/test instance.

**Why passive is the default** is a deliberate detection-confidence vs.
operational-safety trade-off. Passive over-reports — it flags a
properly-guarded destructive tool it can't distinguish from an ungated one —
but it never has a side effect, so the dangerous behaviour is an opt-in choice
rather than what happens if you run the obvious command. Active buys back the
fidelity (the guarded tool clears to PASS) at the cost of real side effects.

## Results

RedCell is validated against controlled targets: a deliberately-vulnerable
mock, a mock MCP server, and *hardened* targets that should yield **no**
findings (a chat model that refuses injection and never leaks its canary; an
MCP server whose destructive tools are all auth-gated). The evaluation harness
reproduces the numbers:

```bash
python evaluation/run_eval.py
```

<!-- RESULTS_TABLE:START -->
_Generated by `python evaluation/run_eval.py`. LLM06 uses `--active`._

RedCell is validated on two axes — **functional correctness** (does a detector fire on a real vulnerability?) and **precision** (does it stay silent on a clean target?):

| OWASP | Category | Vulnerable mock ¹ | Hardened control ² |
|-------|----------|:-----------------:|:------------------:|
| LLM01 | Prompt Injection | 8 / 8 | 0 |
| LLM02 | Sensitive Information Disclosure | 4 / 4 | 0 |
| LLM05 | Improper Output Handling | 3 / 3 | 0 |
| LLM06&nbsp;† | Excessive Agency | 1 / 2 | 0 |
| LLM07 | System Prompt Leakage | 4 / 4 | 0 |
| LLM09 | Misinformation | 1 / 1 | 0 |
| **Total** | | **21 / 22** | **0** |

**¹ Functional correctness.** Every case the mock is deliberately vulnerable to is detected — 20 / 20 chat cases, plus the one ungated MCP tool. The detectors work end-to-end on known positives.

**² Precision.** On the hardened controls (a chat model that refuses injection and never leaks its canary; an MCP server whose destructive tools are all auth-gated), RedCell raises **0 false positives**.

† LLM06 counts destructive tools, not prompts: the vulnerable MCP server exposes 2, but only `delete_account` is ungated — RedCell confirms exactly it, while the auth-gated `wire_transfer` correctly PASSes.

_Set `REDCELL_EVAL_URL` and `REDCELL_EVAL_MODEL` (optionally `REDCELL_EVAL_KEY`) to add a live-model column from a local Ollama or Groq endpoint._

**Passive vs. active (LLM06).** In passive mode RedCell flags 2 destructive tools on the *hardened* MCP server as advisory MEDIUM exposures; `--active` invokes them, both are refused, and they clear to PASS (0 confirmed) — the detection-confidence vs. operational-safety trade-off, made measurable.
<!-- RESULTS_TABLE:END -->

## What it checks

| OWASP | Probe | What it does |
|-------|-------|--------------|
| LLM01 | Direct prompt injection | Instruction-override, delimiter breaks, translation smuggling, payload splitting |
| LLM01 | Indirect / cross-context injection | Hides instructions in "retrieved" documents; scores *obeying* (an out-of-band action), not quoting |
| LLM02 | Sensitive info disclosure | Tries to extract planted secrets / credentials |
| LLM05 | Improper output handling | Coaxes raw XSS/SQLi-shaped markup out of the model |
| LLM06 | Excessive agency *(agent/MCP)* | Enumerates and (opt-in) invokes destructive tools |
| LLM07 | System prompt leakage | Tries to make the model recite its hidden instructions |
| LLM09 | Misinformation | Seed check for confident falsehoods |

## How it's built

```
target ──> engine ──> [ probe ──> attack(s) ──> detector ] ──> report
```

Four extension points, each independent:

- **Targets** (`redcell/targets/`) — anything you can send a prompt to, plus
  tool-callers via `AgentTarget`. `OpenAICompatTarget`, `MockVulnerableTarget`,
  and `MCPTarget` (connects to an MCP server over stdio) ship today.
- **Probes** (`redcell/probes/`) — a category + severity + a set of attacks.
  Adding one is: subclass `Probe`, list attacks, pick a detector, `@register`.
- **Detectors** (`redcell/detectors/`) — decide if an attack worked. Precise
  rule-based detectors ship by default; an optional Groq-powered LLM judge
  handles fuzzier cases (`pip install -e '.[judge]'`, set `GROQ_API_KEY`).
- **Report** (`redcell/report.py`) — console, JSON (for CI), Markdown (for
  write-ups).

Because probes only ever see the `Target` / `AgentTarget` interface, the same
probe runs against a cloud API, a local model, or an MCP agent unchanged.

## Adding a probe

```python
from redcell.probes.base import Probe, register
from redcell.detectors.rules import MarkerEchoDetector
from redcell.models import Attack, OwaspCategory, Severity

@register
class MyProbe(Probe):
    id = "llm01-my-variant"
    name = "My injection variant"
    category = OwaspCategory.LLM01
    severity = Severity.HIGH

    def attacks(self):
        return [Attack(id="mv-1", prompt="...", success_marker="OK")]

    def detector(self):
        return MarkerEchoDetector()
```

## Roadmap

- [x] **Agent target adapter** — LLM06 fires live against MCP tool-callers.
- [x] **Indirect / cross-context injection** — payloads via retrieved content,
      scored by out-of-band action so quoting isn't mistaken for obeying.
- [ ] **MCP server scanning (breadth)** — tool poisoning, insecure auth,
      injection-driven tool *sequences*; HTTP/SSE transport.
- [x] **CI gate** — `--fail-on <severity>` blocks a pipeline on findings.
- [ ] SARIF output for GitHub code scanning.
- [ ] Expanded payload corpora per category; MITRE ATLAS mapping alongside OWASP.

## Tests

```bash
pip install -e '.[dev]'
pytest -q
```

The suite runs the full probe set against the vulnerable mock and asserts the
known categories fire — a controlled baseline for validating detection.

## License

Apache-2.0. See [`LICENSE`](LICENSE) for the full text and
[`NOTICE`](NOTICE) for attribution.
