# RedCell

**An OWASP LLM Top 10 vulnerability scanner for LLM apps and agents.**

RedCell points a battery of adversarial probes at any LLM endpoint (or, soon,
MCP server / tool-using agent), maps each finding to the
[OWASP Top 10 for LLM Applications (2025)](https://owasp.org/www-project-top-10-for-large-language-model-applications/),
and produces a graded report you can drop into CI or a security review.

Think of it as a `nmap`/`nikto` for the prompt layer: a red-cell in a box.

> ⚠️ **Authorised testing only.** RedCell is a defensive red-teaming tool.
> Run it against systems you own or have explicit permission to test. The
> payloads are standard, publicly documented patterns included so *defenders*
> can find these weaknesses before attackers do.

---

## Quickstart

```bash
pip install -e .

# 1. Offline demo - no API key, no network. Scans a deliberately
#    vulnerable built-in mock so you can see output immediately.
redcell scan --demo

# 2. Scan a real OpenAI-compatible endpoint (OpenAI, Groq, Ollama,
#    LM Studio, or your own FastAPI wrapper).
redcell scan \
  --target-url http://localhost:11434/v1 \
  --model llama3 \
  --system-prompt "You are a support bot for ACME."

# 3. Filter to specific categories, and export a report.
redcell scan --demo -c LLM01 -c LLM07 -o report.md -f md

# See the catalogue
redcell list-probes
```

Passing `--system-prompt` lets RedCell plant a secret canary in the context,
which makes the leak / sensitive-info probes score reliably instead of
falling back to heuristics.

## What it checks (starter probe set)

| OWASP | Probe | What it does |
|-------|-------|--------------|
| LLM01 | Direct prompt injection | Instruction-override, delimiter breaks, translation smuggling, payload splitting |
| LLM02 | Sensitive info disclosure | Tries to extract planted secrets / credentials |
| LLM05 | Improper output handling | Coaxes raw XSS/SQLi-shaped markup out of the model |
| LLM06 | Excessive agency *(agent-only)* | Attempts unauthorised/destructive tool calls |
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

Because probes only ever see the `Target` interface, the same probe runs
against a cloud API, a local model, or a future agent adapter unchanged.

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

## Scanning an MCP server

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

**Why passive is the default.** It's a deliberate detection-confidence vs.
operational-safety trade-off. Passive over-reports — it flags a
properly-guarded destructive tool it can't distinguish from an ungated one —
but it never has a side effect, so the dangerous behaviour is an opt-in choice
rather than what happens if you run the obvious command. Active buys back the
fidelity (the guarded tool clears to PASS) at the cost of real side effects,
which is exactly the sort of thing you only want to opt into on a target you
control.

## Roadmap

- [x] **Agent target adapter** — LLM06 fires live against MCP tool-callers.
- [ ] **MCP server scanning (breadth)** — tool poisoning, insecure auth,
      injection-driven tool *sequences*; HTTP/SSE transport.
- [ ] Indirect / cross-context injection (poisoned documents, RAG sources).
- [ ] CI action (`--fail-on high`) + SARIF output for GitHub code scanning.
- [ ] Expanded payload corpora per category; MITRE ATLAS mapping alongside OWASP.

## Tests

```bash
pip install -e '.[dev]'
pytest -q
```

The suite runs the full probe set against the vulnerable mock and asserts the
known categories fire — a controlled baseline you can point to when validating
detection.

## License

Apache-2.0. See `LICENSE`.
