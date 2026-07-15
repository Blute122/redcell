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

- **Targets** (`redcell/targets/`) — anything you can send a prompt to.
  `OpenAICompatTarget`, `MockVulnerableTarget` today; MCP/agent adapters next.
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

## Roadmap

- [ ] **MCP server scanning** — tool poisoning, insecure auth, injection-driven
      tool sequences (the widest-open gap in the market right now).
- [ ] **Agent target adapter** — make LLM06 fully live against tool-callers.
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
