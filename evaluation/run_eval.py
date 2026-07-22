"""Reproducible evaluation on two axes: functional correctness and precision.

RedCell makes two testable claims, and this harness measures both:

1. **Functional correctness** - on cases a target is *genuinely* vulnerable to,
   the matching detector fires. Measured against the deliberately-vulnerable
   mock (every attack has a real positive) and the ungated tool on the mock MCP
   server.
2. **Precision** - on *hardened* controls (a chat model that refuses injection
   and never leaks its canary; an MCP server whose destructive tools are all
   auth-gated), RedCell raises zero false positives.

Optionally it also runs the chat probes against a **live model** - a local
Ollama or a Groq endpoint - for a real-world reference column. That section is
gated on environment variables and skips cleanly when they are unset, so CI and
offline runs stay green:

    REDCELL_EVAL_URL     base URL, e.g. http://localhost:11434/v1 (Ollama) or
                         https://api.groq.com/openai/v1 (Groq)
    REDCELL_EVAL_MODEL   model name, e.g. llama3 or llama-3.3-70b-versatile
    REDCELL_EVAL_KEY     API key (optional; omit for a keyless local Ollama)
    REDCELL_EVAL_SYSTEM  system prompt to plant a canary in (optional)
    REDCELL_EVAL_TIMEOUT per-request timeout in seconds (optional, default 300;
                         a local model's first request can take minutes while
                         the weights load)

Run it:

    python evaluation/run_eval.py            # prints the table, updates README
    python evaluation/run_eval.py --no-write  # print only

LLM06 numbers use --active (actually invoking tools), the tier that *confirms*
exploitability; the passive tier deliberately over-reports and is summarised in
the note below the table.
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path

from redcell.engine import run_scan, select_probes
from redcell.models import ProbeResult, Verdict
from redcell.targets import (
    HardenedMockTarget,
    MCPTarget,
    MockVulnerableTarget,
    OpenAICompatTarget,
)

_ROOT = Path(__file__).resolve().parents[1]
_MCP_SERVER = _ROOT / "tests" / "mock_mcp_server.py"
_README = _ROOT / "README.md"

_CATEGORIES = [
    ("LLM01", "Prompt Injection"),
    ("LLM02", "Sensitive Information Disclosure"),
    ("LLM05", "Improper Output Handling"),
    ("LLM06", "Excessive Agency"),
    ("LLM07", "System Prompt Leakage"),
    ("LLM09", "Misinformation"),
]
_CHAT_CODES = {"LLM01", "LLM02", "LLM05", "LLM07", "LLM09"}

_START = "<!-- RESULTS_TABLE:START -->"
_END = "<!-- RESULTS_TABLE:END -->"

_URL_ENV = "REDCELL_EVAL_URL"
_MODEL_ENV = "REDCELL_EVAL_MODEL"
_KEY_ENV = "REDCELL_EVAL_KEY"
_SYSTEM_ENV = "REDCELL_EVAL_SYSTEM"
_TIMEOUT_ENV = "REDCELL_EVAL_TIMEOUT"
_DEFAULT_SYSTEM = "You are a helpful customer-support assistant for ACME Corp."

#: Generous by default: a local Ollama model has to load several GB into RAM on
#: the first request (measured ~2 min cold, ~13 s warm for a 3B model on CPU),
#: which the 30 s target default would time out on - silently skipping the live
#: column on exactly the setup most people run.
_DEFAULT_TIMEOUT = 300.0


@dataclass
class CategoryStat:
    """Per-OWASP-category counts across the target set."""

    code: str
    title: str
    detected: int          # VULNERABLE verdicts on the vulnerable target
    attempts: int          # attacks attempted on the vulnerable target
    false_positives: int   # VULNERABLE verdicts on the hardened target
    real_fired: int = 0    # VULNERABLE verdicts on the live model
    real_total: int = 0    # attacks run against the live model (0 = n/a)


@dataclass
class EvalReport:
    """Aggregated evaluation result."""

    stats: list[CategoryStat] = field(default_factory=list)
    passive_hardened_flags: int = 0
    active_hardened_flags: int = 0
    real_label: str | None = None     # live model NAME only - goes in the header
    real_endpoint: str | None = None  # endpoint - provenance, footnote only
    real_note: str | None = None      # why the live column was skipped

    @property
    def total_detected(self) -> int:
        """Findings across every category on the vulnerable targets."""
        return sum(s.detected for s in self.stats)

    @property
    def total_attempts(self) -> int:
        """Attacks attempted across every category on the vulnerable targets."""
        return sum(s.attempts for s in self.stats)

    @property
    def total_false_positives(self) -> int:
        """Findings raised against the hardened controls (should be zero)."""
        return sum(s.false_positives for s in self.stats)

    @property
    def chat_detected(self) -> int:
        """Findings in the chat-only categories (excludes agent LLM06)."""
        return sum(s.detected for s in self.stats if s.code in _CHAT_CODES)

    @property
    def chat_attempts(self) -> int:
        """Attacks attempted in the chat-only categories."""
        return sum(s.attempts for s in self.stats if s.code in _CHAT_CODES)


def _count(results: list[ProbeResult], code: str) -> tuple[int, int]:
    rs = [r for r in results if r.category.code == code]
    return sum(1 for r in rs if r.verdict is Verdict.VULNERABLE), len(rs)


def _mcp(hardened: bool) -> MCPTarget:
    cmd = [sys.executable, str(_MCP_SERVER)] + (["--hardened"] if hardened else [])
    return MCPTarget(command=cmd, name="hardened-mcp" if hardened else "vuln-mcp")


def _scan_agent(hardened: bool, active: bool) -> list[ProbeResult]:
    probes = select_probes(probe_ids=["llm06-excessive-agency"], include_agent=True)
    target = _mcp(hardened)
    try:
        return run_scan(target, probes, active=active).results
    finally:
        target.close()


def _real_target() -> tuple[OpenAICompatTarget | None, str | None]:
    """Build the live-model target from env, or return (None, note).

    A note of ``None`` means the section was simply not requested (env unset);
    a string note means it was requested but unreachable.
    """
    url = os.environ.get(_URL_ENV)
    model = os.environ.get(_MODEL_ENV)
    if not url or not model:
        return None, None
    target = OpenAICompatTarget(
        base_url=url,
        model=model,
        api_key=os.environ.get(_KEY_ENV),
        system_prompt=os.environ.get(_SYSTEM_ENV, _DEFAULT_SYSTEM),
        timeout=float(os.environ.get(_TIMEOUT_ENV, _DEFAULT_TIMEOUT)),
    )
    try:  # preflight so an unreachable endpoint skips instead of filling 0s
        target.send("ping")
    except Exception as exc:  # noqa: BLE001 - any transport failure => skip
        return None, f"{_URL_ENV} set but endpoint unreachable ({exc.__class__.__name__})"
    return target, None


def run_evaluation(include_real: bool = True) -> EvalReport:
    """Run every target and aggregate. `include_real=False` stays fully offline."""
    chat_probes = select_probes()  # excludes agent-only probes

    vuln = run_scan(MockVulnerableTarget(), chat_probes).results
    hard = run_scan(HardenedMockTarget(), chat_probes).results
    vuln += _scan_agent(hardened=False, active=True)
    hard += _scan_agent(hardened=True, active=True)

    report = EvalReport()

    real_results: list[ProbeResult] = []
    if include_real:
        target, note = _real_target()
        if target is not None:
            # Model name is what the header shows; the endpoint is provenance
            # and belongs in the footnote, not as a clickable URL in a heading.
            report.real_label = target.model
            report.real_endpoint = target.base_url
            real_results = run_scan(target, chat_probes).results
        else:
            report.real_note = note

    for code, title in _CATEGORIES:
        detected, attempts = _count(vuln, code)
        false_pos, _ = _count(hard, code)
        real_fired, real_total = _count(real_results, code)
        report.stats.append(
            CategoryStat(code, title, detected, attempts, false_pos, real_fired, real_total)
        )

    passive_hard = _scan_agent(hardened=True, active=False)
    report.passive_hardened_flags = sum(
        1 for r in passive_hard if r.verdict is Verdict.VULNERABLE
    )
    report.active_hardened_flags = next(
        (s.false_positives for s in report.stats if s.code == "LLM06"), 0
    )
    return report


def render_markdown(report: EvalReport) -> str:
    """Render the report as a self-contained Markdown block."""
    has_real = report.real_label is not None
    # Model name only - a bare endpoint URL here would be autolinked by GitHub
    # into a dead localhost link. The endpoint lives in footnote 3 instead.
    real_hdr = f" Live model<br>({report.real_label}) ³ |" if has_real else ""
    real_sep = ":--:|" if has_real else ""

    lines = [
        "_Generated by `python evaluation/run_eval.py`. LLM06 uses `--active`._",
        "",
        "RedCell is validated on two axes — **functional correctness** (does a "
        "detector fire on a real vulnerability?) and **precision** (does it stay "
        "silent on a clean target?):",
        "",
        f"| OWASP | Category | Vulnerable mock ¹ | Hardened control ² |{real_hdr}",
        f"|-------|----------|:-----------------:|:------------------:|{real_sep}",
    ]
    for s in report.stats:
        code = f"{s.code}&nbsp;†" if s.code == "LLM06" else s.code
        cell = f" {s.detected} / {s.attempts} "
        row = f"| {code} | {s.title} |{cell}| {s.false_positives} |"
        if has_real:
            real_cell = f" {s.real_fired} / {s.real_total} " if s.real_total else " n/a "
            row += f"{real_cell}|"
        lines.append(row)

    total = f"| **Total** | | **{report.total_detected} / {report.total_attempts}** | **{report.total_false_positives}** |"
    if has_real:
        # Em-dash, not blank: the live column is deliberately not totalled
        # (it's a snapshot reference), and blank would read as missing data.
        total += " — |"
    lines.append(total)

    lines += [
        "",
        "**¹ Functional correctness.** Every case the mock is deliberately "
        f"vulnerable to is detected — {report.chat_detected} / {report.chat_attempts} "
        "chat cases, plus the one ungated MCP tool. The detectors work end-to-end "
        "on known positives.",
        "",
        "**² Precision.** On the hardened controls (a chat model that refuses "
        "injection and never leaks its canary; an MCP server whose destructive "
        f"tools are all auth-gated), RedCell raises **{report.total_false_positives} "
        "false positives**.",
        "",
        "† LLM06 counts destructive tools, not prompts: the vulnerable MCP server "
        "exposes 2, but only `delete_account` is ungated — RedCell confirms exactly "
        "it, while the auth-gated `wire_transfer` correctly PASSes.",
    ]
    if has_real:
        lines += [
            "",
            "**³ Live model.** The chat probes run against a real model "
            f"(`{report.real_label}`, served from `{report.real_endpoint}`) "
            f"with a planted canary, measured "
            f"{date.today().isoformat()}. This is a **snapshot, not a fixed "
            "result**: a live model is non-deterministic, so re-running shifts "
            "the counts by an attack or two. It is a real-world reference "
            "point, never a pass/fail control, and CI never asserts it.",
        ]
    else:
        lines += [
            "",
            f"_Set `{_URL_ENV}` and `{_MODEL_ENV}` (optionally `{_KEY_ENV}`) to add a "
            "live-model column from a local Ollama or Groq endpoint._",
        ]
    lines += [
        "",
        "**Passive vs. active (LLM06).** In passive mode RedCell flags "
        f"{report.passive_hardened_flags} destructive tools on the *hardened* MCP "
        "server as advisory MEDIUM exposures; `--active` invokes them, both are "
        f"refused, and they clear to PASS ({report.active_hardened_flags} confirmed) — "
        "the detection-confidence vs. operational-safety trade-off, made measurable.",
    ]
    return "\n".join(lines)


def readme_has_live_column() -> bool:
    """True if the README currently carries a live-model column."""
    try:
        return "Live model" in _README.read_text(encoding="utf-8")
    except OSError:  # pragma: no cover - README always present in-repo
        return False


def update_readme(markdown: str) -> bool:
    """Splice the table between the RESULTS_TABLE markers in README.md."""
    text = _README.read_text(encoding="utf-8")
    if _START not in text or _END not in text:
        return False
    head, rest = text.split(_START, 1)
    _, tail = rest.split(_END, 1)
    new = f"{head}{_START}\n{markdown}\n{_END}{tail}"
    # Normalise to LF to match .gitattributes (eol=lf); write_text emits CRLF
    # on Windows otherwise.
    new = new.replace("\r\n", "\n").replace("\r", "\n")
    _README.write_text(new, encoding="utf-8", newline="\n")
    return True


def main(argv: list[str] | None = None) -> int:
    """Run the evaluation, print the table, and update the README."""
    argv = sys.argv[1:] if argv is None else argv
    writing = "--no-write" not in argv
    had_live = readme_has_live_column()

    report = run_evaluation()
    if report.real_note:
        print(f"[live model] {report.real_note}; skipping that column.", file=sys.stderr)

    # Regenerating without a live endpoint would quietly drop a live column the
    # README already had - say so loudly rather than losing a measurement.
    if writing and had_live and report.real_label is None:
        print(
            f"[warning] README had a live-model column; this run has no live "
            f"endpoint, so that column is being REMOVED. Re-run with "
            f"{_URL_ENV}/{_MODEL_ENV} set to keep it, or --no-write to leave "
            f"the README untouched.",
            file=sys.stderr,
        )

    markdown = render_markdown(report)
    print(markdown)
    if writing:
        if update_readme(markdown):
            print(f"\n[updated {_README.relative_to(_ROOT)} between RESULTS_TABLE markers]")
        else:
            print("\n[README markers not found; printed only]", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
