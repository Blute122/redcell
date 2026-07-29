"""Tool-metadata poisoning detector (rule-based).

A malicious MCP server can weaponise the *tool metadata itself* — names,
descriptions, and parameter descriptions the model ingests before it ever calls
anything. This detector inspects that metadata for poisoning indicators. It is
purely passive: it reads what ``list_tools()`` advertised and never invokes a
tool.

Boundary: this catches poisoning present in the *advertised metadata*. It does
NOT catch poisoning injected at tool-call time — a tool that returns a malicious
result mid-conversation — which is the multi-step sequence problem handled
elsewhere, not here.

The indicators are deliberately curated so a legitimate tool description can
carry imperative language, URLs, and encoded examples without tripping. Each
indicator was designed against the clean case that could trip a naive version:

* **hidden-characters** — invisible/non-printing chars that hide instructions
  from a human reader (zero-width space, bidi *overrides*, C0/C1 controls, the
  Unicode Tags block, a mid-string BOM). It deliberately EXCLUDES ZWJ (U+200D)
  and ZWNJ (U+200C) — the two invisibles with real emoji and Persian/Indic use —
  and only flags a BOM mid-string, sparing emoji, RTL text, and a leading BOM.
* **model-directed-injection** — documented prompt-injection phrasing aimed at
  the model ("ignore previous instructions", "do not tell the user", role
  reassignment, injected control markers), NOT generic imperatives. "Call this
  before fetching user data" and "you must provide an API key" do not match.
* **exfiltration** — an *outbound* movement verb (send/include/append/…, never
  read/retrieve) co-occurring with a sensitive artifact. Two tiers by artifact:
  a filesystem/secret artifact (``~/.ssh``, ``.env``, credentials) is HIGH
  (nothing legitimate reads those from a tool description); a context/history
  artifact (prior conversation, chat history, system prompt) is MEDIUM, because
  a legitimate memory/summarisation tool can phrase it similarly — same
  quoting-vs-obeying ambiguity as indirect injection, so lower confidence.
* **encoded-injection** — base64 substrings are decoded and re-checked against
  the injection phrases; it fires only when the decoded text is printable and
  injection-shaped, so a legitimate base64 image/hash example (which decodes to
  binary) is spared.

Standalone URL detection is deliberately omitted (URLs in descriptions are
documentation), and semantic name/description mismatch is left to the optional
LLM judge — a rule that guessed at it would be guessing at HIGH severity.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import Iterator

from ..models import Attack, Severity, ToolSpec
from ..targets.base import Target
from .rules import Detector

# --- Indicator 1: hidden / non-printing characters ---------------------------

# Invisible code points with no legitimate use in a tool description. ZWJ
# (U+200D) and ZWNJ (U+200C) are intentionally absent - they are used in emoji
# sequences and Persian/Indic scripts. BOM (U+FEFF) is handled separately
# (flagged only mid-string; a leading BOM is a benign encoding artifact).
_HIDDEN_CODEPOINTS: set[int] = (
    {0x200B}                                   # zero-width space
    | {0x202D, 0x202E}                         # bidi overrides (Trojan Source)
    | set(range(0x00, 0x09)) | {0x0B, 0x0C} | set(range(0x0E, 0x20))  # C0 controls
    | set(range(0x7F, 0xA0))                   # C1 controls
    | set(range(0xE0000, 0xE0080))             # Unicode Tags block (ASCII smuggling)
)

# --- Indicator 2: model-directed injection phrasing --------------------------

_INJECTION_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"ignore\s+(?:all\s+|any\s+|the\s+)*(?:previous|prior|above|preceding|earlier)"
        r"\s+(?:instructions?|prompts?|messages?|context|rules?)",
        r"disregard\s+(?:all\s+|any\s+|the\s+)*(?:previous|prior|above|preceding|your)"
        r"\s+(?:instructions?|rules?|guidelines?|prompts?)",
        r"forget\s+(?:all\s+|everything\s+|the\s+)*(?:previous|prior|above)"
        r"\s+(?:instructions?|context|messages?)",
        r"do\s*not\s+(?:tell|inform|reveal|mention|disclose|notify|alert)\s+(?:the\s+)?user",
        r"\byou\s+are\s+now\b",
        r"from\s+now\s+on,?\s+you\s+(?:are|will|must)\b",
        r"your\s+(?:new\s+)?(?:system\s+prompt|instructions?)\s+(?:is|are)\b",
        r"<\s*important\s*>",
        r"\[\s*system\s*\]",
        r"<\s*system\s*>",
        r"###\s*instructions?\b",
    )
]

# --- Indicator 3: exfiltration (outbound verb + sensitive artifact) ----------

# Outbound movement only. read/retrieve/fetch are deliberately excluded: they
# describe reading data IN (a legit "retrieve conversation history" tool), while
# exfiltration is about moving data OUT to a parameter or sink.
_OUTBOUND_VERB = re.compile(
    r"\b(?:send|transmit|forward|upload|post|exfiltrate|include|append|attach|embed|leak|copy)\b",
    re.IGNORECASE,
)

_FILESYSTEM_ARTIFACT = re.compile(
    r"(?:~/\.ssh|id_rsa|id_ed25519|private\s+key|\.env\b|/etc/passwd|/etc/shadow"
    r"|credentials?|passwords?|api[_\s-]?keys?|secret[_\s-]?keys?"
    r"|access[_\s-]?tokens?|environment\s+variables?|env\s+vars?)",
    re.IGNORECASE,
)

_CONTEXT_ARTIFACT = re.compile(
    r"(?:(?:prior|previous|earlier|full|entire|all)\s+(?:conversation|messages?|chat|context"
    r"|history|user\s+messages?)|conversation\s+history|chat\s+history|system\s+prompt"
    r"|system\s+context)",
    re.IGNORECASE,
)


@dataclass
class PoisonSignal:
    """One poisoning indicator that fired, with its confidence-appropriate severity."""

    indicator: str
    severity: Severity
    evidence: str


def _schema_strings(schema: object) -> Iterator[str]:
    """Yield human-readable strings (description/title) nested in an input schema."""
    if isinstance(schema, dict):
        for key, value in schema.items():
            if key in ("description", "title") and isinstance(value, str):
                yield value
            else:
                yield from _schema_strings(value)
    elif isinstance(schema, list):
        for item in schema:
            yield from _schema_strings(item)


class ToolPoisoningDetector(Detector):
    """Inspects a ``ToolSpec``'s metadata for poisoning indicators."""

    def evaluate(self, attack: Attack, response: str, target: Target) -> tuple[bool, str]:
        """Unused: poisoning is judged from tool metadata via ``inspect``, not
        from a chat response. Present only to satisfy the ``Detector`` contract."""
        return False, ""

    def inspect(self, spec: ToolSpec) -> list[PoisonSignal]:
        """Return every poisoning signal found in the tool's metadata."""
        fields: list[tuple[str, str]] = [("name", spec.name), ("description", spec.description)]
        fields += [("parameter", s) for s in _schema_strings(spec.input_schema)]

        signals: list[PoisonSignal] = []
        for where, text in fields:
            if not text:
                continue
            signals += self._hidden_characters(where, text)
            signals += self._injection_phrases(where, text)
            signals += self._exfiltration(where, text)
            signals += self._encoded_injection(where, text)
        return signals

    # --- indicators --------------------------------------------------------

    def _hidden_characters(self, where: str, text: str) -> list[PoisonSignal]:
        found = {ord(c) for c in text if ord(c) in _HIDDEN_CODEPOINTS}
        if 0xFEFF in {ord(c) for c in text[1:]}:  # BOM only mid-string
            found.add(0xFEFF)
        if not found:
            return []
        listed = ", ".join(f"U+{cp:04X}" for cp in sorted(found))
        return [PoisonSignal(
            "hidden-characters", Severity.HIGH,
            f"{where} contains hidden/non-printing characters ({listed}) that can "
            "smuggle instructions past a human reviewer.",
        )]

    def _injection_phrases(self, where: str, text: str) -> list[PoisonSignal]:
        for pattern in _INJECTION_PATTERNS:
            match = pattern.search(text)
            if match:
                return [PoisonSignal(
                    "model-directed-injection", Severity.HIGH,
                    f"{where} contains an instruction aimed at the model: "
                    f"'{match.group(0).strip()}'.",
                )]
        return []

    def _exfiltration(self, where: str, text: str) -> list[PoisonSignal]:
        if not _OUTBOUND_VERB.search(text):
            return []
        fs = _FILESYSTEM_ARTIFACT.search(text)
        if fs:
            return [PoisonSignal(
                "exfiltration", Severity.HIGH,
                f"{where} pairs an outbound action with a sensitive artifact "
                f"('{fs.group(0).strip()}') - exfiltration of secrets/files.",
            )]
        ctx = _CONTEXT_ARTIFACT.search(text)
        if ctx:
            return [PoisonSignal(
                "exfiltration", Severity.MEDIUM,
                f"{where} pairs an outbound action with conversation context "
                f"('{ctx.group(0).strip()}'). Lower confidence: a legitimate "
                "memory/summarisation tool can phrase this similarly.",
            )]
        return []

    def _encoded_injection(self, where: str, text: str) -> list[PoisonSignal]:
        for candidate in re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", text):
            decoded = _try_decode_text(candidate)
            if decoded and any(p.search(decoded) for p in _INJECTION_PATTERNS):
                return [PoisonSignal(
                    "encoded-injection", Severity.HIGH,
                    f"{where} contains base64 that decodes to an injection "
                    f"instruction: '{decoded[:80].strip()}'.",
                )]
        return []


def _try_decode_text(candidate: str) -> str | None:
    """Base64-decode a candidate, returning printable UTF-8 text or None."""
    if len(candidate) % 4:
        candidate += "=" * (-len(candidate) % 4)
    try:
        raw = base64.b64decode(candidate, validate=True)
        text = raw.decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return None
    # Require mostly-printable text so a decoded image/hash (binary) is skipped.
    printable = sum(c.isprintable() or c.isspace() for c in text)
    if text and printable / len(text) >= 0.9:
        return text
    return None
