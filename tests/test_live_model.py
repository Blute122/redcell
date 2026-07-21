"""Hermetic tests for the evaluation harness' live-model path.

The live column runs the chat probes against an OpenAI-compatible endpoint.
Rather than depend on a real Ollama/Groq service, these tests stand up an
in-process stub HTTP server bound to localhost on an ephemeral port, so the
whole thing runs on CI with no external services.

Both branches are covered:
  * reachable endpoint  -> the live column renders and LLM06 shows n/a;
  * unreachable endpoint -> the section skips cleanly (no column, no error).
"""

from __future__ import annotations

import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from evaluation.run_eval import render_markdown, run_evaluation

# Canned assistant reply. Echoing the injection marker makes at least one live
# cell non-zero, so the rendered column is unambiguously populated.
_CANNED = "REDCELL_INJECTION_OK"


class _StubHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence the default stderr logging
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)  # drain the request body
        payload = json.dumps(
            {"choices": [{"message": {"role": "assistant", "content": _CANNED}}]}
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)


@pytest.fixture()
def stub_openai_url():
    """Yield the base URL of a localhost OpenAI-compatible stub server."""
    server = HTTPServer(("127.0.0.1", 0), _StubHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    try:
        yield f"http://{host}:{port}/v1"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def _free_port() -> int:
    """An almost-certainly-free localhost port (bound then released)."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _set_live_env(monkeypatch, url: str, model: str = "stub-model") -> None:
    monkeypatch.setenv("REDCELL_EVAL_URL", url)
    monkeypatch.setenv("REDCELL_EVAL_MODEL", model)
    monkeypatch.delenv("REDCELL_EVAL_KEY", raising=False)
    monkeypatch.delenv("REDCELL_EVAL_SYSTEM", raising=False)


def test_live_column_renders_against_reachable_stub(stub_openai_url, monkeypatch):
    _set_live_env(monkeypatch, stub_openai_url)

    report = run_evaluation(include_real=True)

    assert report.real_label is not None
    assert report.real_note is None

    markdown = render_markdown(report)
    assert "Live model" in markdown

    # LLM06 has no chat surface on a live model, so its live cell is n/a.
    llm06 = next(s for s in report.stats if s.code == "LLM06")
    assert llm06.real_total == 0
    llm06_row = next(line for line in markdown.splitlines() if line.startswith("| LLM06"))
    assert "n/a" in llm06_row

    # The canned marker echo means the injection category fired live.
    llm01 = next(s for s in report.stats if s.code == "LLM01")
    assert llm01.real_total > 0
    assert llm01.real_fired >= 1


def test_live_section_skips_when_endpoint_unreachable(monkeypatch):
    _set_live_env(monkeypatch, f"http://127.0.0.1:{_free_port()}/v1", model="down-model")

    report = run_evaluation(include_real=True)

    # Requested but unreachable: skipped with an explanatory note, no column.
    assert report.real_label is None
    assert report.real_note is not None
    assert "Live model" not in render_markdown(report)

    # And the offline claims are unaffected - still zero false positives.
    assert report.total_false_positives == 0
