"""HTTP/SSE MCP transport (MCPHttpTarget) — hermetic, against a localhost stub.

Mirrors the stdio coverage in test_mcp_agent.py so the two transports are held
to the same behaviour, plus the HTTP-only concerns: SSE framing, session id,
graceful skip on an unreachable URL, and that auth headers reach the server but
never leak into a report.
"""

from __future__ import annotations

import socket

import pytest

from mock_mcp_http_server import http_mcp_server

from redcell.engine import run_scan, select_probes
from redcell.models import Verdict
from redcell.probes.excessive_agency import ExcessiveAgency
from redcell.report import to_json, to_sarif
from redcell.targets import MCPHttpTarget
from redcell.targets.mcp_http import _sse_data_frames
from redcell.targets.mcp_protocol import MCPError, MCPSession, MCPTransport


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# --- end-to-end over HTTP (json transport) ----------------------------------

def test_lists_tools_over_http():
    with http_mcp_server() as srv:
        target = MCPHttpTarget(url=srv.url)
        try:
            names = {t.name for t in target.list_tools()}
        finally:
            target.close()
    assert names == {"list_files", "delete_account", "wire_transfer"}


def test_call_tool_success_and_denial_over_http():
    with http_mcp_server() as srv:
        target = MCPHttpTarget(url=srv.url)
        try:
            ok = target.call_tool("delete_account", {"account_id": "u1"})
            denied = target.call_tool("wire_transfer", {"to": "x", "amount": 10})
        finally:
            target.close()
    assert ok.ok and not ok.is_error and "deleted" in ok.output.lower()
    assert not denied.ok and denied.is_error


def test_excessive_agency_fires_over_http():
    with http_mcp_server() as srv:
        target = MCPHttpTarget(url=srv.url)
        try:
            results = ExcessiveAgency(active=True).run(target)
        finally:
            target.close()
    by_tool = {r.attack.metadata.get("tool"): r for r in results}
    assert by_tool["delete_account"].verdict is Verdict.VULNERABLE
    assert by_tool["wire_transfer"].verdict is Verdict.PASS


def test_engine_runs_agent_probe_over_http():
    with http_mcp_server() as srv:
        target = MCPHttpTarget(url=srv.url)
        try:
            scan = run_scan(target, select_probes(include_agent=True), active=True)
        finally:
            target.close()
    llm06 = [r for r in scan.results if r.category.code == "LLM06"]
    assert any(r.verdict is Verdict.VULNERABLE for r in llm06)


# --- HTTP-only transport concerns -------------------------------------------

def test_sse_transport_is_parsed():
    # Same result, but the server answers as text/event-stream.
    with http_mcp_server(sse=True) as srv:
        target = MCPHttpTarget(url=srv.url)
        try:
            names = {t.name for t in target.list_tools()}
        finally:
            target.close()
    assert names == {"list_files", "delete_account", "wire_transfer"}


def test_session_id_is_captured_and_resent():
    # The stub rejects every non-initialize request that lacks the session id it
    # issued on initialize; a successful list_tools proves the transport resent it.
    with http_mcp_server() as srv:
        target = MCPHttpTarget(url=srv.url)
        try:
            tools = target.list_tools()  # would 400 if the session id were dropped
        finally:
            target.close()
    assert tools  # got a real tool list back


def test_unreachable_url_raises_mcp_error():
    target = MCPHttpTarget(url=f"http://127.0.0.1:{_free_port()}/mcp")
    try:
        with pytest.raises(MCPError):
            target.list_tools()
    finally:
        target.close()


def test_engine_records_error_not_crash_on_unreachable():
    # The scan must degrade gracefully, not raise, on a dead endpoint.
    target = MCPHttpTarget(url=f"http://127.0.0.1:{_free_port()}/mcp")
    try:
        scan = run_scan(target, select_probes(include_agent=True), active=True)
    finally:
        target.close()
    llm06 = [r for r in scan.results if r.category.code == "LLM06"]
    assert llm06 and all(r.verdict is Verdict.ERROR for r in llm06)


# --- credential handling ----------------------------------------------------

def test_auth_header_reaches_server_but_never_leaks_into_reports():
    secret = "Bearer super-secret-token-9f8e7d"
    with http_mcp_server() as srv:
        target = MCPHttpTarget(url=srv.url, headers={"Authorization": secret})
        try:
            scan = run_scan(target, select_probes(include_agent=True), active=True)
        finally:
            target.close()
        # It reached the server...
        assert srv.last_authorization == secret
    # ...but appears in neither the target name nor any rendered report.
    assert secret not in target.name
    assert "super-secret-token" not in to_json(scan)
    assert "super-secret-token" not in to_sarif(scan)


# --- shared protocol layer (transport-agnostic) -----------------------------

class _FakeTransport(MCPTransport):
    """Canned transport to unit-test MCPSession without any real I/O."""

    def __init__(self, response: dict):
        self._response = response
        self.sent: list[dict] = []

    def send_request(self, message):
        self.sent.append(message)
        return {**self._response, "id": message["id"]}

    def send_notification(self, message):
        self.sent.append(message)


def test_session_raises_mcp_error_on_jsonrpc_error():
    session = MCPSession(_FakeTransport({"jsonrpc": "2.0", "error": {"message": "nope"}}))
    with pytest.raises(MCPError, match="nope"):
        session.request("tools/call")


def test_session_handshake_runs_once():
    transport = _FakeTransport({"jsonrpc": "2.0", "result": {"tools": []}})
    session = MCPSession(transport)
    session.ensure_ready()
    session.ensure_ready()  # idempotent
    methods = [m.get("method") for m in transport.sent]
    assert methods.count("initialize") == 1
    assert "notifications/initialized" in methods


def test_sse_data_frames_parser():
    body = "event: message\ndata: {\"a\": 1}\n\nevent: message\ndata: {\"b\": 2}\n\n"
    assert _sse_data_frames(body) == ['{"a": 1}', '{"b": 2}']
