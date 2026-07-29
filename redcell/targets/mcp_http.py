"""MCP server target adapter — Streamable HTTP / SSE transport.

Reaches a *hosted* MCP server by URL, rather than launching a local subprocess.
It implements the same ``list_tools()`` / ``call_tool()`` contract as the stdio
``MCPTarget`` by reusing the shared :class:`MCPSession` protocol layer; only the
wire transport differs.

Streamable HTTP transport:

* client -> server messages are HTTP POSTs of a JSON-RPC envelope, with
  ``Accept: application/json, text/event-stream``;
* the server answers a request either with a single JSON body or with an SSE
  stream (``text/event-stream``) whose ``data:`` frame carries the JSON-RPC
  response — this adapter handles both;
* if the server issues an ``Mcp-Session-Id`` on initialize, the adapter echoes
  it on every subsequent request;
* notifications are POSTs whose (202) body is ignored.

Auth headers are credentials: they are held only in the transport, sent only to
the server, and never logged, never placed in the target name, and never written
to reports or SARIF.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlparse

import httpx

from ..models import ToolCallResult, ToolSpec
from .base import AgentTarget
from .mcp_protocol import MCPError, MCPSession, MCPTransport

# Streamable HTTP is a 2025-03-26+ transport; advertise that era so hosted
# servers negotiate it rather than the older HTTP+SSE transport.
_HTTP_PROTOCOL_VERSION = "2025-03-26"


class HttpTransport(MCPTransport):
    """JSON-RPC 2.0 framing over MCP Streamable HTTP."""

    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        timeout: float = 30.0,
    ) -> None:
        self._url = url
        self._session_id: str | None = None
        # Base headers include any caller-supplied auth headers (credentials).
        self._headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
        }
        if headers:
            self._headers.update(headers)
        self._client = httpx.Client(timeout=timeout)

    def _request_headers(self) -> dict[str, str]:
        headers = dict(self._headers)
        if self._session_id:
            headers["Mcp-Session-Id"] = self._session_id
        return headers

    def _post(self, message: dict[str, Any]) -> httpx.Response:
        try:
            resp = self._client.post(
                self._url, json=message, headers=self._request_headers()
            )
        except httpx.HTTPError as exc:
            # Deliberately surface only the exception *type*, never str(exc),
            # which can carry the URL/headers.
            raise MCPError(
                f"HTTP transport to MCP server failed: {exc.__class__.__name__}"
            ) from None
        # Capture a session id the server may have issued on initialize.
        session_id = resp.headers.get("mcp-session-id")
        if session_id:
            self._session_id = session_id
        return resp

    def send_request(self, message: dict[str, Any]) -> dict[str, Any]:
        """POST one request and return the matching JSON-RPC response envelope."""
        resp = self._post(message)
        if resp.status_code >= 400:
            raise MCPError(f"MCP server returned HTTP {resp.status_code}")
        return self._response_envelope(resp, message.get("id"))

    def send_notification(self, message: dict[str, Any]) -> None:
        """POST a notification; expect 202 Accepted with no body to read."""
        resp = self._post(message)
        # A notification expects 202 Accepted with no body; anything <400 is fine.
        if resp.status_code >= 400:
            raise MCPError(f"MCP server rejected notification: HTTP {resp.status_code}")

    def _response_envelope(self, resp: httpx.Response, expected_id: Any) -> dict[str, Any]:
        content_type = resp.headers.get("content-type", "")
        if "text/event-stream" in content_type:
            payloads = _sse_data_frames(resp.text)
        else:
            payloads = [resp.text] if resp.text.strip() else []
        for raw in payloads:
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                continue
            if isinstance(msg, dict) and msg.get("id") == expected_id:
                return msg
        raise MCPError("no matching JSON-RPC response from MCP server")

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._client.close()


def _sse_data_frames(body: str) -> list[str]:
    """Extract the ``data:`` payloads from an SSE body, one per event."""
    frames: list[str] = []
    current: list[str] = []
    for line in body.splitlines():
        if line.startswith("data:"):
            current.append(line[len("data:"):].lstrip())
        elif line == "":  # blank line terminates an event
            if current:
                frames.append("\n".join(current))
                current = []
    if current:
        frames.append("\n".join(current))
    return frames


class MCPHttpTarget(AgentTarget):
    """A hosted Model Context Protocol server (Streamable HTTP), as a target."""

    #: MCP servers expose tools, not a chat interface.
    chat_capable = False

    def __init__(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        name: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        super().__init__()
        if not url:
            raise ValueError("MCPHttpTarget requires a URL")
        self.url = url
        # Name from host only - never the full URL (which may carry a token in a
        # query string) and never the auth headers.
        host = urlparse(url).netloc or url
        self.name = name or f"mcp:{host}"
        transport = HttpTransport(url, headers=headers, timeout=timeout)
        self._session = MCPSession(transport, protocol_version=_HTTP_PROTOCOL_VERSION)

    def list_tools(self) -> list[ToolSpec]:
        """Enumerate the tools the MCP server advertises."""
        return self._session.list_tools()

    def call_tool(self, name: str, arguments: dict) -> ToolCallResult:
        """Invoke a tool and report whether it actually executed."""
        return self._session.call_tool(name, arguments)

    def send(self, prompt: str) -> str:  # pragma: no cover - not chat-capable
        """Not supported: an MCP server exposes tools, not a chat endpoint."""
        raise NotImplementedError(
            "MCPHttpTarget exposes tools, not a chat endpoint; it is not chat_capable."
        )

    def close(self) -> None:
        """Close the underlying HTTP client."""
        self._session.close()
