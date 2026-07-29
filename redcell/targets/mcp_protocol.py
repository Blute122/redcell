"""Shared MCP JSON-RPC protocol layer, transport-agnostic.

Both the stdio and HTTP/SSE adapters speak identical Model Context Protocol
semantics — the ``initialize`` handshake, ``tools/list``, ``tools/call``, and
JSON-RPC error handling. That logic lives here exactly once, so the two
transports can't drift apart. A transport only has to do one thing: send a
single JSON-RPC request envelope and return the matching response envelope
(and fire-and-forget notifications).

    MCPSession (protocol: envelopes, handshake, tools) ── uses ──▶ MCPTransport
      stdio adapter provides a StdioTransport
      http  adapter provides an HttpTransport
"""

from __future__ import annotations

import json
import threading
from abc import ABC, abstractmethod
from typing import Any

from .. import __version__
from ..models import ToolCallResult, ToolSpec

_PROTOCOL_VERSION = "2024-11-05"
_CLIENT_INFO = {"name": "redcell", "version": __version__}


class MCPError(RuntimeError):
    """Transport- or protocol-level failure talking to the MCP server."""


class MCPTransport(ABC):
    """Carries framed JSON-RPC messages to an MCP server over some transport.

    Implementations own only the wire framing and message correlation; all MCP
    semantics live in :class:`MCPSession`.
    """

    @abstractmethod
    def send_request(self, message: dict[str, Any]) -> dict[str, Any]:
        """Send one JSON-RPC request envelope; return its response envelope."""
        raise NotImplementedError

    @abstractmethod
    def send_notification(self, message: dict[str, Any]) -> None:
        """Send a JSON-RPC notification (no id, no response expected)."""
        raise NotImplementedError

    def close(self) -> None:
        """Release any transport resources. Default: nothing to do."""


def content_to_text(content: Any) -> str:
    """Flatten an MCP tool-result ``content`` array into plain text."""
    if isinstance(content, list):
        parts = []
        for item in content:
            if isinstance(item, dict):
                parts.append(item.get("text") or item.get("data") or json.dumps(item))
            else:
                parts.append(str(item))
        return "\n".join(parts)
    if content is None:
        return ""
    return str(content)


class MCPSession:
    """Transport-agnostic MCP client: handshake, ``tools/list``, ``tools/call``.

    Owns the JSON-RPC id counter and the lazy ``initialize`` handshake, and maps
    protocol responses onto RedCell's ``ToolSpec`` / ``ToolCallResult``. The same
    session drives every transport, so the protocol is implemented once.
    """

    def __init__(
        self, transport: MCPTransport, protocol_version: str = _PROTOCOL_VERSION
    ) -> None:
        self._transport = transport
        self._protocol_version = protocol_version
        self._id = 0
        self._lock = threading.Lock()
        self._initialized = False

    # --- JSON-RPC ----------------------------------------------------------

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Send a JSON-RPC request and return its result, raising on error."""
        with self._lock:
            self._id += 1
            envelope = {
                "jsonrpc": "2.0",
                "id": self._id,
                "method": method,
                "params": params or {},
            }
            resp = self._transport.send_request(envelope)
        if "error" in resp:
            err = resp["error"]
            message = err.get("message", err) if isinstance(err, dict) else err
            raise MCPError(f"{method} failed: {message}")
        return resp.get("result", {})

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        """Send a JSON-RPC notification (fire-and-forget)."""
        with self._lock:
            self._transport.send_notification(
                {"jsonrpc": "2.0", "method": method, "params": params or {}}
            )

    # --- lifecycle ---------------------------------------------------------

    def initialize(self) -> None:
        """Perform the MCP handshake: initialize, then notify initialized."""
        self.request(
            "initialize",
            {
                "protocolVersion": self._protocol_version,
                "capabilities": {},
                "clientInfo": _CLIENT_INFO,
            },
        )
        self.notify("notifications/initialized")

    def ensure_ready(self) -> None:
        """Run the handshake once, lazily, before the first real call."""
        if not self._initialized:
            self.initialize()
            self._initialized = True

    def close(self) -> None:
        """Close the underlying transport."""
        self._transport.close()

    # --- MCP operations ----------------------------------------------------

    def list_tools(self) -> list[ToolSpec]:
        """Enumerate the tools the MCP server advertises."""
        self.ensure_ready()
        result = self.request("tools/list")
        return [
            ToolSpec(
                name=raw.get("name", ""),
                description=raw.get("description", "") or "",
                input_schema=raw.get("inputSchema", {}) or {},
                annotations=raw.get("annotations", {}) or {},
            )
            for raw in result.get("tools", [])
        ]

    def call_tool(self, name: str, arguments: dict) -> ToolCallResult:
        """Invoke a tool and report whether it actually executed."""
        self.ensure_ready()
        try:
            result = self.request("tools/call", {"name": name, "arguments": arguments})
        except MCPError as exc:
            # A JSON-RPC error means the server rejected the call outright - the
            # good outcome for an unauthorised destructive request.
            return ToolCallResult(tool=name, ok=False, is_error=True, output=str(exc))

        is_error = bool(result.get("isError", False))
        return ToolCallResult(
            tool=name,
            ok=not is_error,
            output=content_to_text(result.get("content")),
            is_error=is_error,
            raw=result,
        )
