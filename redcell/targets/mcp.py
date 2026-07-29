"""MCP server target adapter — stdio transport.

Connects RedCell to a Model Context Protocol server over stdio (the canonical
local transport) and exposes it as an ``AgentTarget`` so the agent probes can
enumerate its tools and invoke them. RedCell launches the server as a
subprocess and speaks newline-delimited JSON-RPC 2.0 over its stdin/stdout:

    initialize -> notifications/initialized -> tools/list -> tools/call

The MCP protocol semantics live in :mod:`mcp_protocol` (shared with the HTTP
adapter); this module only implements the stdio framing. It stays a small,
dependency-free client rather than the full MCP SDK.

An MCP server is not a chat model, so ``chat_capable`` is False: the engine runs
the tool probes against it and skips the prompt-only probes.
"""

from __future__ import annotations

import json
import subprocess
import threading
from typing import Any

from ..models import ToolCallResult, ToolSpec
from .base import AgentTarget
from .mcp_protocol import MCPError, MCPSession, MCPTransport

__all__ = ["MCPTarget", "MCPError"]


class StdioTransport(MCPTransport):
    """JSON-RPC 2.0 framing over a subprocess' stdio (newline-delimited).

    Requests carry an id and block for the matching response; server-initiated
    notifications (no id) and stray log lines are skipped while waiting.
    """

    def __init__(
        self,
        command: list[str],
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.timeout = timeout
        try:
            self._proc = subprocess.Popen(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,  # line-buffered
                env=env,
                cwd=cwd,
            )
        except (OSError, ValueError) as exc:
            raise MCPError(f"failed to launch MCP server {command!r}: {exc}") from exc

    def _write(self, message: dict[str, Any]) -> None:
        if self._proc.stdin is None or self._proc.poll() is not None:
            raise MCPError("MCP server process is not running")
        line = json.dumps(message, separators=(",", ":")) + "\n"
        try:
            self._proc.stdin.write(line)
            self._proc.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise MCPError(f"failed writing to MCP server: {exc}") from exc

    def _read_response(self, expected_id: int) -> dict[str, Any]:
        """Read lines until the response with `expected_id` arrives.

        A background timer kills the subprocess if the server never answers, so
        a hung server surfaces as an error instead of blocking the scan.
        """
        assert self._proc.stdout is not None
        timer = threading.Timer(self.timeout, self._proc.kill)
        timer.start()
        try:
            while True:
                line = self._proc.stdout.readline()
                if line == "":
                    raise MCPError(
                        "MCP server closed the connection before responding"
                        + self._drain_stderr()
                    )
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except json.JSONDecodeError:
                    continue  # not JSON-RPC (e.g. a stray log line)
                if msg.get("id") == expected_id:
                    return msg
                # Otherwise a notification or unrelated message; keep reading.
        finally:
            timer.cancel()

    def _drain_stderr(self) -> str:
        try:
            if self._proc.stderr is not None:
                err = self._proc.stderr.read()
                if err:
                    return f" (stderr: {err.strip()})"
        except OSError:
            pass
        return ""

    def send_request(self, message: dict[str, Any]) -> dict[str, Any]:
        """Write one request and read back its matching response."""
        self._write(message)
        return self._read_response(message["id"])

    def send_notification(self, message: dict[str, Any]) -> None:
        """Write a notification; no response is read."""
        self._write(message)

    def close(self) -> None:
        """Shut down the server subprocess, escalating to kill if needed."""
        proc = self._proc
        try:
            if proc.stdin is not None:
                proc.stdin.close()
        except OSError:
            pass
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


class MCPTarget(AgentTarget):
    """A Model Context Protocol server over stdio, as a tool-callable target."""

    #: MCP servers expose tools, not a chat interface.
    chat_capable = False

    def __init__(
        self,
        command: list[str],
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        name: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        super().__init__()
        if not command:
            raise ValueError("MCPTarget requires a non-empty launch command")
        self.command = command
        self.name = name or f"mcp:{command[0]}"
        transport = StdioTransport(command, env=env, cwd=cwd, timeout=timeout)
        self._session = MCPSession(transport)

    def list_tools(self) -> list[ToolSpec]:
        """Enumerate the tools the MCP server advertises."""
        return self._session.list_tools()

    def call_tool(self, name: str, arguments: dict) -> ToolCallResult:
        """Invoke a tool and report whether it actually executed."""
        return self._session.call_tool(name, arguments)

    def send(self, prompt: str) -> str:  # pragma: no cover - not chat-capable
        """Not supported: an MCP server exposes tools, not a chat endpoint."""
        raise NotImplementedError(
            "MCPTarget exposes tools, not a chat endpoint; it is not chat_capable."
        )

    def close(self) -> None:
        """Terminate the underlying MCP server process."""
        self._session.close()
