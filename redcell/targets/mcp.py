"""MCP server target adapter.

Connects RedCell to a Model Context Protocol server and exposes it as an
``AgentTarget`` so the agent-only probes (LLM06 excessive agency) can run
against it live: enumerate the tools it advertises and actually invoke them.

Transport is stdio - the canonical local MCP transport. RedCell launches the
server as a subprocess and speaks newline-delimited JSON-RPC 2.0 over its
stdin/stdout:

    initialize -> notifications/initialized -> tools/list -> tools/call

This is a deliberately small, dependency-free client (stdlib + the wire
protocol) rather than the full MCP SDK: the scanner only needs to list and
call tools, and a lean client keeps the tests hermetic. HTTP/SSE transports
can be added behind the same ``MCPTarget`` surface later.

An MCP server is not a chat model, so ``chat_capable`` is False: the engine
runs the tool probes against it and skips the prompt-only probes.
"""

from __future__ import annotations

import json
import subprocess
import threading
from typing import Any

from ..models import ToolCallResult, ToolSpec
from .base import AgentTarget

_PROTOCOL_VERSION = "2024-11-05"
_CLIENT_INFO = {"name": "redcell", "version": "0.1.0"}


class MCPError(RuntimeError):
    """Transport- or protocol-level failure talking to the MCP server."""


class _StdioMCPClient:
    """Minimal JSON-RPC 2.0 client over a subprocess' stdio.

    Messages are newline-delimited JSON. Requests carry an id and block for
    the matching response; server-initiated notifications (no id) and log
    lines are skipped while waiting.
    """

    def __init__(
        self,
        command: list[str],
        env: dict[str, str] | None = None,
        cwd: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        self.command = command
        self.timeout = timeout
        self._id = 0
        self._lock = threading.Lock()
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

    # --- framing ------------------------------------------------------------

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

        A background timer kills the subprocess if the server never answers,
        so a hung server surfaces as an error instead of blocking the scan.
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
                    # Not JSON-RPC (e.g. a stray log line) - ignore.
                    continue
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

    # --- JSON-RPC -----------------------------------------------------------

    def request(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Send a JSON-RPC request and return its result, raising on error."""
        with self._lock:
            self._id += 1
            req_id = self._id
            self._write(
                {"jsonrpc": "2.0", "id": req_id, "method": method, "params": params or {}}
            )
            resp = self._read_response(req_id)
        if "error" in resp:
            err = resp["error"]
            raise MCPError(f"{method} failed: {err.get('message', err)}")
        return resp.get("result", {})

    def notify(self, method: str, params: dict[str, Any] | None = None) -> None:
        """Send a JSON-RPC notification (no id, no response expected)."""
        with self._lock:
            self._write({"jsonrpc": "2.0", "method": method, "params": params or {}})

    # --- lifecycle ----------------------------------------------------------

    def initialize(self) -> None:
        """Perform the MCP handshake: initialize, then notify initialized."""
        self.request(
            "initialize",
            {
                "protocolVersion": _PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": _CLIENT_INFO,
            },
        )
        self.notify("notifications/initialized")

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


def _content_to_text(content: Any) -> str:
    """Flatten an MCP tool-result `content` array into plain text."""
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


class MCPTarget(AgentTarget):
    """A Model Context Protocol server, exposed as a tool-callable target."""

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
        self._client = _StdioMCPClient(command, env=env, cwd=cwd, timeout=timeout)
        self._initialized = False

    def _ensure_ready(self) -> None:
        if not self._initialized:
            self._client.initialize()
            self._initialized = True

    def list_tools(self) -> list[ToolSpec]:
        """Enumerate the tools the MCP server advertises."""
        self._ensure_ready()
        result = self._client.request("tools/list")
        tools = []
        for raw in result.get("tools", []):
            tools.append(
                ToolSpec(
                    name=raw.get("name", ""),
                    description=raw.get("description", "") or "",
                    input_schema=raw.get("inputSchema", {}) or {},
                    annotations=raw.get("annotations", {}) or {},
                )
            )
        return tools

    def call_tool(self, name: str, arguments: dict) -> ToolCallResult:
        """Invoke a tool and report whether it actually executed."""
        self._ensure_ready()
        try:
            result = self._client.request(
                "tools/call", {"name": name, "arguments": arguments}
            )
        except MCPError as exc:
            # A JSON-RPC error means the server rejected the call outright -
            # the good outcome for an unauthorised destructive request.
            return ToolCallResult(tool=name, ok=False, is_error=True, output=str(exc))

        is_error = bool(result.get("isError", False))
        text = _content_to_text(result.get("content"))
        return ToolCallResult(
            tool=name,
            ok=not is_error,
            output=text,
            is_error=is_error,
            raw=result,
        )

    def send(self, prompt: str) -> str:  # pragma: no cover - not chat-capable
        """Not supported: an MCP server exposes tools, not a chat endpoint."""
        raise NotImplementedError(
            "MCPTarget exposes tools, not a chat endpoint; it is not chat_capable."
        )

    def close(self) -> None:
        """Terminate the underlying MCP server process."""
        self._client.close()
