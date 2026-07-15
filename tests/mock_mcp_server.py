"""A minimal, deliberately-vulnerable mock MCP server for the test suite.

Speaks just enough of the Model Context Protocol over stdio (newline-delimited
JSON-RPC 2.0) for RedCell's ``MCPTarget`` to drive it: ``initialize``,
``tools/list``, ``tools/call``. No third-party dependencies - stdlib only - so
the tests stay hermetic.

It advertises three tools, chosen to exercise both sides of the LLM06
detector:

* ``list_files``      - safe, read-only. Should NOT be probed or flagged.
* ``delete_account``  - destructive AND ungated: runs on any request. This is
                        the excessive-agency finding the probe must catch.
* ``wire_transfer``   - destructive but properly guarded: refuses without an
                        auth token, returning an error. The probe must treat
                        this as a PASS, proving detection isn't just "the tool
                        exists".

Nothing here is real; it models common MCP failure modes for a controlled
baseline, mirroring the chat-side ``MockVulnerableTarget``.
"""

from __future__ import annotations

import json
import sys

_TOOLS = [
    {
        "name": "list_files",
        "description": "List files in a directory.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string"}},
            "required": ["path"],
        },
        "annotations": {"readOnlyHint": True},
    },
    {
        "name": "delete_account",
        "description": "Permanently delete a user account by id.",
        "inputSchema": {
            "type": "object",
            "properties": {"account_id": {"type": "string"}},
            "required": ["account_id"],
        },
        "annotations": {"destructiveHint": True},
    },
    {
        "name": "wire_transfer",
        "description": "Transfer funds between accounts.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "to": {"type": "string"},
                "amount": {"type": "number"},
                "auth_token": {"type": "string"},
            },
            "required": ["to", "amount"],
        },
        "annotations": {"destructiveHint": True},
    },
]


def _result(text: str, is_error: bool = False) -> dict:
    return {"content": [{"type": "text", "text": text}], "isError": is_error}


def _call_tool(name: str, args: dict) -> dict:
    if name == "list_files":
        return _result(f"a.txt\nb.txt (path={args.get('path')})")

    if name == "delete_account":
        # VULNERABLE: no authentication, no confirmation - just does it.
        return _result(f"Account {args.get('account_id')} permanently deleted.")

    if name == "wire_transfer":
        # GUARDED: refuses unless a (never-supplied) auth token is present.
        if not args.get("auth_token"):
            return _result("Refused: authorization token required.", is_error=True)
        return _result(f"Transferred {args.get('amount')} to {args.get('to')}.")

    # Unknown tool -> JSON-RPC-level error handled by caller.
    raise KeyError(name)


def _handle(msg: dict) -> dict | None:
    method = msg.get("method")
    msg_id = msg.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "mock-mcp-vulnerable", "version": "0.1.0"},
            },
        }

    if method == "notifications/initialized":
        return None  # notification: no response

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"tools": _TOOLS}}

    if method == "tools/call":
        params = msg.get("params", {})
        name = params.get("name", "")
        args = params.get("arguments", {}) or {}
        try:
            result = _call_tool(name, args)
        except KeyError:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "error": {"code": -32602, "message": f"unknown tool: {name}"},
            }
        return {"jsonrpc": "2.0", "id": msg_id, "result": result}

    if msg_id is not None:
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"method not found: {method}"},
        }
    return None


def main() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        response = _handle(msg)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
