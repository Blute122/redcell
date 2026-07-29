"""In-process Streamable-HTTP MCP stub for hermetic tests.

Serves the *same* tools and dispatch as the stdio mock (``mock_mcp_server``),
just over HTTP, so both transports exercise identical behaviour. Bound to an
ephemeral localhost port like the live-model stub in ``test_live_model.py`` -
no external services, no fixed port.

Exercises the parts of the HTTP transport that stdio can't:

* content type - respond as ``application/json`` or, with ``sse=True``, as an
  SSE ``text/event-stream`` frame;
* session id - issue ``Mcp-Session-Id`` on initialize and *require* it on every
  later request, so a test proves the transport captured and resent it;
* records the last ``Authorization`` header so a test can prove the auth header
  reached the server (and never leaked into reports).
"""

from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Iterator

# yields an HTTPServer with two extra attributes set by http_mcp_server:
#   .url                -> the base URL to point a target at
#   .last_authorization -> the Authorization header of the last request (or None)

import mock_mcp_server as stdio_mock  # same tools + JSON-RPC dispatch

_SESSION_ID = "test-session-abc123"


def _make_handler(sse: bool):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):  # silence default stderr logging
            pass

        def _send(self, status: int, body: bytes = b"", content_type: str | None = None,
                  session_id: str | None = None) -> None:
            self.send_response(status)
            if content_type:
                self.send_header("Content-Type", content_type)
            if session_id:
                self.send_header("Mcp-Session-Id", session_id)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            if body:
                self.wfile.write(body)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            msg = json.loads(self.rfile.read(length) or b"{}")
            method = msg.get("method")

            # Record the auth header so a test can assert it arrived.
            self.server.last_authorization = self.headers.get("Authorization")

            # Enforce the session id on everything after initialize - proves the
            # transport captured it from the initialize response and resends it.
            if method != "initialize":
                if self.headers.get("Mcp-Session-Id") != _SESSION_ID:
                    err = {"jsonrpc": "2.0", "id": msg.get("id"),
                           "error": {"code": -32000, "message": "missing session id"}}
                    self._send(400, json.dumps(err).encode(), "application/json")
                    return

            response = stdio_mock._handle(msg)
            if response is None:  # a notification
                self._send(202)
                return

            body = json.dumps(response)
            issue = _SESSION_ID if method == "initialize" else None
            if sse:
                frame = f"event: message\ndata: {body}\n\n".encode()
                self._send(200, frame, "text/event-stream", issue)
            else:
                self._send(200, body.encode(), "application/json", issue)

    return Handler


@contextmanager
def http_mcp_server(hardened: bool = False, sse: bool = False) -> Iterator[HTTPServer]:
    """Run the stub on an ephemeral port; yield the server (see .url). Cleans up."""
    stdio_mock.HARDENED = hardened
    server = HTTPServer(("127.0.0.1", 0), _make_handler(sse))
    server.last_authorization = None
    host, port = server.server_address
    server.url = f"http://{host}:{port}/mcp"
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        stdio_mock.HARDENED = False
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
