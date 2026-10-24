from __future__ import annotations

import asyncio
import json
import logging
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
import socketserver
from typing import Optional

from chidflow.models import ToolCallRequest
from chidflow.policy import PolicyEngine
from chidflow.proxy import MCPExecutionProxy
from chidflow.vault import CredentialVault

logger = logging.getLogger("chidflow.server")


def create_http_server(
    port: int,
    proxy: MCPExecutionProxy,
) -> HTTPServer:
    """Create a lightweight zero-dependency HTTP server for ChidFlow JSON-RPC."""

    class ChidFlowHTTPHandler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            # Suppress default noisy console logs
            pass

        def do_POST(self):
            if self.path not in ["/mcp", "/rpc", "/"]:
                self.send_response(HTTPStatus.NOT_FOUND)
                self.end_headers()
                return

            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")

            try:
                rpc_request = json.loads(body)
                # Run async handler synchronously within HTTP server thread
                loop = asyncio.new_event_loop()
                try:
                    rpc_response = loop.run_until_complete(
                        proxy.handle_jsonrpc_message(rpc_request)
                    )
                finally:
                    loop.close()

                resp_bytes = json.dumps(rpc_response).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp_bytes)))
                self.end_headers()
                self.wfile.write(resp_bytes)

            except Exception as e:
                err_resp = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32603, "message": str(e)},
                }
                resp_bytes = json.dumps(err_resp).encode("utf-8")
                self.send_response(HTTPStatus.INTERNAL_SERVER_ERROR)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp_bytes)))
                self.end_headers()
                self.wfile.write(resp_bytes)

        def do_GET(self):
            # Health check endpoint
            if self.path in ["/health", "/status"]:
                resp = json.dumps({
                    "status": "healthy",
                    "engine": "chidflow-min-cut-proxy",
                    "version": "0.1.0",
                    "active_nodes": len(proxy.policy_engine.graph.nodes),
                    "active_edges": len(proxy.policy_engine.graph.edges),
                    "cleared_receipts": len(proxy.audit_log),
                }).encode("utf-8")
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)
            else:
                self.send_response(HTTPStatus.NOT_FOUND)
                self.end_headers()

    class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
        daemon_threads = True

    return ThreadedHTTPServer(("0.0.0.0", port), ChidFlowHTTPHandler)
