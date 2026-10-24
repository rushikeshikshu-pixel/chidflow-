from __future__ import annotations

import asyncio
import json
import logging
import sys
from typing import Any, Callable, Coroutine, Dict, Optional

from chidflow.models import AuditReceipt, ToolCallRequest, ToolCallVerdict
from chidflow.policy import PolicyEngine
from chidflow.vault import CredentialVault

logger = logging.getLogger("chidflow.proxy")


class MCPExecutionProxy:
    """
    Runtime Execution Proxy for Model Context Protocol (MCP) agents.
    
    Placed between Agent sandboxes (LangGraph, CrewAI, Claude Desktop)
    and real execution rails (Tools, APIs, SQL, Financial rails).
    """

    def __init__(
        self,
        policy_engine: Optional[PolicyEngine] = None,
        vault: Optional[CredentialVault] = None,
        forwarder: Optional[Callable[[Dict[str, Any]], Coroutine[Any, Any, Dict[str, Any]]]] = None,
    ):
        self.policy_engine = policy_engine or PolicyEngine()
        self.vault = vault or CredentialVault()
        self.forwarder = forwarder
        self.audit_log: list[AuditReceipt] = []

    async def handle_jsonrpc_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Processes a single JSON-RPC 2.0 message:
        Intercepts `tools/call`, tests Min-Cut isolation, injects credentials,
        or yields a synthetic isolation error.
        """
        method = message.get("method")
        rpc_id = message.get("id")

        if method == "tools/call":
            params = message.get("params", {})
            tool_name = params.get("name", "")
            raw_arguments = params.get("arguments", {})

            # 1. Create tool call request
            request = ToolCallRequest(
                rpc_id=rpc_id,
                tool_name=tool_name,
                arguments=raw_arguments,
                caller_node="agent_memory",
            )

            # 2. Real-Time Min-Cut Policy Gate
            verdict: ToolCallVerdict = self.policy_engine.evaluate(request)

            if not verdict.allowed:
                logger.warning(
                    f"[CHIDFLOW BLOCKED] Tool '{tool_name}' violated Min-Cut: {verdict.violation_reason}"
                )
                return verdict.simulated_error or {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "error": {
                        "code": -32001,
                        "message": verdict.violation_reason or "Policy Violation: Min-Cut breach.",
                    },
                }

            # 3. Passed Min-Cut check! Record cryptographic receipt
            if verdict.receipt:
                self.audit_log.append(verdict.receipt)
                logger.info(
                    f"[CHIDFLOW CLEARED] Tool '{tool_name}' receipt={verdict.receipt.receipt_id} "
                    f"seq={verdict.receipt.sequence_no}"
                )

            # 4. Dynamic Credential Injection
            sanitized_args = self.vault.inject_credentials(raw_arguments)
            cleared_message = dict(message)
            cleared_message["params"] = {
                "name": tool_name,
                "arguments": sanitized_args,
            }

            # 5. Forward to real execution rail / upstream MCP server
            if self.forwarder:
                upstream_response = await self.forwarder(cleared_message)
                return upstream_response

            # If no forwarder configured, return standard mock success acknowledging clearance
            return {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {
                    "content": [
                        {
                            "type": "text",
                            "text": f"Successfully executed '{tool_name}' through ChidFlow proxy.",
                        }
                    ],
                    "_chidflow_receipt": verdict.receipt.to_dict() if verdict.receipt else None,
                },
            }

        # Non-tool methods (e.g. initialize, tools/list, ping) pass through directly
        if self.forwarder:
            return await self.forwarder(message)

        # Default handler for standard MCP initialization if mock mode
        if method == "initialize":
            return {
                "jsonrpc": "2.0",
                "id": rpc_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "chidflow-mcp-proxy", "version": "0.1.0"},
                },
            }

        return {
            "jsonrpc": "2.0",
            "id": rpc_id,
            "result": {},
        }

    async def run_stdio(self) -> None:
        """Run MCP proxy loop listening on stdin and responding to stdout."""
        loop = asyncio.get_event_loop()
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await loop.connect_read_pipe(lambda: protocol, sys.stdin)

        while True:
            line = await reader.readline()
            if not line:
                break

            line_str = line.decode("utf-8").strip()
            if not line_str:
                continue

            try:
                rpc_req = json.loads(line_str)
                rpc_res = await self.handle_jsonrpc_message(rpc_req)
                sys.stdout.write(json.dumps(rpc_res) + "\n")
                sys.stdout.flush()
            except Exception as e:
                err_response = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32603, "message": f"Internal proxy error: {str(e)}"},
                }
                sys.stdout.write(json.dumps(err_response) + "\n")
                sys.stdout.flush()
