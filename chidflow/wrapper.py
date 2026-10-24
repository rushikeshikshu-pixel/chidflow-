from __future__ import annotations

import asyncio
import json
import logging
import shlex
import sys
from typing import Any, Dict, Optional

from chidflow.models import ToolCallRequest, ToolCallVerdict
from chidflow.policy import PolicyEngine
from chidflow.vault import CredentialVault

logger = logging.getLogger("chidflow.wrapper")


class SubprocessMCPWrapper:
    """
    Subprocess MCP Wrapper.
    
    Spawns an upstream MCP server as a child process, intercepting stdio communication.
    Guarantees that unauthorized or reachability-violating packets never reach the child process.
    """

    def __init__(
        self,
        upstream_command: str,
        policy_engine: PolicyEngine,
        vault: Optional[CredentialVault] = None,
    ):
        self.upstream_command = upstream_command
        self.policy_engine = policy_engine
        self.vault = vault or CredentialVault()
        self.proc: Optional[asyncio.subprocess.Process] = None

    async def start(self) -> None:
        """Spawn the upstream MCP server."""
        # Split command correctly on Windows / POSIX
        if sys.platform == "win32":
            self.proc = await asyncio.create_subprocess_shell(
                self.upstream_command,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        else:
            args = shlex.split(self.upstream_command)
            self.proc = await asyncio.create_subprocess_exec(
                *args,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        logger.info(f"Spawned upstream MCP server: {self.upstream_command} (PID {self.proc.pid})")

    async def forward_to_upstream(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Send JSON-RPC message to child process and wait for response."""
        if not self.proc or not self.proc.stdin or not self.proc.stdout:
            raise RuntimeError("Upstream MCP process is not running.")

        payload = (json.dumps(message) + "\n").encode("utf-8")
        self.proc.stdin.write(payload)
        await self.proc.stdin.drain()

        # Read line from upstream stdout
        line = await self.proc.stdout.readline()
        if not line:
            return {
                "jsonrpc": "2.0",
                "id": message.get("id"),
                "error": {"code": -32603, "message": "Upstream MCP process terminated unexpectedly"},
            }

        return json.loads(line.decode("utf-8").strip())

    async def run(self) -> None:
        """Main stdio loop reading from sys.stdin and writing to sys.stdout."""
        await self.start()

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
                rpc_res = await self.process_message(rpc_req)
                sys.stdout.write(json.dumps(rpc_res) + "\n")
                sys.stdout.flush()
            except Exception as e:
                err_response = {
                    "jsonrpc": "2.0",
                    "id": None,
                    "error": {"code": -32603, "message": f"Proxy error: {str(e)}"},
                }
                sys.stdout.write(json.dumps(err_response) + "\n")
                sys.stdout.flush()

        if self.proc:
            try:
                self.proc.terminate()
            except ProcessLookupError:
                pass

    async def process_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Intercepts tools/call or passes through directly."""
        method = message.get("method")
        rpc_id = message.get("id")

        if method == "tools/call":
            params = message.get("params", {})
            tool_name = params.get("name", "")
            raw_args = params.get("arguments", {})

            # Run Min-Cut Policy Check
            request = ToolCallRequest(
                rpc_id=rpc_id,
                tool_name=tool_name,
                arguments=raw_args,
            )
            verdict: ToolCallVerdict = self.policy_engine.evaluate(request)

            if not verdict.allowed:
                # SEVERED: Return synthetic error directly. Upstream never sees it.
                return verdict.simulated_error or {
                    "jsonrpc": "2.0",
                    "id": rpc_id,
                    "error": {
                        "code": -32001,
                        "message": verdict.violation_reason or "Policy violation: Min-Cut breach.",
                    },
                }

            # INJECT CREDENTIALS & FORWARD
            sanitized_args = self.vault.inject_credentials(raw_args)
            cleared_message = dict(message)
            cleared_message["params"] = {
                "name": tool_name,
                "arguments": sanitized_args,
            }

            upstream_res = await self.forward_to_upstream(cleared_message)

            # Attach cryptographic clearinghouse receipt
            if verdict.receipt and "result" in upstream_res:
                if isinstance(upstream_res["result"], dict):
                    upstream_res["result"]["_chidflow_receipt"] = verdict.receipt.to_dict()

            return upstream_res

        # Pass non-tool calls directly
        return await self.forward_to_upstream(message)
