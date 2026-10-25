from __future__ import annotations

import json
import logging
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional

from chidflow.graph import DynamicFlowGraph
from chidflow.models import AuditReceipt, SecurityClassification, ToolCallRequest, ToolCallVerdict
from chidflow.policy import PolicyEngine
from chidflow.proof import ClearinghouseSigner

logger = logging.getLogger("chidflow.client")


class ChidFlowClient:
    """
    Client SDK for AI Agents and Swarms.
    
    Provides 3-line integration for:
    - Direct in-memory invariant gating (< 0.2ms)
    - Remote Clearinghouse verification and settlement
    - Function decoration for automated policy checks
    """

    def __init__(
        self,
        endpoint: Optional[str] = None,
        signing_secret: Optional[str] = None,
        policy_engine: Optional[PolicyEngine] = None,
    ) -> None:
        """
        Initialize ChidFlow Client.
        
        :param endpoint: Remote Clearinghouse Gateway URL (e.g. 'http://localhost:8443')
        :param signing_secret: Secret key for verifying or generating cryptographic receipts
        :param policy_engine: Optional local PolicyEngine for in-process sub-millisecond evaluation
        """
        self.endpoint = endpoint.rstrip("/") if endpoint else None
        self.signer = ClearinghouseSigner(signing_secret or "chidflow-client-default-secret")
        
        if policy_engine:
            self.policy_engine = policy_engine
        else:
            graph = DynamicFlowGraph()
            self.policy_engine = PolicyEngine(graph=graph, signer=self.signer)

    def guard_action(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        reads_from: Optional[List[str]] = None,
        writes_to: Optional[List[str]] = None,
        caller_node: str = "agent_memory",
    ) -> ToolCallVerdict:
        """
        Evaluate a pending tool execution locally against the Dynamic Min-Cut Graph.
        
        :return: ToolCallVerdict indicating if allowed and containing cryptographic audit receipt
        """
        if reads_from or writes_to:
            self.policy_engine.register_tool(
                name=tool_name,
                reads_from=reads_from,
                writes_to=writes_to,
            )

        req = ToolCallRequest(
            rpc_id=1,
            tool_name=tool_name,
            arguments=arguments,
            caller_node=caller_node,
        )
        return self.policy_engine.evaluate(req)

    def verify_remote_receipt(self, receipt: AuditReceipt | Dict[str, Any]) -> Dict[str, Any]:
        """
        Send a receipt to the remote Clearinghouse Verification Gateway for validation.
        
        :return: Gateway settlement verdict dictionary
        """
        if not self.endpoint:
            raise ValueError("Endpoint must be configured for remote clearinghouse verification.")

        url = f"{self.endpoint}/v1/clearing/verify"
        payload = receipt if isinstance(receipt, dict) else receipt.to_dict()
        req_data = json.dumps({"receipt": payload}).encode("utf-8")
        req = urllib.request.Request(
            url,
            data=req_data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.URLError as e:
            return {
                "verified": False,
                "status": "GATEWAY_UNAVAILABLE",
                "error": str(e),
            }

    def guard(
        self,
        writes_to: Optional[List[str]] = None,
        reads_from: Optional[List[str]] = None,
        caller_node: str = "agent_memory",
    ):
        """
        Function decorator for automated tool guarding.
        
        Usage:
            @client.guard(writes_to=["banking_wire_rail"])
            def send_money(amount: float, recipient: str):
                ...
        """
        def decorator(func: Callable):
            def wrapper(*args, **kwargs):
                tool_name = func.__name__
                verdict = self.guard_action(
                    tool_name=tool_name,
                    arguments=kwargs,
                    reads_from=reads_from,
                    writes_to=writes_to,
                    caller_node=caller_node,
                )
                if not verdict.allowed:
                    raise PermissionError(
                        f"ChidFlow Invariant Violation: Execution of '{tool_name}' blocked. "
                        f"Reason: {verdict.violation_reason}"
                    )
                return func(*args, **kwargs)
            return wrapper
        return decorator
