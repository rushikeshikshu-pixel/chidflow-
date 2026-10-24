from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional
from chidflow.models import ToolCallRequest, ToolCallVerdict
from chidflow.policy import PolicyEngine
from chidflow.vault import CredentialVault


class ChidFlowToolNode:
    """
    Drop-in Security Guardrail for LangGraph / CrewAI Agent Runtimes.
    
    Intercepts agent tool execution calls before invoking Python functions,
    evaluates real-time Min-Cut reachability, and blocks indirect prompt injection.
    """

    def __init__(
        self,
        tools: List[Callable[..., Any]],
        policy_engine: PolicyEngine,
        vault: Optional[CredentialVault] = None,
    ):
        self.tools_by_name = {t.__name__: t for t in tools}
        self.policy_engine = policy_engine
        self.vault = vault or CredentialVault()

    def invoke(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Executes tools requested in LangGraph state messages,
        passing them through the Min-Cut gate.
        """
        messages = state.get("messages", [])
        if not messages:
            return state

        last_message = messages[-1]
        tool_calls = getattr(last_message, "tool_calls", []) or last_message.get("tool_calls", [])

        results = []
        for call in tool_calls:
            call_id = call.get("id", "call_0")
            name = call.get("name")
            args = call.get("args", {})

            # Run ChidFlow Min-Cut Gate
            request = ToolCallRequest(
                rpc_id=call_id,
                tool_name=name,
                arguments=args,
            )
            verdict: ToolCallVerdict = self.policy_engine.evaluate(request)

            if not verdict.allowed:
                # Blocked: Return simulated synthetic error into agent memory
                results.append({
                    "tool_call_id": call_id,
                    "name": name,
                    "content": f"[CHIDFLOW BLOCKED]: {verdict.violation_reason}",
                    "error": True,
                })
                continue

            # Cleared: Dynamically inject secrets and execute tool
            sanitized_args = self.vault.inject_credentials(args)
            tool_fn = self.tools_by_name.get(name)

            if not tool_fn:
                results.append({
                    "tool_call_id": call_id,
                    "name": name,
                    "content": f"Tool '{name}' not found.",
                    "error": True,
                })
                continue

            try:
                out = tool_fn(**sanitized_args)
                results.append({
                    "tool_call_id": call_id,
                    "name": name,
                    "content": str(out),
                    "_chidflow_receipt": verdict.receipt.to_dict() if verdict.receipt else None,
                })
            except Exception as e:
                results.append({
                    "tool_call_id": call_id,
                    "name": name,
                    "content": f"Execution error: {str(e)}",
                    "error": True,
                })

        return {"messages": results}
