from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional, Tuple

from chidflow.models import ToolCallRequest, ToolCallVerdict
from chidflow.policy import PolicyEngine
from chidflow.vault import CredentialVault

logger = logging.getLogger("chidflow.bridges.openshell")


class OpenShellSupervisorBridge:
    """
    NVIDIA OpenShell Supervisor Interception Bridge.
    
    Allows ChidFlow to sit inside or alongside NVIDIA OpenShell's Supervisor proxy.
    While OpenShell manages container jailing and raw network egress, ChidFlow provides
    the missing Dynamic Information Flow Graph (DIFG) semantic intelligence.
    """

    def __init__(
        self,
        policy_engine: PolicyEngine,
        vault: Optional[CredentialVault] = None,
        enforce_strict_isolation: bool = True,
    ):
        self.policy_engine = policy_engine
        self.vault = vault or CredentialVault()
        self.enforce_strict_isolation = enforce_strict_isolation

    def intercept_openshell_request(
        self,
        sandbox_id: str,
        http_method: str,
        destination_url: str,
        payload: Dict[str, Any],
    ) -> Tuple[bool, Dict[str, Any]]:
        """
        Intercepts an outbound request from OpenShell's supervisor.
        
        Args:
            sandbox_id: ID of the microVM or Landlock container.
            http_method: POST, GET, etc.
            destination_url: Upstream API endpoint.
            payload: Parsed JSON payload or MCP tool call.

        Returns:
            (allowed: bool, modified_payload_or_error: Dict)
        """
        # Determine tool name or intent
        tool_name = payload.get("tool") or payload.get("name") or destination_url
        raw_args = payload.get("arguments") or payload.get("params") or {}

        # Synthesize tool call request from OpenShell envelope
        request = ToolCallRequest(
            rpc_id=payload.get("id", sandbox_id),
            tool_name=tool_name,
            arguments=raw_args,
            caller_node=f"sandbox_{sandbox_id}",
        )

        # Evaluate real-time Min-Cut
        verdict: ToolCallVerdict = self.policy_engine.evaluate(request)

        if not verdict.allowed:
            logger.warning(
                f"[OPENSHELL ENFORCEMENT SEVERED] Sandbox {sandbox_id} tried calling {tool_name} "
                f"causing reachability violation: {verdict.violation_reason}"
            )
            return False, {
                "error": "CHIDFLOW_MIN_CUT_POLICY_VIOLATION",
                "status_code": 403,
                "detail": verdict.violation_reason,
                "choke_points": verdict.choke_points,
            }

        # Dynamic credential substitution
        cleared_payload = self.vault.inject_credentials(payload)

        # Attach cryptographic audit receipt into headers or payload
        if verdict.receipt:
            cleared_payload["_chidflow_receipt"] = verdict.receipt.to_dict()

        return True, cleared_payload
