"""
ChidFlow: Runtime Graph Execution Proxy for Autonomous AI Agents.
Transforms static graph isolation into real-time MCP / JSON-RPC policy gating.
"""

__version__ = "0.1.0"

from chidflow.models import (
    SecurityClassification,
    GraphNode,
    GraphEdge,
    ToolCallRequest,
    ToolCallVerdict,
    AuditReceipt,
)
from chidflow.graph import DynamicFlowGraph
from chidflow.policy import PolicyEngine
from chidflow.vault import CredentialVault
from chidflow.proof import ClearinghouseSigner
from chidflow.proxy import MCPExecutionProxy
from chidflow.client import ChidFlowClient

__all__ = [
    "SecurityClassification",
    "GraphNode",
    "GraphEdge",
    "ToolCallRequest",
    "ToolCallVerdict",
    "AuditReceipt",
    "DynamicFlowGraph",
    "PolicyEngine",
    "CredentialVault",
    "ClearinghouseSigner",
    "MCPExecutionProxy",
    "ChidFlowClient",
]
