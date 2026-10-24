from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple, Union


class SecurityClassification(str, enum.Enum):
    """
    Security classifications for nodes in the dynamic agent execution graph.
    """
    UNTRUSTED_SOURCE = "UNTRUSTED_SOURCE"     # Public internet, scraped HTML, external webhooks
    AGENT_CONTEXT = "AGENT_CONTEXT"           # Agent memory, working scratchpad, LLM context
    CONFIDENTIAL_ASSET = "CONFIDENTIAL_ASSET" # Internal PII, financial ledgers, customer records
    RESTRICTED_SECRET = "RESTRICTED_SECRET"   # API keys, passwords, database credentials
    CRITICAL_SINK = "CRITICAL_SINK"           # Wire transfers, SQL write execution, external email egress


@dataclass
class GraphNode:
    """A node representing a data asset, memory boundary, or external interface."""
    id: str
    classification: SecurityClassification
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "classification": self.classification.value,
            "description": self.description,
            "metadata": self.metadata,
            "created_at": self.created_at,
        }


@dataclass
class GraphEdge:
    """A directed edge representing data flow or invocation permission."""
    source: str
    target: str
    capacity: float = 1.0  # Min-cut flow capacity (weight)
    taint_label: str = ""
    created_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "capacity": self.capacity,
            "taint_label": self.taint_label,
            "created_at": self.created_at,
        }


@dataclass
class ToolCallRequest:
    """An intercepted tool call request (from MCP JSON-RPC)."""
    rpc_id: Union[str, int]
    tool_name: str
    arguments: Dict[str, Any]
    caller_node: str = "agent_memory"
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditReceipt:
    """Cryptographic clearinghouse receipt certifying reachability check."""
    receipt_id: str
    sequence_no: int
    timestamp: str
    tool_name: str
    args_hash: str
    graph_state_hash: str
    signature: str
    public_key: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "sequence_no": self.sequence_no,
            "timestamp": self.timestamp,
            "tool_name": self.tool_name,
            "args_hash": self.args_hash,
            "graph_state_hash": self.graph_state_hash,
            "signature": self.signature,
            "public_key": self.public_key,
        }


@dataclass
class ToolCallVerdict:
    """The decision made by the execution proxy."""
    allowed: bool
    choke_points: List[Tuple[str, str]] = field(default_factory=list)
    violation_reason: Optional[str] = None
    receipt: Optional[AuditReceipt] = None
    simulated_error: Optional[Dict[str, Any]] = None
