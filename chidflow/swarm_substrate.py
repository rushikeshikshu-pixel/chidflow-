from __future__ import annotations

import collections
import enum
import hashlib
import hmac
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from chidflow.graph import DynamicFlowGraph
from chidflow.models import AuditReceipt, SecurityClassification
from chidflow.proof import ClearinghouseSigner

logger = logging.getLogger("chidflow.swarm.substrate")


class SwarmTaskStatus(str, enum.Enum):
    PENDING = "PENDING"
    ROUTED = "ROUTED"
    CONSENSUS_REACHED = "CONSENSUS_REACHED"
    SEVERED_BY_INVARIANT = "SEVERED_BY_INVARIANT"
    COMMITTED_AND_CLEARED = "COMMITTED_AND_CLEARED"
    DEADLOCK_ABORTED = "DEADLOCK_ABORTED"


@dataclass
class SwarmMessage:
    """A routed message or delegation step between agents in the swarm."""
    message_id: str
    sender_agent: str
    receiver_agent: str
    payload: Dict[str, Any]
    taint_source: Optional[str] = None
    timestamp: float = field(default_factory=time.time)


@dataclass
class SwarmProposal:
    """A proposed collective action synthesized by the agent swarm."""
    proposal_id: str
    origin_agent: str
    target_tool_or_sink: str
    action_args: Dict[str, Any]
    participating_agents: List[str]
    consensus_votes: int = 0
    required_quorum: int = 2


@dataclass
class SwarmClearingReceipt:
    """
    Unified Swarm Clearinghouse Receipt.
    Certifies both Swarm Consensus (Winner 4) and Min-Cut Invariant Safety (Winner 3).
    """
    receipt_id: str
    proposal_id: str
    sequence_no: int
    participating_agents: List[str]
    target_sink: str
    consensus_score: str
    min_cut_flow: float
    state_digest: str
    swarm_signature: str
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "proposal_id": self.proposal_id,
            "sequence_no": self.sequence_no,
            "participating_agents": self.participating_agents,
            "target_sink": self.target_sink,
            "consensus_score": self.consensus_score,
            "min_cut_flow": self.min_cut_flow,
            "state_digest": self.state_digest,
            "swarm_signature": self.swarm_signature,
            "timestamp": self.timestamp,
        }


@dataclass
class SwarmRoutingVerdict:
    status: SwarmTaskStatus
    allowed: bool
    choke_point: Optional[Tuple[str, str]]
    receipt: Optional[SwarmClearingReceipt]
    violation_reason: Optional[str]
    latency_ms: float


class AutonomicSwarmSubstrate:
    """
    The Unified Autonomic Agent Substrate (Winner 3 + Winner 4).
    
    Combines:
      1. Swarm Coordination & Consensus: routes messages, prevents deadlocks,
         and collects multi-agent quorum.
      2. The Invariant Clearinghouse: tracks taint dynamically across the swarm delegation
         tree and mathematically severs any reachability bridge to the Treasure (Min-Cut = 0).
    """

    def __init__(
        self,
        graph: Optional[DynamicFlowGraph] = None,
        signer: Optional[ClearinghouseSigner] = None,
        max_delegation_depth: int = 6,
    ):
        self.graph = graph or DynamicFlowGraph()
        self.signer = signer or ClearinghouseSigner()
        self.max_delegation_depth = max_delegation_depth
        self.registered_agents: Dict[str, Dict[str, Any]] = {}
        self.message_history: List[SwarmMessage] = []
        self._delegation_stack: List[str] = []
        self.critical_sinks = set(self.graph.get_nodes_by_classification(SecurityClassification.CRITICAL_SINK))

    def register_swarm_agent(self, agent_id: str, role: str, classification: SecurityClassification = SecurityClassification.AGENT_CONTEXT) -> None:
        """Register an autonomous agent node into the swarm topology."""
        self.registered_agents[agent_id] = {"role": role, "registered_at": time.time()}
        if agent_id not in self.graph.nodes:
            self.graph.add_node(agent_id, classification, description=f"Swarm Agent: {role}")

    def route_swarm_message(self, message: SwarmMessage) -> SwarmRoutingVerdict:
        """
        Route a message/task delegation from sender agent to receiver agent.
        Prevents circular deadlock loops and dynamically registers taint edges.
        """
        start_time = time.time()

        # 1. Deadlock & Infinite Recursion Prevention
        if message.sender_agent == message.receiver_agent:
            latency_ms = (time.time() - start_time) * 1000
            return SwarmRoutingVerdict(
                status=SwarmTaskStatus.DEADLOCK_ABORTED,
                allowed=False,
                choke_point=None,
                receipt=None,
                violation_reason="CIRCULAR_SELF_DELEGATION_DETECTED",
                latency_ms=latency_ms,
            )

        # Check recursion depth
        self._delegation_stack.append(message.receiver_agent)
        if len(self._delegation_stack) > self.max_delegation_depth:
            self._delegation_stack.pop()
            latency_ms = (time.time() - start_time) * 1000
            return SwarmRoutingVerdict(
                status=SwarmTaskStatus.DEADLOCK_ABORTED,
                allowed=False,
                choke_point=None,
                receipt=None,
                violation_reason=f"DELEGATION_DEPTH_LIMIT_EXCEEDED (Max {self.max_delegation_depth})",
                latency_ms=latency_ms,
            )

        # 2. Register Agents if not already in graph
        for a_id in (message.sender_agent, message.receiver_agent):
            if a_id not in self.graph.nodes:
                self.graph.add_node(a_id, SecurityClassification.AGENT_CONTEXT)

        # 3. Add dynamic taint provenance edge in the graph
        taint_label = message.taint_source or f"delegation:{message.sender_agent}->{message.receiver_agent}"
        self.graph.add_edge(message.sender_agent, message.receiver_agent, taint_label=taint_label)
        self.message_history.append(message)

        latency_ms = (time.time() - start_time) * 1000
        return SwarmRoutingVerdict(
            status=SwarmTaskStatus.ROUTED,
            allowed=True,
            choke_point=None,
            receipt=None,
            violation_reason=None,
            latency_ms=latency_ms,
        )

    def evaluate_swarm_proposal(self, proposal: SwarmProposal) -> SwarmRoutingVerdict:
        """
        Evaluate a collective multi-agent execution proposal targeting a critical sink.
        Enforces both Quorum Consensus (Winner 4) and Min-Cut Invariant Safety (Winner 3).
        """
        start_time = time.time()

        # Step A: Consensus Quorum Check (Winner 4)
        if proposal.consensus_votes < proposal.required_quorum:
            latency_ms = (time.time() - start_time) * 1000
            return SwarmRoutingVerdict(
                status=SwarmTaskStatus.SEVERED_BY_INVARIANT,
                allowed=False,
                choke_point=None,
                receipt=None,
                violation_reason=f"INSUFFICIENT_SWARM_QUORUM: {proposal.consensus_votes}/{proposal.required_quorum} votes",
                latency_ms=latency_ms,
            )

        # Step B: Speculative Min-Cut Invariant Gate (Winner 3)
        self.graph.checkpoint()
        try:
            # Speculatively connect origin agent to target sink
            sink_node = proposal.target_tool_or_sink
            if sink_node in self.graph.nodes:
                self.graph.add_edge(proposal.origin_agent, sink_node, taint_label=f"proposal:{proposal.proposal_id}")

            untrusted_sources = self.graph.get_nodes_by_classification(SecurityClassification.UNTRUSTED_SOURCE)
            critical_sinks = self.graph.get_nodes_by_classification(SecurityClassification.CRITICAL_SINK)

            flow, choke_points = self.graph.compute_min_cut(untrusted_sources, critical_sinks)
            latency_ms = (time.time() - start_time) * 1000

            if flow > 0:
                # Transitive prompt injection or taint exfiltration detected across swarm!
                choke = choke_points[0] if choke_points else (proposal.origin_agent, sink_node)
                logger.warning(
                    f"[SWARM INVARIANT SEVERED] Swarm proposal '{proposal.proposal_id}' by {proposal.origin_agent} "
                    f"created reachability flow ({flow}) to critical sink '{sink_node}'. Choke: {choke}."
                )
                return SwarmRoutingVerdict(
                    status=SwarmTaskStatus.SEVERED_BY_INVARIANT,
                    allowed=False,
                    choke_point=choke,
                    receipt=None,
                    violation_reason=f"MIN_CUT_INVARIANT_VIOLATION: Swarm tainted by upstream ingress. Flow={flow}",
                    latency_ms=latency_ms,
                )

            # Step C: Issue Unified Swarm Clearinghouse Receipt
            timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            state_digest = self.graph.get_state_hash()
            raw_sig_payload = f"{proposal.proposal_id}|{proposal.target_tool_or_sink}|{timestamp}|{state_digest}".encode("utf-8")
            swarm_sig = hmac.new(self.signer._secret, raw_sig_payload, hashlib.sha256).hexdigest()
            receipt_id = f"swm_{hashlib.sha256(swarm_sig.encode()).hexdigest()[:12]}"

            receipt = SwarmClearingReceipt(
                receipt_id=receipt_id,
                proposal_id=proposal.proposal_id,
                sequence_no=len(self.message_history) + 1,
                participating_agents=proposal.participating_agents,
                target_sink=sink_node,
                consensus_score=f"{proposal.consensus_votes}/{proposal.required_quorum} Quorum Approved",
                min_cut_flow=0.0,
                state_digest=state_digest,
                swarm_signature=swarm_sig,
                timestamp=timestamp,
            )

            return SwarmRoutingVerdict(
                status=SwarmTaskStatus.COMMITTED_AND_CLEARED,
                allowed=True,
                choke_point=None,
                receipt=receipt,
                violation_reason=None,
                latency_ms=latency_ms,
            )

        finally:
            self.graph.rollback()
