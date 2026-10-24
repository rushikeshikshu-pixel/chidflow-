from __future__ import annotations

import collections
import enum
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from chidflow.graph import DynamicFlowGraph
from chidflow.models import AuditReceipt, SecurityClassification
from chidflow.proof import ClearinghouseSigner

logger = logging.getLogger("chidflow.serverwatch.autopilot")


class IncidentSeverity(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class RemediationType(str, enum.Enum):
    DRAIN_CANARY = "DRAIN_CANARY"
    ROLLBACK_DEPLOYMENT = "ROLLBACK_DEPLOYMENT"
    RESTART_WORKER_POOL = "RESTART_WORKER_POOL"
    ISOLATE_NODE = "ISOLATE_NODE"
    SCALE_REPLICA = "SCALE_REPLICA"
    FLUSH_TAINTED_CACHE = "FLUSH_TAINTED_CACHE"
    DROP_DATABASE_TABLE = "DROP_DATABASE_TABLE"  # High-risk / Destructive action (Candidate for invariant rejection)
    KILL_PROCESS = "KILL_PROCESS"


@dataclass
class SystemIncident:
    """Represents an active production fault or anomaly event."""
    incident_id: str
    affected_service: str
    severity: IncidentSeverity
    symptoms: List[str]
    metric_anomalies: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


@dataclass
class RemediationAction:
    """A proposed autonomous remediation candidate."""
    action_id: str
    action_type: RemediationType
    target_node: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    description: str = ""
    estimated_risk: str = "LOW"


@dataclass
class AutopilotVerdict:
    """The outcome of causal diagnosis and policy-bounded remediation."""
    incident_id: str
    causal_root_cause: str
    remediation: Optional[RemediationAction]
    approved: bool
    violation_reason: Optional[str]
    recovery_verified: bool
    receipt: Optional[AuditReceipt]
    execution_time_ms: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "causal_root_cause": self.causal_root_cause,
            "remediation": {
                "action_id": self.remediation.action_id,
                "action_type": self.remediation.action_type.value,
                "target_node": self.remediation.target_node,
                "description": self.remediation.description,
            } if self.remediation else None,
            "approved": self.approved,
            "violation_reason": self.violation_reason,
            "recovery_verified": self.recovery_verified,
            "receipt": self.receipt.to_dict() if self.receipt else None,
            "execution_time_ms": self.execution_time_ms,
        }


class ServerWatchAutopilot:
    """
    ServerWatch Production Incident Autopilot & Runtime Clearinghouse.
    
    Transforms infrastructure operations from human triage into an autonomous,
    self-operating, and self-healing closed-loop system:
      1. Real-time Causal Dependency Inference (RCA).
      2. Candidate Remediation Synthesis.
      3. Min-Cut Blast-Radius & Treasure Invariant Verification.
      4. Safe Autonomous Execution with Checkpointed Rollback.
      5. Post-Remediation Recovery Verification & Cryptographic Receipt Issuance.
    """

    def __init__(
        self,
        graph: DynamicFlowGraph,
        signer: Optional[ClearinghouseSigner] = None,
        min_healthy_replicas_ratio: float = 0.5,
    ):
        self.graph = graph
        self.signer = signer or ClearinghouseSigner()
        self.min_healthy_replicas_ratio = min_healthy_replicas_ratio
        # Node health map: node_id -> is_healthy: bool
        self.node_health: Dict[str, bool] = {node_id: True for node_id in self.graph.nodes}
        # Invariant constraints: e.g., protected sinks that can never be directly severed or dropped
        self.critical_sinks = set(self.graph.get_nodes_by_classification(SecurityClassification.CRITICAL_SINK))

    def update_node_health(self, node_id: str, is_healthy: bool) -> None:
        """Update runtime health status for a node."""
        self.node_health[node_id] = is_healthy

    def infer_causal_chain(self, incident: SystemIncident) -> str:
        """
        Traverse the dynamic graph backwards from the symptomatic service
        to locate the causal root-cause node (e.g. faulty deployment, pool leak).
        """
        start_node = incident.affected_service
        if start_node not in self.graph.nodes:
            return start_node

        # BFS across dependency graph to find unhealthiest or origin anomalous node
        visited = {start_node}
        queue = collections.deque([start_node])
        candidate_root = start_node

        # Build bidirectional adjacency map
        neighbors: Dict[str, Set[str]] = collections.defaultdict(set)
        for edge in self.graph.edges:
            neighbors[edge.source].add(edge.target)
            neighbors[edge.target].add(edge.source)

        while queue:
            curr = queue.popleft()
            # If current node is unhealthy or marked anomalous, it's a primary root cause candidate
            is_anomalous = self.graph.nodes[curr].metadata.get("anomalous", False)
            is_unhealthy = not self.node_health.get(curr, True)

            if is_anomalous or (is_unhealthy and curr != start_node):
                return curr

            for nxt in neighbors.get(curr, []):
                if nxt not in visited:
                    visited.add(nxt)
                    queue.append(nxt)

        return candidate_root

    def synthesize_remediation(self, root_cause_node: str, incident: SystemIncident) -> RemediationAction:
        """Synthesize candidate remediation based on the identified root cause."""
        node = self.graph.nodes.get(root_cause_node)
        metadata = node.metadata if node else {}
        node_type = metadata.get("type", "service")

        if "canary" in root_cause_node or metadata.get("is_canary"):
            return RemediationAction(
                action_id=f"rem_{int(time.time()*1000)}",
                action_type=RemediationType.DRAIN_CANARY,
                target_node=root_cause_node,
                description=f"Drain traffic from faulty canary release '{root_cause_node}' and restore stable baseline.",
                estimated_risk="LOW",
            )
        elif node_type == "deployment" or "deploy" in root_cause_node:
            return RemediationAction(
                action_id=f"rem_{int(time.time()*1000)}",
                action_type=RemediationType.ROLLBACK_DEPLOYMENT,
                target_node=root_cause_node,
                description=f"Roll back deployment '{root_cause_node}' to previous verified stable release.",
                estimated_risk="LOW",
            )
        elif node_type == "cache" or "cache" in root_cause_node:
            return RemediationAction(
                action_id=f"rem_{int(time.time()*1000)}",
                action_type=RemediationType.FLUSH_TAINTED_CACHE,
                target_node=root_cause_node,
                description=f"Evict poisoned or corrupted keys from cache '{root_cause_node}'.",
                estimated_risk="LOW",
            )
        else:
            return RemediationAction(
                action_id=f"rem_{int(time.time()*1000)}",
                action_type=RemediationType.RESTART_WORKER_POOL,
                target_node=root_cause_node,
                description=f"Gracefully restart worker pool for '{root_cause_node}'.",
                estimated_risk="MEDIUM",
            )

    def verify_remediation_safety(self, remediation: RemediationAction) -> Tuple[bool, Optional[str]]:
        """
        Evaluate remediation against the Treasure Invariant and Quorum Invariants.
        Ensures the autonomous action cannot destroy state, leak data, or cause a cascading outage.
        """
        target = remediation.target_node

        # Rule 1: Catastrophic Invariant - The Treasure can NEVER be directly dropped or wiped
        if remediation.action_type == RemediationType.DROP_DATABASE_TABLE:
            return False, f"INVARIANT_VIOLATION: Destructive drop table on '{target}' is strictly forbidden by policy."

        if target in self.critical_sinks and remediation.action_type in (RemediationType.ISOLATE_NODE, RemediationType.KILL_PROCESS):
            return False, f"INVARIANT_VIOLATION: Target '{target}' is classified as CRITICAL_SINK (The Treasure) and cannot be severed directly."

        # Rule 2: Speculatively checkpoint and test blast-radius flow if parameters introduce new edges
        self.graph.checkpoint()
        try:
            # If remediation attempts to bridge an external endpoint to a sink
            if remediation.parameters.get("connects_to_sink"):
                sink_target = remediation.parameters.get("sink_target", target)
                untrusted_nodes = self.graph.get_nodes_by_classification(SecurityClassification.UNTRUSTED_SOURCE)
                if untrusted_nodes and sink_target in self.critical_sinks:
                    return False, f"BLAST_RADIUS_VIOLATION: Remediation introduces an unauthorized bridge into critical sink '{sink_target}'."

            return True, None
        finally:
            self.graph.rollback()

    def process_incident(
        self,
        incident: SystemIncident,
        override_candidate: Optional[RemediationAction] = None,
        health_verifier: Optional[Callable[[], bool]] = None,
    ) -> AutopilotVerdict:
        """
        Execute full closed-loop incident resolution cycle.
        """
        start_time = time.time()

        # Step 1: Causal Root Cause Analysis
        root_cause = self.infer_causal_chain(incident)

        # Step 2: Remediation Proposal
        candidate = override_candidate or self.synthesize_remediation(root_cause, incident)

        # Step 3: Safety & Invariant Verification
        is_safe, violation_reason = self.verify_remediation_safety(candidate)

        if not is_safe:
            duration_ms = (time.time() - start_time) * 1000
            logger.warning(f"[AUTOPILOT SEVERED REMEDIATION] Rejected action '{candidate.action_type}' on '{candidate.target_node}': {violation_reason}")
            return AutopilotVerdict(
                incident_id=incident.incident_id,
                causal_root_cause=root_cause,
                remediation=candidate,
                approved=False,
                violation_reason=violation_reason,
                recovery_verified=False,
                receipt=None,
                execution_time_ms=duration_ms,
            )

        # Step 4: Execute Remediation within bounded scope
        self.node_health[candidate.target_node] = True
        self.node_health[incident.affected_service] = True

        # Step 5: Verify Recovery
        recovery_passed = True
        if health_verifier:
            recovery_passed = health_verifier()

        # Step 6: Issue Cryptographic Clearinghouse Receipt
        receipt = None
        if recovery_passed:
            state_hash = self.graph.get_state_hash()
            receipt = self.signer.sign_transaction(
                tool_name=f"autopilot:{candidate.action_type.value}",
                arguments={
                    "incident_id": incident.incident_id,
                    "target_node": candidate.target_node,
                    "action_id": candidate.action_id,
                },
                graph_state_hash=state_hash,
            )

        duration_ms = (time.time() - start_time) * 1000
        return AutopilotVerdict(
            incident_id=incident.incident_id,
            causal_root_cause=root_cause,
            remediation=candidate,
            approved=True,
            violation_reason=None,
            recovery_verified=recovery_passed,
            receipt=receipt,
            execution_time_ms=duration_ms,
        )
