from __future__ import annotations

import collections
import enum
import hashlib
import hmac
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from chidflow.graph import DynamicFlowGraph
from chidflow.models import AuditReceipt, SecurityClassification
from chidflow.proof import ClearinghouseSigner

logger = logging.getLogger("chidflow.edge.daemon")


class DeviceType(str, enum.Enum):
    LAPTOP_WORKSTATION = "LAPTOP_WORKSTATION"
    MOBILE_PHONE = "MOBILE_PHONE"
    EDGE_GATEWAY = "EDGE_GATEWAY"
    REMOTE_VM = "REMOTE_VM"


@dataclass
class EdgeTaskRequest:
    """An autonomous task executed remotely or in the background on an edge device."""
    task_id: str
    device_id: str
    device_type: DeviceType
    agent_id: str
    action_type: str  # e.g., "BACKGROUND_WEB_RESEARCH", "READ_CREDENTIALS", "DISPATCH_API_CALL"
    source_origin: str  # e.g., "https://untrusted-web.com", "local_filesystem"
    target_asset: str  # e.g., "local_keychain", "aws_credentials", "upstream_cloud_gateway"
    arguments: Dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)


@dataclass
class EdgeDevicePassport:
    """A cryptographic passport certifying that a remote edge execution satisfied local invariants."""
    passport_id: str
    device_id: str
    task_id: str
    timestamp: str
    device_signature: str
    state_digest: str
    cleared_for_cloud_settlement: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            "passport_id": self.passport_id,
            "device_id": self.device_id,
            "task_id": self.task_id,
            "timestamp": self.timestamp,
            "device_signature": self.device_signature,
            "state_digest": self.state_digest,
            "cleared_for_cloud_settlement": self.cleared_for_cloud_settlement,
        }


@dataclass
class EdgeVerdict:
    allowed: bool
    status_code: int
    reason: str
    passport: Optional[EdgeDevicePassport]
    severed_path: Optional[List[str]]
    execution_latency_ms: float


class EdgeDeviceDaemon:
    """
    Chid Technologies Edge Invariant & Device Daemon.
    
    Runs locally as a lightweight background daemon on MacBooks, mobile devices,
    and remote edge nodes. Enforces local "Protect the Treasure" invariants so agents
    can roam and execute thousands of background tasks without risking local credentials.
    """

    def __init__(
        self,
        device_id: str,
        device_type: DeviceType = DeviceType.LAPTOP_WORKSTATION,
        device_secret: Optional[str] = None,
    ):
        self.device_id = device_id
        self.device_type = device_type
        self.device_secret = (device_secret or f"dev_secret_{device_id}").encode("utf-8")
        self.graph = DynamicFlowGraph()
        
        # Local Device Treasures (The Crown Jewels on the Laptop/Phone)
        self.local_treasures: Set[str] = {
            "local_keychain",
            "ssh_private_keys",
            "aws_credentials",
            "banking_session_token",
            "biometric_auth_vault",
        }
        self._initialize_device_topology()

    def _initialize_device_topology(self) -> None:
        """Register default device nodes and security boundaries."""
        # Untrusted edge sources
        self.graph.add_node("public_web_ingress", SecurityClassification.UNTRUSTED_SOURCE, "Messy internet downloads / scraped HTML")
        self.graph.add_node("local_scratchpad", SecurityClassification.AGENT_CONTEXT, "Agent background working memory")
        
        # The Treasures on the device
        for treasure in self.local_treasures:
            self.graph.add_node(treasure, SecurityClassification.CRITICAL_SINK, f"Protected device asset: {treasure}")

        # Cloud Settlement Egress
        self.graph.add_node("upstream_cloud_gateway", SecurityClassification.CRITICAL_SINK, "Enterprise production cloud bridge")

    def evaluate_edge_task(self, request: EdgeTaskRequest) -> EdgeVerdict:
        """
        Evaluate an autonomous task running in the background on the local device.
        """
        start_time = time.time()

        # 1. Check if the task is attempting an unverified bridge to a local device treasure
        is_target_treasure = request.target_asset in self.local_treasures
        is_source_untrusted = "untrusted" in request.source_origin or request.source_origin == "public_web_ingress"

        self.graph.checkpoint()
        try:
            # Speculatively connect source to agent memory
            if request.source_origin not in self.graph.nodes:
                self.graph.add_node(
                    request.source_origin,
                    SecurityClassification.UNTRUSTED_SOURCE if is_source_untrusted else SecurityClassification.AGENT_CONTEXT,
                )

            self.graph.add_edge(request.source_origin, "local_scratchpad", taint_label=f"task:{request.action_type}")

            # Speculatively connect agent memory to target asset
            if request.target_asset in self.graph.nodes:
                self.graph.add_edge("local_scratchpad", request.target_asset, taint_label=f"target:{request.target_asset}")

            # Run Min-Cut reachability check from all untrusted sources to critical sinks
            untrusted_sources = self.graph.get_nodes_by_classification(SecurityClassification.UNTRUSTED_SOURCE)
            critical_sinks = self.graph.get_nodes_by_classification(SecurityClassification.CRITICAL_SINK)

            flow, choke_points = self.graph.compute_min_cut(untrusted_sources, critical_sinks)
            latency_ms = (time.time() - start_time) * 1000

            if flow > 0:
                # VIOLATION: An untrusted payload is trying to reach a device treasure or enterprise cloud!
                paths = []
                for s in untrusted_sources:
                    for t in critical_sinks:
                        p = self.graph.find_paths(s, t)
                        if p:
                            paths.extend(p)

                logger.warning(
                    f"[EDGE INVARIANT VIOLATION] Device {self.device_id} blocked task '{request.action_type}' "
                    f"targeting local treasure '{request.target_asset}'. Severed flow ({flow})."
                )

                return EdgeVerdict(
                    allowed=False,
                    status_code=403,
                    reason=f"EDGE_INVARIANT_VIOLATION: Autonomous task '{request.action_type}' formed a tainted bridge to '{request.target_asset}'.",
                    passport=None,
                    severed_path=paths[0] if paths else None,
                    execution_latency_ms=latency_ms,
                )

            # Legitimate Task: Issue Cryptographic Edge Device Passport
            timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            state_digest = self.graph.get_state_hash()
            passport_payload = f"{self.device_id}|{request.task_id}|{timestamp}|{state_digest}".encode("utf-8")
            signature = hmac.new(self.device_secret, passport_payload, hashlib.sha256).hexdigest()
            passport_id = f"pass_{hashlib.sha256(signature.encode()).hexdigest()[:12]}"

            passport = EdgeDevicePassport(
                passport_id=passport_id,
                device_id=self.device_id,
                task_id=request.task_id,
                timestamp=timestamp,
                device_signature=signature,
                state_digest=state_digest,
                cleared_for_cloud_settlement=True,
            )

            return EdgeVerdict(
                allowed=True,
                status_code=200,
                reason="EDGE_INVARIANT_VERIFIED: Action mathematically isolated from device treasures.",
                passport=passport,
                severed_path=None,
                execution_latency_ms=latency_ms,
            )

        finally:
            self.graph.rollback()

    def verify_edge_passport(self, passport: EdgeDevicePassport) -> bool:
        """Verify the authenticity of a passport received by upstream cloud systems."""
        payload = f"{passport.device_id}|{passport.task_id}|{passport.timestamp}|{passport.state_digest}".encode("utf-8")
        expected_sig = hmac.new(self.device_secret, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected_sig, passport.device_signature)
