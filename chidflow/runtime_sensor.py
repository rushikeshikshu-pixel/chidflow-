from __future__ import annotations

import hashlib
import hmac
import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from chidflow.models import AuditReceipt
from chidflow.proof import ClearinghouseSigner

logger = logging.getLogger("chidflow.serverwatch.sensor")


@dataclass
class SocketConnectionRequest:
    """Represents an inbound network socket or kernel IPC request targeting a critical sink."""
    connection_id: str
    source_process: str
    source_ip: str
    destination_resource: str  # e.g., "postgres_cluster:5432", "stripe_gateway", "kms_vault"
    port: int
    payload_hash: str
    receipt_token: Optional[Dict[str, Any]] = None
    timestamp: float = field(default_factory=time.time)


@dataclass
class SocketVerdict:
    allowed: bool
    status_code: int
    reason: str
    connection_id: str
    dropped_at_kernel: bool = False


class EBPFRuntimeSensor:
    """
    ServerWatch eBPF & Socket Invariant Gatekeeper.
    
    Acts as the lightweight, in-kernel or host-level runtime guard that enforces
    zero-trust access directly at the Treasure's network sockets and file descriptors:
    
    1. Intercepts connection attempts to protected resources.
    2. Validates cryptographic clearinghouse tickets issued by the policy engine.
    3. Drops unverified or tainted connections with zero host overhead (no BSODs).
    """

    def __init__(self, signer: ClearinghouseSigner):
        self.signer = signer
        # Protected resource registries (The "Treasure")
        self.protected_resources: Set[str] = {
            "postgres_cluster:5432",
            "production_db",
            "stripe_api_rail",
            "aws_kms_vault",
        }
        self.active_connections: Dict[str, SocketConnectionRequest] = {}
        self.blocked_attempts: List[Dict[str, Any]] = []

    def register_protected_resource(self, resource_name: str) -> None:
        """Register a critical sink resource to be protected at the socket layer."""
        self.protected_resources.add(resource_name)

    def evaluate_socket_connection(self, request: SocketConnectionRequest) -> SocketVerdict:
        """
        Evaluate an inbound socket connection attempt before completing the TCP handshake.
        """
        # If the destination is not a protected critical sink, allow immediately (100% velocity)
        if request.destination_resource not in self.protected_resources:
            return SocketVerdict(
                allowed=True,
                status_code=200,
                reason="DESTINATION_NOT_RESTRICTED",
                connection_id=request.connection_id,
            )

        # The destination IS the Treasure -> Require valid clearinghouse receipt
        token_data = request.receipt_token
        if not token_data:
            logger.warning(
                f"[eBPF KERNEL DROP] Process '{request.source_process}' attempted unauthenticated "
                f"socket connection to '{request.destination_resource}'. Dropping packet."
            )
            self.blocked_attempts.append({
                "connection_id": request.connection_id,
                "process": request.source_process,
                "destination": request.destination_resource,
                "reason": "MISSING_CLEARINGHOUSE_RECEIPT",
                "timestamp": request.timestamp,
            })
            return SocketVerdict(
                allowed=False,
                status_code=403,
                reason="MISSING_CLEARINGHOUSE_RECEIPT: Direct socket access to treasure without clearing ticket is blocked by eBPF sensor.",
                connection_id=request.connection_id,
                dropped_at_kernel=True,
            )

        # Synthesize receipt object for cryptographic validation
        try:
            receipt = AuditReceipt(
                receipt_id=token_data.get("receipt_id", ""),
                sequence_no=token_data.get("sequence_no", 0),
                timestamp=token_data.get("timestamp", ""),
                tool_name=token_data.get("tool_name", ""),
                args_hash=token_data.get("args_hash", ""),
                graph_state_hash=token_data.get("graph_state_hash", ""),
                signature=token_data.get("signature", ""),
                public_key=token_data.get("public_key", self.signer.public_key_id),
            )

            is_valid = self.signer.verify_receipt(receipt)
            if not is_valid:
                logger.warning(
                    f"[eBPF CRYPTO REJECT] Process '{request.source_process}' provided an invalid or "
                    f"tampered signature for '{request.destination_resource}'. Dropping connection."
                )
                self.blocked_attempts.append({
                    "connection_id": request.connection_id,
                    "process": request.source_process,
                    "destination": request.destination_resource,
                    "reason": "INVALID_SIGNATURE",
                    "timestamp": request.timestamp,
                })
                return SocketVerdict(
                    allowed=False,
                    status_code=401,
                    reason="TAMPERED_OR_CORRUPT_CLEARINGHOUSE_RECEIPT",
                    connection_id=request.connection_id,
                    dropped_at_kernel=True,
                )

            # Ticket is verified! Socket connection permitted.
            self.active_connections[request.connection_id] = request
            return SocketVerdict(
                allowed=True,
                status_code=200,
                reason="VERIFIED_CLEARINGHOUSE_RECEIPT",
                connection_id=request.connection_id,
                dropped_at_kernel=False,
            )

        except Exception as e:
            return SocketVerdict(
                allowed=False,
                status_code=500,
                reason=f"VALIDATION_ERROR: {str(e)}",
                connection_id=request.connection_id,
                dropped_at_kernel=True,
            )
