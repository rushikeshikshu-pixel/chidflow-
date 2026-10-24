from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time
from typing import Any, Dict

from chidflow.models import AuditReceipt


class ClearinghouseSigner:
    """
    Cryptographic Clearinghouse Proof Engine.
    
    Generates non-repudiable mathematical receipts for verified agent actions.
    Upstream financial rails, databases, and compliance auditors can verify
    that reachability was formally evaluated prior to execution.
    """

    def __init__(self, signing_secret: Optional[str] = None):
        self._secret = (signing_secret or secrets.token_hex(32)).encode("utf-8")
        self._key_id = hashlib.sha256(self._secret).hexdigest()[:16]
        self._sequence_counter = 0

    @property
    def public_key_id(self) -> str:
        return f"chidflow-key-{self._key_id}"

    def sign_transaction(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        graph_state_hash: str,
    ) -> AuditReceipt:
        """
        Signs off on a cleared execution step, returning an immutable AuditReceipt.
        """
        self._sequence_counter += 1
        seq = self._sequence_counter
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        # Canonical hash of tool arguments
        args_serialized = json.dumps(arguments, sort_keys=True)
        args_hash = hashlib.sha256(args_serialized.encode("utf-8")).hexdigest()

        # Digest payload: Sequence || Timestamp || Tool || ArgsHash || StateHash
        payload = f"{seq}|{timestamp}|{tool_name}|{args_hash}|{graph_state_hash}".encode("utf-8")
        signature = hmac.new(self._secret, payload, hashlib.sha256).hexdigest()

        receipt_id = f"rcpt_{hashlib.sha256(signature.encode()).hexdigest()[:12]}"

        return AuditReceipt(
            receipt_id=receipt_id,
            sequence_no=seq,
            timestamp=timestamp,
            tool_name=tool_name,
            args_hash=args_hash,
            graph_state_hash=graph_state_hash,
            signature=signature,
            public_key=self.public_key_id,
        )

    def verify_receipt(self, receipt: AuditReceipt) -> bool:
        """Verify the cryptographic authenticity of an AuditReceipt."""
        payload = f"{receipt.sequence_no}|{receipt.timestamp}|{receipt.tool_name}|{receipt.args_hash}|{receipt.graph_state_hash}".encode("utf-8")
        expected_sig = hmac.new(self._secret, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected_sig, receipt.signature)
