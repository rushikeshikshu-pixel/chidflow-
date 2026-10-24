from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from chidflow.models import AuditReceipt
from chidflow.proof import ClearinghouseSigner


class ClearinghouseExplorer:
    """
    Clearinghouse Audit Ledger Explorer.
    
    Provides auditors, financial institutions, and compliance officers
    with tools to inspect and mathematically verify transaction clearance proofs.
    """

    def __init__(self, signer: ClearinghouseSigner):
        self.signer = signer
        self.ledger: List[AuditReceipt] = []

    def record_receipt(self, receipt: AuditReceipt) -> None:
        self.ledger.append(receipt)

    def verify_ledger_integrity(self) -> Dict[str, Any]:
        """Verify the signature and sequence continuity of all cleared actions."""
        verified_count = 0
        corrupted = []

        last_seq = 0
        for r in self.ledger:
            is_valid = self.signer.verify_receipt(r)
            seq_valid = r.sequence_no > last_seq
            last_seq = r.sequence_no

            if is_valid and seq_valid:
                verified_count += 1
            else:
                corrupted.append(r.receipt_id)

        return {
            "total_transactions": len(self.ledger),
            "verified_valid": verified_count,
            "corrupted_or_tampered": corrupted,
            "ledger_status": "INTACT" if not corrupted else "COMPROMISED",
        }

    def render_ascii_ledger(self) -> str:
        lines = []
        lines.append("=" * 76)
        lines.append("       CHIDFLOW CRYPTOGRAPHIC CLEARINGHOUSE LEDGER EXPLORER")
        lines.append("=" * 76)
        lines.append(f"{'SEQ':<5} | {'RECEIPT ID':<16} | {'TOOL NAME':<20} | {'SIG (HMAC-SHA256)':<24} | {'STATUS'}")
        lines.append("-" * 76)

        for r in self.ledger:
            is_valid = self.signer.verify_receipt(r)
            status = "\033[92mVALID\033[0m" if is_valid else "\033[91mINVALID\033[0m"
            sig_short = r.signature[:20] + "..."
            lines.append(f"{r.sequence_no:<5} | {r.receipt_id:<16} | {r.tool_name:<20} | {sig_short:<24} | {status}")

        lines.append("=" * 76)
        return "\n".join(lines)
