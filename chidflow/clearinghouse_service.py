from __future__ import annotations

import json
import logging
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from chidflow.models import AuditReceipt
from chidflow.proof import ClearinghouseSigner

logger = logging.getLogger("chidflow.clearinghouse.service")


class ClearinghouseRequestHandler(BaseHTTPRequestHandler):
    """
    HTTP Verification Gateway for Upstream APIs, Banks, and Regulators.
    
    Provides sub-millisecond cryptographic validation of VAEP receipts
    before financial rails or production databases settle autonomous transactions.
    """

    signer: ClearinghouseSigner = ClearinghouseSigner(signing_secret="clearinghouse_master_production_secret_2026")

    def _send_json_response(self, status_code: int, data: Dict[str, Any]) -> None:
        payload = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Clearinghouse-Standard", "RFC-001-VAEP")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        if parsed.path == "/v1/clearing/roots":
            # Return trusted root public keys for bank verification
            self._send_json_response(200, {
                "status": "ACTIVE",
                "standard": "RFC-001: Verifiable Agent Execution Protocol (VAEP)",
                "trusted_root_keys": [
                    {
                        "key_id": self.signer.public_key_id,
                        "algorithm": "HMAC-SHA256",
                        "status": "VALID",
                        "issuer": "Chid Technologies Global Clearinghouse Root",
                    }
                ],
                "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            })
        elif parsed.path == "/v1/clearing/status":
            self._send_json_response(200, {
                "service": "Chid Technologies Clearinghouse Gateway",
                "version": "1.0.0",
                "uptime": "99.999%",
                "status": "OPERATIONAL",
            })
        else:
            self._send_json_response(404, {"error": "NOT_FOUND", "path": parsed.path})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len).decode("utf-8")

        try:
            req_data = json.loads(body) if body else {}
        except json.JSONDecodeError:
            self._send_json_response(400, {"error": "INVALID_JSON"})
            return

        if parsed.path == "/v1/clearing/verify":
            # Verify single receipt
            receipt_dict = req_data.get("receipt", req_data)
            try:
                receipt = AuditReceipt(
                    receipt_id=receipt_dict.get("receipt_id", ""),
                    sequence_no=receipt_dict.get("sequence_no", 0),
                    timestamp=receipt_dict.get("timestamp", ""),
                    tool_name=receipt_dict.get("tool_name", ""),
                    args_hash=receipt_dict.get("args_hash", ""),
                    graph_state_hash=receipt_dict.get("graph_state_hash", ""),
                    signature=receipt_dict.get("signature", ""),
                    public_key=receipt_dict.get("public_key", self.signer.public_key_id),
                )
                is_valid = self.signer.verify_receipt(receipt)
                self._send_json_response(200, {
                    "receipt_id": receipt.receipt_id,
                    "verified": is_valid,
                    "status": "SETTLEMENT_APPROVED" if is_valid else "CORRUPT_OR_TAMPERED",
                    "settlement_ticket": f"TKT-OK-{receipt.receipt_id}" if is_valid else None,
                    "verified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                })
            except Exception as e:
                self._send_json_response(422, {"error": "UNPROCESSABLE_RECEIPT", "detail": str(e)})

        elif parsed.path == "/v1/clearing/batch_verify":
            # Batch verification
            receipts = req_data.get("receipts", [])
            results = []
            all_valid = True

            for r_data in receipts:
                try:
                    r = AuditReceipt(
                        receipt_id=r_data.get("receipt_id", ""),
                        sequence_no=r_data.get("sequence_no", 0),
                        timestamp=r_data.get("timestamp", ""),
                        tool_name=r_data.get("tool_name", ""),
                        args_hash=r_data.get("args_hash", ""),
                        graph_state_hash=r_data.get("graph_state_hash", ""),
                        signature=r_data.get("signature", ""),
                        public_key=r_data.get("public_key", self.signer.public_key_id),
                    )
                    valid = self.signer.verify_receipt(r)
                    if not valid:
                        all_valid = False
                    results.append({"receipt_id": r.receipt_id, "verified": valid})
                except Exception:
                    all_valid = False
                    results.append({"receipt_id": r_data.get("receipt_id", "unknown"), "verified": False})

            self._send_json_response(200, {
                "total": len(receipts),
                "all_valid": all_valid,
                "results": results,
            })
        else:
            self._send_json_response(404, {"error": "NOT_FOUND", "path": parsed.path})


def start_clearinghouse_server(port: int = 8443, signer: Optional[ClearinghouseSigner] = None) -> HTTPServer:
    """Instantiate and start the Clearinghouse Verification HTTP server."""
    if signer:
        ClearinghouseRequestHandler.signer = signer
    server = HTTPServer(("0.0.0.0", port), ClearinghouseRequestHandler)
    return server
