import json
import threading
import time
import urllib.request
import pytest

from chidflow.clearinghouse_service import start_clearinghouse_server
from chidflow.proof import ClearinghouseSigner


@pytest.fixture(scope="module")
def server_port():
    signer = ClearinghouseSigner(signing_secret="test_clearinghouse_svc_secret")
    server = start_clearinghouse_server(port=9876, signer=signer)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.1)  # allow server to bind
    yield 9876, signer
    server.shutdown()
    server.server_close()


class TestClearinghouseService:
    def test_get_roots_and_status(self, server_port):
        port, signer = server_port
        base_url = f"http://127.0.0.1:{port}"

        # 1. Test status
        with urllib.request.urlopen(f"{base_url}/v1/clearing/status") as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode())
            assert data["status"] == "OPERATIONAL"

        # 2. Test roots
        with urllib.request.urlopen(f"{base_url}/v1/clearing/roots") as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode())
            assert "RFC-001" in data["standard"]
            assert len(data["trusted_root_keys"]) == 1

    def test_post_verify_single_receipt(self, server_port):
        port, signer = server_port
        base_url = f"http://127.0.0.1:{port}"

        # Create authentic receipt
        legit_receipt = signer.sign_transaction(
            tool_name="stripe:charge",
            arguments={"amount": 5000},
            graph_state_hash="sample_hash_state_001",
        )

        req_body = json.dumps({"receipt": legit_receipt.to_dict()}).encode("utf-8")
        req = urllib.request.Request(
            f"{base_url}/v1/clearing/verify",
            data=req_body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode())
            assert data["verified"] is True
            assert data["status"] == "SETTLEMENT_APPROVED"
            assert data["settlement_ticket"].startswith("TKT-OK-")

    def test_post_verify_tampered_receipt_rejected(self, server_port):
        port, signer = server_port
        base_url = f"http://127.0.0.1:{port}"

        # Corrupted receipt
        tampered = {
            "receipt_id": "rcpt_tampered_99",
            "sequence_no": 99,
            "timestamp": "2026-10-25T10:00:00Z",
            "tool_name": "stripe:charge",
            "args_hash": "bad_hash",
            "graph_state_hash": "bad_state",
            "signature": "corrupted_signature_000000000000",
            "public_key": signer.public_key_id,
        }

        req_body = json.dumps({"receipt": tampered}).encode("utf-8")
        req = urllib.request.Request(
            f"{base_url}/v1/clearing/verify",
            data=req_body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        with urllib.request.urlopen(req) as resp:
            assert resp.status == 200
            data = json.loads(resp.read().decode())
            assert data["verified"] is False
            assert data["status"] == "CORRUPT_OR_TAMPERED"
            assert data["settlement_ticket"] is None
