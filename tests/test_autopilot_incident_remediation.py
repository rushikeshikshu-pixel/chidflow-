import pytest
from chidflow.autopilot import (
    IncidentSeverity,
    RemediationAction,
    RemediationType,
    ServerWatchAutopilot,
    SystemIncident,
)
from chidflow.graph import DynamicFlowGraph
from chidflow.models import SecurityClassification
from chidflow.proof import ClearinghouseSigner
from chidflow.runtime_sensor import EBPFRuntimeSensor, SocketConnectionRequest


@pytest.fixture
def test_cluster():
    graph = DynamicFlowGraph()
    # Nodes
    graph.add_node("public_internet", SecurityClassification.UNTRUSTED_SOURCE)
    graph.add_node("gateway", SecurityClassification.AGENT_CONTEXT)
    graph.add_node("billing_api", SecurityClassification.AGENT_CONTEXT)
    canary = graph.add_node("canary_worker", SecurityClassification.AGENT_CONTEXT)
    canary.metadata["is_canary"] = True
    canary.metadata["anomalous"] = True
    graph.add_node("stable_worker", SecurityClassification.AGENT_CONTEXT)
    graph.add_node("core_database", SecurityClassification.CRITICAL_SINK)
    graph.add_node("payment_gateway", SecurityClassification.CRITICAL_SINK)

    # Edges
    graph.add_edge("public_internet", "gateway")
    graph.add_edge("gateway", "billing_api")
    graph.add_edge("billing_api", "canary_worker")
    graph.add_edge("billing_api", "stable_worker")
    graph.add_edge("stable_worker", "core_database")
    graph.add_edge("canary_worker", "core_database")
    graph.add_edge("billing_api", "payment_gateway")

    signer = ClearinghouseSigner(signing_secret="test_secret_key_1234567890")
    autopilot = ServerWatchAutopilot(graph=graph, signer=signer)
    sensor = EBPFRuntimeSensor(signer=signer)
    sensor.register_protected_resource("core_database:5432")

    return graph, signer, autopilot, sensor


class TestServerWatchAutopilot:
    def test_causal_root_cause_inference(self, test_cluster):
        graph, signer, autopilot, sensor = test_cluster

        # Mark canary worker as unhealthy
        autopilot.update_node_health("canary_worker", False)
        autopilot.update_node_health("billing_api", False)

        incident = SystemIncident(
            incident_id="INC-TEST-001",
            affected_service="billing_api",
            severity=IncidentSeverity.CRITICAL,
            symptoms=["500 Internal Server Error", "Database lock contention"],
        )

        root_cause = autopilot.infer_causal_chain(incident)
        assert root_cause == "canary_worker", f"Expected 'canary_worker' as root cause, got {root_cause}"

    def test_destructive_remediation_blocked_by_invariant(self, test_cluster):
        graph, signer, autopilot, sensor = test_cluster

        incident = SystemIncident(
            incident_id="INC-TEST-002",
            affected_service="billing_api",
            severity=IncidentSeverity.HIGH,
            symptoms=["Queue backlog"],
        )

        # Candidate attempting to drop core_database table to resolve lock
        destructive_action = RemediationAction(
            action_id="rem_drop_db",
            action_type=RemediationType.DROP_DATABASE_TABLE,
            target_node="core_database",
            description="Drop table to release lock",
        )

        verdict = autopilot.process_incident(incident, override_candidate=destructive_action)
        assert not verdict.approved
        assert "INVARIANT_VIOLATION" in (verdict.violation_reason or "")
        assert verdict.receipt is None

    def test_direct_critical_sink_sever_blocked(self, test_cluster):
        graph, signer, autopilot, sensor = test_cluster

        incident = SystemIncident(
            incident_id="INC-TEST-003",
            affected_service="core_database",
            severity=IncidentSeverity.CRITICAL,
            symptoms=["Connection spike"],
        )

        # Trying to isolate or kill the treasure itself
        kill_action = RemediationAction(
            action_id="rem_kill_db",
            action_type=RemediationType.ISOLATE_NODE,
            target_node="core_database",
            description="Isolate DB",
        )

        verdict = autopilot.process_incident(incident, override_candidate=kill_action)
        assert not verdict.approved
        assert "CRITICAL_SINK (The Treasure)" in (verdict.violation_reason or "")

    def test_safe_remediation_executed_and_verified(self, test_cluster):
        graph, signer, autopilot, sensor = test_cluster

        autopilot.update_node_health("canary_worker", False)
        incident = SystemIncident(
            incident_id="INC-TEST-004",
            affected_service="billing_api",
            severity=IncidentSeverity.HIGH,
            symptoms=["Elevated p99 latency"],
        )

        verdict = autopilot.process_incident(incident)

        assert verdict.approved
        assert verdict.recovery_verified
        assert verdict.remediation is not None
        assert verdict.remediation.action_type == RemediationType.DRAIN_CANARY
        assert verdict.receipt is not None
        assert signer.verify_receipt(verdict.receipt)

    def test_ebpf_socket_guard_enforcement(self, test_cluster):
        graph, signer, autopilot, sensor = test_cluster

        # 1. Unauthenticated socket connection attempt -> Dropped
        rogue_req = SocketConnectionRequest(
            connection_id="conn_unauth_01",
            source_process="malicious_payload",
            source_ip="10.0.0.99",
            destination_resource="core_database:5432",
            port=5432,
            payload_hash="somehash",
            receipt_token=None,
        )
        verdict = sensor.evaluate_socket_connection(rogue_req)
        assert not verdict.allowed
        assert verdict.status_code == 403
        assert verdict.dropped_at_kernel

        # 2. Tampered signature -> Rejected
        tampered_req = SocketConnectionRequest(
            connection_id="conn_tamper_02",
            source_process="compromised_worker",
            source_ip="10.0.0.100",
            destination_resource="core_database:5432",
            port=5432,
            payload_hash="somehash",
            receipt_token={
                "receipt_id": "fake_rcpt",
                "sequence_no": 999,
                "timestamp": "2026-10-25T00:00:00Z",
                "tool_name": "fake_tool",
                "args_hash": "fake_args",
                "graph_state_hash": "fake_state",
                "signature": "corrupted_signature_0000000000000000",
            },
        )
        tamper_verdict = sensor.evaluate_socket_connection(tampered_req)
        assert not tamper_verdict.allowed
        assert tamper_verdict.status_code == 401

        # 3. Legitimate connection with valid Clearinghouse Receipt -> Permitted
        legit_receipt = signer.sign_transaction(
            tool_name="autopilot:DRAIN_CANARY",
            arguments={"action": "remediate"},
            graph_state_hash=graph.get_state_hash(),
        )

        valid_req = SocketConnectionRequest(
            connection_id="conn_valid_03",
            source_process="billing_api",
            source_ip="10.0.0.12",
            destination_resource="core_database:5432",
            port=5432,
            payload_hash="legithash",
            receipt_token=legit_receipt.to_dict(),
        )
        legit_verdict = sensor.evaluate_socket_connection(valid_req)
        assert legit_verdict.allowed
        assert legit_verdict.status_code == 200
