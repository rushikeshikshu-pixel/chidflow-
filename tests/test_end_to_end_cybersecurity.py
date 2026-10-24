import pytest
from chidflow.cybersec import EndToEndSecurityMesh, ThreatLevel
from chidflow.graph import DynamicFlowGraph
from chidflow.models import SecurityClassification
from chidflow.proof import ClearinghouseSigner
from chidflow.runtime_sensor import EBPFRuntimeSensor


@pytest.fixture
def mesh_cluster():
    graph = DynamicFlowGraph()
    # Nodes
    graph.add_node("external_attacker", SecurityClassification.UNTRUSTED_SOURCE)
    graph.add_node("compromised_analytics_pod", SecurityClassification.AGENT_CONTEXT)
    graph.add_node("internal_queue", SecurityClassification.AGENT_CONTEXT)
    graph.add_node("postgres_treasure", SecurityClassification.CRITICAL_SINK)

    # Initial benign edges
    graph.add_edge("internal_queue", "postgres_treasure")

    signer = ClearinghouseSigner(signing_secret="cybersec_mesh_secret_998877")
    sensor = EBPFRuntimeSensor(signer=signer)
    sensor.register_protected_resource("postgres_treasure:5432")

    mesh = EndToEndSecurityMesh(
        graph=graph,
        sensor=sensor,
        signer=signer,
        max_mutation_rate_per_sec=10,
    )
    return graph, signer, sensor, mesh


class TestEndToEndCybersecurity:
    def test_lateral_movement_unauthorized_socket_blocked(self, mesh_cluster):
        graph, signer, sensor, mesh = mesh_cluster

        # Compromised pod attempts direct lateral connection to Postgres without ticket
        verdict = mesh.evaluate_lateral_hop(
            source_node="compromised_analytics_pod",
            target_node="postgres_treasure",
            socket_port=5432,
            receipt_token=None,
        )

        assert verdict.severed
        assert "compromised_analytics_pod" in verdict.quarantined_nodes
        assert "MISSING_CLEARINGHOUSE_RECEIPT" in verdict.violation_code
        assert verdict.receipt is None

    def test_transitive_reachability_lateral_hop_blocked(self, mesh_cluster):
        graph, signer, sensor, mesh = mesh_cluster

        # Connect external attacker to compromised pod
        graph.add_edge("external_attacker", "compromised_analytics_pod")

        # Now compromised pod attempts lateral hop to internal_queue
        # That hop would complete a path: external_attacker -> pod -> internal_queue -> postgres_treasure
        verdict = mesh.evaluate_lateral_hop(
            source_node="compromised_analytics_pod",
            target_node="internal_queue",
        )

        assert verdict.severed
        assert verdict.violation_code == "TRANSITIVE_REACHABILITY_VIOLATION"
        assert "compromised_analytics_pod" in mesh.quarantined_nodes

    def test_legitimate_internal_hop_permitted_with_receipt(self, mesh_cluster):
        graph, signer, sensor, mesh = mesh_cluster

        # Add isolated internal service
        graph.add_node("auth_service", SecurityClassification.AGENT_CONTEXT)
        graph.add_node("session_cache", SecurityClassification.CONFIDENTIAL_ASSET)

        verdict = mesh.evaluate_lateral_hop(
            source_node="auth_service",
            target_node="session_cache",
        )

        assert not verdict.severed
        assert verdict.violation_code == "ALLOWED"
        assert verdict.receipt is not None
        assert signer.verify_receipt(verdict.receipt)

    def test_ransomware_mass_mutation_halt(self, mesh_cluster):
        graph, signer, sensor, mesh = mesh_cluster

        # Normal mutation velocity (5 writes/sec <= 10)
        allowed, _ = mesh.evaluate_mutation_rate("postgres_treasure", count=5)
        assert allowed

        # Burst of rapid mutations simulating ransomware encryption (15 writes/sec > 10)
        blocked, reason = mesh.evaluate_mutation_rate("postgres_treasure", count=15)
        assert not blocked
        assert "RANSOMWARE_INVARIANT_TRIPPED" in reason

    def test_forensic_dossier_generation(self, mesh_cluster):
        graph, signer, sensor, mesh = mesh_cluster

        dossier = mesh.generate_forensic_dossier("evt_1001")
        assert dossier["dossier_id"] == "DOSS-evt_1001"
        assert dossier["treasure_status"] == "SECURE_AND_INTACT"
        assert dossier["regulatory_compliance"]["soc2_cc6_1"] == "PASS"
        assert dossier["regulatory_compliance"]["iso_42001_reachability"] == "PASS"
