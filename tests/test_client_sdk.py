import pytest
from chidflow.client import ChidFlowClient
from chidflow.graph import DynamicFlowGraph
from chidflow.models import SecurityClassification
from chidflow.policy import PolicyEngine
from chidflow.proof import ClearinghouseSigner


class TestChidFlowClient:
    def test_client_guard_action_benign_allowed(self):
        graph = DynamicFlowGraph()
        graph.add_node("agent_ctx", SecurityClassification.AGENT_CONTEXT)
        graph.add_node("db_sink", SecurityClassification.CRITICAL_SINK)

        signer = ClearinghouseSigner(signing_secret="client_test_secret_123")
        policy = PolicyEngine(graph=graph, signer=signer)
        client = ChidFlowClient(policy_engine=policy)

        verdict = client.guard_action(
            tool_name="update_user_profile",
            arguments={"user_id": 42},
            writes_to=["agent_ctx"],
        )
        assert verdict.allowed is True
        assert verdict.receipt is not None
        assert signer.verify_receipt(verdict.receipt) is True

    def test_client_guard_action_transitive_injection_blocked(self):
        graph = DynamicFlowGraph()
        graph.add_node("untrusted_web", SecurityClassification.UNTRUSTED_SOURCE)
        graph.add_node("agent_ctx", SecurityClassification.AGENT_CONTEXT)
        graph.add_node("vault_sink", SecurityClassification.CRITICAL_SINK)

        # External untrusted taint enters agent
        graph.add_edge("untrusted_web", "agent_ctx")

        signer = ClearinghouseSigner(signing_secret="client_test_secret_123")
        policy = PolicyEngine(graph=graph, signer=signer)
        client = ChidFlowClient(policy_engine=policy)

        # Agent tries to execute tool writing to critical sink
        verdict = client.guard_action(
            tool_name="export_vault_secrets",
            arguments={"path": "/vault"},
            reads_from=["agent_ctx"],
            writes_to=["vault_sink"],
        )
        assert verdict.allowed is False
        assert "reachability bridge" in verdict.violation_reason
        assert len(verdict.choke_points) > 0

    def test_client_decorator_guard_enforcement(self):
        graph = DynamicFlowGraph()
        graph.add_node("untrusted_ingress", SecurityClassification.UNTRUSTED_SOURCE)
        graph.add_node("internal_agent", SecurityClassification.AGENT_CONTEXT)
        graph.add_node("wire_rail", SecurityClassification.CRITICAL_SINK)

        # Ingress taint
        graph.add_edge("untrusted_ingress", "internal_agent")

        policy = PolicyEngine(graph=graph)
        client = ChidFlowClient(policy_engine=policy)

        @client.guard(reads_from=["internal_agent"], writes_to=["wire_rail"])
        def transfer_funds(amount: int, to: str):
            return f"Transferred ${amount} to {to}"

        # Must raise PermissionError
        with pytest.raises(PermissionError) as exc_info:
            transfer_funds(amount=1000, to="attacker")

        assert "ChidFlow Invariant Violation" in str(exc_info.value)
