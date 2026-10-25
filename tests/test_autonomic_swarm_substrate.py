import pytest
from chidflow.graph import DynamicFlowGraph
from chidflow.models import SecurityClassification
from chidflow.proof import ClearinghouseSigner
from chidflow.swarm_substrate import (
    AutonomicSwarmSubstrate,
    SwarmMessage,
    SwarmProposal,
    SwarmTaskStatus,
)


@pytest.fixture
def swarm_setup():
    graph = DynamicFlowGraph()
    # Nodes
    graph.add_node("external_web", SecurityClassification.UNTRUSTED_SOURCE)
    graph.add_node("agent_researcher", SecurityClassification.AGENT_CONTEXT)
    graph.add_node("agent_analyst", SecurityClassification.AGENT_CONTEXT)
    graph.add_node("agent_executor", SecurityClassification.AGENT_CONTEXT)
    graph.add_node("core_financial_db", SecurityClassification.CRITICAL_SINK)

    signer = ClearinghouseSigner(signing_secret="swarm_substrate_master_key_2026")
    substrate = AutonomicSwarmSubstrate(graph=graph, signer=signer)

    substrate.register_swarm_agent("agent_researcher", "Web Ingestion Specialist")
    substrate.register_swarm_agent("agent_analyst", "Data Structuring Specialist")
    substrate.register_swarm_agent("agent_executor", "Action Execution SRE")

    return graph, signer, substrate


class TestAutonomicSwarmSubstrate:
    def test_swarm_message_routing_and_delegation(self, swarm_setup):
        graph, signer, substrate = swarm_setup

        msg1 = SwarmMessage(
            message_id="msg_01",
            sender_agent="agent_researcher",
            receiver_agent="agent_analyst",
            payload={"summary": "Market data parsed"},
        )
        verdict1 = substrate.route_swarm_message(msg1)
        assert verdict1.allowed
        assert verdict1.status == SwarmTaskStatus.ROUTED

        msg2 = SwarmMessage(
            message_id="msg_02",
            sender_agent="agent_analyst",
            receiver_agent="agent_executor",
            payload={"trade_plan": "Execute trade"},
        )
        verdict2 = substrate.route_swarm_message(msg2)
        assert verdict2.allowed
        assert len(substrate.message_history) == 2

    def test_deadlock_circular_delegation_aborted(self, swarm_setup):
        graph, signer, substrate = swarm_setup

        # Circular self-delegation loop
        loop_msg = SwarmMessage(
            message_id="msg_loop",
            sender_agent="agent_analyst",
            receiver_agent="agent_analyst",
            payload={"loop": True},
        )
        verdict = substrate.route_swarm_message(loop_msg)
        assert not verdict.allowed
        assert verdict.status == SwarmTaskStatus.DEADLOCK_ABORTED
        assert "CIRCULAR_SELF_DELEGATION" in verdict.violation_reason

    def test_insufficient_quorum_rejected(self, swarm_setup):
        graph, signer, substrate = swarm_setup

        # Proposal with only 1 vote when 2 required
        proposal = SwarmProposal(
            proposal_id="prop_01",
            origin_agent="agent_executor",
            target_tool_or_sink="core_financial_db",
            action_args={"action": "update_balance"},
            participating_agents=["agent_executor"],
            consensus_votes=1,
            required_quorum=2,
        )

        verdict = substrate.evaluate_swarm_proposal(proposal)
        assert not verdict.allowed
        assert "INSUFFICIENT_SWARM_QUORUM" in verdict.violation_reason

    def test_swarm_transitive_taint_severed_by_invariant(self, swarm_setup):
        graph, signer, substrate = swarm_setup

        # 1. External prompt injection infects agent_researcher
        graph.add_edge("external_web", "agent_researcher", taint_label="prompt_injection")

        # 2. Researcher routes to Analyst
        substrate.route_swarm_message(SwarmMessage("m1", "agent_researcher", "agent_analyst", {}))

        # 3. Analyst routes to Executor
        substrate.route_swarm_message(SwarmMessage("m2", "agent_analyst", "agent_executor", {}))

        # 4. Swarm gathers quorum and tries to mutate core_financial_db
        proposal = SwarmProposal(
            proposal_id="prop_tainted_02",
            origin_agent="agent_executor",
            target_tool_or_sink="core_financial_db",
            action_args={"transfer": 1000000},
            participating_agents=["agent_researcher", "agent_analyst", "agent_executor"],
            consensus_votes=3,
            required_quorum=2,
        )

        verdict = substrate.evaluate_swarm_proposal(proposal)
        assert not verdict.allowed
        assert verdict.status == SwarmTaskStatus.SEVERED_BY_INVARIANT
        assert "MIN_CUT_INVARIANT_VIOLATION" in verdict.violation_reason
        assert verdict.receipt is None

    def test_clean_swarm_proposal_committed_and_receipt_issued(self, swarm_setup):
        graph, signer, substrate = swarm_setup

        # Safe internal swarm coordination without untrusted ingress
        substrate.route_swarm_message(SwarmMessage("m_clean_1", "agent_analyst", "agent_executor", {}))

        proposal = SwarmProposal(
            proposal_id="prop_clean_03",
            origin_agent="agent_executor",
            target_tool_or_sink="core_financial_db",
            action_args={"settlement_id": "ST-9912"},
            participating_agents=["agent_analyst", "agent_executor"],
            consensus_votes=2,
            required_quorum=2,
        )

        verdict = substrate.evaluate_swarm_proposal(proposal)
        assert verdict.allowed
        assert verdict.status == SwarmTaskStatus.COMMITTED_AND_CLEARED
        assert verdict.receipt is not None
        assert verdict.receipt.min_cut_flow == 0.0
        assert "Quorum Approved" in verdict.receipt.consensus_score
