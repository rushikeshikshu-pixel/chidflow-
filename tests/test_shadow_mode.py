import pytest
from chidflow.graph import DynamicFlowGraph
from chidflow.models import SecurityClassification
from chidflow.shadow_mode import ShadowModeRunner


class TestShadowModeRunner:
    def test_shadow_runner_records_benign_and_violations(self):
        graph = DynamicFlowGraph()
        graph.add_node("public_web", SecurityClassification.UNTRUSTED_SOURCE)
        graph.add_node("agent_ctx", SecurityClassification.AGENT_CONTEXT)
        graph.add_node("crm_pii", SecurityClassification.CONFIDENTIAL_ASSET)
        graph.add_node("wire_rail", SecurityClassification.CRITICAL_SINK)

        runner = ShadowModeRunner(graph=graph)

        # 1. Benign tool call
        evt1 = runner.record_tool_call(
            tool_name="read_crm",
            arguments={"id": "cust_1"},
            reads_from=["crm_pii"],
            caller_node="agent_ctx",
        )
        assert evt1.verdict_allowed is True
        assert evt1.simulated_receipt_id is not None
        assert evt1.latency_ms < 5.0

        # 2. Ingest untrusted taint
        graph.add_edge("public_web", "agent_ctx")

        # 3. Transitive violation attempted in shadow mode
        evt2 = runner.record_tool_call(
            tool_name="initiate_wire",
            arguments={"amount": 10000},
            writes_to=["wire_rail"],
            caller_node="agent_ctx",
        )
        # Should record violation without throwing exception
        assert evt2.verdict_allowed is False
        assert len(evt2.choke_points) > 0
        assert "reachability bridge" in evt2.violation_reason

        # 4. Generate report
        report = runner.generate_report()
        assert report.total_events == 2
        assert report.benign_passed == 1
        assert report.violations_caught == 1
        assert report.avg_latency_ms < 5.0

        md = report.to_markdown()
        assert "Enterprise Shadow-Mode Audit Report" in md
        assert "initiate_wire" in md
        assert "ZERO FALSE POSITIVES" in md
