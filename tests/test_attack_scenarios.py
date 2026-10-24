import unittest
from chidflow.graph import DynamicFlowGraph
from chidflow.models import SecurityClassification, ToolCallRequest
from chidflow.policy import PolicyEngine
from chidflow.proof import ClearinghouseSigner


class TestAttackScenarios(unittest.TestCase):
    def setUp(self):
        self.graph = DynamicFlowGraph()
        self.signer = ClearinghouseSigner()
        self.policy = PolicyEngine(self.graph, self.signer)

    def test_multihop_transitive_exfiltration_blocked(self):
        """
        Scenario:
        1. Agent reads untrusted web article.
        2. Agent passes data to Subagent 1.
        3. Subagent 1 writes to Subagent 2.
        4. Subagent 2 tries to call drop_sql_database or send_external_webhook.
        ChidFlow must trace the transitive path and block the step.
        """
        self.graph.add_node("public_web", SecurityClassification.UNTRUSTED_SOURCE)
        self.graph.add_node("agent_main", SecurityClassification.AGENT_CONTEXT)
        self.graph.add_node("subagent_1", SecurityClassification.AGENT_CONTEXT)
        self.graph.add_node("subagent_2", SecurityClassification.AGENT_CONTEXT)
        self.graph.add_node("prod_database", SecurityClassification.CRITICAL_SINK)

        self.policy.register_tool("fetch_article", reads_from=["public_web"])
        self.policy.register_tool("delegate_to_sub1", reads_from=["agent_main"], writes_to=["subagent_1"])
        self.policy.register_tool("delegate_to_sub2", reads_from=["subagent_1"], writes_to=["subagent_2"])
        self.policy.register_tool("execute_sql", writes_to=["prod_database"])

        # Step 1: Agent reads untrusted web
        req1 = ToolCallRequest(1, "fetch_article", {"url": "https://attacker.org"}, caller_node="agent_main")
        v1 = self.policy.evaluate(req1)
        self.assertTrue(v1.allowed)

        # Step 2: Agent delegates to subagent 1
        req2 = ToolCallRequest(2, "delegate_to_sub1", {"task": "analyze"}, caller_node="agent_main")
        v2 = self.policy.evaluate(req2)
        self.assertTrue(v2.allowed)

        # Step 3: Subagent 1 delegates to subagent 2
        req3 = ToolCallRequest(3, "delegate_to_sub2", {"task": "execute"}, caller_node="subagent_1")
        v3 = self.policy.evaluate(req3)
        self.assertTrue(v3.allowed)

        # Step 4: Subagent 2 attempts to write to critical sink
        req4 = ToolCallRequest(4, "execute_sql", {"query": "DROP TABLE users;"}, caller_node="subagent_2")
        v4 = self.policy.evaluate(req4)

        # MUST BE BLOCKED
        self.assertFalse(v4.allowed)
        self.assertIn("creates an unauthorized reachability bridge", v4.violation_reason)
        self.assertEqual(v4.simulated_error["error"]["code"], -32001)

    def test_isolated_benign_subgraph_allowed(self):
        """
        Verify that unrelated clean agents are NOT blocked even if another agent is tainted.
        """
        self.graph.add_node("untrusted_source", SecurityClassification.UNTRUSTED_SOURCE)
        self.graph.add_node("tainted_agent", SecurityClassification.AGENT_CONTEXT)
        self.graph.add_node("clean_agent", SecurityClassification.AGENT_CONTEXT)
        self.graph.add_node("critical_sink", SecurityClassification.CRITICAL_SINK)

        # Taint the first agent
        self.graph.add_edge("untrusted_source", "tainted_agent")

        self.policy.register_tool("sink_action", writes_to=["critical_sink"])

        # Clean agent calls sink_action -> Should be ALLOWED
        req_clean = ToolCallRequest(10, "sink_action", {}, caller_node="clean_agent")
        v_clean = self.policy.evaluate(req_clean)
        self.assertTrue(v_clean.allowed)

        # Tainted agent calls sink_action -> Should be BLOCKED
        req_tainted = ToolCallRequest(11, "sink_action", {}, caller_node="tainted_agent")
        v_tainted = self.policy.evaluate(req_tainted)
        self.assertFalse(v_tainted.allowed)


if __name__ == "__main__":
    unittest.main()
