import json
import unittest
from chidflow.benchmark import BenchmarkRunner
from chidflow.config import PolicyConfigLoader
from chidflow.integrations.langgraph import ChidFlowToolNode
from chidflow.models import SecurityClassification
from chidflow.policy import PolicyEngine


class TestBenchmarkAndIntegrations(unittest.TestCase):
    def test_benchmark_runs_and_identifies_vulnerability(self):
        res = BenchmarkRunner.run_transitive_attack_benchmark(iterations=10)
        self.assertFalse(res["static_openshell"]["attack_mitigated"])
        self.assertTrue(res["chidflow_proxy"]["attack_mitigated"])
        self.assertLess(res["chidflow_proxy"]["latency_per_session_ms"], 25.0)

    def test_config_loader(self):
        sample_config = {
            "nodes": [
                {"id": "src", "classification": "UNTRUSTED_SOURCE", "description": "Web"},
                {"id": "agent", "classification": "AGENT_CONTEXT", "description": "Agent"},
                {"id": "sink", "classification": "CRITICAL_SINK", "description": "Bank"},
            ],
            "tools": [
                {"name": "fetch_web", "reads_from": ["src"]},
                {"name": "send_cash", "writes_to": ["sink"]},
            ],
            "credentials": {
                "TEST_KEY": "val_123"
            }
        }
        policy, vault = PolicyConfigLoader.load_from_dict(sample_config)
        self.assertIn("src", policy.graph.nodes)
        self.assertIn("sink", policy.graph.nodes)
        self.assertIn("agent_memory", policy.graph.nodes)
        self.assertEqual(vault.inject_credentials("$CREDENTIAL{TEST_KEY}"), "val_123")

    def test_langgraph_middleware_blocks_attack(self):
        def web_search(query: str):
            return "scraped text"

        def transfer_funds(amount: int):
            return "transferred"

        policy = PolicyEngine()
        policy.graph.add_node("public_web", SecurityClassification.UNTRUSTED_SOURCE)
        policy.graph.add_node("bank_api", SecurityClassification.CRITICAL_SINK)

        policy.register_tool("web_search", reads_from=["public_web"])
        policy.register_tool("transfer_funds", writes_to=["bank_api"])

        node = ChidFlowToolNode(tools=[web_search, transfer_funds], policy_engine=policy)

        # Step 1: Agent calls web_search
        state1 = {
            "messages": [{
                "tool_calls": [{"id": "c1", "name": "web_search", "args": {"query": "test"}}]
            }]
        }
        res1 = node.invoke(state1)
        self.assertEqual(res1["messages"][0]["content"], "scraped text")

        # Step 2: Agent attempts transfer_funds -> Should be blocked by ChidFlowToolNode
        state2 = {
            "messages": [{
                "tool_calls": [{"id": "c2", "name": "transfer_funds", "args": {"amount": 1000}}]
            }]
        }
        res2 = node.invoke(state2)
        self.assertTrue(res2["messages"][0].get("error"))
        self.assertIn("[CHIDFLOW BLOCKED]", res2["messages"][0]["content"])


if __name__ == "__main__":
    unittest.main()
