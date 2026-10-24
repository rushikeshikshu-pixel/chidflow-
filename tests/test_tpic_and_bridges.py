import unittest
from benchmarks.tpic_suite import TPICBenchmark
from chidflow.bridges.nvidia_openshell import OpenShellSupervisorBridge
from chidflow.explorer import ClearinghouseExplorer
from chidflow.graph import DynamicFlowGraph
from chidflow.models import SecurityClassification
from chidflow.policy import PolicyEngine
from chidflow.proof import ClearinghouseSigner
from chidflow.vault import CredentialVault


class TestTPICAndBridges(unittest.TestCase):
    def test_tpic_benchmark_results(self):
        results = TPICBenchmark.evaluate_all()
        # OpenShell static whitelist should score 0% on transitive multi-hop attacks
        self.assertIn("0%", results["openshell_score"])
        # ChidFlow dynamic min-cut should score 100%
        self.assertIn("100%", results["chidflow_score"])
        self.assertEqual(results["total_scenarios"], 5)

    def test_nvidia_openshell_supervisor_bridge(self):
        graph = DynamicFlowGraph()
        graph.add_node("public_web", SecurityClassification.UNTRUSTED_SOURCE)
        graph.add_node("sandbox_sbx101", SecurityClassification.AGENT_CONTEXT)
        graph.add_node("stripe_sink", SecurityClassification.CRITICAL_SINK)

        policy = PolicyEngine(graph=graph)
        policy.register_tool("scrape_external", reads_from=["public_web"])
        policy.register_tool("stripe_charge", writes_to=["stripe_sink"])

        vault = CredentialVault({"STRIPE_KEY": "sk_live_secret"})
        bridge = OpenShellSupervisorBridge(policy_engine=policy, vault=vault)

        # 1. Benign tool call from OpenShell sandbox
        allowed, payload = bridge.intercept_openshell_request(
            sandbox_id="sbx101",
            http_method="POST",
            destination_url="https://api.internal/scrape_external",
            payload={"tool": "scrape_external", "arguments": {"url": "https://news.com"}},
        )
        self.assertTrue(allowed)
        self.assertIn("_chidflow_receipt", payload)

        # 2. Transitive attack step from same sandbox to critical sink
        allowed2, err = bridge.intercept_openshell_request(
            sandbox_id="sbx101",
            http_method="POST",
            destination_url="https://api.stripe.com/charge",
            payload={"tool": "stripe_charge", "arguments": {"amount": 1000, "key": "$CREDENTIAL{STRIPE_KEY}"}},
        )
        self.assertFalse(allowed2)
        self.assertEqual(err["error"], "CHIDFLOW_MIN_CUT_POLICY_VIOLATION")
        self.assertEqual(err["status_code"], 403)

    def test_clearinghouse_explorer(self):
        signer = ClearinghouseSigner("secret_ledger_key")
        explorer = ClearinghouseExplorer(signer)

        receipt = signer.sign_transaction("tool_a", {"foo": "bar"}, "graph_hash_123")
        explorer.record_receipt(receipt)

        audit = explorer.verify_ledger_integrity()
        self.assertEqual(audit["ledger_status"], "INTACT")
        self.assertEqual(audit["verified_valid"], 1)

        ascii_table = explorer.render_ascii_ledger()
        self.assertIn("CHIDFLOW CRYPTOGRAPHIC CLEARINGHOUSE LEDGER", ascii_table)


if __name__ == "__main__":
    unittest.main()
