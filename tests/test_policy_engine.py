import unittest
from chidflow.graph import DynamicFlowGraph
from chidflow.models import SecurityClassification, ToolCallRequest
from chidflow.policy import PolicyEngine
from chidflow.proof import ClearinghouseSigner
from chidflow.vault import CredentialVault


class TestPolicyEngine(unittest.TestCase):
    def setUp(self):
        self.graph = DynamicFlowGraph()
        self.signer = ClearinghouseSigner("test-secret-key")
        self.vault = CredentialVault({"API_KEY": "super_secret_value"})
        self.policy = PolicyEngine(self.graph, self.signer)

    def test_benign_call_cleared_with_receipt(self):
        self.graph.add_node("agent_memory", SecurityClassification.AGENT_CONTEXT)
        self.graph.add_node("internal_cache", SecurityClassification.CONFIDENTIAL_ASSET)

        self.policy.register_tool("read_cache", reads_from=["internal_cache"])

        req = ToolCallRequest(
            rpc_id=10,
            tool_name="read_cache",
            arguments={"key": "user_settings"},
        )
        verdict = self.policy.evaluate(req)

        self.assertTrue(verdict.allowed)
        self.assertIsNotNone(verdict.receipt)
        self.assertTrue(self.signer.verify_receipt(verdict.receipt))

    def test_credential_vault_injection_and_scrubbing(self):
        payload = {"auth": "Bearer $CREDENTIAL{API_KEY}", "id": 123}
        injected = self.vault.inject_credentials(payload)
        self.assertEqual(injected["auth"], "Bearer super_secret_value")

        scrubbed = self.vault.scrub_credentials(f"Log: sent to super_secret_value successfully")
        self.assertIn("[REDACTED_API_KEY]", scrubbed)


if __name__ == "__main__":
    unittest.main()
