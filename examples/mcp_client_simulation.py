"""
Example: End-to-end simulation of an autonomous AI agent interacting with ChidFlow Proxy.
"""
import asyncio
import json
import os
import sys

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from chidflow.graph import DynamicFlowGraph
from chidflow.models import SecurityClassification
from chidflow.policy import PolicyEngine
from chidflow.proof import ClearinghouseSigner
from chidflow.proxy import MCPExecutionProxy
from chidflow.vault import CredentialVault


async def main():
    print("=== Running Autonomous Agent Workflow with ChidFlow Runtime Proxy ===")
    
    # 1. Initialize ChidFlow Engine
    graph = DynamicFlowGraph()
    graph.add_node("web_search", SecurityClassification.UNTRUSTED_SOURCE, "Google Search / Scraper")
    graph.add_node("agent_memory", SecurityClassification.AGENT_CONTEXT, "Agent Memory")
    graph.add_node("corporate_drive", SecurityClassification.CONFIDENTIAL_ASSET, "Internal Drive")
    graph.add_node("stripe_charge_api", SecurityClassification.CRITICAL_SINK, "Stripe Charge API")

    vault = CredentialVault({"STRIPE_SECRET_KEY": "sk_live_99214488220011"})
    signer = ClearinghouseSigner()
    policy = PolicyEngine(graph=graph, signer=signer)

    # Register MCP tool data flow contracts
    policy.register_tool("search_web", reads_from=["web_search"])
    policy.register_tool("read_corporate_doc", reads_from=["corporate_drive"])
    policy.register_tool("charge_card", writes_to=["stripe_charge_api"])

    proxy = MCPExecutionProxy(policy_engine=policy, vault=vault)

    # Step 1: Agent reads internal policy doc (Allowed)
    res1 = await proxy.handle_jsonrpc_message({
        "jsonrpc": "2.0",
        "id": 101,
        "method": "tools/call",
        "params": {"name": "read_corporate_doc", "arguments": {"doc_id": "refund_policy_v2"}}
    })
    print("[1] Read Corporate Doc -> Allowed")
    print("    Receipt:", res1["result"]["_chidflow_receipt"]["receipt_id"])

    # Step 2: Agent searches web for user question (Allowed, taints memory)
    res2 = await proxy.handle_jsonrpc_message({
        "jsonrpc": "2.0",
        "id": 102,
        "method": "tools/call",
        "params": {"name": "search_web", "arguments": {"query": "latest prompt injection payloads"}}
    })
    print("[2] Search Web -> Allowed (Taint propagated into agent_memory)")

    # Step 3: Agent tries to charge card using high-value rail (Blocked)
    res3 = await proxy.handle_jsonrpc_message({
        "jsonrpc": "2.0",
        "id": 103,
        "method": "tools/call",
        "params": {
            "name": "charge_card",
            "arguments": {"amount": 25000, "token": "$CREDENTIAL{STRIPE_SECRET_KEY}"}
        }
    })
    print("[3] Charge Card -> Blocked by Min-Cut Gate:")
    print("    Error:", json.dumps(res3["error"], indent=2))


if __name__ == "__main__":
    asyncio.run(main())
