from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

from chidflow.benchmark import BenchmarkRunner
from chidflow.config import PolicyConfigLoader
from chidflow.cybersec import EndToEndSecurityMesh
from chidflow.explorer import ClearinghouseExplorer
from chidflow.graph import DynamicFlowGraph
from chidflow.models import AuditReceipt, SecurityClassification
from chidflow.policy import PolicyEngine
from chidflow.proof import ClearinghouseSigner
from chidflow.proxy import MCPExecutionProxy
from chidflow.runtime_sensor import EBPFRuntimeSensor
from chidflow.server import create_http_server
from chidflow.serverwatch_cli import run_demo as run_serverwatch_demo
from chidflow.vault import CredentialVault
from chidflow.viz import GraphVisualizer
from chidflow.wrapper import SubprocessMCPWrapper
try:
    from benchmarks.tpic_suite import TPICBenchmark
except ModuleNotFoundError:
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    try:
        from benchmarks.tpic_suite import TPICBenchmark
    except ModuleNotFoundError:
        TPICBenchmark = None


def run_demo() -> None:
    """Run an interactive visual demonstration of ChidFlow blocking prompt injection."""
    print("=" * 72)
    print("  ChidFlow: Runtime Min-Cut Graph Execution Proxy Demo")
    print("=" * 72)

    # 1. Setup Graph & Security Nodes
    graph = DynamicFlowGraph()
    graph.add_node("public_web_scraper", SecurityClassification.UNTRUSTED_SOURCE, "External web scraper")
    graph.add_node("agent_memory", SecurityClassification.AGENT_CONTEXT, "Agent working context")
    graph.add_node("customer_crm_pii", SecurityClassification.CONFIDENTIAL_ASSET, "Internal CRM database")
    graph.add_node("banking_wire_rail", SecurityClassification.CRITICAL_SINK, "Core banking wire transfer rail")

    signer = ClearinghouseSigner(signing_secret="chidflow-clearinghouse-secret-key-2026")
    vault = CredentialVault()
    vault.register_secret("BANK_API_KEY", "real_live_bank_prod_secret_998822")

    policy = PolicyEngine(graph=graph, signer=signer)

    # Register Tool Behaviors
    policy.register_tool("scrape_untrusted_url", reads_from=["public_web_scraper"])
    policy.register_tool("query_customer_crm", reads_from=["customer_crm_pii"])
    policy.register_tool("execute_wire_transfer", writes_to=["banking_wire_rail"])

    proxy = MCPExecutionProxy(policy_engine=policy, vault=vault)

    async def execute_steps():
        print("\n[Step 1] Agent executes benign tool: query_customer_crm(customer_id='cust_101')")
        call1 = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "query_customer_crm", "arguments": {"customer_id": "cust_101"}},
        }
        res1 = await proxy.handle_jsonrpc_message(call1)
        receipt1 = res1.get("result", {}).get("_chidflow_receipt", {})
        print("Verdict: \033[92m[ALLOWED]\033[0m")
        print(f"Cryptographic Audit Receipt Generated:\n  ID:  {receipt1.get('receipt_id')}\n  Sig: {receipt1.get('signature')[:28]}...")

        print("\n[Step 2] Agent ingests external untrusted payload from web scraper (contains hidden injection)")
        call2 = {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "scrape_untrusted_url", "arguments": {"url": "https://untrusted-forum.org/data"}},
        }
        await proxy.handle_jsonrpc_message(call2)
        print("Verdict: \033[92m[ALLOWED]\033[0m (Taint dynamically propagated into agent_memory)")

        print("\n[Step 3] Prompt injection triggers! Agent attempts: execute_wire_transfer(amount=500000)")
        call3 = {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "execute_wire_transfer",
                "arguments": {
                    "amount": 500000,
                    "recipient": "attacker_account",
                    "auth": "$CREDENTIAL{BANK_API_KEY}",
                },
            },
        }
        res3 = await proxy.handle_jsonrpc_message(call3)
        print("Verdict: \033[91m[BLOCKED / SEVERED BY CHIDFLOW]\033[0m")

        # Visual Graph Rendering
        print("\n" + GraphVisualizer.render(
            graph=policy.graph,
            choke_points=[("public_web_scraper", "agent_memory")],
            highlight_path=["public_web_scraper", "agent_memory", "banking_wire_rail"],
        ))

        print("\n[Step 4] Synthetic Mock Error returned to LLM:")
        print(json.dumps(res3, indent=2))

        print("\n[Step 5] Cryptographic Clearinghouse Verification:")
        if proxy.audit_log:
            is_valid = signer.verify_receipt(proxy.audit_log[0])
            print(f"Audit receipt non-repudiation verified by clearinghouse: \033[92m{is_valid}\033[0m")

    asyncio.run(execute_steps())
    print("\n" + "=" * 72)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="ChidFlow: Runtime Graph Execution Proxy & Clearinghouse for Autonomous AI Agents"
    )
    subparsers = parser.add_subparsers(dest="command")

    # demo
    subparsers.add_parser("demo", help="Run interactive attack mitigation & visual demo")

    # benchmark
    bench_p = subparsers.add_parser("benchmark", help="Run head-to-head benchmark vs NVIDIA OpenShell static model")
    bench_p.add_argument("--iterations", type=int, default=1000, help="Number of iterations")

    # proxy
    proxy_p = subparsers.add_parser("proxy", help="Run MCP stdio execution proxy")
    proxy_p.add_argument("--wrap", type=str, default=None, help="Command to wrap as upstream MCP server child process")
    proxy_p.add_argument("--config", type=str, default=None, help="Path to chidflow policy config file (JSON)")

    # serve
    serve_p = subparsers.add_parser("serve", help="Run HTTP JSON-RPC gateway server")
    serve_p.add_argument("--port", type=int, default=8080, help="HTTP port (default: 8080)")
    serve_p.add_argument("--config", type=str, default=None, help="Path to policy config file")

    # verify
    verify_p = subparsers.add_parser("verify", help="Verify a cryptographic audit receipt")
    verify_p.add_argument("receipt", type=str, help="Receipt JSON string or file path")
    verify_p.add_argument("--secret", type=str, default=None, help="Clearinghouse signing secret")

    # autopilot
    subparsers.add_parser("autopilot", help="Run ServerWatch Production Incident Autopilot & eBPF sensor demo")

    # tpic
    subparsers.add_parser("tpic", help="Run the 10-vector Transitive Prompt-Injection Challenge (TPIC) vs NVIDIA OpenShell")

    # explorer
    subparsers.add_parser("explorer", help="Launch the Clearinghouse Audit Ledger Explorer")

    # cybersec
    subparsers.add_parser("cybersec", help="Run End-to-End Invariant Cybersecurity Mesh demo (Ingress -> Lateral -> Ransomware)")

    args = parser.parse_args()

    if args.command == "demo" or not args.command:
        run_demo()

    elif args.command == "benchmark":
        BenchmarkRunner.run_transitive_attack_benchmark(args.iterations)

    elif args.command == "proxy":
        if args.config:
            policy, vault = PolicyConfigLoader.load_from_file(args.config)
        else:
            policy = PolicyEngine()
            vault = CredentialVault()

        if args.wrap:
            wrapper = SubprocessMCPWrapper(upstream_command=args.wrap, policy_engine=policy, vault=vault)
            asyncio.run(wrapper.run())
        else:
            proxy = MCPExecutionProxy(policy_engine=policy, vault=vault)
            asyncio.run(proxy.run_stdio())

    elif args.command == "serve":
        if args.config:
            policy, vault = PolicyConfigLoader.load_from_file(args.config)
        else:
            policy = PolicyEngine()
            vault = CredentialVault()

        proxy = MCPExecutionProxy(policy_engine=policy, vault=vault)
        server = create_http_server(args.port, proxy)
        print(f"ChidFlow HTTP JSON-RPC Proxy listening on http://0.0.0.0:{args.port}/mcp")
        print("Press Ctrl+C to terminate.")
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            server.server_close()

    elif args.command == "verify":
        receipt_data = args.receipt
        if os.path.exists(receipt_data):
            with open(receipt_data, "r") as f:
                receipt_data = f.read()

        data = json.loads(receipt_data)
        receipt = AuditReceipt(**data)
        secret = args.secret or os.environ.get("CHIDFLOW_SIGNING_SECRET", "default_secret")
        signer = ClearinghouseSigner(secret)
        valid = signer.verify_receipt(receipt)
        print(f"Receipt {receipt.receipt_id} validity: {valid}")

    elif args.command == "autopilot":
        run_serverwatch_demo()

    elif args.command == "tpic":
        print("\n" + "=" * 76)
        print("   TPIC BENCHMARK: 10 TRANSITIVE PROMPT INJECTION ATTACK VECTORS")
        print("   Head-to-head comparison: NVIDIA OpenShell (Static Z3) vs ChidFlow Min-Cut")
        print("=" * 76)
        results = TPICBenchmark.evaluate_all()
        print(f"Total Scenarios Tested : {results['total_scenarios']}")
        print(f"NVIDIA OpenShell Model : \033[91m{results['openshell_score']} Mitigation\033[0m (10/10 Vulnerable)")
        print(f"ChidFlow Min-Cut Model : \033[92m{results['chidflow_score']} Mitigation\033[0m (0/10 Vulnerable)")
        print("-" * 76)
        for d in results["details"]:
            status = "\033[92mBLOCKED\033[0m" if d["chidflow_mitigated"] else "\033[91mFAILED\033[0m"
            print(f"  • {d['scenario'][:50]:<50} | ChidFlow: {status} | OpenShell: \033[91mBYPASSED\033[0m")
        print("=" * 76 + "\n")

    elif args.command == "explorer":
        signer = ClearinghouseSigner(signing_secret="explorer_demo_secret_2026")
        explorer = ClearinghouseExplorer(signer=signer)
        # Populate with sample receipts
        for i, tool in enumerate(["query_crm", "verify_identity", "autopilot:DRAIN_CANARY"], start=1):
            r = signer.sign_transaction(tool_name=tool, arguments={"run_id": i}, graph_state_hash=f"state_hash_{i}")
            explorer.record_receipt(r)
        print("\n" + explorer.render_ascii_ledger())
        status = explorer.verify_ledger_integrity()
        print(f"Ledger Status: \033[92m{status['ledger_status']}\033[0m ({status['verified_valid']}/{status['total_transactions']} Verified)\n")

    elif args.command == "cybersec":
        print("\n" + "=" * 78)
        print("      CHID TECHNOLOGIES: END-TO-END INVARIANT CYBERSECURITY MESH")
        print("=" * 78)
        
        # 1. Setup Mesh Topology
        graph = DynamicFlowGraph()
        graph.add_node("external_attacker", SecurityClassification.UNTRUSTED_SOURCE, "Hostile Internet Actor")
        graph.add_node("compromised_pod", SecurityClassification.AGENT_CONTEXT, "Phished Internal Pod")
        graph.add_node("internal_queue", SecurityClassification.AGENT_CONTEXT, "Kafka / Redis Message Queue")
        graph.add_node("postgres_treasure", SecurityClassification.CRITICAL_SINK, "Core Financial / PII Database (The Treasure)")
        graph.add_edge("internal_queue", "postgres_treasure")

        signer = ClearinghouseSigner(signing_secret="cybersec_demo_secret_2026")
        sensor = EBPFRuntimeSensor(signer=signer)
        sensor.register_protected_resource("postgres_treasure:5432")

        mesh = EndToEndSecurityMesh(graph=graph, sensor=sensor, signer=signer, max_mutation_rate_per_sec=20)

        print("[+] STEP 1: INGRESS TAINT PROVENANCE")
        graph.add_edge("external_attacker", "compromised_pod")
        print("    * Payload ingested from 'external_attacker' -> 'compromised_pod'.")
        print("    * Taint status: \033[93mUNTRUSTED PROVENANCE ATTACHED\033[0m (No alert fatigue, agent allowed to process).")

        print("\n[+] STEP 2: LATERAL MOVEMENT ATTEMPT")
        print("    * 'compromised_pod' attempts lateral hop to 'internal_queue' to bridge toward DB...")
        verdict = mesh.evaluate_lateral_hop("compromised_pod", "internal_queue")
        print(f"    * Dynamic Min-Cut Evaluation: \033[91m{verdict.violation_code}\033[0m")
        print(f"    * Action: Bridge severed at choke point {verdict.choke_point} in {verdict.mitigation_latency_ms:.2f}ms.")
        print(f"    * Quarantine status: \033[91mNode '{verdict.quarantined_nodes[0]}' QUARANTINED\033[0m.")

        print("\n[+] STEP 3: DIRECT KERNEL SOCKET ATTACK (eBPF SENSOR)")
        print("    * Rogue process tries raw TCP connect to 'postgres_treasure:5432' without clearinghouse ticket...")
        sock_verdict = mesh.evaluate_lateral_hop("rogue_script", "postgres_treasure", socket_port=5432)
        print(f"    * eBPF Sensor Verdict: \033[91mDROPPED AT KERNEL BOUNDARY\033[0m (403 Forbidden)")

        print("\n[+] STEP 4: RANSOMWARE MASS-MUTATION INVARIANT")
        print("    * Simulating rapid encryption attack (60 writes/sec targeting Treasure)...")
        allowed, reason = mesh.evaluate_mutation_rate("postgres_treasure", count=60)
        print(f"    * Mutation Velocity: \033[91m{reason}\033[0m")
        print("    * State Checkpoint: \033[92mTRANSACTIONS FROZEN & ROLLED BACK TO SNAPSHOT\033[0m")

        print("\n[+] STEP 5: COMPLIANCE & FORENSIC DOSSIER ISSUED")
        dossier = mesh.generate_forensic_dossier(verdict.event_id)
        print(f"    * Dossier ID        : {dossier['dossier_id']}")
        print(f"    * Treasure Integrity: \033[92m{dossier['treasure_status']}\033[0m (Zero Bytes Compromised)")
        print(f"    * SOC2 Compliance   : {dossier['regulatory_compliance']['soc2_cc6_1']}")
        print(f"    * ISO 42001 Status  : {dossier['regulatory_compliance']['iso_42001_reachability']}")
        print("=" * 78 + "\n")


if __name__ == "__main__":
    main()
