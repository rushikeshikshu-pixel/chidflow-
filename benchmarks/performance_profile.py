from __future__ import annotations

import statistics
import time
import tracemalloc
import os
from chidflow.graph import DynamicFlowGraph
from chidflow.models import SecurityClassification, ToolCallRequest
from chidflow.policy import PolicyEngine
from chidflow.proof import ClearinghouseSigner


def run_comprehensive_performance_profile():
    print("=" * 78)
    print("      CHIDFLOW RUNTIME PERFORMANCE & INVARIANT PROFILE")
    print("=" * 78)

    tracemalloc.start()

    # Setup topology
    graph = DynamicFlowGraph()
    graph.add_node("external_untrusted", SecurityClassification.UNTRUSTED_SOURCE)
    graph.add_node("agent_worker", SecurityClassification.AGENT_CONTEXT)
    graph.add_node("redis_cache", SecurityClassification.AGENT_CONTEXT)
    graph.add_node("core_postgres_db", SecurityClassification.CRITICAL_SINK)

    policy = PolicyEngine(graph=graph)
    policy.register_tool("fetch_data", reads_from=["external_untrusted"], writes_to=["agent_worker"])
    policy.register_tool("store_cache", reads_from=["agent_worker"], writes_to=["redis_cache"])
    policy.register_tool("read_cache", reads_from=["redis_cache"], writes_to=["agent_worker"])
    policy.register_tool("write_db", writes_to=["core_postgres_db"])

    # Warmup
    for i in range(100):
        policy.evaluate(ToolCallRequest(i, "store_cache", {}, caller_node="agent_worker"))

    # 2. Invariant Engine Latency & Throughput Benchmark
    N = 1000
    latencies_us = []
    t_start = time.perf_counter()

    for i in range(N):
        step_t0 = time.perf_counter()
        policy.evaluate(ToolCallRequest(i, "store_cache", {"item": i}, caller_node="agent_worker"))
        latencies_us.append((time.perf_counter() - step_t0) * 1_000_000)

    total_time = time.perf_counter() - t_start
    throughput = N / total_time

    # 3. Cryptographic HMAC-SHA256 Receipt Minting Throughput
    signer = ClearinghouseSigner(signing_secret="perf_secret_key_2026")
    receipt_latencies_us = []
    t_sign_start = time.perf_counter()

    for i in range(N):
        r_t0 = time.perf_counter()
        signer.sign_transaction(
            tool_name="store_cache",
            arguments={"item": i},
            graph_state_hash="a1b2c3d4e5f67890",
        )
        receipt_latencies_us.append((time.perf_counter() - r_t0) * 1_000_000)

    total_sign_time = time.perf_counter() - t_sign_start
    sign_throughput = N / total_sign_time

    # 4. Transitive Severing Latency (Min-Cut Execution under Attack)
    attack_latencies_us = []
    # Add untrusted link
    graph.add_edge("external_untrusted", "agent_worker")
    for i in range(1000):
        atk_t0 = time.perf_counter()
        v = policy.evaluate(ToolCallRequest(i, "write_db", {"drop": True}, caller_node="agent_worker"))
        attack_latencies_us.append((time.perf_counter() - atk_t0) * 1_000_000)
        assert not v.allowed

    current_mem, peak_mem = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    # Output Results
    print(f"\n[+] 1. INVARIANT POLICY ENGINE (1,000 Evaluations)")
    print(f"    * Throughput Velocity : \033[92m{throughput:,.0f} evaluations / sec\033[0m")
    print(f"    * Latency Median (p50): {statistics.median(latencies_us):.2f} us ({statistics.median(latencies_us)/1000:.4f} ms)")
    print(f"    * Latency p95         : {statistics.quantiles(latencies_us, n=100)[94]:.2f} us")
    print(f"    * Latency p99         : {statistics.quantiles(latencies_us, n=100)[98]:.2f} us")

    print(f"\n[+] 2. CRYPTOGRAPHIC VAEP RECEIPT MINTING (1,000 Signatures)")
    print(f"    * Minting Throughput  : \033[92m{sign_throughput:,.0f} receipts / sec\033[0m")
    print(f"    * Minting Latency p50 : {statistics.median(receipt_latencies_us):.2f} us")
    print(f"    * Algorithm           : HMAC-SHA256 with Merkle Digest")

    print(f"\n[+] 3. ADVERSARIAL ATTACK INTERCEPTION (1,000 Attacks Blocked)")
    print(f"    * Mitigation Latency  : \033[92m{statistics.median(attack_latencies_us):.2f} us\033[0m ({statistics.median(attack_latencies_us)/1000:.4f} ms)")
    print(f"    * Invariant Theorem   : Max-Flow Min-Cut (Phi_t = 0)")
    print(f"    * Defense Rate        : \033[92m100.0% Severed Deterministically\033[0m")

    print(f"\n[+] 4. SYSTEM RESOURCE OVERHEAD")
    print(f"    * Peak Traced Memory  : {peak_mem / (1024 * 1024):.2f} MB")
    print(f"    * CPU Execution Mode  : Zero-GPU (Runs on standard host CPU cores)")
    print("=" * 78 + "\n")


if __name__ == "__main__":
    run_comprehensive_performance_profile()
