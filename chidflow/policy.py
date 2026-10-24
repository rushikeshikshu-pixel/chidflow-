from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from chidflow.graph import DynamicFlowGraph
from chidflow.models import (
    AuditReceipt,
    SecurityClassification,
    ToolCallRequest,
    ToolCallVerdict,
)
from chidflow.proof import ClearinghouseSigner


class ToolBehavior:
    """Describes how an MCP tool mutates the Information Flow Graph."""

    def __init__(
        self,
        name: str,
        reads_from: Optional[List[str]] = None,
        writes_to: Optional[List[str]] = None,
        custom_mutator: Optional[Callable[[DynamicFlowGraph, ToolCallRequest], None]] = None,
    ):
        self.name = name
        self.reads_from = reads_from or []
        self.writes_to = writes_to or []
        self.custom_mutator = custom_mutator


class PolicyEngine:
    """
    Real-Time Min-Cut Policy Gate for Autonomous AI Agents.
    
    Simulates tentative edge mutations on MCP tool calls, performs reachability /
    max-flow cut analysis, and severs transitive exfiltration bridges before
    any real-world payload transmission.
    """

    def __init__(
        self,
        graph: Optional[DynamicFlowGraph] = None,
        signer: Optional[ClearinghouseSigner] = None,
    ):
        self.graph = graph or DynamicFlowGraph()
        self.signer = signer or ClearinghouseSigner()
        self._tool_registry: Dict[str, ToolBehavior] = {}
        self._initialize_default_topology()

    def _initialize_default_topology(self) -> None:
        """Seed default nodes for standard agentic execution boundaries."""
        if "agent_memory" not in self.graph.nodes:
            self.graph.add_node(
                "agent_memory",
                SecurityClassification.AGENT_CONTEXT,
                description="Agent working memory and context window",
            )

    def register_tool(
        self,
        name: str,
        reads_from: Optional[List[str]] = None,
        writes_to: Optional[List[str]] = None,
        custom_mutator: Optional[Callable[[DynamicFlowGraph, ToolCallRequest], None]] = None,
    ) -> None:
        """Register a tool's data flow profile."""
        self._tool_registry[name] = ToolBehavior(
            name=name,
            reads_from=reads_from,
            writes_to=writes_to,
            custom_mutator=custom_mutator,
        )

    def evaluate(self, request: ToolCallRequest) -> ToolCallVerdict:
        """
        Evaluate an intercepted MCP `tools/call` invocation:
        1. Checkpoint current graph state.
        2. Simulate tentative information flow edges.
        3. Run Min-Cut / reachability check from untrusted sources to critical sinks.
        4. If flow > 0 (bridge detected): rollback and return simulated JSON-RPC error.
        5. If flow == 0: commit state mutation and issue cryptographic audit receipt.
        """
        behavior = self._tool_registry.get(
            request.tool_name,
            ToolBehavior(name=request.tool_name, reads_from=[], writes_to=[]),
        )

        # 1. Snapshot prior state
        self.graph.checkpoint()

        try:
            # 2. Simulate tentative mutation
            caller = request.caller_node
            if caller not in self.graph.nodes:
                self.graph.add_node(caller, SecurityClassification.AGENT_CONTEXT)

            # Ingest reads (e.g. Scraper -> Agent)
            for src_node in behavior.reads_from:
                if src_node in self.graph.nodes:
                    self.graph.add_edge(
                        source=src_node,
                        target=caller,
                        taint_label=f"read:{request.tool_name}",
                    )

            # Egress writes (e.g. Agent -> Banking API)
            for sink_node in behavior.writes_to:
                if sink_node in self.graph.nodes:
                    self.graph.add_edge(
                        source=caller,
                        target=sink_node,
                        taint_label=f"write:{request.tool_name}",
                    )

            if behavior.custom_mutator:
                behavior.custom_mutator(self.graph, request)

            # 3. Min-Cut Reachability Check
            untrusted_sources = self.graph.get_nodes_by_classification(
                SecurityClassification.UNTRUSTED_SOURCE
            )
            critical_sinks = self.graph.get_nodes_by_classification(
                SecurityClassification.CRITICAL_SINK
            )

            # Find paths from any active untrusted source to critical sinks
            max_flow, choke_points = self.graph.compute_min_cut(
                untrusted_sources, critical_sinks
            )

            if max_flow > 0:
                # VIOLATION: An un-isolated data exfiltration or prompt-injection path exists!
                # Identify path details for human-readable diagnostic error
                violating_paths = []
                for s in untrusted_sources:
                    for t in critical_sinks:
                        paths = self.graph.find_paths(s, t)
                        if paths:
                            violating_paths.extend(paths)

                path_str = " -> ".join(violating_paths[0]) if violating_paths else "unknown"
                choke_str = ", ".join([f"{u}->{v}" for u, v in choke_points])

                error_msg = (
                    f"Policy Violation: Tool '{request.tool_name}' creates an unauthorized "
                    f"reachability bridge [{path_str}]. Identified Min-Cut choke points: [{choke_str}]."
                )

                # Rollback graph mutation
                self.graph.rollback()

                return ToolCallVerdict(
                    allowed=False,
                    choke_points=choke_points,
                    violation_reason=error_msg,
                    simulated_error={
                        "jsonrpc": "2.0",
                        "id": request.rpc_id,
                        "error": {
                            "code": -32001,
                            "message": error_msg,
                            "data": {
                                "choke_points": choke_points,
                                "violating_path": violating_paths[0] if violating_paths else None,
                            },
                        },
                    },
                )

            # 4. APPROVED: Commit state mutation permanently
            self.graph.commit_checkpoint()
            state_hash = self.graph.get_state_hash()

            receipt = self.signer.sign_transaction(
                tool_name=request.tool_name,
                arguments=request.arguments,
                graph_state_hash=state_hash,
            )

            return ToolCallVerdict(
                allowed=True,
                receipt=receipt,
            )

        except Exception as ex:
            self.graph.rollback()
            raise ex
