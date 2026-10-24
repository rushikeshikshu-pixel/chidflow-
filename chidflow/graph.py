from __future__ import annotations

import collections
import hashlib
import json
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from chidflow.models import GraphEdge, GraphNode, SecurityClassification


class DynamicFlowGraph:
    """
    Dynamic Information Flow Graph (DIFG) tracking agent runtime state,
    taint propagation, and reachability.
    
    Implements Edmonds-Karp Max-Flow / Min-Cut to identify exact choke points
    between untrusted sources and sensitive/critical sinks.
    """

    def __init__(self):
        self.nodes: Dict[str, GraphNode] = {}
        self.edges: List[GraphEdge] = []
        # Adjacency lists for fast traversal: node_id -> list of outgoing edges
        self._adj: Dict[str, List[GraphEdge]] = collections.defaultdict(list)
        # Snapshot stack for tentative speculative simulations
        self._snapshot_stack: List[Tuple[Dict[str, GraphNode], List[GraphEdge]]] = []

    def add_node(
        self,
        node_id: str,
        classification: SecurityClassification,
        description: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> GraphNode:
        """Register or update a node in the execution graph."""
        node = GraphNode(
            id=node_id,
            classification=classification,
            description=description,
            metadata=metadata or {},
        )
        self.nodes[node_id] = node
        if node_id not in self._adj:
            self._adj[node_id] = []
        return node

    def add_edge(
        self,
        source: str,
        target: str,
        capacity: float = 1.0,
        taint_label: str = "",
    ) -> GraphEdge:
        """Add a directed information flow or permission edge."""
        if source not in self.nodes:
            raise KeyError(f"Source node '{source}' does not exist in graph.")
        if target not in self.nodes:
            raise KeyError(f"Target node '{target}' does not exist in graph.")

        edge = GraphEdge(
            source=source,
            target=target,
            capacity=capacity,
            taint_label=taint_label,
            created_at=time.time(),
        )
        self.edges.append(edge)
        self._adj[source].append(edge)
        return edge

    def get_nodes_by_classification(self, classification: SecurityClassification) -> List[str]:
        """Return all node IDs matching a classification."""
        return [n.id for n in self.nodes.values() if n.classification == classification]

    def checkpoint(self) -> None:
        """Save a snapshot of the current graph state for rollback."""
        # Deepcopy of nodes and shallow copy of edges
        nodes_copy = {k: GraphNode(v.id, v.classification, v.description, dict(v.metadata), v.created_at)
                      for k, v in self.nodes.items()}
        edges_copy = list(self.edges)
        self._snapshot_stack.append((nodes_copy, edges_copy))

    def rollback(self) -> None:
        """Roll back to the previous graph snapshot."""
        if not self._snapshot_stack:
            raise RuntimeError("No snapshot available to rollback to.")
        nodes_prev, edges_prev = self._snapshot_stack.pop()
        self.nodes = nodes_prev
        self.edges = edges_prev
        self._rebuild_adjacency()

    def commit_checkpoint(self) -> None:
        """Discard the latest snapshot, keeping changes permanent."""
        if self._snapshot_stack:
            self._snapshot_stack.pop()

    def _rebuild_adjacency(self) -> None:
        """Rebuild internal adjacency lookup table."""
        self._adj = collections.defaultdict(list)
        for node_id in self.nodes:
            self._adj[node_id] = []
        for edge in self.edges:
            self._adj[edge.source].append(edge)

    def find_paths(self, source: str, target: str) -> List[List[str]]:
        """Find all simple directed paths from source to target using BFS."""
        if source not in self.nodes or target not in self.nodes:
            return []

        all_paths: List[List[str]] = []
        queue = collections.deque([[source]])

        while queue:
            path = queue.popleft()
            current = path[-1]

            if current == target:
                all_paths.append(path)
                continue

            for edge in self._adj.get(current, []):
                nxt = edge.target
                if nxt not in path:  # Avoid cycles
                    queue.append(path + [nxt])

        return all_paths

    def compute_min_cut(
        self, sources: List[str], sinks: List[str]
    ) -> Tuple[float, List[Tuple[str, str]]]:
        """
        Computes Max-Flow and finds the Min-Cut (choke points) between multi-source
        and multi-sink sets using the Edmonds-Karp algorithm.
        
        Creates virtual super-source `__SUPER_SRC__` and super-sink `__SUPER_SINK__`.
        Returns:
            Tuple of (max_flow_value, list_of_choke_point_edges)
        """
        if not sources or not sinks:
            return 0.0, []

        super_src = "__SUPER_SRC__"
        super_sink = "__SUPER_SINK__"

        # Build capacity matrix
        capacity: Dict[Tuple[str, str], float] = collections.defaultdict(float)
        adj_nodes: Dict[str, Set[str]] = collections.defaultdict(set)

        # 1. Existing edges
        for edge in self.edges:
            capacity[(edge.source, edge.target)] += edge.capacity
            adj_nodes[edge.source].add(edge.target)
            adj_nodes[edge.target].add(edge.source)  # for residual back-edges

        # 2. Connect super-source to all sources with infinite capacity
        INF = float("inf")
        for s in sources:
            if s in self.nodes:
                capacity[(super_src, s)] = INF
                adj_nodes[super_src].add(s)
                adj_nodes[s].add(super_src)

        # 3. Connect all sinks to super-sink with infinite capacity
        for t in sinks:
            if t in self.nodes:
                capacity[(t, super_sink)] = INF
                adj_nodes[t].add(super_sink)
                adj_nodes[super_sink].add(t)

        # 4. Edmonds-Karp implementation
        flow: Dict[Tuple[str, str], float] = collections.defaultdict(float)
        total_flow = 0.0

        while True:
            # BFS for shortest augmenting path in residual graph
            parent: Dict[str, str] = {}
            visited: Set[str] = {super_src}
            queue = collections.deque([super_src])

            while queue and super_sink not in visited:
                u = queue.popleft()
                for v in adj_nodes[u]:
                    residual = capacity[(u, v)] - flow[(u, v)]
                    if v not in visited and residual > 1e-9:
                        visited.add(v)
                        parent[v] = u
                        queue.append(v)

            if super_sink not in visited:
                break  # No more augmenting paths

            # Find bottleneck capacity along path
            bottleneck = INF
            curr = super_sink
            while curr != super_src:
                prev = parent[curr]
                residual = capacity[(prev, curr)] - flow[(prev, curr)]
                bottleneck = min(bottleneck, residual)
                curr = prev

            # Push flow
            curr = super_sink
            while curr != super_src:
                prev = parent[curr]
                flow[(prev, curr)] += bottleneck
                flow[(curr, prev)] -= bottleneck
                curr = prev

            total_flow += bottleneck

        # 5. Identify Min-Cut Choke Points:
        # Find reachable nodes from super_src in the residual network
        visited_nodes: Set[str] = {super_src}
        q = collections.deque([super_src])
        while q:
            u = q.popleft()
            for v in adj_nodes[u]:
                residual = capacity[(u, v)] - flow[(u, v)]
                if v not in visited_nodes and residual > 1e-9:
                    visited_nodes.add(v)
                    q.append(v)

        # The cut edges are edges in original graph from visited_nodes to non-visited_nodes
        choke_points: List[Tuple[str, str]] = []
        for edge in self.edges:
            if edge.source in visited_nodes and edge.target not in visited_nodes:
                choke_points.append((edge.source, edge.target))

        return total_flow, choke_points

    def get_state_hash(self) -> str:
        """
        Generates a deterministic SHA256 digest of the canonical graph topology.
        Used for cryptographic clearinghouse receipts.
        """
        canonical = {
            "nodes": sorted([n.to_dict() for n in self.nodes.values()], key=lambda x: x["id"]),
            "edges": sorted([e.to_dict() for e in self.edges], key=lambda x: (x["source"], x["target"])),
        }
        serialized = json.dumps(canonical, sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
