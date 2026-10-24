from __future__ import annotations

from typing import List, Optional, Set, Tuple
from chidflow.graph import DynamicFlowGraph
from chidflow.models import SecurityClassification


class GraphVisualizer:
    """Renders ASCII / ANSI diagrams of the Dynamic Flow Graph and severed cuts."""

    COLORS = {
        SecurityClassification.UNTRUSTED_SOURCE: "\033[91m",  # Red
        SecurityClassification.AGENT_CONTEXT: "\033[93m",     # Yellow
        SecurityClassification.CONFIDENTIAL_ASSET: "\033[94m",# Blue
        SecurityClassification.RESTRICTED_SECRET: "\033[95m",  # Magenta
        SecurityClassification.CRITICAL_SINK: "\033[96m",     # Cyan
    }
    RESET = "\033[0m"
    BOLD = "\033[1m"
    RED_BG = "\033[41m\033[97m"

    @classmethod
    def render(
        cls,
        graph: DynamicFlowGraph,
        choke_points: Optional[List[Tuple[str, str]]] = None,
        highlight_path: Optional[List[str]] = None,
    ) -> str:
        choke_set: Set[Tuple[str, str]] = set(choke_points or [])
        lines = []
        lines.append("+" + "-" * 68 + "+")
        lines.append("| " + f"{cls.BOLD}ChidFlow Dynamic Information Flow Graph (DIFG){cls.RESET}".center(76) + " |")
        lines.append("+" + "-" * 68 + "+")

        # List Nodes with security classifications
        lines.append(f"{cls.BOLD}Nodes & Security Boundaries:{cls.RESET}")
        for node in graph.nodes.values():
            color = cls.COLORS.get(node.classification, "")
            lines.append(
                f"  [{color}{node.id}{cls.RESET}] ({node.classification.value}) - {node.description}"
            )

        lines.append("")
        lines.append(f"{cls.BOLD}Active Directed Flow Edges:{cls.RESET}")
        if not graph.edges:
            lines.append("  (No active edges)")
        else:
            for edge in graph.edges:
                is_choke = (edge.source, edge.target) in choke_set
                if is_choke:
                    status = f" {cls.RED_BG}[SEVERED BY CHIDFLOW MIN-CUT]{cls.RESET}"
                    arrow = f" ===X===> "
                else:
                    status = ""
                    arrow = f" -------> "

                lines.append(f"  [{edge.source}]{arrow}[{edge.target}]{status}")

        if highlight_path:
            lines.append("")
            path_str = " -> ".join([f"[{p}]" for p in highlight_path])
            lines.append(f"{cls.BOLD}Blocked Transitive Path:{cls.RESET} \033[91m{path_str}\033[0m")

        lines.append("+" + "-" * 68 + "+")
        return "\n".join(lines)
