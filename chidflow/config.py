from __future__ import annotations

import json
import os
from typing import Any, Dict, List, Optional

from chidflow.graph import DynamicFlowGraph
from chidflow.models import SecurityClassification
from chidflow.policy import PolicyEngine
from chidflow.proof import ClearinghouseSigner
from chidflow.vault import CredentialVault


class PolicyConfigLoader:
    """Loads and compiles declarative ChidFlow policy configurations."""

    @staticmethod
    def load_from_dict(
        data: Dict[str, Any],
        signing_secret: Optional[str] = None,
    ) -> tuple[PolicyEngine, CredentialVault]:
        graph = DynamicFlowGraph()

        # 1. Register Nodes
        for node_def in data.get("nodes", []):
            node_id = node_def["id"]
            classification_str = node_def.get("classification", "AGENT_CONTEXT")
            classification = SecurityClassification(classification_str)
            description = node_def.get("description", "")
            metadata = node_def.get("metadata", {})
            graph.add_node(node_id, classification, description, metadata)

        # 2. Register Initial Edges
        for edge_def in data.get("edges", []):
            graph.add_edge(
                source=edge_def["source"],
                target=edge_def["target"],
                capacity=float(edge_def.get("capacity", 1.0)),
                taint_label=edge_def.get("taint_label", ""),
            )

        # 3. Setup Vault
        vault = CredentialVault()
        for key, value in data.get("credentials", {}).items():
            # Support reading from environment variable if starts with $ENV:
            if isinstance(value, str) and value.startswith("$ENV:"):
                env_key = value[5:]
                vault.register_secret(key, os.environ.get(env_key, ""))
            else:
                vault.register_secret(key, str(value))

        # 4. Setup Signer & Policy Engine
        secret = signing_secret or data.get("signing_secret")
        signer = ClearinghouseSigner(secret)
        policy_engine = PolicyEngine(graph=graph, signer=signer)

        # 5. Register Tools
        for tool_def in data.get("tools", []):
            policy_engine.register_tool(
                name=tool_def["name"],
                reads_from=tool_def.get("reads_from", []),
                writes_to=tool_def.get("writes_to", []),
            )

        return policy_engine, vault

    @classmethod
    def load_from_file(
        cls, file_path: str, signing_secret: Optional[str] = None
    ) -> tuple[PolicyEngine, CredentialVault]:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        if file_path.endswith(".json"):
            data = json.loads(content)
        else:
            # Simple minimal YAML-like key-value parser or standard json
            try:
                import yaml
                data = yaml.safe_load(content)
            except ImportError:
                # If pyyaml not installed, fallback to json parsing
                data = json.loads(content)

        return cls.load_from_dict(data, signing_secret)
