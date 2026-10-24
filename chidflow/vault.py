from __future__ import annotations

import re
from typing import Any, Dict, Optional


class CredentialVault:
    """
    Dynamic Credential Vault for Agent Execution.
    
    Prevents autonomous agents from holding raw API tokens or database credentials.
    The agent passes placeholder identifiers (e.g., "$CREDENTIAL{STRIPE_SECRET_KEY}")
    which the proxy injects just-in-time ONLY upon a successful Min-Cut clearance.
    """

    def __init__(self, secrets: Optional[Dict[str, str]] = None):
        self._secrets: Dict[str, str] = secrets or {}
        self._token_pattern = re.compile(r"\$CREDENTIAL\{([A-Za-z0-9_]+)\}")

    def register_secret(self, key: str, value: str) -> None:
        """Store a high-privilege credential in the vault."""
        self._secrets[key] = value

    def inject_credentials(self, obj: Any) -> Any:
        """
        Recursively traverses tool arguments / headers and substitutes
        placeholder tokens with real secrets.
        """
        if isinstance(obj, str):
            def replacer(match):
                var_name = match.group(1)
                return self._secrets.get(var_name, match.group(0))
            return self._token_pattern.sub(replacer, obj)

        elif isinstance(obj, dict):
            return {k: self.inject_credentials(v) for k, v in obj.items()}

        elif isinstance(obj, list):
            return [self.inject_credentials(item) for item in obj]

        return obj

    def scrub_credentials(self, text: str) -> str:
        """
        Scrub real secrets from outbound logs or responses to prevent leakage.
        """
        sanitized = text
        for key, secret in self._secrets.items():
            if secret and len(secret) > 4:
                sanitized = sanitized.replace(secret, f"[REDACTED_{key}]")
        return sanitized
