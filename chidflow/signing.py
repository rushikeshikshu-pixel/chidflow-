"""Resolve the HMAC signing secret.

Operational commands require ``CHIDFLOW_SIGNING_SECRET`` or an explicit secret.
Demo commands may fall back to a public, obviously labelled value.
"""

from __future__ import annotations

import os
import sys
from typing import Optional

SIGNING_SECRET_ENV = "CHIDFLOW_SIGNING_SECRET"

# Public on purpose. Demo commands print a warning when they fall back to these.
DEMO_SIGNING_SECRET = "demo-only-insecure-signing-secret"
DEMO_BANK_API_KEY = "demo-only-insecure-bank-api-key"
DEMO_DEVICE_SECRET = "demo-only-insecure-device-secret"


class MissingSigningSecretError(RuntimeError):
    """An operational command was started without a signing secret."""


def optional_signing_secret(explicit: Optional[str] = None) -> Optional[str]:
    """Return an explicit secret, otherwise ``CHIDFLOW_SIGNING_SECRET``, otherwise ``None``.

    ``None`` means the caller should generate an ephemeral key. Blank strings
    count as missing so an empty environment value cannot be used as a key.
    """
    if explicit is not None and explicit.strip():
        return explicit.strip()
    env_value = os.environ.get(SIGNING_SECRET_ENV, "").strip()
    return env_value or None


def resolve_signing_secret(explicit: Optional[str] = None) -> str:
    """Return a signing secret or raise ``MissingSigningSecretError``.

    There is no built-in production default.
    """
    secret = optional_signing_secret(explicit)
    if secret:
        return secret
    raise MissingSigningSecretError(
        f"{SIGNING_SECRET_ENV} is not set. "
        "Set it in the environment (see .env.example) or pass --secret. "
        "Refusing to start with a built-in signing key."
    )


def demo_signing_secret() -> str:
    """Signing secret for local demo commands.

    Uses ``CHIDFLOW_SIGNING_SECRET`` when it is set. Otherwise returns the
    public demo value and writes a warning to stderr so ``chid demo`` still
    runs with no configuration.
    """
    env_value = os.environ.get(SIGNING_SECRET_ENV, "").strip()
    if env_value:
        return env_value
    print(
        "warning: CHIDFLOW_SIGNING_SECRET is not set; "
        f"using {DEMO_SIGNING_SECRET}. This value is public. "
        "Do not use it with serve-clearing, docker compose, or any deployment.",
        file=sys.stderr,
    )
    return DEMO_SIGNING_SECRET
