"""Signing-secret resolution: operational commands fail closed, demos stay runnable."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from chidflow.clearinghouse_service import (
    ClearinghouseRequestHandler,
    start_clearinghouse_server,
)
from chidflow.config import PolicyConfigLoader
from chidflow.proof import ClearinghouseSigner
from chidflow.signing import (
    DEMO_SIGNING_SECRET,
    MissingSigningSecretError,
    SIGNING_SECRET_ENV,
    demo_signing_secret,
    resolve_signing_secret,
)

ROOT = Path(__file__).resolve().parents[1]

# Pieces are concatenated so this file does not contain the banned text itself.
BANNED_SNIPPETS = (
    "sk_" + "live_",
    "rk_" + "live_",
    "clearinghouse_master_production_" + "secret_2026",
    "prod_clearinghouse_master_" + "secret_2026",
    "prod-clearinghouse-" + "secret-key-32bytes",
    "real_live_bank_" + "prod_secret",
    "serverwatch_production_" + "master_secret",
    "your-clearinghouse-" + "production-secret",
    "chidflow-client-" + "default-secret",
)


def test_resolve_signing_secret_requires_env(monkeypatch):
    monkeypatch.delenv(SIGNING_SECRET_ENV, raising=False)
    with pytest.raises(MissingSigningSecretError, match=SIGNING_SECRET_ENV):
        resolve_signing_secret()


def test_resolve_signing_secret_reads_env_and_explicit_wins(monkeypatch):
    monkeypatch.setenv(SIGNING_SECRET_ENV, "from-env")
    assert resolve_signing_secret() == "from-env"
    assert resolve_signing_secret("  from-flag  ") == "from-flag"
    assert resolve_signing_secret("   ") == "from-env"


def test_demo_signing_secret_warns_when_unset(monkeypatch, capsys):
    monkeypatch.delenv(SIGNING_SECRET_ENV, raising=False)
    assert demo_signing_secret() == DEMO_SIGNING_SECRET
    err = capsys.readouterr().err
    assert "warning:" in err
    assert DEMO_SIGNING_SECRET in err
    assert "public" in err


def test_demo_signing_secret_uses_env_without_warning(monkeypatch, capsys):
    monkeypatch.setenv(SIGNING_SECRET_ENV, "configured-demo-secret")
    assert demo_signing_secret() == "configured-demo-secret"
    assert capsys.readouterr().err == ""


def test_policy_env_placeholder_requires_variable(monkeypatch):
    monkeypatch.delenv(SIGNING_SECRET_ENV, raising=False)
    with pytest.raises(MissingSigningSecretError, match=SIGNING_SECRET_ENV):
        PolicyConfigLoader.load_from_dict(
            {"signing_secret": f"$ENV:{SIGNING_SECRET_ENV}"}
        )


def test_policy_env_placeholder_sets_signer(monkeypatch):
    monkeypatch.setenv(SIGNING_SECRET_ENV, "policy-unit-secret")
    policy, _vault = PolicyConfigLoader.load_from_dict(
        {"signing_secret": f"$ENV:{SIGNING_SECRET_ENV}"}
    )
    expected = ClearinghouseSigner("policy-unit-secret")
    assert policy.signer.public_key_id == expected.public_key_id


def test_example_policy_references_env_not_a_literal():
    policy_path = ROOT / "examples" / "policy.json"
    data = json.loads(policy_path.read_text(encoding="utf-8"))
    assert data["signing_secret"] == "$ENV:CHIDFLOW_SIGNING_SECRET"
    assert data["credentials"]["STRIPE_API_KEY"] == "$ENV:STRIPE_API_KEY"


def test_start_clearinghouse_requires_secret(monkeypatch):
    monkeypatch.delenv(SIGNING_SECRET_ENV, raising=False)
    with pytest.raises(MissingSigningSecretError):
        start_clearinghouse_server(port=0, signer=None)


def test_start_clearinghouse_uses_env_secret(monkeypatch):
    monkeypatch.setenv(SIGNING_SECRET_ENV, "unit-test-clearinghouse-secret")
    previous = ClearinghouseRequestHandler.signer
    server = start_clearinghouse_server(port=0, signer=None)
    try:
        expected = ClearinghouseSigner("unit-test-clearinghouse-secret")
        assert ClearinghouseRequestHandler.signer is not None
        assert ClearinghouseRequestHandler.signer.public_key_id == expected.public_key_id
    finally:
        ClearinghouseRequestHandler.signer = previous
        server.server_close()


def _cli_env() -> dict:
    env = os.environ.copy()
    env.pop(SIGNING_SECRET_ENV, None)
    env["PYTHONPATH"] = str(ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    return env


def test_cli_demo_runs_without_signing_secret():
    proc = subprocess.run(
        [sys.executable, "-m", "chidflow.cli", "demo"],
        cwd=ROOT,
        env=_cli_env(),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert "warning:" in proc.stderr
    assert DEMO_SIGNING_SECRET in proc.stderr
    assert "SEVERED" in proc.stdout or "BLOCKED" in proc.stdout


def test_cli_serve_with_example_policy_requires_secret():
    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "chidflow.cli",
            "serve",
            "--config",
            "examples/policy.json",
            "--port",
            "0",
        ],
        cwd=ROOT,
        env=_cli_env(),
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 2, proc.stderr
    assert SIGNING_SECRET_ENV in proc.stderr


def test_cli_serve_clearing_and_verify_fail_without_secret():
    env = _cli_env()
    clearing = subprocess.run(
        [sys.executable, "-m", "chidflow.cli", "serve-clearing", "--port", "0"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert clearing.returncode == 2
    assert SIGNING_SECRET_ENV in clearing.stderr
    assert "built-in" in clearing.stderr

    verify = subprocess.run(
        [sys.executable, "-m", "chidflow.cli", "verify", "{}"],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert verify.returncode == 2
    assert SIGNING_SECRET_ENV in verify.stderr


def test_working_tree_has_no_live_looking_secret_snippets():
    skip_dirs = {".git", "__pycache__", ".pytest_cache", ".venv", "dist", "build"}
    suffixes = {".py", ".json", ".yml", ".yaml", ".md", ".toml", ".txt", ".example"}
    offenders = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in skip_dirs for part in path.parts):
            continue
        if path.suffix not in suffixes and path.name not in {".env.example", ".gitignore", "Dockerfile"}:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore")
        for snippet in BANNED_SNIPPETS:
            if snippet in text:
                offenders.append(f"{path.relative_to(ROOT)}: {snippet}")
    assert offenders == []
