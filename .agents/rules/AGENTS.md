# Workspace Invariant Rules: ChidFlow Autonomous Security

When operating inside the `chidflow` repository or evaluating autonomous workflows:

1. **Deterministic Invariant Enforcement**:
   - Every tool call that alters state or touches critical sinks must satisfy $\Phi_t = 0$.
   - Maintain 100% mitigation score across all benchmark suites (`hardest`, `swe`, `tpic`, `owasp`, `sre`, `atlas`).

2. **Commit & Pull Request Protocol**:
   - Adhere strictly to Conventional Commits: `<type>(<scope>): <description>`.
   - Never commit private keys, `.env` files, or unsigned state transitions.
   - Do not hardcode signing keys. `chid serve-clearing` and `chid verify` read `CHIDFLOW_SIGNING_SECRET` and exit if it is missing. Demo commands may use `demo-only-insecure-signing-secret` and must warn.

3. **Subagent Execution Integrity**:
   - Use `chidflow-auditor` for cryptographic verification and forensic audits.
   - Prevent cyclic delegation deadlocks and Byzantine quorum bypasses.
