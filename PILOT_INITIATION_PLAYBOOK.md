# Chid Technologies: Enterprise Pilot Initiation Playbook (Step 2)
**B2B Enterprise Go-To-Market & Shadow-Mode Deployment Playbook**
*Document Version: 1.0.0 (Production Release 2026)*

---

## 1. Target Account Profiles & The Bengaluru Wedge

Our initial enterprise beachhead targets **fast-moving fintechs, developer platforms, and high-growth AI startups** whose leadership wants to grant autonomous AI agents write permissions to databases, APIs, and workstations, but whose security/compliance officers are blocking deployment.

### Primary Bengaluru & Global Target List:

| Target Company | Decision Maker | Current Risk & Pain Point | Wedge Solution |
| :--- | :--- | :--- | :--- |
| **Razorpay / Cashfree** | CTO / VP Engineering | Multi-agent customer payouts & merchant reconciliation | Invariant guard on banking payout APIs ($\Phi_t = 0$) |
| **CRED / Juspay** | Head of Infra / CISO | Background agents operating credit ledger systems | eBPF kernel socket protection on Postgres (Port 5432) |
| **BrowserStack** | VP Engineering | Remote VM & browser test automation agents | Ambient Edge Daemon protecting SSH keys & host secrets |
| **Hasura / Postman** | CTO / Head of Product | AI agents executing raw GraphQL / SQL queries | DIFG reachability check on sensitive tables |
| **Emerging AI Labs** | Founder / CTO | Autonomous coding / SRE agents modifying prod repos | Closed-loop incident autopilot with zero blast-radius |

---

## 2. High-Converting Executive Outreach Kit

### Email / LinkedIn DM to CTOs:

**Subject:** `Giving agents DB write access without prompt injection liability`

```text
Hi [First Name],

I noticed your engineering team is actively exploring autonomous multi-agent workflows for [specific use case, e.g. automated reconciliation / SRE debugging].

The common blocker we hear from fintech CTOs in Bengaluru is simple:
The second you grant an agent write permissions to a database or banking API, you are one prompt injection away from unauthorized table drops or wire transfers.

Current solutions (LLM-as-a-judge, regex guardrails, NVIDIA OpenShell) fail because language input space is infinite O(∞) and attackers split injections across multiple benign tool hops.

We built ChidFlow (backed by ServerWatch): a runtime execution proxy based on Dynamic Information Flow Graphs and Max-Flow Min-Cut reachability.

Instead of guessing whether an LLM prompt is malicious, we mathematically enforce that network flow to critical sinks is zero (Φ_t = 0) in < 0.2ms. When clean, we mint HMAC audit receipts compliant with EU AI Act and RBI data governance.

We scored 10/10 in our transitive prompt injection benchmark (TPIC) against NVIDIA OpenShell's 0/10.

Could we run a 14-day non-intrusive shadow mode on your staging cluster? It monitors agent traces passively without blocking traffic, giving you a complete blast-radius audit report with zero false positives.

Best,
Rishi
Founder & Chief Architect, Chid Technologies
https://github.com/chidflow/chidflow
```

---

## 3. The 10-Minute CTO Whiteboard / Demo Script

```
[00:00 - 02:00] THE INVERSION
"Every guardrail you've evaluated tries to inspect prompts. That is mathematically doomed.
Language is infinite. The Treasure is finite.
We don't look at the prompt. We look at the Information Flow Graph."

[02:00 - 04:00] THE PROOF (TPIC BENCHMARK)
Run terminal command:
$ chid tpic
"Here are 10 multi-hop attack vectors (subagent ladder, memory poisoning, Jira injection).
NVIDIA OpenShell allows all 10 because each step looks benign.
ChidFlow blocks all 10 in 0.18ms because the directed path completes to the sink."

[04:00 - 07:00] LIVE AUTOPILOT & MISSION CONTROL
Run terminal command:
$ chid dashboard
Open browser to show live canvas graph:
- Trigger external untrusted ingress taint.
- Watch agent attempt lateral movement.
- Watch ChidFlow sever the exact choke point before the database is touched.
- Show the minted cryptographic HMAC-SHA256 receipt.

[07:00 - 10:00] THE ZERO-RISK OFFER (SHADOW MODE)
"We don't ask you to trust us with production traffic today.
We deploy in Shadow Mode (Passive Tap) on your staging environment for 14 days.
It incurs < 0.4ms latency overhead and blocks zero user requests.
At Day 7, we hand you an executive audit report of every hidden transitive path."
```

---

## 4. One-Page Mutual Shadow-Mode Pilot Agreement (SLA)

### Terms of Pilot Engagement:

1. **Deployment Scope**:
   - Customer deploys ChidFlow in **Passive Shadow Mode** within their staging or testing Kubernetes / ECS environment.
   - ChidFlow observes tool calls, calculates Min-Cut reachability, and logs simulated verdicts.
   - **Zero Traffic Disruption Guarantee**: In Shadow Mode, ChidFlow never blocks or terminates live agent execution.

2. **Performance Benchmarks (Success Criteria)**:
   - **Latency Overhead**: Mean evaluation latency strictly $< 1.0\text{ ms}$ per tool invocation.
   - **Accuracy**: $100\%$ detection of mutually agreed simulated injection test vectors.
   - **False Positive Rate**: Zero false positives on verified benign customer workload traces.
   - **Compliance Readiness**: Generation of complete cryptographic audit dossiers for all audited interactions.

3. **Commercial Conversion**:
   - Upon meeting the performance benchmarks at Day 14, Customer transitions from Shadow Mode to **Active Invariant Enforcement** under an annual enterprise license ($30,000 – $50,000 ARR per cluster).

---

## 5. The 14-Day Implementation Roadmap

```
Day 1 - 2: Architecture Alignment & Asset Classification
  • Identify the customer's "Treasure" (core DB tables, payment APIs, KMS keys).
  • Deploy ChidFlow container or Python middleware in shadow mode:
    `chid shadow --trace-file staging_logs.json`

Day 3 - 6: Passive Tap Monitoring
  • Ingest live staging agent interactions.
  • Verify latency overhead remains < 0.4ms under concurrent agent traffic.

Day 7: The Mid-Point Audit Review
  • Generate executive Markdown dossier using `chid shadow --export report.md`.
  • Walk the CTO through detected transitive paths and shadow violations.

Day 8 - 12: Red Team Verification
  • Customer's security team injects adversarial prompts and multi-hop delegation attacks.
  • Confirm 100% interception at the Min-Cut boundary.

Day 13 - 14: Transition to Active Enforcement & Contract Signing
  • Flip switch from Shadow Mode to Active Enforcement (`@client.guard`).
  • Sign annual enterprise agreement.
```
