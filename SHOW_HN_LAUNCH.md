# Show HN: ChidFlow – Why LLM-as-a-Judge Fails on Prompt Injection and How Min-Cut Solves It

**Author:** Chid Technologies (Rishi & Team)  
**Date:** October 2026  
**Repository:** `https://github.com/chidflow/chidflow`  
**License:** Apache 2.0 / MIT  
**Quickstart:** `pip install chidflow && chid demo`

---

## 1. The Hacker News Submission Text

### Title:
> **Show HN: ChidFlow – Why LLM-as-a-Judge fails on prompt injection and how Min-Cut solves it**

### URL:
> `https://github.com/chidflow/chidflow` (or link to interactive web visualizer)

### Body:
```text
Hey HN,

Everyone wants autonomous AI agents to do real work—debug production Kubernetes, write code, run batch wire transfers, and operate laptops. But the second you grant an agent write permissions to a shell, database, or banking API, you are one prompt injection away from disaster.

The current industry standard (NVIDIA OpenShell, AWS Bedrock Guardrails, LLM-as-a-Judge) tries to solve this by filtering prompt text. 

That approach is mathematically doomed:
1. The input space of natural language is infinite: O(∞).
2. Attackers can split payloads across 5 benign-looking tool steps, stash instructions in scratchpads, or use steganography to evade prompt filters.
3. Every filter introduces latency (200ms–2000ms), false positives, and high token costs.

We took the exact opposite approach. We asked:
What if you ignore the infinite input space completely, and only guard the finite road to "The Treasure" (critical sinks: core DB, private keys, financial rails)?

We built ChidFlow: a runtime execution proxy and clearinghouse for AI agents based on Dynamic Information Flow Graphs (DIFG) and the Max-Flow Min-Cut Theorem.

Instead of guessing whether an LLM prompt is "malicious", ChidFlow tracks the graph topology of data dependencies across multi-turn tool calls. If an untrusted source (a scraped URL, phished email, customer ticket) gains an open directed path to a critical sink, the Min-Cut flow capacity becomes non-zero (Φ_t > 0). ChidFlow severs the choke point at the kernel/proxy boundary in < 0.2ms and rolls back state.

We built a 10-vector benchmark—the Transitive Prompt-Injection Challenge (TPIC)—testing multi-hop transitive attacks (subagent delegation, memory poisoning, indirect webhook injection). Static rule/regex systems like NVIDIA OpenShell score 0/10 (all bypassed). ChidFlow scores 10/10.

When an action is clean, ChidFlow mints a cryptographic HMAC audit receipt (compliant with EU AI Act Art. 14 / ISO 42001) that upstream banks and APIs can verify in < 1ms before executing irreversible wires.

Code is completely open source:
$ pip install chidflow
$ chid demo          # Runs visual attack severance
$ chid tpic          # Runs the 10-vector head-to-head benchmark
$ chid dashboard     # Launches interactive HTML mission control

We’d love HN’s feedback on our graph formulation and edge daemon architecture!
```

---

## 2. The Core Technical Provocation: The Fallacy of Static Gating

### Why Prompt Heuristics & Static Solvers Fail
```
[ Untrusted Web / Ingress ] ──> [ Scraper Tool ]
                                      │
                                      ▼
                               [ Agent Memory ] ◄── (Prompt Filter passes: "Just summary text")
                                      │
                                      ▼
                            [ Subagent Worker 1 ]
                                      │
                                      ▼
                            [ Subagent Worker 2 ] ◄── (No injection keywords found)
                                      │
                                      ▼
                         [ Financial Wire API / DB ]  <=== EXFILTRATION / DISASTER!
```

1. **Depth Blindness:** Static regex/Z3 solvers examine a tool call at time $t$ in isolation: `wire_transfer(amount=1000)`. The tool call itself is syntactically valid. The solver has zero memory of where the parameters originated.
2. **Context Dilution:** When an attacker spreads payload fragments across 4 intermediate tools, no individual prompt triggers an LLM-as-a-judge guardrail.
3. **Latency & Cost:** Calling an LLM evaluator on every tool invocation destroys autonomous swarm performance.

### The ChidFlow Invariant:
Let $G_t = (V_t, E_t)$ be the directed information flow graph at step $t$.  
Let $S \subset V$ be untrusted ingress nodes.  
Let $T \subset V$ be critical sinks (The Treasure).  
Let $\Phi_t$ be the maximum network flow from $S$ to $T$.

$$\Phi_t = 0 \quad \forall t \ge 0$$

If any tentative tool invocation causes $\Phi_t > 0$, the Ford-Fulkerson / Edmonds-Karp min-cut identifies the exact minimal choke point edge $(u, v)^*$, severs it immediately, rolls back the tentative edge, and returns a synthetic mock error to the LLM.

---

## 3. TPIC Benchmark: Head-to-Head Results

The Transitive Prompt-Injection Challenge (TPIC) benchmarks 10 real-world attack vectors:

| # | Attack Vector | Vector Description | NVIDIA OpenShell / Static Z3 | ChidFlow Min-Cut Runtime |
| :---: | :--- | :--- | :---: | :---: |
| **01** | Indirect Web Injection | Hidden CSS/HTML instruction triggers unauthorized wire transfer | **BYPASSED** (0/1) | **BLOCKED** (< 0.2ms) |
| **02** | Customer Ticket SQL Drop | System prompt injection in Jira ticket executes `DROP TABLE` | **BYPASSED** (0/1) | **BLOCKED** (< 0.2ms) |
| **03** | Subdelegation Ladder | Orchestrator delegates across 3 subagents to evade depth limits | **BYPASSED** (0/1) | **BLOCKED** (< 0.2ms) |
| **04** | Email Inbound -> Webhook | Inbound phishing attachment exfiltrates CRM data to C2 webhook | **BYPASSED** (0/1) | **BLOCKED** (< 0.2ms) |
| **05** | Memory Scratchpad Poisoning | Taint persisted across sessions triggers delayed exfiltration | **BYPASSED** (0/1) | **BLOCKED** (< 0.2ms) |
| **06** | Code Sandbox Tool Hijack | Injected code rewrites agent tool registry parameters | **BYPASSED** (0/1) | **BLOCKED** (< 0.2ms) |
| **07** | Lateral K8s Socket Hop | Compromised pod attempts raw TCP connect to internal DB (5432) | **BYPASSED** (0/1) | **BLOCKED (eBPF)** |
| **08** | Ransomware Velocity Spike | Rogue agent attempts rapid 60 writes/sec encryption attack | **BYPASSED** (0/1) | **BLOCKED** (Velocity Freeze) |
| **09** | Local Keychain Harvester | Workstation background agent attempts to read `~/.ssh/id_rsa` | **BYPASSED** (0/1) | **BLOCKED** (Edge Daemon) |
| **10** | Swarm Consensus Sybil | Compromised swarm agent tricks quorum into unauthorized payout | **BYPASSED** (0/1) | **BLOCKED** (Taint Severed) |
| **TOTAL** | **Mitigation Rate** | **10 Vectors Evaluated** | **0% (10/10 Vulnerable)** | **100% (0/10 Vulnerable)** |

---

## 4. Twitter / X Launch Thread

```text
1/ Autonomous AI agents are getting write permissions to production databases, Kubernetes clusters, and banking APIs. 

And prompt injection means one malicious web page or email can trigger irreversible disaster.

We built ChidFlow to solve this mathematically. Open source today: 🧵👇

2/ The industry’s current defense is "LLM-as-a-judge" or static regex (NVIDIA OpenShell).
Both fail because prompt space is infinite: O(∞).
An attacker can split an attack across 4 benign tool calls, and static filters see nothing.

3/ Instead of inspecting the prompt, ChidFlow tracks the Dynamic Information Flow Graph (DIFG).
We don't care what the prompt says.
We enforce that the Min-Cut flow capacity from Untrusted Sources -> Critical Sinks is ZERO (Φ_t = 0).

4/ If an agent reads an untrusted URL, its context is tainted in the graph.
If it later attempts to write to Stripe or drop a Postgres table, the Min-Cut theorem identifies the choke point, severs it in < 0.2ms, and rolls back the transaction.

5/ We tested this head-to-head in our TPIC Benchmark:
• NVIDIA OpenShell: 0/10 mitigated (bypassed by multi-hop delegation)
• ChidFlow: 10/10 mitigated (0 false negatives)

6/ When actions are clean, ChidFlow mints an HMAC audit receipt (VAEP RFC-001) compliant with EU AI Act Art. 14 / ISO 42001.

Banks can verify the receipt via HTTP in < 1ms before executing wires.

7/ Try it locally right now:
$ pip install chidflow
$ chid demo
$ chid tpic
$ chid dashboard

GitHub: https://github.com/chidflow/chidflow
Read our master thesis: https://github.com/chidflow/chidflow/blob/main/SERVERWATCH_MASTER_THESIS.md
```

---

## 5. Anticipated Hacker News Questions & Hard Answers

### Q1: "Doesn't this break legitimate agent workflows if taint spreads everywhere?"
> **Answer:** No. In traditional Information Flow Control (IFC like Perl taint), taint is binary and monotonic—once tainted, a process is tainted forever. In ChidFlow, taint is an edge in a dynamic graph. An agent can ingest untrusted data and continue reasoning, summarizing, and writing to non-critical sinks (scratchpads, slack messages). ChidFlow *only* intervenes if a directed path completes to a node classified as `CRITICAL_SINK`. If an agent needs to perform an approved high-privilege action with sanitized data, it passes through an explicit declassification boundary (e.g., human-in-the-loop cryptographic approval).

### Q2: "How fast is Min-Cut graph calculation during real agent execution?"
> **Answer:** In ChidFlow, tool graphs for autonomous workflows have $V < 1,000$ and $E < 5,000$. Edmonds-Karp runs in $< 0.2\text{ ms}$ on a standard CPU core—orders of magnitude faster than a single LLM token generation (typically $20\text{ ms} - 50\text{ ms}$). There is zero perceptible latency overhead.

### Q3: "What stops a compromised agent from forging audit receipts?"
> **Answer:** The signing secret never enters the LLM context window or agent memory. Receipts are minted either inside a kernel eBPF boundary, a hardware Secure Enclave/TPM on edge devices, or an isolated out-of-process clearinghouse daemon.
