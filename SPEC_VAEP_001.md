# RFC-001: Verifiable Agent Execution Protocol (VAEP)

**Standard Track | Working Group Draft | October 2026**

---

## 1. Abstract

The **Verifiable Agent Execution Protocol (VAEP)** defines an open standard for real-time reachability governance, taint propagation, and cryptographic clearinghouse verification for autonomous AI agent tool calls.

Unlike traditional static authorization mechanisms (RBAC, ABAC, OPA) that evaluate point-in-time endpoint permissions, VAEP continuously models agent context as a **Dynamic Information Flow Graph (DIFG)** and enforces mathematical **Min-Cut isolation** prior to side-effect commitment on external execution rails (APIs, databases, and financial systems).

---

## 2. Dynamic State Graph Formalism

Let the execution environment at discrete step $t$ be represented by a directed graph:

$$\mathcal{G}_t = (\mathcal{V}_t, \mathcal{E}_t, \mathcal{C}_t)$$

Where:
- $\mathcal{V}_t$: Vertices partitioned into:
  - $\mathcal{S}_{\text{untrusted}} \subset \mathcal{V}$: Untrusted ingestion sources (scraped HTML, external webhooks, unverified user input).
  - $\mathcal{A}_{\text{context}} \subset \mathcal{V}$: Agent working memory boundaries (context window, scratchpad, subagents).
  - $\mathcal{D}_{\text{confidential}} \subset \mathcal{V}$: Confidential internal assets (CRM, PII, internal repositories).
  - $\mathcal{T}_{\text{sink}} \subset \mathcal{V}$: High-value / irreversible execution rails (payment rails, SQL writes, egress webhooks).
- $\mathcal{E}_t$: Directed information flow and permission edges.
- $\mathcal{C}_t(u, v) \in \mathbb{R}^+$: Flow capacity assigned to each edge.

---

## 3. Protocol Operations

### 3.1. Tentative State Mutation Rule
When an agent submits an execution request $m = (\text{rpc\_id}, \text{tool}, \text{args})$:
1. The proxy checkpoints $\mathcal{G}_t \to \mathcal{G}_t^{\text{snap}}$.
2. For reading tools: $\forall u \in \text{Inputs}(\text{tool}), (u \to \mathcal{A}_{\text{caller}})$ is speculatively added.
3. For writing tools: $\forall v \in \text{Outputs}(\text{tool}), (\mathcal{A}_{\text{caller}} \to v)$ is speculatively added.

### 3.2. Min-Cut Clearance Criterion
The proxy computes the maximum flow / minimum cut capacity between all active untrusted sources and critical sinks:

$$\Phi_t = \text{MaxFlow}(\mathcal{S}_{\text{untrusted}} \to \mathcal{T}_{\text{sink}})$$

$$\text{Verdict} = \begin{cases} 
\text{ALLOW \& SIGN}(\mathcal{R}_t), & \text{if } \Phi_t = 0 \\ 
\text{SEVER \& ROLLBACK}(-32001), & \text{if } \text{CutEdges}(\Phi_t) \neq \emptyset 
\end{cases}$$

If $\Phi_t > 0$, the proxy rolls back to $\mathcal{G}_t^{\text{snap}}$, terminates packet transmission to the execution rail, and returns standard JSON-RPC error code `-32001`.

---

## 4. Cryptographic Clearinghouse Receipts

Every cleared transaction MUST be accompanied by an immutable audit receipt:

$$\mathcal{R}_t = \left\{ \text{receipt\_id}, \text{seq}, \text{timestamp}, \text{tool}, \mathcal{H}_{\text{args}}, \mathcal{H}_{\text{state}}, \sigma_{\text{proxy}} \right\}$$

Where:
- $\mathcal{H}_{\text{args}} = \text{SHA256}(\text{CanonicalJSON}(\text{arguments}))$
- $\mathcal{H}_{\text{state}} = \text{SHA256}(\text{CanonicalTopology}(\mathcal{G}_t))$
- $\sigma_{\text{proxy}} = \text{HMAC-SHA256}_{K_{\text{proxy}}}(\text{seq} \parallel \text{timestamp} \parallel \text{tool} \parallel \mathcal{H}_{\text{args}} \parallel \mathcal{H}_{\text{state}})$

Upstream financial rails and audit bodies MUST verify $\sigma_{\text{proxy}}$ using the clearinghouse public key prior to settlement.
