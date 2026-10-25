# Chid Technologies: Deployment & Field Operations Manual
**Universal Invariant Runtime, Edge Daemon & Clearinghouse Substrate**
*Document Version: 1.0.0 (Production Release 2026)*

---

## 1. Quickstart & Deployment Topologies

ChidFlow and the ServerWatch invariant engine operate in three deployment topologies:

```
[ Ambient Edge Devices ]       [ Multi-Agent Swarms ]         [ Core Kubernetes Cluster ]
 (MacBooks, Mobile, Linux)       (CrewAI, LangGraph, Claude)     (Postgres, Kafka, Stripe API)
         │                                 │                                    │
         ▼                                 ▼                                    ▼
   [ Edge Daemon ]               [ ChidFlow SDK / Proxy ]            [ eBPF Socket Guard ]
  (TPM / Enclave Invariant)       (Dynamic Min-Cut Checkpoint)        (Port 5432 / KMS Invariant)
         │                                 │                                    │
         └─────────────────────────────────┼────────────────────────────────────┘
                                           ▼
                    [ Clearinghouse Verification Gateway ]
                      (HTTP / JSON-RPC RFC-001 VAEP Rails)
```

---

## 2. Installation & Local Binary Setup

### Install via pip (Editable or Production Wheel)
```bash
git clone https://github.com/chidflow/chidflow.git
cd chidflow
pip install -e .
```

### Verify Global CLI Binaries
Three global command-line aliases are installed:
```bash
# 1. Full unified multi-tool
chidflow --help

# 2. Fast developer shortcut
chid --help

# 3. Production Incident Autopilot & SRE console
serverwatch
```

---

## 3. Containerized & Kubernetes Deployment

### Option A: Docker Compose (Instant Local Stack)
```bash
docker compose up -d
```
- **Clearinghouse Gateway**: `http://localhost:8443`
- **MCP Proxy**: `http://localhost:8080`

### Option B: Kubernetes DaemonSet (eBPF Kernel Protection)
Deploy the eBPF kernel invariant sensor across every node in your production cluster:
```bash
kubectl apply -f deploy/k8s-daemonset.yaml
```

Inspect sensor health and dropped packets:
```bash
kubectl logs -n chidflow-system -l app=serverwatch-ebpf -f
```

---

## 4. Third-Party Agent Framework Integration

### A. Python Client SDK (Zero-Network In-Memory Mode)
Protect any Python agent or function in 3 lines:

```python
from chidflow import ChidFlowClient, DynamicFlowGraph, SecurityClassification

# 1. Initialize client
client = ChidFlowClient()

# 2. Define protected critical sink (The Treasure)
client.policy_engine.graph.add_node("financial_wire_rail", SecurityClassification.CRITICAL_SINK)

# 3. Guard tool execution with decorator
@client.guard(writes_to=["financial_wire_rail"])
def send_payout(recipient: str, amount_usd: float):
    return {"status": "PAID", "recipient": recipient, "amount": amount_usd}

# Ingress untrusted data (e.g. prompt injection payload)
client.policy_engine.graph.add_edge("public_internet", "agent_memory")

# Attempting execution will automatically fail-close with PermissionError
send_payout(recipient="attacker_account", amount_usd=1000000.0)
# PermissionError: ChidFlow Invariant Violation: Execution blocked.
```

### B. MCP Stdio Wrapper (Claude Desktop / Anthropic Computer Use)
Wrap any MCP tool server without modifying its source code:
```bash
chid proxy --wrap "python -m my_tools_server" --config policies/prod_rules.json
```

---

## 5. Bank & Upstream API Settlement Verification (RFC-001 VAEP)

Upstream banks, payment processors, and critical database endpoints verify receipts before committing irreversible mutations:

### HTTP Settlement Check ($< 1\text{ ms}$)
```bash
curl -X POST http://localhost:8443/v1/clearing/verify \
  -H "Content-Type: application/json" \
  -d '{
    "receipt": {
      "receipt_id": "rcpt_7f30a9e1",
      "sequence_no": 104,
      "timestamp": "2026-10-25T10:00:00Z",
      "tool_name": "stripe:charge",
      "args_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      "graph_state_hash": "a1b2c3d4e5f67890",
      "signature": "3f8a91bc74e...",
      "public_key": "pub_chid_2026_root_01"
    }
  }'
```

**Expected JSON Response:**
```json
{
  "receipt_id": "rcpt_7f30a9e1",
  "verified": true,
  "status": "SETTLEMENT_APPROVED",
  "settlement_ticket": "TKT-OK-rcpt_7f30a9e1",
  "verified_at": "2026-10-25T10:00:01Z"
}
```

---

## 6. Enterprise Field Demonstration Script (CTO Meeting)

When presenting to enterprise CTOs, SRE directors, or fintech architects, run the live demonstration suite:

```bash
# 1. Show the 10-vector Transitive Prompt-Injection benchmark vs NVIDIA OpenShell
chid tpic

# 2. Demonstrate closed-loop incident self-healing with zero blast-radius violations
serverwatch

# 3. Demonstrate ambient workstation protection (MacBook / Edge Daemon)
chid edge

# 4. Demonstrate unified multi-agent swarm consensus + min-cut clearing
chid swarm
```

### Key Talking Points for Enterprise Leaders
1. **Zero Guesswork / Zero LLM-as-a-Judge**: We don't evaluate prompts with heuristics. We evaluate reachability over directed information flow graphs ($O(V+E)$).
2. **Mathematically Guaranteed Blast Radius**: The invariant guarantees $\Phi_t = 0$. Critical sinks cannot be reached regardless of agent hallucination or prompt injection.
3. **Regulatory Non-Repudiation**: Every permitted state mutation issues a cryptographically signed HMAC receipt compliant with EU AI Act Article 14 and ISO 42001.
