# Agent Runtime Security Model

This document describes the security model, sandbox isolation boundaries, and
blast radius containment mechanisms for the Eunox agent runtime
(`internal/agentruntime/`).

---

## 1. Overview

The agent runtime is an embeddable Go library that AI agent frameworks (e.g.,
LangChain, CrewAI) use to acquire capability tokens, generate DPoP proofs, and
invoke tools through the Eunox Tool Gateway. It operates under a **zero ambient
authority** principle: an agent starts with no access and must prove possession
of a valid, scoped capability token for every side-effecting operation.

---

## 2. Security Architecture

### 2.1 Trust Boundaries

```
┌─────────────────────────────────────────────────────────────────────┐
│  UNTRUSTED ZONE — Agent Sandbox                                     │
│                                                                     │
│  ┌──────────────────────────────────────┐                           │
│  │  Agent Process (LLM + tools)         │                           │
│  │  ├── agentruntime library            │                           │
│  │  │   ├── TokenProvider (caches JWT)  │                           │
│  │  │   ├── DPoP key pair (ephemeral)   │                           │
│  │  │   └── ToolInvoker                 │                           │
│  │  └── Application code                │                           │
│  └──────────────────────────────────────┘                           │
│           │ HTTPS only (network egress restricted)                   │
│           ▼                                                         │
├─────────────────────────────────────────────────────────────────────┤
│  TRUSTED ZONE — Platform Services                                   │
│                                                                     │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────────┐    │
│  │  Issuer      │   │  Gateway     │   │  Protected Backends  │    │
│  │  (port 3001) │   │  (port 3002) │   │  (CRM, DB, Storage)  │    │
│  └──────────────┘   └──────────────┘   └──────────────────────┘    │
│                                                                     │
│  ┌──────────────┐   ┌──────────────┐   ┌──────────────────────┐    │
│  │  Redis       │   │  KMS/HSM     │   │  Audit Ledger        │    │
│  └──────────────┘   └──────────────┘   └──────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
```

**Key trust boundary:** The agent process is entirely within the untrusted zone.
It cannot:

- Directly access protected backends (network policies block egress)
- Forge capability tokens (requires KMS private key)
- Replay tokens (DPoP binds tokens to specific method+URL)
- Bypass enforcement (gateway is the sole ingress to backends)

### 2.2 Credential Exposure

| Secret                 | Resides In   | Exposure Window                   | Mitigation                               |
| ---------------------- | ------------ | --------------------------------- | ---------------------------------------- |
| Capability token (JWT) | Agent memory | Until expiry (typically 5–15 min) | Short TTL, DPoP binding, revocation list |
| DPoP private key       | Agent memory | Lifetime of runtime instance      | Ephemeral P-256 key, never persisted     |
| Identity token         | Agent memory | Until first exchange or expiry    | One-time use or short-lived OIDC token   |

The agent never holds:

- KMS keys (signing happens server-side)
- Database credentials (minted on-demand by DB Token Service)
- Storage secrets (presigned URLs issued by Storage Grant Service)
- Redis connection strings
- Admin API keys

---

## 3. Sandbox Isolation Mechanisms

### 3.1 Kubernetes Environments

The agent sandbox architecture uses layered isolation:

#### Layer 1: Kernel/VM Isolation

| Platform      | Technology                       | Boundary                                   |
| ------------- | -------------------------------- | ------------------------------------------ |
| AKS           | Kata Containers (Pod Sandboxing) | Separate lightweight VM per pod            |
| GKE Autopilot | gVisor (GKE Sandbox)             | Syscall interception via user-space kernel |
| EKS           | Firecracker microVMs (via Kata)  | Hardware-virtualized isolation             |

Each agent pod runs in a separate kernel context. A compromised agent cannot
access host kernel data structures, /proc of other containers, or shared memory.

#### Layer 2: Container Security Controls

```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 65534 # nobody
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
  seccompProfile:
    type: RuntimeDefault
```

- **Non-root execution**: Agent runs as unprivileged user
- **Read-only rootfs**: No filesystem writes except to designated tmpfs mounts
- **Dropped capabilities**: No `CAP_NET_RAW`, `CAP_SYS_ADMIN`, etc.
- **Seccomp filtering**: Only permitted syscalls allowed

#### Layer 3: Network Isolation

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: agent-sandbox-egress
spec:
  podSelector:
    matchLabels:
      eunox.io/role: agent
  policyTypes: ["Egress"]
  egress:
    - to:
        - podSelector:
            matchLabels:
              eunox.io/role: gateway
      ports:
        - port: 3002
          protocol: TCP
    - to:
        - podSelector:
            matchLabels:
              eunox.io/role: issuer
      ports:
        - port: 3001
          protocol: TCP
```

The agent can **only** communicate with:

1. The Capability Issuer (to acquire tokens)
2. The Tool Gateway (to invoke tools)

All other egress is denied. DNS is restricted to cluster-internal resolution.

#### Layer 4: Resource Limits

```yaml
resources:
  limits:
    cpu: "2"
    memory: "4Gi"
    ephemeral-storage: "1Gi"
  requests:
    cpu: "500m"
    memory: "1Gi"
```

Prevents resource exhaustion attacks (fork bombs, memory bombs, disk filling).

### 3.2 Non-Kubernetes Environments

For bare-metal, VM, or standalone container deployments:

| Mechanism                                 | Purpose                                 |
| ----------------------------------------- | --------------------------------------- |
| Firecracker microVM                       | Full VM isolation without K8s           |
| Docker `--security-opt=no-new-privileges` | Prevent privilege escalation            |
| `--cap-drop=ALL`                          | Remove all Linux capabilities           |
| `--read-only`                             | Immutable root filesystem               |
| AppArmor/SELinux profiles                 | MAC enforcement                         |
| iptables/nftables                         | Restrict egress to gateway only         |
| cgroups v2                                | Resource limits (CPU, memory, I/O)      |
| Overlay filesystem                        | Ephemeral write layer destroyed on exit |

---

## 4. Tool Execution Security

### 4.1 How Tool Execution Works

The agent runtime does **not** execute tools directly. Instead:

1. Agent proposes a tool call (name, arguments)
2. `ToolInvoker.Invoke()` sends the request to the gateway's `/api/v1/enforce`
3. Gateway verifies the capability token, evaluates conditions
4. If **allowed**: gateway proxies the request to the upstream backend
5. If **denied**: gateway returns a denial response with reason

The agent never has direct network access to protected backends.

### 4.2 What Prevents Privilege Escalation?

| Attack Vector                       | Mitigation                                                                |
| ----------------------------------- | ------------------------------------------------------------------------- |
| Forge token claims                  | JWT signed by KMS; agent has no signing key                               |
| Replay token for different endpoint | DPoP binds token to specific HTTP method + URL                            |
| Reuse JTI (replay attack)           | Gateway maintains JTI replay cache                                        |
| Escalate scope mid-session          | Tokens are immutable; new token requires re-issuance                      |
| Tamper with tool arguments          | Arguments are evaluated by gateway against capability conditions          |
| Call unauthorized backend directly  | NetworkPolicy blocks all egress except gateway/issuer                     |
| Prompt injection to bypass controls | Enforcement is external to agent — prompt injection cannot bypass gateway |
| Exfiltrate data via side channels   | Network isolation prevents covert channels; audit logs detect anomalies   |

### 4.3 Timeout Enforcement

Tool execution timeouts are enforced end-to-end:

```
Agent timeout (context.WithTimeout)
    └── ToolInvoker timeout (context propagation)
        └── HTTPClient timeout (30s default, configurable)
            └── Gateway enforcement timeout (per-request deadline)
                └── Upstream backend timeout (gateway-enforced)
```

- The agent's `context.Context` carries deadlines through the entire call chain
- If context is cancelled (timeout or explicit cancellation), all in-flight requests abort
- The HTTP client enforces a maximum response body size (10 MB) to prevent DoS
- The gateway independently enforces its own per-request timeout

### 4.4 Blast Radius Containment

If an agent is compromised:

| Blast Radius       | Contained By                                                               |
| ------------------ | -------------------------------------------------------------------------- |
| **Within session** | Token scoped to specific tools/resources; conditions enforce action limits |
| **Cross-session**  | Each session has independent token; kill switch terminates by session ID   |
| **Cross-agent**    | Network isolation prevents lateral movement; DID-scoped kill switch        |
| **Cross-tenant**   | Tenant isolation at every layer (tokens, Redis keys, audit partitions)     |
| **Infrastructure** | VM/gVisor boundary prevents host compromise                                |

Operator response path:

1. Kill switch (session or agent scope) — propagates in <1s via pub/sub
2. Token revocation — immediate denial on next gateway call
3. Global kill switch — blocks all agent traffic fleet-wide

---

## 5. DPoP (Demonstration of Proof-of-Possession)

### 5.1 Key Generation

Each `Runtime` instance generates a fresh ECDSA P-256 key pair at startup:

```go
dpop, err := NewDPoPProofGenerator()
// Generates crypto/ecdsa P-256 key pair using crypto/rand
// Computes JWK Thumbprint (RFC 7638) for key binding
```

The private key exists only in memory and is never persisted or transmitted.

### 5.2 Proof Structure

Each tool invocation includes a DPoP proof JWT:

```json
{
  "typ": "dpop+jwt",
  "alg": "ES256",
  "jwk": { "kty": "EC", "crv": "P-256", "x": "...", "y": "..." }
}
{
  "jti": "<unique-id>",
  "htm": "POST",
  "htu": "https://gateway.example.com/api/v1/enforce",
  "iat": 1716767940,
  "nonce": "<server-provided-nonce>"
}
```

### 5.3 Verification (Gateway Side)

The gateway verifies DPoP proofs by:

1. Computing JWK thumbprint from the proof's public key
2. Verifying it matches the `cnf.jkt` claim in the capability token
3. Verifying `htm` matches the request HTTP method
4. Verifying `htu` matches the request URL
5. Verifying `jti` has not been seen before (replay detection)
6. Length-prefixed hash input prevents concatenation collision attacks

---

## 6. Failure Modes and Resilience

### 6.1 Token Provider Failures

The token provider implements graceful degradation:

| Failure                     | Behavior                                                                          |
| --------------------------- | --------------------------------------------------------------------------------- |
| Issuer unreachable          | Circuit breaker opens after threshold; serves stale token for 60s grace period    |
| Token expired during outage | Returns error after grace period; agent must handle denial                        |
| Clock skew                  | Refresh triggers 30s before expiry to absorb minor skew                           |
| Network partition           | Retry with exponential backoff + jitter; circuit breaker prevents thundering herd |

### 6.2 Gateway Failures

| Failure               | Behavior                                                |
| --------------------- | ------------------------------------------------------- |
| Gateway returns 5xx   | Transient retry (up to 3 attempts with backoff)         |
| Gateway returns 429   | Transient retry with backoff; respects Retry-After      |
| Gateway unreachable   | Same as 5xx; network isolation means no bypass possible |
| Gateway denies action | Non-retryable; returns denial to agent                  |

### 6.3 Agent Misbehavior Detection

The platform detects agent misbehavior through:

- **Audit trail analysis**: Unusual patterns trigger alerts (many denials, scope probing)
- **Rate limiting**: Per-agent and per-session rate limits
- **Call counting**: Action budgets tracked via Redis call counters
- **Kill switch**: Immediate termination on detection

---

## 7. Configuration Reference

| Parameter               | Default    | Description                                       |
| ----------------------- | ---------- | ------------------------------------------------- |
| `IssuerURL`             | (required) | Capability issuer endpoint                        |
| `GatewayURL`            | (required) | Tool Gateway enforcement endpoint                 |
| `IdentityToken`         | —          | Static identity token for authentication          |
| `IdentityTokenProvider` | —          | Dynamic identity token provider                   |
| `RefreshBeforeExpiry`   | 30s        | Proactive refresh window                          |
| `MaxRetries`            | 3          | Max retry attempts for transient errors           |
| `RetryBaseDelay`        | 100ms      | Initial backoff delay                             |
| `RetryMaxDelay`         | 5s         | Maximum backoff delay                             |
| `DPoPEnabled`           | true       | Enable proof-of-possession                        |
| `HTTPClient`            | (default)  | Custom HTTP client (30s timeout, 10MB body limit) |

---

## 8. Threat Model Summary

| Threat                  | Likelihood | Impact   | Mitigation                                            | Residual Risk                         |
| ----------------------- | ---------- | -------- | ----------------------------------------------------- | ------------------------------------- |
| Token theft             | Medium     | Medium   | Short TTL, DPoP binding, revocation                   | Stale-token grace window (60s)        |
| Prompt injection        | High       | Medium   | External enforcement (gateway), not in-agent          | Agent may waste quota on denied calls |
| Container escape        | Low        | Critical | Kata/gVisor/Firecracker VM boundary                   | Zero-day in VM technology             |
| Supply chain compromise | Low        | High     | Immutable images, signed manifests                    | Compromised base image                |
| Network-level attack    | Low        | Medium   | mTLS, NetworkPolicy, no ambient egress                | DNS rebinding (mitigated by policy)   |
| DPoP key extraction     | Low        | Low      | Ephemeral key, per-instance; token still time-limited | Memory forensics on live process      |

---

## 9. Recommendations for Operators

1. **Always deploy with kernel isolation** (Kata, gVisor, or Firecracker) for
   production workloads handling sensitive data.
2. **Set aggressive token TTLs** (5–15 minutes) to minimize exposure window.
3. **Monitor audit logs** for denial patterns and scope probing.
4. **Configure kill switch pub/sub** for sub-second agent termination.
5. **Use NetworkPolicy** even in development to catch accidental direct
   backend calls early.
6. **Rotate DPoP nonces** by configuring the gateway's nonce rotation interval.
7. **Enable call counting** to enforce per-agent action budgets.

---

## 10. Related Documents

- [Sandboxing Reference Architecture](sandboxing.md) — Full sandbox implementation guide
- [Distributed State](distributed-state.md) — Kill switch and revocation architecture
- [Architecture Overview](architecture.md) — System-wide component interactions
- [Deployment Guide](deployment.md) — Production deployment patterns
- [Redis Failure Modes](redis-failure-modes.md) — Failure mode policies for Redis-dependent components
