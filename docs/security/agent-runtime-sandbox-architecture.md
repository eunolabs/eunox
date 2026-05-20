# Agent Runtime Sandbox Architecture

> **Author role:** Principal Platform & Security Architect
> **Date:** May 2026
> **Scope:** Runtime sandboxing and egress restriction for the `agent-runtime` service.
> **Related files:** `k8s/agent-runtime.yaml`, `k8s/seccomp/agent-runtime.json`,
> `k8s/network-policies.yaml`, `euno-platform/packages/agent-runtime/`

---

## 1. Threat Model

The adversary is the **agent process itself**, not an external attacker.
Attack scenarios in scope:

| Scenario | Vector |
|----------|--------|
| Prompt injection | Malicious tool output or user prompt causes the agent to issue unintended tool calls |
| Supply-chain compromise | Malicious NPM package opens a reverse shell or exfiltrates tokens |
| LLM-induced jailbreak | Agent LLM is instructed to exfiltrate the bearer/DPoP key |
| Kernel exploit | Agent exploits a Node.js or Linux CVE to escape the container |

**Out of scope:** model alignment, content filtering, training-phase sandboxing.

**Security objective:** the agent can _only_ make outbound connections to the
designated Tool Gateway and Capability Issuer — no arbitrary egress, no
filesystem writes outside declared scratch volumes, no shell access, no kernel
exploits upward.

---

## 2. Existing Controls (Baseline)

The following controls were already implemented before the hardening described in
this document:

| Layer | Mechanism | File |
|-------|-----------|------|
| Network egress | Kubernetes `NetworkPolicy` — default-deny + explicit allow to gateway/issuer/DNS | `k8s/network-policies.yaml` |
| Namespace PSA | `pod-security.kubernetes.io/enforce: restricted` | `k8s/pod-security-standards.yaml` |
| Capabilities | `--cap-drop ALL` | `k8s/agent-runtime.yaml` |
| Root filesystem | `readOnlyRootFilesystem: true` | `k8s/agent-runtime.yaml` |
| Privilege escalation | `allowPrivilegeEscalation: false` | `k8s/agent-runtime.yaml` |
| Non-root UID | UID/GID 1000 | `k8s/agent-runtime.yaml`, `Dockerfile` |
| Seccomp | `RuntimeDefault` (Docker's default blocklist) | `k8s/agent-runtime.yaml` |
| Soft policy pre-screen | AGT in-process guard — checks tool name against capability manifest | `src/agt-guard.ts` |
| Hard enforcement | Tool Gateway — cryptographic token verification, audit chain | `tool-gateway` package |
| DPoP (optional) | Sender-constrained tokens — stolen bearer is unusable without the private key | `src/runtime.ts` |

---

## 3. Gap Analysis

Mapping the five enforcement tiers from the threat model to current status:

| Tier | Mechanism | Status |
|------|-----------|--------|
| 1 | Hypervisor-level tap iptables (Firecracker) | ❌ Not implemented — plain OCI |
| 2 | Network namespace + iptables | ✅ Kubernetes `NetworkPolicy` (CNI-enforced) |
| 3 | WASM capability grant | ❌ Not applicable (Node.js runtime) |
| 4 | Landlock + custom seccomp allowlist | ⚠️ `RuntimeDefault` blocklist only; no Landlock |
| 5 | AppArmor/SELinux profiles | ⚠️ None defined for agent pods |

### Gap 1 — No gVisor / Kata runtime class (shared host kernel)
Agent pods run on the host kernel. A Node.js CVE or kernel 0-day from inside
the container is a full escape. `docs/sandboxing.md` calls for gVisor/Kata
Containers but this is not wired in any manifest.

### Gap 2 — Custom seccomp allowlist absent
`RuntimeDefault` is Docker's blocklist of ~50 syscalls. A tailored Node.js 18
allowlist blocks ~90% more of the exploitable syscall surface (e.g. `ptrace`,
`mount`, `clone(CLONE_NEWUSER)`, `bpf`, `io_uring`, `keyctl`,
`perf_event_open`).

### Gap 3 — `AUTH_TOKEN` in environment variable
`AUTH_TOKEN` is required as a plain env var (visible in `kubectl describe pod`,
stored in a `Secret`). It should be obtained via projected workload identity
(Azure Workload Identity, SPIRE SVID, or a short-TTL projected service account
token) and supplied through `AgentRuntimeConfig.authTokenProvider`.

### Gap 4 — ServiceAccount token automounting
The `agent-runtime` ServiceAccount has `automountServiceAccountToken` unset
(defaults to `true`). The agent process has no legitimate reason to call the
Kubernetes API; the projected token enlarges the attack surface.

### Gap 5 — Unbounded `emptyDir` volumes
`/tmp`, `/app/tmp`, `/app/logs` have no `sizeLimit`. A misbehaving agent can
fill node disk, causing a node-wide eviction cascade (DoS to other workloads).

### Gap 6 — Plain HTTP to gateway
`GATEWAY_URL` defaults to `http://envoy-shard-router:3002`. Network-level
attackers inside the cluster can observe tool calls. DPoP mitigates bearer-token
theft but not content confidentiality.

---

## 4. Implemented Hardening (this PR)

### 4.1 Custom seccomp allowlist — `k8s/seccomp/agent-runtime.json`

A tight syscall allowlist for Node.js 18 running as a plain HTTPS client.
All unlisted syscalls return `EPERM`. Explicitly blocked (belt-and-suspenders):

- `ptrace` — process inspection / injection
- `mount` / `umount2` — filesystem namespace manipulation
- `clone` with `CLONE_NEWUSER` — user-namespace privilege escalation
- `setuid` / `setgid` / `setresuid` — credential escalation
- `bpf` — eBPF program loading
- `io_uring_setup` / `io_uring_enter` — io_uring (frequent exploit vector)
- `perf_event_open` — side-channel / speculative execution instrumentation
- `keyctl` / `add_key` / `request_key` — kernel keyring manipulation
- `init_module` / `finit_module` — kernel module loading

The profile is deployed to cluster nodes and referenced via
`seccompProfile.type: Localhost` in the pod spec.

### 4.2 Disable ServiceAccount token automounting

`automountServiceAccountToken: false` on the `agent-runtime` ServiceAccount
removes the projected Kubernetes API token from the pod filesystem entirely.

### 4.3 Volume size limits

All `emptyDir` volumes are capped:
- `/tmp` and `/app/tmp` — 64 MiB
- `/app/logs` — 128 MiB

This prevents a compromised agent from exhausting node disk storage.

### 4.4 `runtimeClassName` annotation (operator-configurable)

The pod spec carries a commented-out `runtimeClassName` block with instructions
for enabling AKS Pod Sandboxing (`kata-mshv-vm-isolation`) or gVisor
(`gvisor`). Activating either gives the agent a fully isolated kernel — the
highest-confidence defence against container-escape exploits.

**AKS:** enable `--workload-runtime KataMshvVmIsolation` on the agent node pool.
**Self-managed K8s:** add a gVisor node pool; label it and schedule agent pods there.

---

## 5. Remaining Recommendations (not implemented)

### P1 — Replace static `AUTH_TOKEN` with workload identity

Use **Azure Workload Identity** (AKS) or **SPIRE** to federate the agent's
pod identity to the Capability Issuer without any stored secret:

1. Annotate the `agent-runtime` ServiceAccount with
   `azure.workload.identity/client-id: <managed-identity-client-id>`.
2. Mount the projected OIDC token at `/var/run/service-account/token`.
3. Implement `AgentRuntimeConfig.authTokenProvider` to exchange the OIDC token
   for a capability token via the issuer's `/api/v1/issue` endpoint.

### P2 — Enable HTTPS with mTLS between agent and gateway

Change `GATEWAY_URL` to `https://` and configure mTLS via:
- **Istio / Linkerd** (automatic per-pod SPIFFE mTLS), or
- **cert-manager** cluster-internal CA + projected certificate volumes.

### P3 — Landlock self-restriction in `main.ts`

Compile a small `landlock-wrapper` binary (Rust or C) that installs Landlock
network restrictions (port 3001 + 3002 only) then `execve()`s Node. Use it as
the container `CMD`. Requires Linux ≥ 6.7 (available in AKS node pools as of
2025).

### P3 — Ephemeral per-session pods

For untrusted agent code or multi-tenant deployments, replace the long-lived
`agent-runtime` Deployment with a Kubernetes `Job` per agent session. Use
[`kubernetes-sigs/agent-sandbox`](https://github.com/kubernetes-sigs/agent-sandbox)
`SandboxWarmPool` to pre-warm pods and hide cold-start latency.

### P3 — Cilium L7 `CiliumNetworkPolicy`

If the cluster uses Cilium CNI (AKS default since 2024), replace the standard
`NetworkPolicy` objects with `CiliumNetworkPolicy` resources enforced at eBPF
TC layer. Add an L7 rule restricting the agent to `POST /api/v1/invoke` only
(blocking admin endpoints at the network layer).

---

## 6. Environment Decision Matrix

| Deployment scenario | Recommended primary sandbox | Secondary layers |
|--------------------|-----------------------------|-----------------|
| **AKS (current)** | AKS Pod Sandboxing (`kata-mshv-vm-isolation`) | NetworkPolicy ✅, cap-drop ✅, custom seccomp ✅ |
| **Self-managed K8s** | gVisor node pool (`runtimeClassName: gvisor`) | same |
| **On-prem / docker-compose** | Firecracker + jailer (host iptables on tap) | read-only rootfs, non-root UID |
| **Edge** | WASM (wasmtime, if agent compiled to WASM) | Landlock + seccomp wrapper |
| **Serverless (Fly, Lambda)** | Platform microVM (Firecracker-backed) | already provided |

The network enforcement layer (`NetworkPolicy`) is the critical piece — everything
else is defence-in-depth that builds on it. The highest-value next step for this
deployment is enabling the `runtimeClassName` for gVisor/Kata on the agent node
pool to eliminate the shared-kernel risk.

---

## 7. Enforcement Confidence Hierarchy

1. **Hypervisor-level iptables on tap** (Firecracker) — agent kernel is separate; cannot touch host network rules.
2. **Network namespace + iptables** (Kubernetes `NetworkPolicy`) — enforced in host kernel; a kernel exploit breaks it. **Current primary control.**
3. **Custom seccomp allowlist** — removes ~90% of exploitable syscall surface; bypassed by a kernel 0-day. **Added in this PR.**
4. **`emptyDir` size limits** — prevents disk exhaustion DoS. **Added in this PR.**
5. **`automountServiceAccountToken: false`** — removes Kubernetes API credential. **Added in this PR.**
6. **Landlock + seccomp** — process-level; bypassed by privilege escalation. **Recommended future work.**
7. **AppArmor/SELinux profiles** — useful but coarse for network. **Recommended future work.**
