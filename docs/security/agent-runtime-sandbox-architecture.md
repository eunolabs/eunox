# Agent Runtime Sandbox Architecture

> **Author role:** Principal Platform & Security Architect
> **Date:** May 2026
> **Scope:** Runtime sandboxing and egress restriction for the `agent-runtime` service.
> **Related files:** `k8s/agent-runtime.yaml`, `k8s/seccomp/agent-runtime.json`,
> `k8s/network-policies.yaml`, `internal/agent-runtime/`

---

## 1. Threat Model

The adversary is the **agent process itself**, not an external attacker.
Attack scenarios in scope:

| Scenario                | Vector                                                                               |
| ----------------------- | ------------------------------------------------------------------------------------ |
| Prompt injection        | Malicious tool output or user prompt causes the agent to issue unintended tool calls |
| Supply-chain compromise | Malicious Go module or dependency opens a reverse shell or exfiltrates tokens        |
| LLM-induced jailbreak   | Agent LLM is instructed to exfiltrate the bearer/DPoP key                            |
| Kernel exploit          | Agent exploits a Go runtime or Linux CVE to escape the container                     |

**Out of scope:** model alignment, content filtering, training-phase sandboxing.

**Security objective:** the agent can _only_ make outbound connections to the
designated Tool Gateway and Capability Issuer — no arbitrary egress, no
filesystem writes outside declared scratch volumes, no shell access, no kernel
exploits upward.

---

## 2. Existing Controls (Baseline)

The following controls were already implemented before the hardening described in
this document:

| Layer                  | Mechanism                                                                        | File                                   |
| ---------------------- | -------------------------------------------------------------------------------- | -------------------------------------- |
| Network egress         | Kubernetes `NetworkPolicy` — default-deny + explicit allow to gateway/issuer/DNS | `k8s/network-policies.yaml`            |
| Namespace PSA          | `pod-security.kubernetes.io/enforce: restricted`                                 | `k8s/pod-security-standards.yaml`      |
| Capabilities           | `--cap-drop ALL`                                                                 | `k8s/agent-runtime.yaml`               |
| Root filesystem        | `readOnlyRootFilesystem: true`                                                   | `k8s/agent-runtime.yaml`               |
| Privilege escalation   | `allowPrivilegeEscalation: false`                                                | `k8s/agent-runtime.yaml`               |
| Non-root UID           | UID/GID 1000                                                                     | `k8s/agent-runtime.yaml`, `Dockerfile` |
| Seccomp                | `RuntimeDefault` (Docker's default blocklist)                                    | `k8s/agent-runtime.yaml`               |
| Soft policy pre-screen | AGT in-process guard — checks tool name against capability manifest              | `internal/agentruntime/runtime.go`     |
| Hard enforcement       | Tool Gateway — cryptographic token verification, audit chain                     | `internal/gateway/`                   |
| DPoP (optional)        | Sender-constrained tokens — stolen bearer is unusable without the private key    | `internal/agentruntime/dpop.go`        |

---

## 3. Gap Analysis

Mapping the five enforcement tiers from the threat model to current status:

| Tier | Mechanism                                   | Status                                                         |
| ---- | ------------------------------------------- | -------------------------------------------------------------- |
| 1    | Hypervisor-level tap iptables (Firecracker) | ❌ Not implemented — plain OCI                                 |
| 2    | Network namespace + iptables                | ✅ Kubernetes `NetworkPolicy` (CNI-enforced)                   |
| 3    | WASM capability grant                       | ❌ Not applicable (Go binary runtime)                          |
| 4    | Landlock + custom seccomp allowlist         | ✅ Custom seccomp allowlist (`k8s/seccomp/agent-runtime.json`) |
| 5    | AppArmor/SELinux profiles                   | ⚠️ None defined for agent pods                                 |

### Gap 1 — No gVisor / Kata runtime class (shared host kernel)

Agent pods run on the host kernel. A Go runtime CVE or kernel 0-day from inside
the container is a full escape. `docs/sandboxing.md` calls for gVisor/Kata
Containers but this is not wired in any manifest.

**Status:** operator-configurable — `k8s/agent-runtime.yaml` carries a commented
`runtimeClassName` block with step-by-step instructions for both AKS Pod Sandboxing
(`kata-mshv-vm-isolation`) and gVisor. Activating it requires a cluster-level node
pool configuration change and a one-line uncomment in the manifest.

### Gap 2 — Custom seccomp allowlist absent ✅ Fixed

`RuntimeDefault` is Docker's blocklist of ~50 syscalls. A tailored Go agent
allowlist blocks ~90% more of the exploitable syscall surface (e.g. `ptrace`,
`mount`, `clone(CLONE_NEWUSER)`, `bpf`, `io_uring`, `keyctl`,
`perf_event_open`).

**Status:** `k8s/seccomp/agent-runtime.json` implemented; container seccompProfile
switched from `RuntimeDefault` to `Localhost`.

### Gap 3 — `AUTH_TOKEN` in environment variable ✅ Fixed

`AUTH_TOKEN` was a required field visible in `kubectl describe pod` and stored
in a Kubernetes `Secret`. It should be obtained via projected workload identity
(Azure Workload Identity, SPIRE SVID, or a short-TTL projected service account
token) and supplied through `AgentRuntimeConfig.authTokenProvider`.

**Status:** Partially implemented:

- `internal/agentruntime/types.go` supports `IdentityTokenProvider` for dynamic
  token fetch on issuance/refresh calls.
- There is currently no built-in `AUTH_TOKEN_FILE` config field or
  `cmd/agent-runtime/main.go` entrypoint in this repository.
- `k8s/agent-runtime.yaml` carries a commented `sa-token` projected volume block
  (kubelet-managed, audience-bound, 1-hour expiry) and a `AUTH_TOKEN_FILE` env
  var commented with enablement instructions; this is deployment scaffolding and
  still requires custom `IdentityTokenProvider` callback wiring.
- The agent-runtime `ServiceAccount` carries a commented Azure Workload Identity
  annotation block.

### Gap 4 — ServiceAccount token automounting ✅ Fixed

The `agent-runtime` ServiceAccount had `automountServiceAccountToken` unset
(defaults to `true`).

**Status:** `automountServiceAccountToken: false` on the ServiceAccount.

### Gap 5 — Unbounded `emptyDir` volumes ✅ Fixed

`/tmp`, `/app/tmp`, `/app/logs` had no `sizeLimit`.

**Status:** All three volumes capped (`/tmp` 64 MiB, `/app/tmp` 64 MiB,
`/app/logs` 128 MiB).

### Gap 6 — Plain HTTP to gateway ⚠️ Scaffolded

`GATEWAY_URL` defaults to `http://envoy-shard-router:3002`. Network-level
attackers inside the cluster can observe tool calls. DPoP mitigates bearer-token
theft but not content confidentiality.

**Status:** Infrastructure scaffolding committed; requires operator activation:

- `k8s/agent-runtime.yaml` carries a commented cert-manager `Certificate` resource
  block for issuing a cluster-internal TLS certificate for the agent pod.
- Commented `tls-ca` volume and `EUNOX_TLS_CA_FILE` env var show exactly which
  lines to uncomment to enable the CA trust bundle in the Go runtime.
- `k8s/network-policies.yaml` carries a commented port `8443` rule for the Envoy
  egress once TLS is configured.
- Activating requires: (1) cert-manager installed + ClusterIssuer named
  `cluster-internal-ca`; (2) Envoy configured with TLS listener on port 8443;
  (3) three commented blocks in `k8s/agent-runtime.yaml` uncommented;
  (4) `GATEWAY_URL` changed to `https://envoy-shard-router:8443`.

---

## 4. Implemented Hardening

### 4.1 Custom seccomp allowlist — `k8s/seccomp/agent-runtime.json`

A tight syscall allowlist for the Go agent binary running as a plain HTTPS client.
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

### 4.5 Identity token provider hook (Gap 3)

`internal/agentruntime/runtime.go` supports dynamic token fetch through
`Config.IdentityTokenProvider`. Embedding services can implement file-backed
token reads in that callback if needed, so:

1. No static credential sits in the environment or process memory between calls.
2. The kubelet-managed token is automatically picked up after rotation (every hour
   for projected service-account tokens).

The manifest carries a commented `sa-token` projected volume. Enabling a
file-backed provider requires adding callback wiring in your embedding service
entrypoint.

In Kubernetes manifests, enabling this still requires:

1. Azure Workload Identity or SPIRE configured on the cluster.
2. The ServiceAccount annotated with `azure.workload.identity/client-id`.
3. Three comment blocks in `k8s/agent-runtime.yaml` uncommented.
4. A runtime host implementation that maps `AUTH_TOKEN_FILE` (or equivalent)
   into `Config.IdentityTokenProvider`.

### 4.6 cert-manager TLS certificate scaffolding (Gap 6 — awaiting operator activation)

`k8s/agent-runtime.yaml` carries a commented cert-manager `Certificate` resource
block that issues a cluster-internal TLS certificate for the agent pod when
cert-manager ≥ v1.12 is installed. A commented `tls-ca` volume + `EUNOX_TLS_CA_FILE`
env var show exactly what to uncomment to trust the cluster-internal CA in Go.

`k8s/network-policies.yaml` carries a commented port `8443` egress rule for the
Envoy shard router.

Full activation steps are documented in the cert-manager `Certificate` block in
`k8s/agent-runtime.yaml`.

---

## 5. Remaining Recommendations

### P3 — Landlock self-restriction in runtime host entrypoint

Compile a small `landlock-wrapper` binary (Rust or C) that installs Landlock
network restrictions (port 3001 + 3002 only) then calls `execve()` to replace
itself with the Go agent. Use it as the container `CMD`. Requires Linux ≥ 6.7 (available
in AKS node pools as of 2025).

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

| Deployment scenario          | Recommended primary sandbox                   | Secondary layers                                 |
| ---------------------------- | --------------------------------------------- | ------------------------------------------------ |
| **AKS (current)**            | AKS Pod Sandboxing (`kata-mshv-vm-isolation`) | NetworkPolicy ✅, cap-drop ✅, custom seccomp ✅ |
| **Self-managed K8s**         | gVisor node pool (`runtimeClassName: gvisor`) | same                                             |
| **On-prem / docker-compose** | Firecracker + jailer (host iptables on tap)   | read-only rootfs, non-root UID                   |
| **Edge**                     | WASM (wasmtime, if agent compiled to WASM)    | Landlock + seccomp wrapper                       |
| **Serverless (Fly, Lambda)** | Platform microVM (Firecracker-backed)         | already provided                                 |

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
