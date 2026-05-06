# Sandboxing Autonomous AI Agents — Reference Architecture & Implementation Guide

## 1. Introduction and Threat Models

This document specifies a reference architecture for **secure sandboxing of autonomous AI agent execution environments** under two distinct threat models:

*   **High-Assurance (Adversarial)** — The agent's runtime is treated as potentially malicious or compromised. An attacker may inject or control code within the agent (via prompt injection, supply chain compromise, or direct exploitation). The sandbox must provide strong isolation (up to separate kernel or hypervisor boundaries) to contain a worst-case scenario where the agent actively attempts to escape, escalate privileges, or exfiltrate data. The trusted computing base (TCB) must be minimized; no assumptions can be made about cooperative behavior from the agent.
*   **Enterprise-Risk (Misuse / Bug)** — The agent is well-intentioned but may misbehave due to bugs, prompt injection, or inadvertent misuse of available privileges. Isolation measures focus on preventing unintended damage or data leakage while balancing performance and integration with monitoring tools.

**Scope:** Runtime sandboxing during **agent execution** (inference/decision loops and tool use). Covers both **Kubernetes** (AKS/EKS/GKE-style) environments and **non-Kubernetes** (standalone VM, bare-metal, containers without K8s, edge) environments. The design spans single-organization and cross-organization contexts.

**Core Goals:**

*   **Zero Ambient Authority:** Agents start with no default access to any sensitive system resource or external service. The sandbox denies all outbound network access by default; any attempt to initiate network connections must go through a mediated path. The agent process sees an empty filesystem or a limited view, with specific bind-mounts only for directories the agent has explicit access to.

*   **Deterministic Mediation:** All agent-initiated operations with side effects are intercepted by a **reference monitor (tool gateway)** outside the agent's trust zone. This component validates the agent's request against its capability tokens before performing the action on the agent's behalf. The agent cannot bypass this monitor due to sandbox enforcement.

*   **Defense in Depth:** The sandbox is one layer in a multi-layer security model:
    *   *Sandbox & OS/VM Isolation (outer layer):* Contains the agent's impact on system resources and other workloads.
    *   *Reference Monitor & Capability Enforcement (mid layer):* Limits agent-initiated actions to pre-authorized, audited operations.
    *   *In-Agent Policy/Monitoring (inner layer):* Optionally watches the agent's behavior for early detection, with the understanding that if it fails the outer layers still hold.

*   **Minimized TCB:** The agent can be executed in a container or VM with user-space restrictions — running as a non-root user with seccomp and AppArmor profiles, or using **gVisor or Firecracker microVMs** to intercept syscalls. This ensures that even if the agent exploits a vulnerability, it cannot break out of the sandbox.

*   **Consistency Across Environments:** The same agent code should not need to be aware of whether it's running under Kubernetes or not; the platform abstracts this. Whether isolated by a Kubernetes pod with Kata Containers or by a Firecracker VM on a bare-metal server, the agent sees a similar minimal environment with identical mechanisms.

**Non-Goals:** This document does not cover model alignment, content filtering, or training-phase sandboxing. The focus is on runtime environmental isolation and control for deployed agents.

***

## 2. Sandbox Design Principles

*   **Complete mediation of side-effects:** An agent's ability to affect systems or data outside its internal memory is fully mediated by the sandbox and associated monitors. The agent cannot directly make kernel calls (beyond what the sandbox permits), initiate network connections, or modify files, except through mechanisms the sandbox explicitly allows and monitors.

*   **Least privilege & need-to-know:** The sandbox restricts the agent's access to only the specific resources it needs for its task, and only for the duration needed. If an agent needs to read certain files, it receives file handle capabilities (e.g., an open file descriptor or a reference to a virtual file service).

*   **Process and kernel isolation:** In stronger configurations, the agent runs under a separate kernel or hypervisor (lightweight virtual machine). AKS Pod Sandboxing provides an isolation boundary between the container application and the shared kernel and compute resources of the container host such as CPU, memory, and networking — applications are spun up in isolated, lightweight pod virtual machines. In moderate configurations, the agent runs as a container with separate namespaces and seccomp-projected system call filtering under the host kernel. [\[learn.microsoft.com\]](https://learn.microsoft.com/en-us/azure/aks/use-pod-sandboxing)

*   **Ephemeral and immutable infrastructure:** Each agent runs in a throwaway environment destroyed or reverted after use. Any state that must persist is written to external services or mounted volumes under the control of the platform.

*   **No silent failures:** If sandbox security features fail to initialize, the system fails closed — refusing to run the agent without sandboxing. Any escape attempt or abnormal system call triggers immediate termination of the agent process and revocation of its capabilities.

*   **Platform-agnostic design:** The sandbox presents a consistent interface (filesystem layout, environment variables, sidecar proxies) to the agent regardless of the underlying isolation technology.

***

## 3. Sandbox Architecture — Layers and Components

[\[learn.microsoft.com\]](https://learn.microsoft.com/en-us/azure/aks/use-pod-sandboxing)

The sandboxed agent architecture comprises the following elements:

### 3.1 Isolated Execution Environment

A container or microVM where the agent code (LLM runtime and tool integration code) runs with **dedicated CPU/memory** allocation, isolated from other workloads.

*   **Kubernetes:** Use a dedicated Pod per agent session. The `kubernetes-sigs/agent-sandbox` project provides a layered Kubernetes-native architecture designed to manage isolated, stateful, singleton workloads, structured in three tiers: a **Core Layer** managing the `Sandbox` CRD (providing a stable identity and persistent storage for a single Pod), an **Extensions Layer** orchestrating Sandbox resources through templates, claims, and pre-warmed pools to reduce startup latency (`SandboxClaim`, `SandboxWarmPool`), and a **Connectivity & SDK Layer** providing the `sandbox-router` for traffic ingress and Python/Go SDKs for programmatic lifecycle management. Each Sandbox has a stable hostname and network identity, and supports a `ShutdownPolicy` (either `Delete` or `Retain`). The project supports isolated runtimes including gVisor and Kata Containers. [\[deepwiki.com\]](https://deepwiki.com/kubernetes-sigs/agent-sandbox/1.2-architecture-overview)

*   **Non-Kubernetes:** Launch each agent in an isolated container or VM using Docker/Podman (with restrictive seccomp profiles, dropped capabilities, read-only root filesystem, non-root UID) or **microVMs** (Firecracker, QEMU/KVM) for high-assurance requirements.

### 3.2 Networking Guard

Outbound network access from the sandbox is tightly controlled. By default, **deny all egress** from the agent's network namespace. On Kubernetes or cloud VM, this is enforced via network policies or firewall rules that only allow traffic to the Tool Gateway or specific endpoints. In Azure, the agent container runs in a subnet with a Network Security Group blocking egress except to an allowlist of approved internal endpoints.

### 3.3 Filesystem & I/O Control

The agent process sees an empty filesystem or a limited view. Using Linux container techniques, an empty filesystem or tmpfs is mounted as the agent's root, plus specific bind-mounts for directories the agent has explicit access to.

**Key constraints:**

*   Read-only root filesystem with only whitelisted directories writeable
*   No host paths mounted unless absolutely necessary (no `hostPath` in K8s)
*   No device files shared into the container (no `--privileged`)
*   No lingering credentials — use short-lived tokens injected at runtime

### 3.4 Identity & Attestation

Each sandboxed agent runs under a distinct identity. The **SPIFFE/SPIRE framework** solves the "secret zero" problem by defining an API for workloads to retrieve an identity without holding any initial secrets. SPIRE relies on environment-specific attestors — verifying a Kubernetes pod's UID and namespace, an AWS IAM role, or kernel-level attributes — to securely issue an SVID uniquely bound to that workload, cryptographically verifiable by any downstream system. Azure's **Workload Identity Federation** allows an identity from an OpenID Connect Provider outside of Azure to authenticate as a user-assigned managed identity by establishing a trust between Azure AD and the OpenID Connect identity provider. This enables agents running in Kubernetes, GitHub Actions, or other cloud providers to authenticate to Azure resources without stored secrets — the external token is exchanged for a local access token via OIDC-compliant protocols.

### 3.5 Reference Monitor Proxy

Every sandboxed agent is paired with a reference monitor that runs outside the sandbox:

*   **In Kubernetes:** A sidecar container in the same Pod or a node-local daemon. The agent sends all requests for performing actions to the monitor. The monitor verifies capability tokens before forwarding. For example, a sidecar exposes an HTTP proxy at `http://localhost:8282`, and the agent is configured to use this proxy for all external HTTP requests.
*   **In non-K8s environments:** A monitoring proxy on the host, with the agent's sandbox configured such that it cannot reach the internet or filesystem except through that proxy.

### 3.6 Observability & Audit Hooks

*   Record all decisions made by the reference monitor (both allowed and denied actions) with context
*   Monitor sandbox resource usage for anomalies
*   Connect host-based detection systems (eBPF-based sensors where compatible)
*   All logs feed into a centralized logging system

***

## 4. Kubernetes Sandbox Implementation

### 4.1 Cloud-Specific Architectural Decisions

The choice of sandbox technology on managed Kubernetes has significant consequences that vary by cloud provider. As the ARMO implementation guide notes, GKE is the only one of the three major clouds where architectural decisions at cluster creation **mutually exclude** primitives across security pillars — *"they compose, and each one reshapes which primitives are available for every phase"*. [\[armosec.io\]](https://www.armosec.io/blog/implement-ai-agent-security-framework-gke/)

**GKE Forced-Choice Decision Matrix:**

| **Decision**                                                         | **What It Gives You**                                                                                                                                                                                                        | **What It Takes Away**                                                                                                                                                                                                                                                                                                                                                                                                                      |
| -------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Autopilot vs Standard**                                            | Autopilot: Workload Identity on by default, gVisor on every node, managed node hardening. Standard: full DaemonSet access, custom node images, runtime class control.                                                        | Autopilot: privileged workloads rejected by default; eBPF runtime sensors require a `WorkloadAllowlist` CRD (available in GKE 1.35+) [\[armosec.io\]](https://www.armosec.io/blog/implement-ai-agent-security-framework-gke/). Standard: must configure Workload Identity, gVisor, hardening, and node-pool policies explicitly.                                                                                                            |
| **Agent Sandbox CRD + managed gVisor vs Container Threat Detection** | Agent Sandbox CRD: Google's AI-agent-specific isolation built on gVisor by default (Kata Containers also supported as alternative backend), kernel-level sandbox, warm pools for sub-second startup, API version `v1alpha1`. | Per Google's documentation, **Container Threat Detection is incompatible with GKE Sandbox** and must be disabled on affected node pools. Every cluster must keep at least one non-sandboxed node pool [\[armosec.io\]](https://www.armosec.io/blog/implement-ai-agent-security-framework-gke/). Teams following Google's recommended agent architecture silently lose Google's own runtime detection on the exact pool where AI agents run. |
| **Self-hosted GKE vs Vertex AI Agent Builder**                       | GKE: full kernel access, behavioral baselines at syscall granularity. Agent Builder: managed infrastructure, no cluster operations.                                                                                          | Agent Builder: runtime surface abstracted; behavioral detection at kernel layer unavailable. Enforcement boundaries are Google-defined, not customer-defined [\[armosec.io\]](https://www.armosec.io/blog/implement-ai-agent-security-framework-gke/).                                                                                                                                                                                      |

[\[armosec.io\]](https://www.armosec.io/blog/implement-ai-agent-security-framework-gke/)

**AKS Pod Sandboxing:**

Pod Sandboxing on AKS builds on the open-source **Kata Containers** project. The solution architecture comprises four components: the **Azure Linux container host for AKS**, **Microsoft Hyper-V Hypervisor**, the open-source **Cloud-Hypervisor** Virtual Machine Monitor (VMM), and integration with **Kata Container** for the runtime. Kata Containers running on the Azure Linux container host provides VM-based isolation and a separate kernel for each pod. Pod Sandboxing allows users to allocate resources for each pod and doesn't share them with other Kata Containers or namespace containers running on the same host. [\[learn.microsoft.com\]](https://learn.microsoft.com/en-us/azure/aks/use-pod-sandboxing)

AKS supports Pod Sandboxing on **Kubernetes version 1.27.0 and higher**. To use this feature, the only difference is adding `runtimeClassName: kata-vm-isolation` to the pod spec. When a pod uses this runtimeClass, the hypervisor spins up a lightweight virtual machine with its own kernel for the workload to operate in. [\[learn.microsoft.com\]](https://learn.microsoft.com/en-us/azure/aks/use-pod-sandboxing)

**AKS Pod Sandboxing Limitations:**

*   Kata containers might not reach the IOPS performance limits that traditional containers can reach on Azure Files and high-performance local SSD [\[learn.microsoft.com\]](https://learn.microsoft.com/en-us/azure/aks/use-pod-sandboxing)
*   **Microsoft Defender for Containers does not support assessing Kata runtime pods** [\[learn.microsoft.com\]](https://learn.microsoft.com/en-us/azure/aks/use-pod-sandboxing)
*   Kata host-network access is not supported — it is not possible to directly access the host networking configuration from within the VM [\[learn.microsoft.com\]](https://learn.microsoft.com/en-us/azure/aks/use-pod-sandboxing)
*   CPU and memory allocation with Pod Sandboxing has additional considerations compared to `runc` [\[learn.microsoft.com\]](https://learn.microsoft.com/en-us/azure/aks/use-pod-sandboxing)

### 4.2 Pod Security Configuration

**Security Context (per container):**

```yaml
securityContext:
  runAsUser: 1000
  runAsNonRoot: true
  allowPrivilegeEscalation: false
  capabilities:
    drop: ["ALL"]
  readOnlyRootFilesystem: true
  seccompProfile:
    type: RuntimeDefault  # or a custom profile
```

**Pod-Level Settings:**

*   Use Pod Security Standards (PSS) in "restricted" mode to enforce non-root, no privileged, no host mounts cluster-wide
*   Apply OPA/Gatekeeper constraints for agent-specific requirements (e.g., "all agent pods must use runtimeClass=kata-vm-isolation" for high-security deployments)

### 4.3 RuntimeClass Selection

| **Assurance Level** | **RuntimeClass**                                                            | **Isolation Mechanism**                             | **Trade-offs**                                                                                                                |
| ------------------- | --------------------------------------------------------------------------- | --------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- |
| **High-Assurance**  | `kata-vm-isolation` (AKS) or GKE Sandbox with gVisor/Kata【4†L77-L94】【3†L33】 | Separate kernel per pod; hypervisor-level isolation | Performance overhead on I/O; Defender for Containers cannot assess Kata pods【4†L47】; CTD disabled on GKE Sandbox nodes【3†L33】 |
| **Enterprise-Risk** | Default `runc` with seccomp + AppArmor                                      | Namespace isolation with kernel sharing             | Near-native performance; full compatibility with eBPF-based monitoring tools; less isolation against kernel exploits          |

### 4.4 Network Policies

Define **egress NetworkPolicy** for each agent namespace or pod. By default, block all egress, then open only what's needed:

```yaml
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: agent-egress
spec:
  podSelector: {}
  policyTypes: ["Egress"]
  egress:
  - to:
    - ipBlock:
        cidr: 10.0.0.10/32  # Capability gateway service
    ports:
    - port: 3128
```

This blocks all egress except to the internal capability gateway. For GKE Autopilot, note that kernel-level telemetry from eBPF sensors is reachable on both Autopilot and Standard cluster modes, but the operational path differs materially — Autopilot requires a `WorkloadAllowlist` CRD installation before eBPF sensors deploy【3†L29】【3†L75】.

### 4.5 Monitoring Compatibility

eBPF-based sensor deployment overhead on GKE Standard lands at **1–2.5% CPU and approximately 1% memory per node**【3†L75】.

**Critical compatibility constraints:**

| **Monitoring Tool**               | **Standard Container (runc)** | **Kata / gVisor Sandbox**                                       |
| --------------------------------- | ----------------------------- | --------------------------------------------------------------- |
| eBPF-based sensors (Falco, ARMO)  | ✅ Fully functional            | ⚠️ Limited or requires WorkloadAllowlist (Autopilot)            |
| Microsoft Defender for Containers | ✅ Supported                   | ❌ Does not support Kata runtime pods【4†L47】                     |
| GKE Container Threat Detection    | ✅ Active                      | ❌ Incompatible with GKE Sandbox on same node pool【3†L33】【3†L59】 |
| Application-level logging         | ✅                             | ✅ (Compensates for reduced kernel-level visibility)             |

**Mitigation for high-assurance mode:** When kernel-level monitoring is blinded by isolation, emphasize verbose application logging and external observation (network logs, proxy logs). Use the hypervisor's telemetry if available. Tighten seccomp profiles so even novel attacks result in termination.

### 4.6 Warm Pools for Fast Start

If agent instantiation time is a concern, implement a pool of pre-initialized sandbox pods using a controller like the `SandboxWarmPool` in `kubernetes-sigs/agent-sandbox`. The extensions layer orchestrates Sandbox resources through templates, claims, and pre-warmed pools to reduce startup latency【1†L43-L49】. Pre-warmed pods remain in standby, fully sandboxed but not yet possessing capabilities. When a new agent task arrives, a warm pod is instantly assigned, capability tokens injected, and the agent begins executing with minimal cold-start latency. Cleanup must ensure all sensitive data from the last run is wiped before reusing the pod.

### 4.7 Resource Limits & Node Hardening

*   Set `resources.requests` and `resources.limits` on agent Pods to prevent runaway resource usage
*   Use Kubernetes `ResourceQuota` to avoid a flood of agent pods exhausting cluster resources
*   Use minimal host OS images (AKS's Azure Linux or GKE's COS)
*   Leverage Workload Identity so escaping agents do not find ambient cloud credentials on the node

Production sandbox hardening requires: minimal OS base container images (alpine or distroless), confirmed no root access (non-root user in Dockerfiles, dropped Linux capabilities), and tested container escape resilience — verifying that crashing or resource-exhausting an agent doesn't affect the host or other agents【5009†L187-L192】.

***

## 5. Non-Kubernetes Sandbox Implementation

In environments outside Kubernetes, the same principles apply through OS and virtualization tools:

### 5.1 Isolation Options

| **Approach**                              | **Isolation Level**                 | **Overhead**                          | **Best For**                              |
| ----------------------------------------- | ----------------------------------- | ------------------------------------- | ----------------------------------------- |
| **Firecracker microVM**                   | Separate kernel, hypervisor-level   | \~125 MB memory, tens of ms startup   | High-assurance; equivalent to Kata in K8s |
| **Docker/Podman with gVisor**             | User-space kernel interception      | 5–10% CPU for syscall-heavy workloads | Moderate assurance; good compatibility    |
| **Docker/Podman with seccomp + AppArmor** | Namespace isolation, kernel sharing | Near-native                           | Enterprise-risk; simplest deployment      |
| **systemd-nspawn / LXC**                  | Namespace isolation                 | Near-native                           | Single-host, process-level isolation      |
| **QEMU/KVM full VM**                      | Complete hardware virtualization    | Higher memory and startup             | Maximum isolation; legacy compatibility   |

### 5.2 Container Engine Hardening (Non-K8s)

When using Docker or Podman directly:

*   Run with `--security-opt=no-new-privileges`, `--cap-drop=ALL`, and a custom seccomp profile
*   Use `--user` flag for non-root execution
*   Use `--read-only` for immutable root filesystem
*   Use `--network=none` for fully offline agents, or a user-defined network with egress rules
*   Set `--memory` and `--cpu` flags to constrain resources via cgroups
*   No `--privileged` flag; no extra `--device` flags

### 5.3 Network Isolation on Host

Without Kubernetes NetworkPolicy:

*   Create a separate **Linux network namespace** for the agent process or container
*   Use **iptables** or `nftables` on the host to allow/block traffic from the agent's namespace
*   Run an **HTTP proxy on the host** as the sole egress path, performing capability checks

### 5.4 Process Supervision

*   Use systemd transient services with sandboxing directives: `PrivateTmp=yes`, `NoNewPrivileges=yes`, `PrivateUsers=yes`, `PrivateNetwork=yes`, `ProtectSystem=strict`
*   Incorporate health checks and automatic cleanup on crash
*   Use `pids.max` cgroup to limit processes/threads (contain fork bombs)

### 5.5 Identity Bootstrapping Without Kubernetes

The SPIFFE/SPIRE framework provides a portable solution: SPIRE relies on environment-specific attestors — verifying an AWS IAM role or kernel-level attributes — to securely issue an SVID uniquely bound to that workload【5009†L356-L361】. Cloud providers offer analogous mechanisms: Azure's Workload Identity Federation enables agents running outside Azure to authenticate to Azure resources without stored secrets via OIDC-compliant protocols【5009†L369-L373】.

***

## 6. Execution Flow

### 6.1 Agent Action Lifecycle

1.  **Agent proposes action:** The LLM reasoning loop outputs a tool invocation request (e.g., `send_email(recipient="bob@external.com", body="...")`).

2.  **Sandbox intercepts:** Because the agent has no direct network or filesystem access, the request is routed to the reference monitor (sidecar proxy or host proxy). In Kubernetes, the agent's only allowed egress destination is the proxy service via NetworkPolicy. In non-K8s, iptables or network namespaces enforce the same constraint.

3.  **Reference monitor validates:** The proxy extracts the capability token from the request, verifies:
    *   Cryptographic signature (issuer's public key)
    *   Standard claims (`iss`, `sub`, `exp`)
    *   Action/resource match against token scope
    *   Proof of possession (if DPoP is used)
    *   Revocation status

4.  **Decision and execution:**
    *   **Allow:** Forward the request to the target service, injecting any downstream credentials from the capability. Log `ActionExecuted` event.
    *   **Deny:** Return error to agent. Log `DeniedAction` event with reason.

5.  **Audit:** Every decision (allow or deny) is recorded in the Capability Audit Ledger with agent identity, capability ID, action, resource, timestamp, and outcome.

### 6.2 Failure and Deny Paths

| **Failure Condition**                                  | **System Response**                                                         |
| ------------------------------------------------------ | --------------------------------------------------------------------------- |
| Missing capability token                               | Gateway returns 401; logged as `DeniedAction`                               |
| Invalid/tampered token                                 | Gateway returns 403; logged; alert triggered if repeated                    |
| Expired token                                          | Gateway returns 401; agent must request renewal from Issuer                 |
| Revoked token                                          | Gateway returns 401; session may be killed if revocation was administrative |
| Agent attempts direct network access (bypassing proxy) | Blocked by NetworkPolicy/firewall; connection refused at OS level           |
| Agent attempts prohibited syscall                      | seccomp returns SIGSYS (process killed) or EPERM; logged by audit subsystem |
| Resource limit exceeded (CPU/memory)                   | OOM killer terminates process; K8s restarts pod per `restartPolicy`         |
| Reference monitor crashes                              | Fail-closed: agent cannot reach any external resource; alert triggered      |

***

## 7. Revocation, Kill-Switches, and Incident Response

### 7.1 Capability Expiration

All capability tokens carry short lifetimes (minutes). The Capability Issuer can refuse to reissue new tokens if an agent is suspected of compromise, effectively muzzling the agent from further external influence without requiring process termination.

### 7.2 Kill-Switch Mechanisms

| **Mechanism**             | **Scope**             | **Latency**                      | **Implementation**                                                                  |
| ------------------------- | --------------------- | -------------------------------- | ----------------------------------------------------------------------------------- |
| **Session blacklist**     | Single agent          | Immediate (in-memory lookup)     | Gateway maintains blacklist of killed agent IDs; returns 403 on all requests        |
| **Token revocation list** | Specific capabilities | Seconds (distributed cache sync) | Issuer publishes to Redis/shared cache; Gateways poll or receive push notifications |
| **Pod/VM termination**    | Single agent          | Seconds                          | K8s: `kubectl delete pod`; non-K8s: `kill`/VM destroy                               |
| **Global halt**           | All agents            | Immediate                        | Gateway flag rejects all requests; K8s: scale all agent deployments to zero         |

In Kubernetes, the `Sandbox` CRD supports a `ShutdownPolicy` of either `Delete` or `Retain`【1†L157-L175】, providing flexibility for forensic preservation or immediate cleanup.

### 7.3 Containment on Breakout Attempt

*   **Seccomp violation** → triggers SIGSYS (fatal by default); use `SCMP_ACT_KILL` not `SCMP_ACT_LOG`
*   **Memory/CPU limit exceeded** → kernel OOM killer or cgroup event triggers; treat as potential abuse
*   **Repeated denied actions** → reference monitor signals for agent termination; alert security team
*   **Fork bomb** → `pids.max` cgroup limit prevents further forks; system kills agent

### 7.4 Forensics and Cleanup

When an agent is killed for security reasons:

*   Preserve recent log buffers (ensure log collector grabbed them before volume deletion)
*   Snapshot the filesystem/container layer for post-mortem if needed
*   Revoke all credentials issued to the agent
*   Audit all uses of those credentials via the Capability Audit Graph
*   If escape or serious violation confirmed, pause similar agents and conduct security review

***

## 8. Operational Considerations

### 8.1 Performance Overhead Comparison

| **Isolation Method**                     | **Startup Latency**          | **Runtime Overhead**                    | **I/O Impact**                                                                   |
| ---------------------------------------- | ---------------------------- | --------------------------------------- | -------------------------------------------------------------------------------- |
| Standard container (runc)                | Milliseconds                 | Negligible                              | None                                                                             |
| gVisor (user-space kernel)               | Low (pre-started)            | \~5–10% CPU for syscall-heavy workloads | Moderate                                                                         |
| Kata Containers (microVM)                | Sub-second (with warm pools) | \~1–3% CPU                              | Might not reach IOPS limits on Azure Files and high-performance local SSD【4†L46】 |
| Firecracker microVM                      | Tens of milliseconds         | \~125 MB memory per VM                  | Comparable to Kata                                                               |
| eBPF monitoring sensors (on top of runc) | N/A                          | 1–2.5% CPU, \~1% memory per node【3†L75】 | Negligible                                                                       |

**Mitigation strategies:**

*   Use **warm pools** to eliminate cold-start latency for VM-based isolation
*   Use **in-memory token verification** (hash table lookup + cryptographic verification) for sub-millisecond reference monitor overhead
*   Co-locate reference monitor as sidecar to avoid network hops

### 8.2 Monitoring Compatibility Trade-offs

Running high-assurance sandboxes (Kata/gVisor) **disables some kernel-level monitoring capabilities:**

*   GKE Sandbox disables Container Threat Detection on affected node pools; teams following Google's recommended agent architecture silently lose Google's own runtime detection on the exact pool where AI agents run【3†L33】
*   Microsoft Defender for Containers does not support assessing Kata runtime pods on AKS【4†L47】

**Compensation strategy:** Deploy alternative monitoring at the application layer (agent sidecars, proxy logging). The runtime behavioral layer — the gap between "authorized action" and "normal for this specific agent at this time against this resource" — is the one capability that stays constant across all architectural decisions【3†L49】.

### 8.3 Cross-Organizational Execution

When an agent in Organization A must execute within Organization B's environment, Org B applies the same sandboxing and monitoring controls as it would to its own agents. The security model is identical whether single-org or cross-org: authority flows via cryptographic chains, each delegation attenuates privileges, every executor proves identity with a signature, and constraints are enforced by the receiving gateway.

### 8.4 Coexistence with In-Process Policy Engines

Integration of a system like the Microsoft Agent Governance Toolkit (AGT) inside the sandbox augments security but must not replace sandbox controls:

| **Assurance Level** | **Role of In-Process Policy Engine**                                                                                                                                                       |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **High-Assurance**  | Primarily logging and early warning. If the agent process is fully compromised, in-process hooks could be bypassed. Sandbox and reference monitor enforce critical policies independently. |
| **Enterprise-Risk** | Can enforce many policies directly (content filtering, anomaly detection, loop detection). Sandbox serves as backstop if in-process controls fail.                                         |

### 8.5 GKE-Specific Primitive Boundaries

The ARMO guide catalogs where each GCP-native primitive stops being useful for AI agent behavior:

| **Primitive**                                 | **What It Contributes**                                 | **Where It Stops**                                                                                  |
| --------------------------------------------- | ------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| Cloud Audit Logs                              | API-level audit trail: who called which API, when       | Cannot see what the agent did inside the pod after the API returned【3†L57】                          |
| Workload Identity Federation (KSA principals) | Per-pod IAM identity via short-lived OAuth2 tokens      | Grants the permissions ceiling, not the actual permissions needed【3†L58】                            |
| Container Threat Detection                    | Runtime eBPF detection for known-bad container patterns | Incompatible with GKE Sandbox; ships static rules, no behavioral baselines【3†L59】                   |
| Model Armor                                   | Content-plane screening for prompts and responses       | Operates on the language plane, not on the agent's subsequent behavior【3†L61】                       |
| Agent Sandbox CRD + gVisor                    | Kernel-level isolation for LLM-generated code execution | Controls where the agent runs, not what it does once running. Disables CTD on affected pools【3†L64】 |
| Binary Authorization                          | Admission-time image attestation                        | Does not observe runtime behavior; attested image can still host a compromised agent【3†L65】         |

【3†L55-L66】

***

## 9. Implementation Guidance — Reference Patterns and Trade-offs

### 9.1 High-Assurance vs Standard Mode

| **Feature**             | **High-Assurance Mode** (Adversarial)                                                   | **Standard Mode** (Enterprise Risk)                                                  |
| ----------------------- | --------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| **Isolation boundary**  | Lightweight VM (Kata Containers, Firecracker) with separate kernel per agent【4†L59-L66】 | Standard container (runc) with seccomp/AppArmor                                      |
| **Syscall permissions** | Nearly all syscalls blocked except essential; deny-by-default seccomp whitelist         | Docker/K8s default seccomp (moderately restrictive); tailored as needed              |
| **Networking**          | No direct external egress; all traffic through controlled proxy                         | Egress limited to needed domains/IPs using NetworkPolicy or firewall                 |
| **Filesystem**          | Read-only root; ephemeral overlay; no host mounts; only preapproved data sources        | Read-only root if compatible; necessary paths only; non-root user                    |
| **Identity**            | Unique per-agent; short-lived credentials; hardware-backed attestation possible         | May reuse service identities per service; still short-lived tokens for external APIs |
| **Monitoring**          | Minimal kernel-level (blinded by isolation); emphasize application and proxy logging    | Full host monitoring via eBPF, auditd, cloud provider threat detection               |
| **Performance**         | Higher overhead (microVM startup, \~5–10% CPU from isolation)【4†L46】                    | Low overhead (near-native container performance)                                     |
| **Use cases**           | Running truly untrusted code, third-party plugins, multi-tenant agent execution         | Internal automation, single-tenant deployments, known-threat environments            |

### 9.2 When to Choose Stronger vs Lighter Isolation

**Choose VM-level isolation (Kata/gVisor/Firecracker) when:**

*   The agent executes third-party or user-submitted code
*   Multiple tenants share the same infrastructure
*   The threat model includes kernel exploits or container escapes
*   Regulatory requirements demand hardware-level separation

**Choose standard container isolation with hardened seccomp when:**

*   Agents run internally developed, trusted code
*   Full compatibility with kernel-level monitoring is required (Defender for Containers, CTD, Falco)
*   Low latency and high I/O throughput are critical
*   The primary concern is accidental misuse rather than deliberate exploitation

### 9.3 DevSecOps Integration

*   Provide **secure defaults** via CI/CD templates that automatically include correct security context, runtimeClass, and network policy
*   Use validating admission controllers to reject misconfigured agent pods
*   Provide internal base container images that automatically route requests through the local proxy and fetch capability tokens
*   Define alert rules: any denied action generates an alert for security review

### 9.4 Testing the Sandbox

*   Run a battery of common container escape attempts in controlled staging environments
*   Penetration testing targeting privilege escalation, container escape, and data exfiltration
*   Simulate prompt injections instructing the agent to perform disallowed actions; verify monitors catch attempts
*   **Incident drills:** Simulate agent compromise, practice incident response (detection → revocation → kill-switch → forensic collection)
*   Incorporate tests into CI/CD and staging environments. High-assurance operations should use chaos engineering techniques: deliberately run benign "red team" agents attempting breakouts to validate sandbox integrity.

***

## 10. Summary

The sandboxing architecture for AI agents hinges on **isolate, restrict, and monitor:**

*   **Isolate** the agent with as strong a barrier as feasible — from namespace-level container isolation for enterprise-risk scenarios to separate-kernel microVM isolation (Kata Containers on AKS【4†L59-L66】, gVisor on GKE【3†L33】, or Firecracker on bare metal) for high-assurance contexts.
*   **Restrict** its capabilities through both system-level controls (CPU, memory, syscalls, filesystem, network) and application-level controls (capability tokens for tools and data), with no ambient authority by default【5009†L10-L20】.
*   **Monitor** everything through proxies, logs, and sensors. Where kernel-level monitoring is blinded by VM isolation (Defender cannot assess Kata pods【4†L47】; CTD is incompatible with GKE Sandbox【3†L33】), compensate with application-layer logging and reference monitor audit trails.

Identity bootstrapping leverages SPIFFE/SPIRE for the "secret zero" problem across environments【5009†L350-L361】, and Workload Identity Federation for cross-cloud authentication without stored secrets【5009†L362-L373】. The `kubernetes-sigs/agent-sandbox` project provides a production-ready Kubernetes-native framework with warm pools, stable identities, and configurable shutdown policies【1†L36-L56】【1†L156-L175】.

By adhering to these principles, organizations can deploy AI agents in both cloud and on-premises environments confident that even if an agent is compromised or manipulated, the damage is contained to the sandbox and its pre-defined blast radius, and that any unauthorized behavior is visible for timely response.
