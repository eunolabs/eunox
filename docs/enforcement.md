# Integrating Protected Tools with the Tools Gateway: Enforcement Strategies and Architectural Guidance

## Core Answer

**Protected tools and APIs do not need to individually validate capability tokens.** Token validation is centralized at the tools gateway (reference monitor), which serves as the single enforcement point for all agent-initiated actions. The architectural foundation is straightforward: agents have **no direct network path to protected tools** — all traffic must transit the gateway, which performs cryptographic token verification before forwarding authorized requests. Requests to perform actions are funneled through the Tool Gateway (policy enforcement point), which consults the agent's set of Capability Tokens to decide allow or deny — no tool invocation or external side effect is possible unless explicitly authorized.

To enforce gateway-only access without deep agent framework modifications, the recommended approach combines **network-level controls** (Kubernetes NetworkPolicies, host firewalls) with **proxy environment configuration** (HTTP_PROXY/HTTPS_PROXY injection). AKS natively supports this pattern: when configured with an HTTP proxy, both AKS nodes and Pods are automatically configured with proxy environment variables, so that standard HTTP clients route all external traffic through the designated proxy without code changes. [\[techcommun...rosoft.com\]](https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/controlling-aks-egress-using-an-http-proxy/4119407)

---

## 1. Centralized Token Validation at the Gateway

### Why Tools Should Not Validate Tokens

Centralizing capability checks at the gateway provides four distinct advantages over distributed validation:

**Minimal changes to tools.** Protected services remain unmodified. They do not need to parse or validate capability tokens, avoiding changes to potentially hundreds of microservices. The gateway validates tokens and forwards authorized requests using its own trusted identity (e.g., mTLS or a service account). Services see nothing unusual — just a call from a known, trusted entity.

**Single source of truth for authorization.** Policy updates (revoking a capability, updating scope definitions, rotating signing keys) happen in one place. Without relying on each service team to correctly implement token checks, the system avoids configuration drift or inconsistent interpretations.

**Performance efficiency.** Token verification (signature check + claims parsing + scope comparison) is a lightweight operation performed once at the gateway per request. If every microservice duplicated this verification, aggregate latency and CPU overhead would scale linearly with the number of downstream services per request chain.

**Defense-in-depth without token re-validation.** Rather than requiring services to parse tokens, protected services can enforce that requests originate **only from the gateway's identity or network location** (e.g., accepting calls only from the gateway's mTLS certificate or a known IP range). This provides secondary assurance that only the gateway can reach them, without introducing full token parsing logic into every service.

### When Tools Might Validate Tokens Directly

Tool-level validation is warranted only in narrow scenarios:

| **Scenario**                                                                                      | **Recommendation**                                                                                                                                                                                               |
| ------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| All agent traffic guaranteed to pass through the gateway (standard deployment)                    | **Gateway-only validation.** Tools do not parse tokens.                                                                                                                                                          |
| Transitional architecture where some agents bypass the gateway temporarily                        | **Temporary tool-level validation** as a bridge, removed once network controls are complete.                                                                                                                     |
| Extremely high-stakes operations (e.g., financial settlement, destructive infrastructure actions) | **Optional double validation** — gateway validates the token, and the service performs a lightweight secondary check (e.g., verifying the token signature and expiry, or requiring the gateway's mTLS identity). |
| Tools exposed directly to the internet without a gateway in front                                 | **Mandatory tool-level validation.** This scenario should be avoided in production agent architectures.                                                                                                          |

**Long-term target:** Eliminate all direct agent-to-tool communication paths, making tool-level capability checks unnecessary.

---

## 2. Ensuring Agents Use the Tools Gateway Without Heavy Framework Modifications

### Network-Level Enforcement (Primary)

The most reliable enforcement mechanism is **preventing agents from reaching tools except through the gateway at the network layer**. Even if an agent's code attempts a direct connection, the traffic never arrives.

**Kubernetes NetworkPolicy.** NetworkPolicies allow specifying rules for traffic flow within a cluster and between Pods and the outside world. For agent sandboxing, apply a **deny-all egress** policy with a single exception for the gateway service:

```yaml
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: agent-egress-lockdown
spec:
  podSelector:
    matchLabels:
      role: agent
  policyTypes: ["Egress"]
  egress:
    - to:
        - podSelector:
            matchLabels:
              app: tools-gateway
      ports:
        - port: 8443
          protocol: TCP
```

This ensures that even if an agent obtains the IP of an internal service and attempts a direct connection, the packet is dropped. The agent will see a network error or timeout — preventing misuse regardless of what the agent's code does.

**Non-Kubernetes environments.** On VMs or bare-metal hosts:

- Create a **separate Linux network namespace** for the agent process or container.
- Use **iptables** or `nftables` rules to allow outbound connections only to the gateway's IP and port.
- Run an **HTTP proxy on the host** as the sole egress path, performing capability checks before forwarding.

The XPIA Risk Review Playbook explicitly requires that sandboxes must not permit arbitrary network ingress/egress. Network-level enforcement is the direct implementation of this requirement.

### Proxy Configuration (Supplemental — Configuration-Only)

Standard HTTP clients in most programming languages honor `HTTP_PROXY` and `HTTPS_PROXY` environment variables. By injecting these variables into the agent's environment, all HTTP/HTTPS traffic is automatically routed through the tools gateway **without any code changes**.

AKS natively supports this. When configured with an HTTP proxy, the feature adds HTTP proxy support to AKS clusters, exposing a straightforward interface that cluster operators can use to secure AKS-required network traffic in proxy-dependent environments. Both AKS nodes and Pods are configured to use the HTTP proxy. The configuration is applied at the cluster level: [\[techcommun...rosoft.com\]](https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/controlling-aks-egress-using-an-http-proxy/4119407)

```json
{
  "httpProxy": "http://<gateway-ip>:8080/",
  "httpsProxy": "https://<gateway-ip>:8080/",
  "noProxy": ["localhost", "127.0.0.1"],
  "trustedCA": "<base64-encoded-CA-cert>"
}
```

When deployed, the proxy environment variables are automatically injected into all pods — verified by inspecting the pod environment, which shows `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY` values configured to route through the proxy. [\[techcommun...rosoft.com\]](https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/controlling-aks-egress-using-an-http-proxy/4119407)

**Critical configuration detail:** The `noProxy` list must be kept minimal. If `noProxy` includes internal service domains (e.g., `.svc.cluster.local`), agents could bypass the gateway for internal calls. By excluding internal domains from `noProxy`, even calls to cluster-internal services are routed through the gateway.

**Framework compatibility:** Python `requests`, `aiohttp`, Node.js `axios`, Go `net/http`, and most standard HTTP clients respect proxy environment variables automatically. Agent frameworks like LangChain, CrewAI, and Semantic Kernel use these standard clients internally, so **no framework code changes are needed** — only environment configuration.

### Non-HTTP Protocols

For database connections, gRPC, or custom TCP protocols that do not honor HTTP proxy variables, additional approaches are required:

| **Technique**                       | **Mechanism**                                                                                            | **Adoption Friction**                                 | **Effectiveness**                                                |
| ----------------------------------- | -------------------------------------------------------------------------------------------------------- | ----------------------------------------------------- | ---------------------------------------------------------------- |
| **iptables REDIRECT**               | Redirect all outbound traffic on specific ports to the gateway's proxy port                              | Low (infrastructure-level; no app changes)            | High — transparent to the agent                                  |
| **Service mesh (Istio, Linkerd)**   | Sidecar proxy captures all outbound TCP traffic and routes it through an egress gateway                  | Medium (requires mesh installation; no app changes)   | High — handles all protocols                                     |
| **Sidecar proxy injection**         | Envoy sidecar in the same pod intercepts agent container's outbound traffic via shared network namespace | Medium (K8s-only; no app changes)                     | High — protocol-agnostic                                         |
| **DNS manipulation**                | Agent's DNS resolves tool hostnames to the gateway's IP                                                  | Low (configuration-only)                              | Moderate — may confuse some protocols expecting specific TLS SNI |
| **Protocol-specific proxy support** | Configure gRPC/database clients to use HTTP CONNECT proxy                                                | Low-medium (requires client config, not code changes) | Moderate — depends on client library support                     |

**Recommended default:** Use **iptables REDIRECT** or a **sidecar proxy** for non-HTTP traffic. Both are transparent to the agent and do not require code changes — only infrastructure configuration managed by the platform team.

---

## 3. Preventing Agents from Calling Locally Accessible Tools

When agents and tools run on the same node, namespace, or cluster, additional care is needed to prevent local bypass:

### Pod Separation (Kubernetes)

**Never co-locate an agent and a protected tool in the same Pod.** Containers in the same Pod share a network namespace and can communicate via `localhost` without passing through any NetworkPolicy. By placing agents and tools in separate Pods, Kubernetes NetworkPolicies apply to all inter-Pod traffic.

### Namespace Isolation

Run agents in a dedicated namespace with strict NetworkPolicies. Protected services in other namespaces are unreachable unless the NetworkPolicy explicitly permits cross-namespace traffic to the gateway only.

### OS-Level Controls

| **Control**                    | **Purpose**                                                                         | **Friction**                                                               | **When to Use**                                                                  |
| ------------------------------ | ----------------------------------------------------------------------------------- | -------------------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| **seccomp (RuntimeDefault)**   | Blocks dangerous syscalls (raw sockets, new namespaces, kernel module loading)      | **Low** — applied via pod security context; no code changes                | **Always** — default for all sandboxed agents                                    |
| **AppArmor (runtime/default)** | Restricts filesystem access, prevents ptrace, limits process execution              | **Low** — available by default on most K8s distros; applied via annotation | **Always** — provides baseline MAC enforcement                                   |
| **Non-root UID**               | Prevents binding to privileged ports, modifying system configuration                | **Low** — set via `runAsUser` in security context                          | **Always**                                                                       |
| **Read-only root filesystem**  | Prevents agent from modifying system files (e.g., `/etc/resolv.conf` to bypass DNS) | **Low** — set via `readOnlyRootFilesystem: true`                           | **Always**                                                                       |
| **SELinux**                    | Fine-grained network and file access labels                                         | **High** — complex to configure; often disabled in K8s environments        | **Only for high-assurance** — use when formal MAC labeling is required by policy |
| **User namespaces**            | Maps container root to unprivileged host UID                                        | **Medium** — requires K8s 1.25+ with feature gate                          | **Recommended for high-assurance**                                               |

**Recommendation:** Use seccomp + AppArmor + non-root + read-only filesystem as the **default stack**. These controls are configuration-only (no code changes), widely supported, and provide strong protection against local bypass. **SELinux is not required for most deployments** — its complexity introduces significant adoption friction with marginal benefit over the default stack when combined with network-level enforcement.

The sandbox must provide strong isolation designed explicitly for untrusted workloads, assuming code is malicious by default, applying a least-privilege execution model, restricting system calls, and restricting native module loading.

### Shared Volume Protection

Agents should not have access to volumes shared with other workloads. Mount only ephemeral scratch space (`emptyDir`) and explicitly bound directories the agent has capability tokens for. No `hostPath` mounts. No shared persistent volumes between agent pods and service pods.

The Fluid Web Previewer compliance checklist requires: no identity/tenant/Copilot context inside the container, network off-by-default with explicitly declared and policy-validated access, brokered host access via constrained messaging, and teardown guarantees between sessions. These requirements directly map to the isolation controls above.

---

## 4. Recommended Enforcement Stack

### What NOT to Require Initially (Reducing Adoption Friction)

| **Requirement to Defer**                                 | **Why Defer**                                                                                     | **When to Introduce**                                             |
| -------------------------------------------------------- | ------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| SELinux custom policies                                  | Complex to author and debug; most benefits covered by seccomp + AppArmor + network controls       | Phase 3 or when regulatory policy mandates formal MAC labeling    |
| Tool-level token validation                              | Unnecessary when network isolation guarantees gateway-only access                                 | Only if direct agent-to-tool paths cannot be fully eliminated     |
| Deep framework code changes (LangChain/CrewAI internals) | Proxy env vars handle most HTTP routing transparently                                             | Only if framework-specific protocols bypass standard HTTP clients |
| Custom seccomp whitelist profiles                        | Requires profiling each agent's syscall patterns; RuntimeDefault is sufficient for most workloads | Phase 2 for high-assurance workloads                              |
| Mandatory sidecar proxy injection                        | Adds operational complexity; NetworkPolicy + proxy env vars are sufficient for HTTP-heavy agents  | When non-HTTP protocols require transparent interception          |

### Cloud Identity Scoping

Ensure the agent's cloud identity (Managed Identity, service account) does **not** have permission to directly call protected APIs. The agent's identity should only be able to authenticate to the Capability Issuer (to request tokens) and to the tools gateway (to present tokens). Protected services should accept calls only from the gateway's identity. This ensures that even if an agent somehow obtained a direct network path, it would lack the identity credentials to authenticate to the target service.

---

## 5. Practical Agent Framework Integration

For common agent frameworks, the integration path is configuration-first:

| **Framework**       | **Integration Approach**                                                                                     | **Code Changes Required**                                         |
| ------------------- | ------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------- |
| **LangChain**       | Set `HTTP_PROXY`/`HTTPS_PROXY` env vars; optionally set `OPENAI_API_BASE` to route LLM calls through gateway | **None** (environment configuration only)                         |
| **CrewAI**          | Same proxy env vars; CrewAI uses standard Python HTTP clients internally                                     | **None**                                                          |
| **Semantic Kernel** | Configure HTTP client settings via `appsettings.json` or env vars to use proxy                               | **None** (configuration file change)                              |
| **AutoGen**         | Same proxy env vars                                                                                          | **None**                                                          |
| **Custom agents**   | Set proxy env vars; ensure all HTTP clients in the codebase respect them                                     | **Minimal** — verify no client explicitly disables proxy settings |

**Optional enhancement for deeper integration:** Provide an internal SDK library (e.g., `agentcap`) that wraps capability token retrieval and attachment. Agents import the library and call `agentcap.init()` at startup, which retrieves tokens from the Capability Issuer and configures the local environment. This is a **one-line addition** to agent code, not a deep framework modification.

---

## 6. Architecture Summary

The enforcement architecture operates in three layers, each independently preventing unauthorized tool access:

1.  **Network layer (hard boundary):** The agent's network namespace permits egress only to the tools gateway. All other traffic is dropped by NetworkPolicy or firewall rules. This is the primary enforcement mechanism and cannot be bypassed by application-level techniques.

2.  **Proxy layer (transparent routing):** HTTP_PROXY/HTTPS_PROXY environment variables route standard HTTP clients through the gateway automatically. This provides correct routing for well-behaved code without requiring awareness of the gateway. [\[techcommun...rosoft.com\]](https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/controlling-aks-egress-using-an-http-proxy/4119407)

3.  **OS layer (containment):** seccomp, AppArmor, non-root execution, and read-only filesystems prevent the agent from manipulating its own networking configuration, spawning privileged processes, or accessing host resources that could enable bypass.

**The tools gateway validates capability tokens once per request.** Protected services receive forwarded requests from the gateway under a trusted identity and do not need to implement token validation logic. This mirrors existing enterprise patterns where intermediary platforms perform authorization and downstream services rely exclusively on the platform's token without conducting internal role validations.

**The result:** agents continue using tools via standard HTTP calls with no framework modifications beyond environment configuration. Protected tools remain unchanged. Security enforcement is fully externalized to the platform infrastructure — the gateway, network policies, and OS-level sandbox — which are managed by the central platform team and applied uniformly to all agent workloads.
