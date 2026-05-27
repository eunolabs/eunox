# Suggested Blog Articles for eunox

A curated list of article ideas spanning background, context, architecture,
user experience, technology choices, and design principles. Articles are
grouped by theme and roughly ordered from introductory to in-depth.

---

## Why AI agents need guardrails

1. **The prompt injection problem: why every AI agent needs a policy layer**
   Walks through a real-world attack — an agent reads a PDF containing a
   hidden instruction to run `DROP TABLE users` — and shows exactly where a
   policy proxy intercepts it. Audience: developers new to AI security.

2. **Least-privilege for AI: translating a 20-year-old principle to the agent era**
   Explains why classical RBAC and OAuth scopes don't map cleanly onto
   multi-tool, multi-step agent workflows, and introduces the capability-token
   model as the correct abstraction.

3. **What goes wrong when you skip agent governance: five failure modes**
   Concrete stories: runaway automation, data exfiltration through a
   `send_email` tool, SQL injection via a cooperative LLM, accidental
   multi-tenant data cross-contamination, and unbounded cost from a looping
   agent. Audience: engineering managers and security architects.

4. **Zero trust for AI agents: a practitioner's guide**
   Frames eunox's architecture in zero-trust terms — never trust, always
   verify, enforce at the policy decision point before reaching the backend.
   Complements the Azure Tech Community post series.

---

## The Model Context Protocol and where eunox fits

5. **MCP explained: the USB-C moment for AI tooling**
   A plain-language introduction to the Model Context Protocol — what it
   standardises, why it matters, and the gap it leaves on the security side.

6. **Building a policy proxy for MCP: design choices and trade-offs**
   Covers the architectural decision to sit between MCP host and upstream
   server rather than instrumenting either side; STDIO vs. HTTP transport
   considerations; and the fail-closed guarantee.

7. **Drop-in governance: adding `eunox-mcp` to Claude Desktop in 5 minutes**
   Step-by-step tutorial with screenshots. Audience: individual developers
   who have never thought about AI agent security.

8. **From local YAML to hosted policy store: eunox's migration story**
   Narrates the transition from a single-process YAML file to a gateway with
   shared Redis call counters, a Postgres audit ledger, and KMS-backed signing.
   Why the policy format stays identical across both modes.

---

## Architecture deep-dives

9. **Capability tokens: a cryptographic contract between agent and operator**
   Explains the JWT-based `AgentCapabilityManifest` — issuer, audience, JTI,
   condition embedding, attenuation chains — and why a token is better than
   a shared API key.

10. **The Tool Gateway as a reference monitor: implementing PDP in practice**
    Covers the enforcement engine pipeline: token verification → condition
    evaluation → obligation application → audit emission. Shows why unknown
    conditions fail closed.

11. **Tamper-evident audit logs: OCSF, HMAC chaining, and KMS-signed evidence**
    Deep dive into the OCSF API Activity schema, the per-row HMAC chain,
    PostgreSQL ledger backends, and the cross-chain anchor that ties replica
    chains together for SOC 2 evidence.

12. **Pluggable adapters: building a cloud-portable identity and signing layer**
    Describes the `IdentityAdapter` / `SigningAdapter` pattern that lets eunox
    swap Azure AD + Key Vault, AWS Cognito + KMS, and GCP Cloud Identity +
    Cloud KMS without changing the enforcement core.

13. **Partner DID federation: cross-org trust without shared secrets**
    Explains W3C DIDs (`did:web`, `did:ion`), the two-eyes approval workflow,
    per-DID circuit breakers, pin attestation, and why non-fault errors never
    trip the circuit.

14. **AGT: defense in depth inside the agent process**
    Introduces the in-process `createAgtGuard()` that checks policy before the
    network ever sees a tool call, and explains the single-audit-entry invariant
    it maintains with the gateway.

---

## Design principles

15. **Fail closed, not fail open: the most important decision in security software**
    Examines how every layer of eunox — unknown conditions, gateway
    unavailability, malformed tokens, network errors — defaults to deny rather
    than allow. Contrasts with real-world systems that chose differently.

16. **Schema parity over version drift: keeping the YAML format honest**
    Explains why `eunox-mcp`, the Go runtime SDK, and the gateway all share a
    single `AgentCapabilityManifest` type from the shared `pkg/` Go packages and why
    the Apache/BUSL license split exists to keep that contract public.

17. **Declarative, not transitive: the partner federation trust model**
    Articulates why eunox's federation model requires an explicit operator
    opt-in per partner DID rather than transitive trust chains, and the
    security properties this choice provides.

18. **Defense-in-depth for SQL injection through an LLM**
    Walks through the layered approach: `allowedOperations` first-word
    extraction, `argumentSchema` pattern guards, disabling multi-statement
    queries, read-only DB credentials, parameterized queries upstream. Honest
    about what each layer can and cannot catch.

---

## User experience and developer ergonomics

19. **One YAML file: the design philosophy behind eunox's policy format**
    Why YAML beats code: version-controllable, reviewable, diff-able, shareable
    between agent developers and security teams. Covers the manifest structure
    and the authoring guide.

20. **From dev to prod: the eunox CLI experience**
    Walks through `eunox init`, `eunox validate`, `eunox request` (PKCE flow),
    `eunox validate-token`, `eunox audit export`, and `eunox discover`. Emphasis
    on the developer feedback loop.

21. **Operator tooling: kill switches, revocation, and SCIM provisioning**
    For platform engineers and security teams: live kill-switch activation,
    per-token revocation, bulk role-to-capability mapping via SCIM 2.0, and
    Prometheus alert examples.

22. **Reference policies: copy-paste guardrails for common MCP servers**
    Annotated walk-through of the five bundled policies (filesystem, Postgres,
    GitHub, Slack, fetch) with commentary on why each constraint was chosen.

---

## Technology choices

23. **Why OCSF? Choosing a schema for AI agent audit events**
    Background on the Open Cybersecurity Schema Framework, why API Activity
    was the right event class, and how eunox maps tool calls into OCSF fields
    for SIEM ingestion.

24. **W3C DIDs in production: lessons from building a partner federation layer**
    Practical experience with `did:web` resolution reliability, ION node
    dependencies, negative caching, and why the circuit breaker needed careful
    fault-error classification.

25. **KMS-backed JWT signing: trade-offs between Azure Key Vault, AWS KMS, and GCP Cloud KMS**
    Compares latency profiles, key-rotation mechanics, managed identity vs.
    service-account auth, and the HSM boundary each service enforces.

26. **Redis as a shared enforcement substrate: call counters, kill-switch, and DPoP replay**
    Explains how the gateway uses Redis for distributed `maxCalls` enforcement,
    the global kill-switch, revocation list, and replay-attack prevention —
    and what happens when Redis is unavailable (fail-closed fallback).

27. **SCIM 2.0 for AI agents: bringing enterprise directory provisioning to capability tokens**
    Walks through the SCIM user / group lifecycle, how eunox maps groups to
    roles to capability templates, and the `externalId` / `userName` fallback
    lookup strategy.

---

## Compliance and enterprise

28. **Building for SOC 2: mapping CC6 and CC7 controls to an AI governance platform**
    Detailed mapping of SOC 2 CC6 (Logical and Physical Access) and CC7
    (System Operations) controls to eunox's audit evidence, signed bundles,
    and the `GET /api/v1/audit/export` endpoint.

29. **Air-gapped AI governance: deploying eunox with no internet dependency**
    Covers the Helm umbrella chart, the air-gap image list, pull scripts,
    offline DID resolution strategies, and on-premises KMS integration.

30. **The BUSL / Apache split: open-source AI security with a sustainable license model**
    Explains the two-folder architecture (`public/` Apache-2.0, platform
    BUSL-1.1), why the core policy types must stay open, and what "non-competing
    use" means for your deployment.

---

## Runtime sandboxing and OS-level controls

31. **Locking down the agent runtime: a field guide to sandboxing every tool call**
    Comprehensive treatment of how to make the Tool Gateway the _only_
    structurally enforced egress path for an agent process, across every deployment
    topology: plain containers, Kubernetes with gVisor or Kata Containers,
    Firecracker microVMs for bare-metal, and constrained edge environments.
    Covers seccomp syscall filtering (with a worked minimum-allowlist profile),
    eBPF runtime enforcement and observability via Cilium/Tetragon, gVisor's
    user-space kernel isolation and its compatibility tradeoffs, Kata Containers
    and Firecracker microVMs for full hypervisor-level isolation, network
    locking patterns per environment (Cilium NetworkPolicy, VPC firewall rules,
    hypervisor-level iptables, vsock proxying), workload identity (projected
    service accounts, SPIFFE/SPIRE) to eliminate secret-zero, the sidecar
    gateway co-location pattern, and an honest accounting of what the
    architecture doesn't protect against (timing side-channels, supply chain
    in the base image, gateway compromise). Concludes with a prioritised
    implementation checklist. Audience: principal engineers and platform
    security architects deploying agent workloads in production.
