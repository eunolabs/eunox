# eunox — Execution Plan

Phased roadmap to close the enterprise adoption gap. Priorities and dependencies wired explicitly.

**Priority levels:** P0 = blocking, do first · P1 = high value, near-term · P2 = strategic, parallel · P3 = later

---

## Phase 1 — Prove the Gap Exists
**Weeks 1–4 · All P0 tasks must close before Phase 2 begins**

---

### T-01 · Build the "Envoy/OPA fails here" reproducible demo
**Priority:** P0 · **Effort:** 3–5 days · **Owner:** Founder/eng · **Depends on:** Nothing — start here

Every enterprise architect evaluating eunox will ask: "why can't I just extend OPA?" Without a concrete, runnable failure demonstration the answer is theoretical and loses. With it, you shift the conversation from "convince me" to "show me where my existing stack breaks."

**Steps:**
1. Set up a minimal OPA + Envoy ext_authz stack with a simple MCP tool call (pick `read_file` or `query_db`)
2. Show it working — enumerate what OPA can enforce at HTTP level
3. Introduce scenario 1: parameter-dependent authorization (`read_file` for `/reports/*` allowed, `/internal/*` blocked). Show Rego complexity explosion as policies compound
4. Introduce scenario 2: sequential tool call that is individually safe but collectively dangerous (`read credentials` → `write to external endpoint`). OPA has no session context. Show the gap
5. Introduce scenario 3: task-lifecycle credential. Time-based STS credential either expires mid-task or is over-privileged. Show both failure modes
6. Show eunox handling all three cleanly with policy definitions that are human-readable
7. Publish as a runnable Docker Compose setup with a 10-minute guided walkthrough in the README

**Success metric:** An enterprise security architect can run this demo in under 15 minutes and hit the failure modes themselves. Not a video — a runnable environment.

---

### T-02 · Native MCP enforcement demo with Claude/Cursor
**Priority:** P0 · **Effort:** 4–6 days · **Owner:** Founder/eng · **Depends on:** T-01

MCP is the protocol that matters right now. Claude Desktop, Cursor, and Windsurf all use it. An enterprise evaluating AI agent governance needs to see eunox intercept and enforce on real MCP traffic from tools their engineers actually use. Without this you're an abstract architecture, not a product.

**Steps:**
1. Stand up a test MCP server (filesystem + a mock DB tool is sufficient)
2. Route Claude Desktop or Cursor through the eunox gateway with zero client-side changes
3. Demonstrate policy enforcement: allow `read_file`, block `write_file`, allow `query_db` only for SELECT statements
4. Demonstrate audit trail: show the full tool call graph in the eunox UI, causal links intact
5. Demonstrate credential lifecycle: short-lived DB token minted at task start, revoked at completion
6. Record a 3-minute screen capture — no voiceover needed, the enforcement events should be self-explanatory
7. Publish demo repo with one-command setup

**Success metric:** Someone watching the demo understands what eunox does within 90 seconds without reading any documentation.

---

### T-03 · Publish a formal threat model document
**Priority:** P0 · **Effort:** 2–3 days · **Owner:** Founder · **Depends on:** Nothing — run in parallel with T-01 and T-02

You are selling a security product into enterprises. Their security team will not approve deployment of a component with no documented threat model. This document unblocks the entire enterprise sales motion. Without it, technical interest stalls at the champion level and never reaches the security review committee.

**Required contents:**
1. Trust boundaries diagram: what eunox trusts, what it verifies, what it ignores
2. Attack classes prevented: token forgery, capability escalation, session hijacking, credential theft via tool call, audit log tampering
3. Attack classes explicitly out of scope: prompt injection, model jailbreak, client-side compromise
4. Failure modes: what happens if the gateway crashes (fail closed by default, configurable), if the issuer is unavailable, if Redis Sentinel fails
5. Data sensitivity: what eunox logs, what it never logs, how to configure redaction
6. Cryptographic primitives used and why
7. Third-party audit status — even if "planned Q3 2026," be honest about where you are

**Success metric:** A CISO at a Fortune 500 can read this document and schedule a security review. It should answer the questions they would otherwise ask via email over 3 weeks.

---

## Phase 2 — Nail the Onboarding Funnel
**Weeks 4–10 · Parallel execution possible on T-04 through T-07**

---

### T-04 · Sub-20-minute local developer setup path
**Priority:** P0 · **Effort:** 1–2 weeks · **Owner:** Eng · **Depends on:** T-02

Infra projects die at the onboarding step. An engineer evaluating eunox has maybe 20–30 minutes of goodwill before they move on. If they don't see enforcement working against their own tool calls in that window, you've lost them. This is not polish — it is the adoption surface.

**Steps:**
1. Define the golden path: one command to start the full stack locally (gateway + issuer + minter + Redis), no external dependencies
2. Provide a pre-seeded default policy set that works out of the box — don't make the user write policy on day one
3. Ship a CLI tool (`eunoctl`) that lets developers issue capability tokens, inspect the audit trail, and simulate policy decisions from the terminal
4. Build a local dashboard (minimal, read-only) that shows live tool call enforcement events — visual feedback is critical for developer trust
5. Time the setup yourself with a cold machine. Target: `git clone` → first enforced tool call in under 15 minutes. If it takes longer, cut scope until it doesn't
6. Write a "Day 0 to first enforcement" doc that is literally a sequence of commands with expected output after each one

**Success metric:** 5 external developers complete setup in under 20 minutes without asking for help. Run this as an informal usability test before calling it done.

> **Risk:** The temptation is to keep adding features before fixing onboarding. Resist. A product that 10 people complete setup for is more valuable than a product with 3 more features that no one can install.

---

### T-05 · OPA bridge: feed agent behavioral context into existing Rego policies
**Priority:** P1 · **Effort:** 1–2 weeks · **Owner:** Eng · **Depends on:** T-01, T-04

Enterprises with existing OPA deployments will not rip them out. If eunox requires replacing OPA, the deal dies at the architecture review. If eunox integrates with OPA by enriching it with agent context that OPA alone cannot see, you become additive rather than competitive. That is a fundamentally easier sell.

**Steps:**
1. Build an OPA data source plugin that pushes current agent session state (active task, tool call history, issued capability tokens) into OPA's data document
2. Provide sample Rego policies that consume this context: "deny if this agent has already called `write_file` more than 3 times in this session"
3. Build an Envoy ext_authz handler that delegates MCP-specific decisions to eunox while passing HTTP decisions through to existing OPA
4. Document the integration pattern explicitly: "keep OPA for your existing HTTP policies, add eunox for the agent-specific layer"
5. Publish as a named integration: "eunox for OPA users"

**Success metric:** An enterprise with existing OPA can add eunox without changing any existing Rego policies. Their existing authorization stack continues to work; eunox adds the agent layer on top.

---

### T-06 · OpenTelemetry-native trace export
**Priority:** P1 · **Effort:** 1 week · **Owner:** Eng · **Depends on:** T-04

Enterprises already have Datadog, Grafana, Jaeger, or Honeycomb. If eunox emits OTel traces with agent-specific span attributes, it becomes immediately visible in their existing dashboards. This turns "add another tool" into "add another data source to the tool you already have."

**Steps:**
1. Instrument gateway, issuer, and minter with `otel-go` SDK — traces, metrics, logs
2. Define custom span attributes: `eunox.task_id`, `eunox.capability_token_id`, `eunox.tool_name`, `eunox.policy_decision`, `eunox.agent_id`
3. Emit a trace per tool call with parent span linking back to the task — this gives the causal chain in any OTel-compatible backend
4. Provide a Grafana dashboard JSON export that visualizes agent tool call graphs, policy decision rates, and credential lifecycle
5. Publish an integration guide for Datadog, Grafana, and Jaeger — these cover 80% of enterprise deployments

**Success metric:** An engineer can see eunox enforcement events in their existing Datadog instance within 30 minutes of enabling the OTel exporter. No new dashboards required on day one.

---

### T-07 · Task-lifecycle credential revocation for AWS/Azure/GCP
**Priority:** P1 · **Effort:** 2–3 weeks · **Owner:** Eng · **Depends on:** T-04

AWS STS minimum session duration is 15 minutes. Azure managed identity has no concept of task completion. eunox can mint short-lived credentials tied to task lifecycle and revoke them on task completion or failure. This is a concrete, demonstrable advantage that cloud IAM literally cannot offer today.

**Steps:**
1. Build the task-completion revocation hook in the minter: on `task.complete` or `task.fail` event, revoke associated credentials immediately
2. Implement AWS: use STS `AssumeRole` with a custom session tag (`eunox_task_id`), then call `STS RevokeSession` on task completion
3. Implement Azure: use managed identity with short-lived tokens (minimum viable duration), refresh only while task is active
4. Implement GCP: Workload Identity Federation with task-scoped service account tokens
5. Build the demo: agent task mints a DB credential, completes, credential is revoked — attempt to reuse the credential after task completion and show it fails
6. Benchmark: show the privilege exposure window — typical STS: 15 minutes, eunox: average task duration (likely under 60 seconds for most tool calls)

**Success metric:** The privilege exposure window comparison is a publishable benchmark that security teams can cite in their own risk assessments.

---

## Phase 3 — Own a Vertical
**Weeks 10–20 · Pick one vertical and go deep before expanding**

---

### T-08 · Build a complete healthcare (HIPAA) reference architecture
**Priority:** P1 · **Effort:** 3–4 weeks · **Owner:** Founder + 1 eng · **Depends on:** T-03, T-06, T-07

Healthcare has the highest urgency around AI agent governance right now. Clinical AI copilots are being deployed on HIPAA-regulated data with no compliance framework for AI tool call authorization. The audit trail requirement alone is a direct eunox use case. Healthcare buyers have budget, are accustomed to buying security tools, and cannot use open-source-only solutions for regulated workloads.

**Deliverables:**
1. Map HIPAA technical safeguard requirements to eunox capabilities: audit controls → tamper-evident audit trail, access controls → capability tokens, transmission security → JWKS + mTLS
2. Build a reference architecture for a clinical AI copilot: EHR read access, note generation, lab result retrieval — all enforced through eunox
3. Document PHI handling: what eunox logs about tool call parameters, how to configure redaction of PHI from audit logs
4. Produce a BAA-ready data flow diagram showing where PHI transits and how it is protected
5. Write a one-pager for compliance officers (not engineers) explaining what eunox does in HIPAA language
6. Partner with one healthcare org for a pilot deployment — even a non-production environment counts as a reference

**Success metric:** One healthcare organization begins a paid pilot. The reference architecture is cited in their HIPAA risk assessment documentation.

---

### T-09 · Policy simulation and dry-run framework
**Priority:** P1 · **Effort:** 1–2 weeks · **Owner:** Eng · **Depends on:** T-04, T-06

Enterprises will not deploy a new enforcement gateway in production without being able to test policies against real traffic in a non-enforcing mode first. This is the same pattern that made OPA's dry-run and audit modes critical for adoption. Without it, the operational risk of a misconfigured policy blocking legitimate agent traffic is too high to accept.

**Steps:**
1. Build dry-run mode: policies are evaluated but not enforced, decisions are logged
2. Build a policy simulator: feed a recorded audit session back through a new policy and show what would have been blocked
3. Build a policy diff tool: given two policy versions, show which tool calls would be newly blocked or newly allowed
4. Build a coverage reporter: given an audit session, show which policy rules were exercised and which were never triggered
5. Integrate into `eunoctl`: `eunoctl policy simulate --session=<id> --policy=new-policy.yaml`

**Success metric:** An enterprise can run eunox in shadow mode for 2 weeks, review dry-run decisions, gain confidence, then flip to enforcement mode — with zero production incidents from policy misconfiguration.

---

### T-10 · Replayable audit sessions with causal timeline UI
**Priority:** P2 · **Effort:** 2–3 weeks · **Owner:** Eng + design · **Depends on:** T-06, T-09

When an incident occurs, the first question is always: "show me exactly what happened and why." No existing tool can answer this for AI agent sessions. eunox has all the data — task ID, tool call sequence, capability tokens issued, policy decisions — but it needs a UI that makes this navigable for a security analyst under pressure.

**Steps:**
1. Build a session timeline view: every tool call in a session rendered as an event on a timeline, with policy decisions annotated inline
2. Add causal linking: clicking any tool call shows which capability token authorized it, which task it belongs to, and which agent invoked it
3. Build replay mode: step through a session chronologically, see the state of the agent's capability set at each point
4. Add SIEM export: CEF and JSON export of session data for Splunk, QRadar, Sentinel integration
5. Build tamper-evidence verification: given a session ID, verify the audit trail hash chain is intact — important for legal admissibility

**Success metric:** A security analyst can answer "what did the agent do and why was it authorized" for any session in under 5 minutes using the eunox UI alone.

---

## Phase 4 — Expand the Moat
**Weeks 20+ · Only start these once Phase 3 has a paying customer**

---

### T-11 · Agent behavioral anomaly detection
**Priority:** P2 · **Effort:** 4–6 weeks · **Owner:** Eng + ML · **Depends on:** T-06, T-10, 3+ production deployments

Anomaly detection requires a baseline, which requires production data, which requires paying customers running eunox in production. Building this before you have real traffic data means building on invented assumptions. Do it after you have 3+ production deployments generating real agent behavior patterns.

**Steps:**
1. Build a baseline model: for each agent type, record the distribution of tool calls, parameter ranges, sequence patterns, and credential usage over a 2-week observation window
2. Build deviation detection: flag sessions where tool call frequency, parameter entropy, or sequence patterns deviate significantly from baseline
3. Integrate with policy: allow "alert on anomaly" and "block on anomaly" policy rules
4. Build the alert UI: show anomaly score, which specific behavior triggered it, and comparable baseline sessions
5. Explicitly scope what this is not: not a jailbreak detector, not a prompt injection detector, not a model behavior analyzer

---

### T-12 · SaaS-hosted control plane with on-prem enforcement
**Priority:** P2 · **Effort:** 6–8 weeks · **Owner:** Founder + eng · **Depends on:** T-08, T-09, T-10

Enterprises want the enforcement gateway in their own network (data never leaves). They want policy management, dashboards, and team collaboration hosted and managed. This is the same model as OPA + Styra, Envoy + Tetrate, or Vault + HCP. It gives you a recurring revenue model without forcing enterprises to accept a fully SaaS enforcement plane for sensitive agent traffic.

**Steps:**
1. Build the control plane separation: gateway and minter run on-prem, policy sync and audit aggregation connect to hosted control plane
2. Build the policy management UI: version control for policies, approval workflows, role-based access for policy authors vs. reviewers
3. Build team features: multiple environments (dev/staging/prod), policy promotion workflow, audit log search and retention
4. Define the data boundary explicitly: audit log metadata goes to control plane (task IDs, decisions), tool call parameters never leave the customer network
5. Publish SOC2 Type II roadmap — table stakes for enterprise SaaS in security tooling

---

## Dependency Graph

| Task | Title | Depends on |
|------|-------|------------|
| T-01 | OPA/Envoy failure demo | — |
| T-02 | MCP demo (Claude/Cursor) | T-01 |
| T-03 | Threat model doc | — |
| T-04 | Sub-20-min onboarding | T-02 |
| T-05 | OPA bridge integration | T-01, T-04 |
| T-06 | OpenTelemetry export | T-04 |
| T-07 | Task-lifecycle credentials | T-04 |
| T-08 | HIPAA reference architecture | T-03, T-06, T-07 |
| T-09 | Policy simulation / dry-run | T-04, T-06 |
| T-10 | Replayable audit sessions | T-06, T-09 |
| T-11 | Behavioral anomaly detection | T-06, T-10 + prod data |
| T-12 | SaaS control plane | T-08, T-09, T-10 |

**Critical path:** T-01 → T-02 → T-04 → T-05 / T-06 / T-07 → T-08 → T-10 → T-12

---

## What to hold onto

- **T-03 has no dependencies.** It can be written today. It unblocks the entire enterprise sales motion and there is no reason to defer it.
- **T-04 is the real bottleneck.** Every downstream task depends on a working, installable product. Onboarding quality is not a nice-to-have — it is the adoption surface.
- **T-05 is the strategic linchpin.** Changing the conversation from "replace OPA" to "extend OPA" is worth more than almost any feature you could ship.
- **Do not start T-11 or T-12 before a paying customer.** Anomaly detection without real production traffic is built on fiction. SaaS infrastructure before a proven deployment model is waste.
