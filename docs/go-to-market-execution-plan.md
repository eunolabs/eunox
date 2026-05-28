# eunox — Go-to-Market Execution Plan

Phased roadmap covering engineering, DevRel, content, and enterprise sales.
Priorities and dependencies are explicit. Engineering tasks and GTM workstreams are unified here — do not maintain separate plans.

> **Last updated:** 2026-05-28
> **Supersedes:** `adoption-plan.md` (deleted)

**Priority levels:** P0 = blocking, start immediately · P1 = high value, near-term · P2 = strategic / parallel · P3 = deferred to later phase

---

## Phase 1 — Prove the Gap Exists
**Weeks 1–4 · All P0 tasks must close before Phase 2 begins**

---

### T-01 · Build the "Envoy/OPA fails here" reproducible demo
**Priority:** P0 · **Effort:** 3–5 days · **Owner:** Founder/eng · **Depends on:** nothing — start here

Every enterprise architect evaluating eunox will ask: "why can't I just extend OPA?" Without a concrete, runnable failure demonstration the answer is theoretical and loses. With it, you shift the conversation from "convince me" to "show me where my existing stack breaks."

**Steps:**
1. Set up a minimal OPA + Envoy ext_authz stack with a simple MCP tool call (`read_file` or `query_db`)
2. Show it working — enumerate what OPA can enforce at HTTP level
3. Scenario 1: parameter-dependent authorization (`read_file` for `/reports/*` allowed, `/internal/*` blocked). Show Rego complexity explosion as policies compound
4. Scenario 2: sequential tool call that is individually safe but collectively dangerous (`read credentials` → `write to external endpoint`). OPA has no session context — show the gap
5. Scenario 3: task-lifecycle credential. Time-based STS credential either expires mid-task or is over-privileged. Show both failure modes
6. Show eunox handling all three cleanly with human-readable policy definitions
7. Publish as a runnable Docker Compose setup with a 10-minute guided walkthrough

**Success metric:** An enterprise security architect can run this demo in under 15 minutes and hit the failure modes themselves. Not a video — a runnable environment.

---

### T-02 · Native MCP enforcement demo with Claude/Cursor
**Priority:** P0 · **Effort:** 4–6 days · **Owner:** Founder/eng · **Depends on:** T-01

MCP is the protocol that matters right now. Claude Desktop, Cursor, and Windsurf all use it. An enterprise evaluating AI agent governance needs to see eunox intercept and enforce on real MCP traffic from tools their engineers actually use.

**Steps:**
1. Stand up a test MCP server (filesystem + a mock DB tool)
2. Route Claude Desktop or Cursor through the eunox gateway with zero client-side changes
3. Demonstrate policy enforcement: allow `read_file`, block `write_file`, allow `query_db` only for SELECT
4. Demonstrate audit trail: show the full tool call graph with causal links intact
5. Demonstrate credential lifecycle: short-lived DB token minted at task start, revoked at completion
6. Record a 3-minute screen capture — no voiceover needed, enforcement events should be self-explanatory
7. Publish demo repo with one-command setup

**Success metric:** Someone watching the demo understands what eunox does within 90 seconds without reading any documentation.

---

### T-03 · Publish a formal threat model document
**Priority:** P0 · **Effort:** 2–3 days · **Owner:** Founder · **Depends on:** nothing — run in parallel with T-01 and T-02

Enterprises will not approve deployment of a component with no documented threat model. This document unblocks the entire enterprise sales motion. Without it, technical interest stalls at the champion level and never reaches the security review committee.

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

### T-04 · Rapid-response content template
**Priority:** P1 · **Effort:** 1–2 days · **Owner:** Content · **Depends on:** nothing — run in parallel

Incident-driven content only works if it can be published fast. Prepare the template before an incident occurs.

**Steps:**
1. Write a fill-in-the-blank incident postmortem template: attack vector, what failed, where eunox enforcement would have intercepted, remediation
2. Pre-write three fictional-but-realistic postmortems (data exfiltration, unauthorized API calls, prompt injection leading to privilege escalation); annotate exactly where enforcement would have stopped the attack chain
3. Establish a monitoring list: AI security researchers, journalists, GitHub security advisories for MCP-related projects — so a real incident is caught within hours

**Success metric:** First fictional postmortem published within week 4; real-incident response can be live within 24 hours of an event.

---

### T-05 · Licensing FAQ
**Priority:** P1 · **Effort:** 1 day · **Owner:** Legal + DevRel · **Depends on:** nothing

> **Note:** The Apache-2.0 / BUSL-1.1 dual-license split is now implemented (`cmd/mcp` is Apache-2.0; platform is BUSL-1.1). The README, NOTICE, and site have been updated. This task covers the remaining documentation gap.

**Steps:**
1. Add a `docs/licensing-faq.md` that answers the deployment scenarios explicitly: "is my use case covered?"
2. Confirm the Apache-2.0 scope for any future `eunox-python` package (see Decision Log)
3. Publish a public commitment on the BUSL conversion timeline (four years from each release) in a prominent location — `README.md` and the FAQ

**Success metric:** Zero "is this actually free?" questions on GitHub Discussions or community channels after week 4.

---

## Phase 2 — Nail the Onboarding Funnel
**Weeks 4–10 · Parallel execution possible on T-06 through T-12**

---

### T-06 · Sub-20-minute developer onboarding
**Priority:** P0 · **Effort:** 1–2 weeks · **Owner:** Eng + DevRel · **Depends on:** T-02

Infra projects die at the onboarding step. An engineer evaluating eunox has maybe 20–30 minutes of goodwill before they move on. This is not polish — it is the adoption surface.

**Steps:**
1. Audit the current "Quick Start" path end-to-end; document actual time-to-enforcement on a cold machine
2. Define the golden path: one command to start the full stack locally, no external dependencies — target `git clone` → first enforced tool call in under 15 minutes
3. Ship `eunox dev` CLI command — single binary, embedded SQLite, self-signed keys, zero external deps; publish on Homebrew and as a `go install` target
4. Provide a pre-seeded default policy set that works out of the box; do not make the user write policy on day one
5. Build a local dashboard (minimal, read-only) showing live enforcement events — visual feedback is critical for developer trust
6. Ship `eunoctl` CLI: issue capability tokens, inspect the audit trail, simulate policy decisions from the terminal
7. Create a 5-minute interactive terminal tutorial: install → configure policy YAML → run agent → see enforcement
8. Record a sub-3-minute demo video showing enforcement stopping an unauthorized tool call
9. Write a "Day 0 to first enforcement" doc: a literal sequence of commands with expected output after each

**Success metric:** 5 external developers complete setup in under 20 minutes without asking for help (usability test before calling it done).

> **Risk:** The temptation is to keep adding features before fixing onboarding. Resist. A product 10 people can install is more valuable than a product with 3 more features nobody can set up.

---

### T-07 · OPA bridge: feed agent behavioral context into existing Rego policies
**Priority:** P1 · **Effort:** 1–2 weeks · **Owner:** Eng · **Depends on:** T-01, T-06

Enterprises with existing OPA deployments will not rip them out. If eunox requires replacing OPA, the deal dies at the architecture review. If eunox integrates with OPA by enriching it with agent context that OPA alone cannot see, you become additive rather than competitive.

**Steps:**
1. Build an OPA data source plugin that pushes current agent session state (active task, tool call history, issued capability tokens) into OPA's data document
2. Provide sample Rego policies that consume this context: "deny if this agent has already called `write_file` more than 3 times in this session"
3. Build an Envoy ext_authz handler that delegates MCP-specific decisions to eunox while passing HTTP decisions through to existing OPA
4. Document the integration pattern explicitly: "keep OPA for your existing HTTP policies, add eunox for the agent-specific layer"
5. Publish as a named integration: "eunox for OPA users"

**Success metric:** An enterprise with existing OPA can add eunox without changing any existing Rego policies. Their existing authorization stack continues working; eunox adds the agent layer on top.

---

### T-08 · OpenTelemetry-native trace export
**Priority:** P1 · **Effort:** 1 week · **Owner:** Eng · **Depends on:** T-06

Enterprises already have Datadog, Grafana, Jaeger, or Honeycomb. If eunox emits OTel traces with agent-specific span attributes, it becomes immediately visible in their existing dashboards — "add another data source" rather than "add another tool."

**Steps:**
1. Instrument gateway, issuer, and minter with `otel-go` SDK — traces, metrics, logs
2. Define custom span attributes: `eunox.task_id`, `eunox.capability_token_id`, `eunox.tool_name`, `eunox.policy_decision`, `eunox.agent_id`
3. Emit a trace per tool call with parent span linking back to the task — this gives the causal chain in any OTel-compatible backend
4. Provide a Grafana dashboard JSON export: agent tool call graphs, policy decision rates, credential lifecycle
5. Publish an integration guide for Datadog, Grafana, and Jaeger (80% of enterprise deployments)

**Success metric:** An engineer can see eunox enforcement events in their existing Datadog instance within 30 minutes of enabling the OTel exporter. No new dashboards required on day one.

---

### T-09 · Task-lifecycle credential revocation for AWS/Azure/GCP
**Priority:** P1 · **Effort:** 2–3 weeks · **Owner:** Eng · **Depends on:** T-06

AWS STS minimum session duration is 15 minutes. Azure managed identity has no concept of task completion. eunox can mint short-lived credentials tied to task lifecycle and revoke them on task completion or failure — a concrete, demonstrable advantage that cloud IAM literally cannot offer today.

**Steps:**
1. Build the task-completion revocation hook in the minter: on `task.complete` or `task.fail` event, revoke associated credentials immediately
2. AWS: use STS `AssumeRole` with a custom session tag (`eunox_task_id`), then call `STS RevokeSession` on task completion
3. Azure: managed identity with short-lived tokens (minimum viable duration), refresh only while task is active
4. GCP: Workload Identity Federation with task-scoped service account tokens
5. Build the demo: agent task mints a DB credential, completes, credential is revoked — attempt to reuse it after task completion and show it fails
6. Benchmark: show the privilege exposure window — typical STS: 15 minutes, eunox: average task duration (likely under 60 seconds for most tool calls)

**Success metric:** The privilege exposure window comparison is a publishable benchmark that security teams can cite in their own risk assessments.

---

### T-10 · MCP-first framework integration: eunox-python + LangGraph
**Priority:** P1 · **Effort:** 2–3 weeks · **Owner:** Eng + DevRel · **Depends on:** T-06

Be the default enforcement layer for MCP-speaking agents, with LangGraph as the hero integration. The strategy is MCP-first (framework-agnostic by default) with thin shims for popular frameworks — not a LangChain-only wrapper that gets outflanked if MCP becomes the standard transport.

**Steps:**
1. Ship `eunox-python` PyPI package — thin MCP client wrapper that interposes policy enforcement on any MCP server connection
2. Build a LangGraph example repo: agent + tools + eunox enforcement, fully runnable in one `docker compose up`
3. Write "How to add governance to your LangGraph agent in 5 minutes" blog post
4. Submit talk proposals to LangChain community events and AI engineering meetups
5. Engage LangChain ecosystem maintainers for potential upstream integration or co-marketing

**Success metric:** 100+ pip installs/week of `eunox-python` by week 10; featured in at least one LangChain community showcase.

---

### T-11 · Incident-driven content engine
**Priority:** P1 · **Effort:** Ongoing · **Owner:** Content · **Depends on:** T-04

Be the project people think of when the first high-profile agent security failure hits the news. The fictional postmortems from T-04 are the foundation; this task sustains the content engine.

**Steps:**
1. Publish 3 fictional-but-realistic incident postmortems (built on T-04 drafts), annotated with exactly where eunox enforcement stops the attack chain
2. Publish a quarterly "State of Agent Security" report summarizing incidents, near-misses, and enforcement patterns — first edition by month 3
3. Build relationships with AI security researchers and journalists; establish eunox as a credible voice to contact when an incident breaks
4. Monitor the space and deploy the rapid-response template (from T-04) within 24 hours of any significant real incident

**Success metric:** First postmortem reaches HN front page or 10k+ views; eunox mentioned in at least 2 third-party articles about agent security within 90 days.

---

### T-12 · Enterprise design partner program
**Priority:** P1 · **Effort:** Ongoing · **Owner:** BD · **Depends on:** T-03

The economic buyers are CISOs and compliance teams. Get 3 design partnerships with regulated-industry companies deploying AI agents — free deployment support and roadmap influence in exchange for case study rights and feedback.

**Steps:**
1. Identify 20 target companies in finance, healthcare, and legal that are publicly deploying AI agents
2. Develop the "Compliance Design Partner" program pitch deck and terms
3. Conduct discovery calls with CISO / compliance teams; map their audit checklist requirements
4. Build compliance-specific features based on partner feedback (SOC 2 evidence export, HIPAA audit trail format)
5. Produce 1 joint case study with the first design partner (month 4–5)

**Success metric:** 3 LOIs signed by week 8; 1 production deployment (or advanced pilot) by month 5.

---

## Phase 3 — Own a Vertical
**Weeks 10–20 · Pick one vertical and go deep before expanding**

---

### T-13 · Build a complete healthcare (HIPAA) reference architecture
**Priority:** P1 · **Effort:** 3–4 weeks · **Owner:** Founder + 1 eng · **Depends on:** T-03, T-08, T-09

Healthcare has the highest urgency around AI agent governance right now. Clinical AI copilots are being deployed on HIPAA-regulated data with no compliance framework for AI tool call authorization. Healthcare buyers have budget, are accustomed to buying security tools, and cannot use open-source-only solutions for regulated workloads.

**Deliverables:**
1. Map HIPAA technical safeguard requirements to eunox capabilities: audit controls → tamper-evident audit trail, access controls → capability tokens, transmission security → JWKS + mTLS
2. Build a reference architecture for a clinical AI copilot: EHR read access, note generation, lab result retrieval — all enforced through eunox
3. Document PHI handling: what eunox logs about tool call parameters, how to configure redaction of PHI from audit logs
4. Produce a BAA-ready data flow diagram showing where PHI transits and how it is protected
5. Write a one-pager for compliance officers (not engineers) explaining what eunox does in HIPAA language
6. Partner with one healthcare org for a pilot deployment

**Success metric:** One healthcare organization begins a paid pilot. The reference architecture is cited in their HIPAA risk assessment documentation.

---

### T-14 · Policy simulation and dry-run framework
**Priority:** P1 · **Effort:** 1–2 weeks · **Owner:** Eng · **Depends on:** T-06, T-08

Enterprises will not deploy a new enforcement gateway in production without being able to test policies against real traffic in a non-enforcing mode first. This is the same pattern that made OPA's dry-run and audit modes critical for adoption.

**Steps:**
1. Build dry-run mode: policies are evaluated but not enforced, decisions are logged
2. Build a policy simulator: feed a recorded audit session back through a new policy and show what would have been blocked
3. Build a policy diff tool: given two policy versions, show which tool calls would be newly blocked or newly allowed
4. Build a coverage reporter: given an audit session, show which policy rules were exercised and which were never triggered
5. Integrate into `eunoctl`: `eunoctl policy simulate --session=<id> --policy=new-policy.yaml`

**Success metric:** An enterprise can run eunox in shadow mode for 2 weeks, review dry-run decisions, gain confidence, then flip to enforcement mode — with zero production incidents from policy misconfiguration.

---

### T-15 · Replayable audit sessions with causal timeline UI
**Priority:** P2 · **Effort:** 2–3 weeks · **Owner:** Eng + design · **Depends on:** T-08, T-14

When an incident occurs, the first question is always: "show me exactly what happened and why." No existing tool can answer this for AI agent sessions. eunox has all the data — task ID, tool call sequence, capability tokens, policy decisions — but needs a UI navigable by a security analyst under pressure.

**Steps:**
1. Build a session timeline view: every tool call rendered as an event on a timeline, with policy decisions annotated inline
2. Add causal linking: clicking any tool call shows which capability token authorized it, which task it belongs to, which agent invoked it
3. Build replay mode: step through a session chronologically, see the state of the agent's capability set at each point
4. Add SIEM export: CEF and JSON export for Splunk, QRadar, Sentinel integration
5. Build tamper-evidence verification: given a session ID, verify the audit trail hash chain is intact — important for legal admissibility

**Success metric:** A security analyst can answer "what did the agent do and why was it authorized" for any session in under 5 minutes using the eunox UI alone.

---

### T-16 · Policy authoring UX (non-engineer audience)
**Priority:** P2 · **Effort:** 4–6 weeks · **Owner:** Design + Eng · **Depends on:** T-06

A non-engineer should be able to author and validate policy without writing YAML. This is a Year 2 moat, not a Day 90 deliverable — start design in month 4, ship as part of the Cloud Team tier.

**Steps:**
1. Design a web-based policy editor with live preview (what an agent can/cannot do under this policy)
2. Implement a policy validation API endpoint that the editor calls for real-time feedback
3. Ship the policy editor as part of the Cloud Team tier (month 5)
4. Offer policy templates for common compliance frameworks (SOC 2, HIPAA, PCI-DSS)

**Success metric:** 50% of Cloud Team users author policies via the UI rather than raw YAML by month 7.

---

## Phase 4 — Expand the Moat
**Weeks 20+ · Only start these once Phase 3 has a paying customer**

---

### T-17 · Agent behavioral anomaly detection
**Priority:** P2 · **Effort:** 4–6 weeks · **Owner:** Eng + ML · **Depends on:** T-08, T-15, 3+ production deployments

Anomaly detection requires a baseline, which requires production data, which requires paying customers. Building this before you have real traffic data means building on invented assumptions.

**Steps:**
1. Build a baseline model: for each agent type, record distribution of tool calls, parameter ranges, sequence patterns, and credential usage over a 2-week observation window
2. Build deviation detection: flag sessions where tool call frequency, parameter entropy, or sequence patterns deviate significantly from baseline
3. Integrate with policy: allow "alert on anomaly" and "block on anomaly" policy rules
4. Build the alert UI: show anomaly score, which specific behavior triggered it, and comparable baseline sessions
5. Explicitly scope what this is not: not a jailbreak detector, not a prompt injection detector, not a model behavior analyzer

**Success metric:** False positive rate under 1% on baseline agent behavior; anomaly detection catches a simulated data exfiltration attempt in a controlled test.

---

### T-18 · SaaS-hosted control plane with on-prem enforcement
**Priority:** P2 · **Effort:** 6–8 weeks · **Owner:** Founder + eng · **Depends on:** T-13, T-14, T-15

Enterprises want enforcement in their own network; they want policy management, dashboards, and team collaboration hosted and managed. This is the same model as OPA + Styra or Vault + HCP. It produces a recurring revenue model without forcing enterprises to accept a fully SaaS enforcement plane for sensitive agent traffic.

**Steps:**
1. Build the control plane separation: gateway and minter run on-prem, policy sync and audit aggregation connect to hosted control plane
2. Build the policy management UI: version control for policies, approval workflows, role-based access for policy authors vs. reviewers
3. Build team features: multiple environments (dev/staging/prod), policy promotion workflow, audit log search and retention
4. Define the data boundary explicitly: audit log metadata goes to control plane (task IDs, decisions), tool call parameters never leave the customer network
5. Publish SOC 2 Type II roadmap — table stakes for enterprise SaaS in security tooling

---

## 90-Day Priority Stack

| Priority | Task | Key Deliverable | Week |
|----------|------|-----------------|------|
| P0 | T-01 | OPA/Envoy failure demo (runnable) | 2 |
| P0 | T-02 | Native MCP demo with Claude/Cursor | 3 |
| P0 | T-03 | Threat model document published | 3 |
| P0 | T-06 | `eunox dev` single-binary + sub-20-min onboarding | 5 |
| P1 | T-04 | 3 fictional postmortems + rapid-response template | 4 |
| P1 | T-05 | Licensing FAQ (Apache/BUSL split documented) | 2 |
| P1 | T-10 | `eunox-python` PyPI + LangGraph example | 7 |
| P1 | T-11 | First incident postmortem published | 4 |
| P1 | T-12 | 3 design partner LOIs signed | 8 |
| P1 | T-07 | OPA bridge integration | 8 |
| P1 | T-08 | OpenTelemetry export | 7 |
| P1 | T-09 | Task-lifecycle credential revocation | 10 |
| P2 | T-14 | Policy simulation / dry-run | 12 |
| P3 | T-16 | Policy editor design (begins Q2) | 12+ |

---

## Dependency Graph

| Task | Title | Depends on |
|------|-------|------------|
| T-01 | OPA/Envoy failure demo | — |
| T-02 | Native MCP demo (Claude/Cursor) | T-01 |
| T-03 | Threat model doc | — |
| T-04 | Rapid-response content template | — |
| T-05 | Licensing FAQ | — |
| T-06 | Sub-20-min developer onboarding | T-02 |
| T-07 | OPA bridge integration | T-01, T-06 |
| T-08 | OpenTelemetry export | T-06 |
| T-09 | Task-lifecycle credential revocation | T-06 |
| T-10 | eunox-python + LangGraph integration | T-06 |
| T-11 | Incident-driven content engine | T-04 |
| T-12 | Enterprise design partner program | T-03 |
| T-13 | HIPAA reference architecture | T-03, T-08, T-09 |
| T-14 | Policy simulation / dry-run | T-06, T-08 |
| T-15 | Replayable audit sessions | T-08, T-14 |
| T-16 | Policy authoring UX | T-06 |
| T-17 | Behavioral anomaly detection | T-08, T-15 + prod data |
| T-18 | SaaS control plane | T-13, T-14, T-15 |

**Critical path:** T-01 → T-02 → T-06 → T-08 / T-09 → T-13 → T-15 → T-18

---

## Key Risks & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| MCP adoption stalls; frameworks don't converge on it | Medium | High | Maintain thin framework-specific shims as insurance; don't over-invest in MCP-only story |
| No high-profile agent incident occurs in 90 days | Low | Medium | Proactive fictional content still drives SEO and credibility; don't depend on external events |
| Design partners stall in procurement | High | Medium | Structure as free pilot with opt-in upgrade; minimize legal overhead |
| Competitor ships similar product with MIT license | Medium | High | Speed is the primary defense; ship faster and build community first |
| `eunox dev` mode confused with production readiness | Low | Medium | Clear "dev-only" warnings in output; docs explicitly separate evaluation from production |
| Developer education gap — most don't understand *why* agents need governance | High | High | Lead with education content (what can go wrong) before solution marketing (how eunox fixes it); postmortems are the primary vehicle |

---

## Key Strategic Anchors

- **T-03 has no dependencies.** It can be written today. It unblocks the entire enterprise sales motion and there is no reason to defer it.
- **T-06 is the real bottleneck.** Every downstream engineering and GTM task depends on a working, installable product. Onboarding quality is not a nice-to-have — it is the adoption surface.
- **T-07 is the strategic linchpin.** Changing the conversation from "replace OPA" to "extend OPA" is worth more than almost any feature you could ship. It moves you from competitive to additive.
- **MCP-first, not LangGraph-first.** eunox enforces at the protocol layer. Own the MCP enforcement story and provide thin framework shims — don't build a LangChain-specific wrapper that gets outflanked when MCP becomes the standard transport. (See Decision Log.)
- **Do not start T-17 or T-18 before a paying customer.** Anomaly detection without real production traffic is built on fiction. SaaS infrastructure before a proven deployment model is waste.

---

## Decision Log

| Decision | Status | Deadline | Owner |
|----------|--------|----------|-------|
| Confirm LangGraph as hero framework vs. pure MCP-first strategy | Pending | Week 2 | Engineering + BD |
| Finalize Apache-2.0 scope for `eunox-python` package (cmd/mcp is Apache-2.0; confirm eunox-python follows the same tier) | Pending | Week 3 | Legal |
| Approve design partner program terms (free pilot + case study rights) | Pending | Week 3 | Leadership |
| Policy editor: build in-house vs. acquire vs. partner with an existing YAML/schema editor | Pending | Month 3 | Engineering + Product |
