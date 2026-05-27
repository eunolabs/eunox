# Go-to-Market Evaluation: Critique & Execution Plan

> **Date:** 2026-05-27
> **Status:** Draft — pending team review

---

## Part 1: Critique of the Evaluation

### What the evaluation gets right

1. **The urgency mismatch diagnosis is accurate.** Enterprise security teams move slowly; developers building agents haven't been burned yet. The "selling a seatbelt to people who haven't crashed" framing is the correct articulation of the primary GTM challenge.

2. **Deployment complexity is the real barrier.** The evaluation correctly identifies that requiring Gateway + Issuer + Minter + Redis for a first look is a non-starter for evaluation. However, this has been *partially* addressed already — the Go reimplementation supports single-binary dev mode with `NODE_ENV=development` and the gateway can run standalone. The evaluation appears to have been written against the older multi-service TypeScript platform, not the current Go monorepo.

3. **The framework integration strategy is sound.** Owning one framework deeply before expanding is the correct sequencing. The evaluation's recommendation to pick LangChain/LangGraph is defensible given ecosystem size, though the MCP protocol itself may be a better integration point since it's framework-agnostic.

4. **The compliance buyer insight is correct.** CISOs and compliance teams are the economic buyers. The evaluation's suggestion to co-design with 3-5 regulated industry customers is good tactical advice.

5. **The incident-driven marketing angle is timely.** Agent security incidents are increasing in frequency. Having pre-built content ready to deploy when a high-profile incident occurs is low-cost, high-optionality preparation.

### What the evaluation gets wrong or oversimplifies

1. **The BUSL characterization is outdated.** The evaluation claims "BUSL with no clear free tier" — but the pricing model already has a clear Apache-2.0 OSS tier (unlimited agents, unlimited local enforcement, file-only audit) *and* a free Cloud tier (5 agents, 50k events/month). The BUSL applies only to the Self-Host tier which is also free. This is already closer to "Option B" than the evaluation acknowledges. The licensing decision has been made; relitigating it is a distraction.

2. **"Kill the Multi-Service First Impression" overstates the current problem.** The Go reimplementation already provides a simplified deployment path. The gateway binary starts with minimal config (see `docs/deployment.md` Quick Start). The evaluation conflates the TypeScript platform's complexity with the current Go implementation. What's actually needed is better *documentation and marketing* of the already-simple path, not necessarily more engineering.

3. **"Pick One Framework" conflicts with the MCP strategy.** Eunox enforces policy at the *protocol layer* (MCP). This means it's inherently framework-agnostic — any agent that speaks MCP gets enforcement for free. Building a LangChain-specific wrapper risks being outflanked if/when MCP becomes the standard transport. The better strategy is to own the MCP enforcement story and provide *thin* integration shims for popular frameworks.

4. **The UI recommendation lacks prioritization discipline.** A visual policy editor is a good eventual product, but building it in the first 90 days would be a classic premature optimization. The target buyer (CISO/compliance team) typically has staff who can write YAML or uses a platform engineering team to manage config. The UI is a Year 2 moat, not a Day 90 deliverable.

5. **The 90-day timeline is optimistic on reference customers.** "Find them in the first month, ship with them by week 12" assumes an enterprise sales cycle that rarely exists. More realistic: identify 3-5 prospects in month 1, have LOIs or design partnerships by month 3, ship jointly by month 6.

6. **Missing: the developer education gap.** The evaluation doesn't address that most developers don't yet understand *why* agents need governance. The content strategy should include education (what can go wrong) before solution marketing (how Eunox fixes it). The incident postmortem piece partially addresses this, but a broader content engine is needed.

---

## Part 2: Execution Plan

### Workstream 1: Collapse Time-to-First-Enforcement

**Goal:** A developer evaluates Eunox and sees enforcement working in under 10 minutes.

| # | Action | Owner | Target |
|---|--------|-------|--------|
| 1.1 | Audit current "Quick Start" path end-to-end; document actual time-to-enforcement | DevRel | Week 1 |
| 1.2 | Ship `eunox dev` CLI command — single binary, embedded SQLite, self-signed keys, zero external deps | Engineering | Week 3 |
| 1.3 | Create a 5-minute interactive tutorial (terminal-based or web) that walks through: install → configure policy YAML → run agent → see enforcement | DevRel | Week 4 |
| 1.4 | Record a sub-3-minute demo video showing enforcement stopping an unauthorized tool call | Marketing | Week 5 |
| 1.5 | Publish `eunox` on Homebrew and as a single `go install` target | Engineering | Week 3 |

**Success metric:** New user goes from zero to seeing a blocked tool call in < 10 minutes, measured via a timed walkthrough with 5 external developers.

---

### Workstream 2: MCP-First Framework Integration

**Goal:** Be the default enforcement layer for MCP-speaking agents, with LangGraph as the hero integration.

| # | Action | Owner | Target |
|---|--------|-------|--------|
| 2.1 | Ship `eunox-python` PyPI package — thin MCP client wrapper that interposes policy enforcement on any MCP server connection | Engineering | Week 5 |
| 2.2 | Build a LangGraph example repo: agent + tools + Eunox enforcement, fully runnable in one `docker compose up` | Engineering | Week 6 |
| 2.3 | Write a "How to add governance to your LangGraph agent in 5 minutes" blog post | DevRel | Week 7 |
| 2.4 | Submit talk proposals to LangChain community events / AI engineering meetups | Marketing | Week 4 |
| 2.5 | Engage LangChain ecosystem maintainers for potential upstream integration or co-marketing | BD | Week 6 |

**Success metric:** 100+ pip installs/week of `eunox-python` by week 10; featured in at least one LangChain community showcase.

---

### Workstream 3: Incident-Driven Content & Thought Leadership

**Goal:** Be the project people think of when the first high-profile agent security failure hits the news.

| # | Action | Owner | Target |
|---|--------|-------|--------|
| 3.1 | Write 3 fictional-but-realistic incident postmortems (data exfiltration, unauthorized API calls, prompt injection leading to privilege escalation) | Content | Week 3 |
| 3.2 | For each postmortem, annotate exactly where Eunox enforcement would have stopped the attack chain | Engineering | Week 4 |
| 3.3 | Create a "rapid response" content template that can be adapted and published within 24 hours of a real incident | Content | Week 2 |
| 3.4 | Build relationships with AI security researchers and journalists; establish Eunox as a credible voice | Marketing | Ongoing |
| 3.5 | Publish a quarterly "State of Agent Security" report summarizing incidents, near-misses, and enforcement patterns | Content | Month 3 |

**Success metric:** First postmortem reaches HN front page or 10k+ views; Eunox mentioned in at least 2 third-party articles about agent security within 90 days.

---

### Workstream 4: Enterprise Design Partners

**Goal:** 3 signed design partnerships with regulated-industry companies deploying AI agents.

| # | Action | Owner | Target |
|---|--------|-------|--------|
| 4.1 | Identify 20 target companies in finance, healthcare, and legal that are publicly deploying AI agents | BD | Week 2 |
| 4.2 | Develop a "Compliance Design Partner" program pitch: free deployment support + influence on roadmap in exchange for case study rights and feedback | BD | Week 3 |
| 4.3 | Conduct discovery calls with CISO / compliance teams at targets; map their audit checklist requirements | BD | Weeks 3–8 |
| 4.4 | Build compliance-specific features based on partner feedback (e.g., SOC 2 evidence export, HIPAA audit trail format) | Engineering | Weeks 8–12 |
| 4.5 | Produce 1 joint case study with first design partner | Marketing | Month 4–5 |

**Success metric:** 3 LOIs signed by week 8; 1 production deployment (or advanced pilot) by month 5.

---

### Workstream 5: Licensing Clarity & Developer Trust

**Goal:** Eliminate license anxiety as a reason not to evaluate.

| # | Action | Owner | Target |
|---|--------|-------|--------|
| 5.1 | Audit current messaging: ensure README, website, and docs clearly communicate the Apache-2.0 OSS tier and what it includes | DevRel | Week 1 |
| 5.2 | Add a prominent "Licensing FAQ" to docs explaining: what's free forever, what requires BSL, what the cloud tiers offer | Legal + DevRel | Week 2 |
| 5.3 | Ensure the `eunox dev` flow and the MCP integration package are unambiguously Apache-2.0 | Legal | Week 2 |
| 5.4 | Consider publishing a public commitment on when/if BSL converts to open (similar to MariaDB/CockroachDB change-date promises) | Leadership | Week 4 |

**Success metric:** Zero "is this actually free?" questions on GitHub Discussions or community channels after week 4.

---

### Workstream 6: Policy Authoring UX (Quarter 2)

**Goal:** A non-engineer can author and validate policy without writing YAML.

| # | Action | Owner | Target |
|---|--------|-------|--------|
| 6.1 | Design a web-based policy editor with live preview (what an agent can/cannot do under this policy) | Design | Month 4 |
| 6.2 | Implement policy validation API endpoint that the editor calls for real-time feedback | Engineering | Month 4 |
| 6.3 | Ship policy editor as part of the Cloud Team tier | Engineering | Month 5 |
| 6.4 | Offer policy templates for common compliance frameworks (SOC 2, HIPAA, PCI-DSS) | Engineering + Compliance | Month 6 |

**Success metric:** 50% of Cloud Team users author policies via the UI rather than raw YAML by month 7.

---

## 90-Day Priority Stack (Ranked)

| Priority | Workstream | Key Deliverable | Week |
|----------|-----------|-----------------|------|
| P0 | 1 | `eunox dev` single-binary mode | 3 |
| P0 | 5 | Licensing clarity in docs + README | 2 |
| P1 | 2 | `eunox-python` PyPI package | 5 |
| P1 | 3 | First incident postmortem published | 4 |
| P1 | 4 | 3 design partner LOIs signed | 8 |
| P2 | 2 | LangGraph example repo | 6 |
| P2 | 3 | Rapid-response content template | 2 |
| P3 | 6 | Policy editor design (begins Q2) | 12+ |

---

## Key Risks & Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|-----------|--------|-----------|
| MCP adoption stalls; frameworks don't converge on it | Medium | High | Maintain thin framework-specific shims as insurance; don't over-invest in MCP-only story |
| No high-profile agent incident occurs in 90 days | Low | Medium | Proactive content still drives SEO and credibility; don't depend on external events |
| Design partners stall in procurement | High | Medium | Structure as free pilot with opt-in upgrade; minimize legal overhead |
| Competitor ships similar product with MIT license | Medium | High | Speed is the primary defense; ship faster and build community first |
| `eunox dev` mode confused with production readiness | Low | Medium | Clear "dev-only" warnings in output; docs explicitly separate evaluation from production |

---

## Decision Log

| Decision | Status | Deadline | Owner |
|----------|--------|----------|-------|
| Confirm LangGraph as hero framework vs. pure MCP-first | Pending | Week 2 | Engineering + BD |
| Finalize Apache-2.0 scope for `eunox-python` package | Pending | Week 2 | Legal |
| Approve design partner program terms | Pending | Week 3 | Leadership |
| Policy editor: build vs. acquire vs. partner | Pending | Month 3 | Engineering + Product |
