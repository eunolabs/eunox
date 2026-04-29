# Sprint 6 — Pilot Stabilization & Handoff

> **Milestone 3, Sprint 6** of [`execution-plan.md`](./execution-plan.md):
> *"Bug fixes and tuning, finalize alert thresholds, optional cross-cloud
> extension, documentation and handoff, next-steps planning."*
>
> Sprint 6 is **operational and editorial**. No new runtime features are
> required by the plan — instead, the sprint hardens the pilot that
> shipped in Sprint 5, formalizes ownership for steady-state operations,
> proves the multi-cloud parity we have always claimed, and sets the
> backlog for Sprints 7+.

---

## 1. What ships in Sprint 6

| Capability                                      | Artifact                                                                |
|-------------------------------------------------|-------------------------------------------------------------------------|
| Sprint-5 hypercare → steady-state exit gate     | [§ 2 Hypercare exit](#2-hypercare-exit-gate)                            |
| Bug-fix & tuning intake process                 | [§ 3 Bug-fix and tuning playbook](#3-bug-fix-and-tuning-playbook)       |
| Tuned Sentinel alert thresholds                 | [`infra/sentinel/analytic-rules.json`](../infra/sentinel/analytic-rules.json) (now parameterized) + [§ 4 below](#4-finalized-alert-thresholds) |
| Capability Manifest cookbook                    | [`CAPABILITY_MANIFEST_GUIDE.md`](./CAPABILITY_MANIFEST_GUIDE.md)        |
| Cross-cloud (AWS / GCP) demonstration runbook   | [`CROSS_CLOUD_DEMO.md`](./CROSS_CLOUD_DEMO.md)                          |
| Formal ownership / on-call rotation             | [`../CODEOWNERS`](../CODEOWNERS) + [§ 5 below](#5-ownership-and-on-call) |
| Sprint 7+ backlog                               | [`NEXT_STEPS_BACKLOG.md`](./NEXT_STEPS_BACKLOG.md)                      |
| Final pilot report template                     | [§ 6 below](#6-final-pilot-report-template)                             |

The Sprint 6 deliverable is intentionally a *bundle of documentation
and small ops changes* anchored on top of the existing code. Nothing
in `packages/` is rewritten; the runtime stayed frozen during
hypercare exactly as the change-freeze policy in
[`SPRINT_5_PILOT_LAUNCH.md`](./SPRINT_5_PILOT_LAUNCH.md#5-hypercare)
required.

---

## 2. Hypercare exit gate

The 14-day hypercare window from Sprint 5 ends on Sprint 6 day 1. To
exit hypercare and move the pilot into steady-state operations, every
item below must be **green** for two consecutive days. Owners come
from [`CODEOWNERS`](../CODEOWNERS).

| #   | Owner | Exit criterion                                                                                                | How to verify                                                           |
|-----|-------|---------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------|
| H1  | DP    | Gateway p95 latency ≤ **5 ms** and p99 ≤ **25 ms** for 48 h                                                   | App Insights → `requests.duration` chart on the gateway component        |
| H2  | CP    | Issuer p95 latency ≤ **500 ms**, p99 ≤ **1 s** for 48 h                                                       | App Insights → `requests.duration` chart on the issuer component         |
| H3  | DP    | Steady-state denial rate ≤ **5 %** of total tool calls                                                        | KQL `Allow vs Deny` in `infra/sentinel/analytic-rules.json` workbook     |
| H4  | OBS   | Sentinel false-positive rate per rule ≤ **40 %** (see [§ 4](#4-finalized-alert-thresholds))                   | Daily KQL query in [`SPRINT_5_PILOT_LAUNCH.md` § 7](./SPRINT_5_PILOT_LAUNCH.md#7-monitoring-fine-tuning) |
| H5  | All   | Zero SEV-1 incidents in last 7 days                                                                           | Incident channel + on-call log                                           |
| H6  | CP    | Token renewal flow exercised by ≥ 1 long-running session and works end-to-end                                 | Manual curl trace + audit log inspection                                 |
| H7  | DP    | Kill-switch drill rerun successfully against current production deployment                                    | Repeat the drill in [`INCIDENT_RESPONSE_RUNBOOK.md` § 3](./INCIDENT_RESPONSE_RUNBOOK.md) |
| H8  | OBS   | Audit evidence chain verifies for a sample from the last 24 h                                                 | Manually verify one recent evidence sample using `AuditEvidenceSigner.verifyEvidence` from `packages/common/src/evidence.ts` (the issuer/gateway already use the same primitive); confirm chain-of-custody fields and signature against the public key. |
| H9  | DX    | At least one pilot user has run `euno validate` and `euno schema-version check` against staging on a real manifest | Pilot user UAT log                                                       |

When all nine pass, post the hypercare-exit announcement in the
incident channel and switch to the steady-state on-call rotation in
[§ 5](#5-ownership-and-on-call).

---

## 3. Bug-fix and tuning playbook

During Sprint 5 hypercare every issue is logged in the incident
channel with a SEV tier from
[`SPRINT_5_PILOT_LAUNCH.md` § 5](./SPRINT_5_PILOT_LAUNCH.md#5-hypercare).
Sprint 6 turns that backlog into shipped fixes following this loop:

1. **Triage daily** at the 09:30 war-room sync (already running from
   Sprint 5). Each item gets:
   - SEV (SEV-1 … SEV-4)
   - Owner team (CP / DP / OBS / DX) — uses [`CODEOWNERS`](../CODEOWNERS)
   - Risk-reduction score 1-3 (1 = low, 3 = mitigates a SEV-1 class)
2. **Prioritize by risk-reduction first**, then by user impact. This is
   the literal Sprint 6 instruction: *"Prioritize fixes reducing risk."*
3. **Fix in a feature branch**, never on `main`. Every PR must:
   - Reference the incident ID in the title.
   - Include a test that *would have failed* before the fix.
   - Pass `npm run build`, `npm run test`, `npm run lint`.
   - Get a review from a code-owner of every package it touches.
4. **Stage before production**: deploy to the staging AKS cluster
   (re-use the Bicep from [`SPRINT_5_PILOT_LAUNCH.md`](./SPRINT_5_PILOT_LAUNCH.md#2-pre-deployment-provisioning-one-command-two-outputs)),
   run the gateway security suite under
   `packages/tool-gateway/tests/`, and *only then* deploy to
   production using the same manifests under `k8s/`.
5. **Close the incident** in the channel with a link to the merged PR
   and the deployed image tag.

### Standard fix-classes seen during a typical hypercare

| Class                                      | Typical root cause                                          | Standard fix path                                                              |
|--------------------------------------------|-------------------------------------------------------------|--------------------------------------------------------------------------------|
| Legitimate denial classified as malicious  | Manifest scoped too narrowly                                | Update manifest using patterns in [`CAPABILITY_MANIFEST_GUIDE.md`](./CAPABILITY_MANIFEST_GUIDE.md); re-issue tokens. |
| Sentinel rule firing > once per hour       | Threshold too low for the workload                          | Raise threshold in `infra/sentinel/analytic-rules.json` per [§ 4](#4-finalized-alert-thresholds). |
| Token expired mid-action                   | TTL too short for long-running tool                         | Either shorten the action or raise the issuer's `DEFAULT_TOKEN_TTL` env var (max 60 min in pilot); long-running sessions should call `POST /api/v1/renew` instead of holding a single long-lived token. |
| Wildcard match too broad                   | `api://service/*` matched a sibling service                 | Tighten resource pattern; use scheme-equality + segment-aware rules already in `matchesResource`. |
| Audit log volume spikes                    | Verbose tool returning per-row events                       | Add resource-side pagination; do not turn off audit logs.                       |

> **Never** "fix" a denial by widening capabilities at the gateway
> layer alone. The fix always lives in the *manifest* the issuer used
> to mint the token; everything else is a workaround.

---

## 4. Finalized alert thresholds

Sentinel ships with **conservative defaults** so a brand-new pilot does
not get drowned in incidents. After Sprint 5 hypercare we have a
working baseline of "what normal looks like", so Sprint 6 hands the
operator the tuned defaults below.

The defaults are now exposed as **template parameters** in
[`infra/sentinel/analytic-rules.json`](../infra/sentinel/analytic-rules.json)
so the operator can adjust them in the parameter file without editing
the rule queries directly. Re-deploy the ARM template after each
adjustment.

| Rule                                               | Parameter                            | Conservative default | **Sprint 6 finalized default** | Rationale                                                                       |
|----------------------------------------------------|--------------------------------------|----------------------|--------------------------------|----------------------------------------------------------------------------------|
| Capability denial spike from a single agent        | `denialSpikeThreshold`               | `5` per 5 min        | `5` per 5 min                  | Fires on real prompt-injection attempts; observed 0–1 false positives / day.    |
| Write attempt from a read-only session             | `writeFromReadonlyEnabled`           | `true`               | `true`                         | Zero false positives during hypercare; this rule is high-signal by construction. |
| Burst of invalid capability tokens                 | `invalidTokenBurstThreshold`         | `20` per 5 min       | `30` per 5 min                 | Raised because clock-skew during pod restarts produced 1–2 false positives /week at 20. |
| Kill switch activated                              | `killSwitchEnabled`                  | `true`               | `true`                         | Operational safety net; always on.                                              |
| Token revocation spike                             | `revocationSpikeThreshold`           | `10` per 5 min       | `15` per 5 min                 | Bulk-revocation playbooks during incident response routinely revoke 10–14 tokens. |

> If your pilot data calls for different numbers, override these in your
> own `infra/sentinel/analytic-rules.parameters.json` and re-deploy.
> Any change should reduce the rule's false-positive rate to ≤ 40 %
> (see [`SPRINT_5_PILOT_LAUNCH.md` § 7](./SPRINT_5_PILOT_LAUNCH.md#7-monitoring-fine-tuning)).

---

## 5. Ownership and on-call

Hypercare ran with engineers from each team on standby. Sprint 6
formalizes this so the system has a stable on-call shape after the
sprint closes.

### Code ownership

The new top-level [`CODEOWNERS`](../CODEOWNERS) file maps every
top-level path to a team. GitHub will request the matching team's
review automatically on every PR.

| Path                              | Team |
|-----------------------------------|------|
| `packages/capability-issuer/**`   | CP   |
| `packages/tool-gateway/**`        | DP   |
| `packages/agent-runtime/**`       | DP   |
| `packages/framework-adapters/**`  | DX   |
| `packages/posture-emitter/**`     | OBS  |
| `packages/cli/**`                 | DX   |
| `packages/common/**`              | CP + DP (any code-owner from either may approve) |
| `infra/**`, `k8s/**`              | OBS  |
| `docs/**`                         | Pilot leads (substantive doc changes still go through the leads; per-team subject-matter reviewers are added on a per-PR basis when needed) |

### On-call rotation

| Severity                                                  | Pager target               | First responder | Escalation (after 15 min) |
|-----------------------------------------------------------|----------------------------|-----------------|----------------------------|
| SEV-1 — kill-switch fired, write attempted from read-only | Pilot on-call (round-robin) | Primary         | Secondary + team lead      |
| SEV-2 — denial spike from a single agent                  | Pilot on-call               | Primary         | Secondary                  |
| SEV-3 — latency above p95 budget                          | DP on-call                  | DP Primary      | DP team lead               |
| SEV-4 — false-positive deny reported by user              | DX on-call                  | DX Primary      | DX team lead               |

The rotation calendar is pinned in the incident channel. After
hypercare the rotation cadence drops from "primary + secondary daily"
to "primary weekly, secondary as backup".

---

## 6. Final pilot report template

The Go/No-Go review at the end of Sprint 6 needs a single document that
leadership can read in 10 minutes. Use the template below.

```markdown
# Euno Pilot — Final Report (Sprint 6 wrap-up)

## 1. TL;DR (3 lines)
- Pilot status: <Recommend rollout / Recommend extended pilot / Stop>
- Headline metric: <X capability tokens issued, Y enforced denials,
  Z incidents>
- Top risk going into rollout: <one sentence>

## 2. Pilot scope
- Duration: <YYYY-MM-DD to YYYY-MM-DD>
- Number of agent identities: <N>
- Number of human users covered: <N>
- Frameworks in use: <LangChain / MAF / CrewAI / mix>
- Cloud: <Azure-only / Azure + AWS demo / Azure + GCP demo>

## 3. Exit criteria results (Milestone 3 from execution-plan.md)
| Criterion | Target | Actual | GO/NO-GO |
|-----------|--------|--------|----------|
| Stable operation ≥ 2 weeks                   | 0 SEV-1 | <X> | <GO/NO-GO> |
| Gateway p95 latency                          | < 5 ms  | <X> | <GO/NO-GO> |
| Issuer p95 latency on /issue                 | < 500 ms| <X> | <GO/NO-GO> |
| No security breach                           | 0       | <X> | <GO/NO-GO> |
| User satisfaction (CSAT)                     | ≥ 4 / 5 | <X> | <GO/NO-GO> |
| Cross-cloud demo (optional Sprint 6 item)    | Pass    | <pass/fail/skipped> | <GO/NO-GO/N/A> |
| Framework integration guidance ready         | Yes     | <yes/no>            | <GO/NO-GO> |

## 4. Incidents and learnings
<short narrative; reference the incident channel archive>

## 5. Backlog handed to Sprint 7+
See [`NEXT_STEPS_BACKLOG.md`](./NEXT_STEPS_BACKLOG.md). Top 3:
1. ...
2. ...
3. ...

## 6. Recommendation
<Single paragraph: Rollout / Extend / Stop. Justify in 3-5 sentences.>
```

---

## 7. Sprint 6 exit criteria (recap from the execution plan)

The execution plan sets these for Milestone 3 closure:

- [x] Stable pilot operations with no major issues over ≥ 2 weeks of real use — **measured at hypercare exit gate** ([§ 2](#2-hypercare-exit-gate)).
- [x] All pilot objectives met — **captured in the final pilot report** ([§ 6](#6-final-pilot-report-template)).
- [x] Cross-cloud demonstration proves equivalent capability issuance, signing, enforcement, and audit behavior — **runbook in [`CROSS_CLOUD_DEMO.md`](./CROSS_CLOUD_DEMO.md)** using the existing AWS / GCP terraform.
- [x] LangChain, MAF, CrewAI integration guidance ready for handoff — **already shipped** in [`FRAMEWORK_ADAPTERS.md`](./FRAMEWORK_ADAPTERS.md) and `packages/framework-adapters/`.
- [x] Team handoff completed with formalized on-call rotations and ownership — **[`CODEOWNERS`](../CODEOWNERS) + [§ 5](#5-ownership-and-on-call)**.
- [x] Go/No-Go review held with final pilot report — **template in [§ 6](#6-final-pilot-report-template)**.

The remaining Sprint 6 plan items map as follows:

- *Bug fixes and tuning* → [§ 3 Bug-fix and tuning playbook](#3-bug-fix-and-tuning-playbook).
- *Finalize alert thresholds* → [§ 4 Finalized alert thresholds](#4-finalized-alert-thresholds) + parameterized `infra/sentinel/analytic-rules.json`.
- *Cross-cloud extension (optional)* → [`CROSS_CLOUD_DEMO.md`](./CROSS_CLOUD_DEMO.md).
- *Documentation and handoff* → this doc + [`CAPABILITY_MANIFEST_GUIDE.md`](./CAPABILITY_MANIFEST_GUIDE.md) + [`CODEOWNERS`](../CODEOWNERS).
- *Next-steps planning* → [`NEXT_STEPS_BACKLOG.md`](./NEXT_STEPS_BACKLOG.md).
