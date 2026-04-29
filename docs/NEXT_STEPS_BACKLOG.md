# Next-Steps Backlog (Sprint 7+)

> Sprint 6 deliverable from
> [`execution-plan.md`](./execution-plan.md): *"Develop backlog items
> for broad adoption: self-service UI for capability requests, dynamic
> policy engines, cross-cloud support, industry standards
> contributions."*
>
> This backlog hands off the next phase of work to whoever owns Euno
> after the Sprint 6 wrap-up. Items are grouped by theme, not by
> sprint, because Sprints 7-8 in `execution-plan.md` are intentionally
> left flexible for the operator to prioritize against pilot
> learnings.

## Status legend

| Symbol | Meaning |
| ------ | ------- |
| 🟥 | Required for general availability |
| 🟨 | Recommended for the second pilot wave |
| 🟦 | Strategic / community contribution |

---

## 1. Adoption surface

| Pri | Item                                                | What it unblocks                                                              | Hint where to start                                                             |
|-----|-----------------------------------------------------|-------------------------------------------------------------------------------|----------------------------------------------------------------------------------|
| 🟥  | **Self-service capability request UI**              | Manifest authors no longer need to learn the YAML schema by hand              | `web/` already exists as a placeholder — front it with a form that emits the schema in [`CAPABILITY_MANIFEST_GUIDE.md`](./CAPABILITY_MANIFEST_GUIDE.md). |
| 🟥  | **Web-based pilot dashboard**                       | Operators see pilot metrics without diving into Sentinel                      | Re-use the KQL from [`SPRINT_5_PILOT_LAUNCH.md` § 4](./SPRINT_5_PILOT_LAUNCH.md#4-metrics--feedback-collection) and render in the same `web/` app. |
| 🟨  | **Manifest approval workflow**                       | Higher-risk manifests (write to PII, etc.) require owner sign-off              | Hook a GitHub PR + CODEOWNERS check on `manifests/**` in the consumer repo.      |
| 🟨  | **`euno doctor`**                                    | One command tells a new user what's misconfigured locally                     | New CLI subcommand under `packages/cli`.                                         |
| 🟦  | **VS Code extension**                                | Real-time linting of manifest YAML in the editor                              | Wraps `euno validate` as an LSP server.                                          |

## 2. Policy engine

| Pri | Item                                                | What it unblocks                                                              | Hint where to start                                                             |
|-----|-----------------------------------------------------|-------------------------------------------------------------------------------|----------------------------------------------------------------------------------|
| 🟥  | **Dynamic policy engine (OPA / Cedar integration)**  | Manifests can reference policies expressed in OPA Rego or Cedar                | Add a new first-class `type` (e.g. `'policy'`) to the `CapabilityCondition` discriminated union in `packages/common/src/types.ts`, register its handler in `packages/common/src/condition-registry.ts`, and ship the validator alongside the existing typed conditions in `packages/common/src/capability-validators.ts`. Do **not** introduce a `kind:` field — conditions are discriminated by `type`. |
| 🟥  | **Policy unit-test framework**                       | Manifest authors can write tests against a policy before issuing tokens        | Extend `packages/integration-tests/` with a manifest-replay harness driven by fixtures. |
| 🟨  | **Time-of-day / risk-based conditional issuance**    | Block sensitive actions outside business hours unless approved                 | New typed condition in `condition-registry.ts`.                                  |
| 🟨  | **Per-user issuance rate limit at the issuer**       | Stops a compromised user from minting unlimited tokens                         | Plug an in-process token bucket into the `/issue` handler; surface metrics.      |

## 3. Cross-cloud and federation depth

| Pri | Item                                                | What it unblocks                                                              | Hint where to start                                                             |
|-----|-----------------------------------------------------|-------------------------------------------------------------------------------|----------------------------------------------------------------------------------|
| 🟥  | **Productionize the cross-cloud demo from Sprint 6** | Run the AWS or GCP profile as a true second region, not just a one-off demo   | Promote [`CROSS_CLOUD_DEMO.md`](./CROSS_CLOUD_DEMO.md) into a permanent runbook plus a CI job that exercises it weekly. |
| 🟥  | **Multi-region active/active issuer**                | Survives a regional Azure outage                                              | Issuer is stateless aside from the KMS key — replicate Key Vault key into a peer region; load-balance with a global front door. |
| 🟨  | **Federated trust to a partner organization**        | Lets an external company's issuer mint tokens you accept                      | Already designed in [`cross-organizations.md`](./cross-organizations.md); promote from reference to runtime by extending `TRUSTED_ISSUERS` resolution to a signed allow-list. |
| 🟨  | **`did:ion` anchored DIDs in production**            | Removes the DNS dependency for issuer trust                                   | The resolver already supports `did:ion`; the gap is operational (anchoring rotation cadence). |

## 4. Observability and assurance

| Pri | Item                                                | What it unblocks                                                              | Hint where to start                                                             |
|-----|-----------------------------------------------------|-------------------------------------------------------------------------------|----------------------------------------------------------------------------------|
| 🟥  | **Continuous evidence-chain verification job**       | Catches log tampering automatically                                           | Wrap `AuditEvidenceSigner.verifyEvidence` from `packages/common/src/evidence.ts` in a small `scripts/verify-evidence.{ts,js}` entry point, schedule it over the previous day's audit batch, and alert on the first failure. |
| 🟨  | **OpenTelemetry tracing across issuer → gateway → backend** | One trace per agent action across services                          | Add `@opentelemetry/api` to `packages/common`; propagate via a single header.    |
| 🟨  | **Posture export to OCSF**                           | Audit data flows into any SIEM that speaks OCSF                                | Add an OCSF formatter to `packages/posture-emitter`.                             |
| 🟦  | **Public reference detections in MITRE ATT&CK**      | Helps adopters map Euno alerts to their existing detection program             | Annotate each rule in `infra/sentinel/analytic-rules.json` with ATT&CK technique IDs (already present for two rules). |

## 5. Standards contributions

| Pri | Item                                                | What it unblocks                                                              | Hint where to start                                                             |
|-----|-----------------------------------------------------|-------------------------------------------------------------------------------|----------------------------------------------------------------------------------|
| 🟦  | **Submit the capability JWT profile as an IETF Internet-Draft** | Industry alignment on AI-agent capability tokens                  | Profile is in [`SCHEMA_VERSIONING.md`](./SCHEMA_VERSIONING.md); polish to RFC style. |
| 🟦  | **Contribute the `validate-jwt` parity matrix to the Microsoft Foundry blog reference architecture** | Closes the loop with the source pattern    | The matrix already lives in [`SPRINT_5_PILOT_LAUNCH.md` § 6](./SPRINT_5_PILOT_LAUNCH.md#6-cloud-portability-matrix). |
| 🟦  | **Open-source the framework adapters under a permissive licence** | Lowers adoption friction for LangChain / MAF / CrewAI users | `packages/framework-adapters` already structured for it; needs a separate publish target. |

## 6. Hardening that did not block the pilot

These are items the team noted during Sprint 5 hypercare that did not
warrant a hot-fix but should land before general availability.

- 🟨 Add `Content-Security-Policy` and HSTS preload headers to the
  issuer's HTTP responses (the gateway already enforces them on the
  proxy path).
- 🟨 Replace the in-memory rate limiter with a Redis-backed one to
  share state across replicas (mirrors what we did for revocation
  and the kill switch).
- 🟨 Add a `--dry-run` flag to `euno request` so users can see the
  exact `/issue` payload that would be sent.
- 🟦 Migrate from `winston` to `pino` for log throughput once the
  Sentinel KQL is regression-tested against the new format.

## 7. Things explicitly **out of scope**

To keep the backlog honest:

- **Replacing the gateway with a fully agent-aware mesh (e.g., Istio
  Ambient with WASM filters)** — interesting research, but the Sprint
  5/6 pilot already meets latency and security goals with the current
  Express-based gateway. Revisit only if a future scale wave demands
  it.
- **Building a proprietary identity provider** — the adapter pattern
  in [`ADAPTER_PATTERN.md`](./ADAPTER_PATTERN.md) is the answer to
  every "but our IdP is X" question. Do not write a new IdP.
- **Allowing the LLM to author its own capability manifest at
  runtime** — this defeats the entire model in
  [`enforcement.md`](./enforcement.md). The manifest is human-authored
  and signed off; only the *attenuation* of an existing manifest can
  be agent-driven.

---

When you start work on any item above, link the PR back to this doc
and tick the item off. Sprint 7 leadership should pick the top three
🟥 items and turn them into stories before the Sprint 7 kickoff.
