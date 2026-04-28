# Sprint 3 & 4 Gap Closure — Design Docs

This folder contains per-item design documents for seven gaps identified
between `docs/execution-plan.md` (Sprints 3–4) and the current
implementation in `packages/`. Each document is the design *only* — no
code is changed by these docs. Each is intended to be turned into one
or more issues / PRs after review.

## Items

| # | Title | Plan reference | Primary touch points |
|---|---|---|---|
| 3 | [Conditional Access policy enforcement](./03-conditional-access.md) | Sprint 4 → Team CP, line 281 | `packages/capability-issuer/src/azure-identity-provider.ts` |
| 4 | [PIM activation checks](./04-pim-activation.md) | Sprint 4 → Team CP, line 281 | `packages/capability-issuer/src/azure-identity-provider.ts` |
| 5 | [Cross-organization trust simulation harness](./05-cross-org-trust-harness.md) | Sprint 4 → Team DP, line 291 | `packages/integration-tests/`, new `packages/partner-issuer-sim`, `k8s/partner-sim/` |
| 6 | [Performance & scalability test suite](./06-perf-scalability-suite.md) | Sprint 4 → Team DP, line 294 | new `tests/load/` |
| 7 | [Storage SAS / S3 presigned / GCS signed-URL issuance](./07-storage-grants.md) | Sprint 3 → Team DP, line 216 | `packages/capability-issuer/`, `packages/common/src/types.ts` |
| 8 | [Short-lived DB access token issuance](./08-db-token-issuance.md) | Sprint 3 → Team DP, line 220 | `packages/capability-issuer/`, `packages/common/src/types.ts` |
| 9 | [AI Posture Management inventory feed](./09-ai-posture-inventory.md) | Sprint 3 → Team OBS, line 242 | new `packages/posture-emitter` |

## Recommended implementation sequence

The seven items are not equally urgent and have natural pairings. Suggested order:

1. **#7 + #8 together (Sprint 3 enforcement gap).** Both follow the
   same "mint a short-lived cloud credential alongside the VC" shape
   and unblock real file-system / database tool enforcement. Sharing
   types and the issuance-pipeline hook keeps the diff coherent.
2. **#3 + #4 together (Sprint 4 Azure identity).** Conditional Access
   evaluation and PIM activation lookup share the same Microsoft Graph
   client, the same caching layer, and the same failure semantics
   (downgrade or deny issuance). Splitting them doubles the integration
   surface for no benefit.
3. **#9 (Sprint 3 observability).** Independent of the rest; can be
   developed in parallel once the issuer emits issuance events to a
   bus or webhook (which it already does via the audit logger).
4. **#5 (Sprint 4 cross-org).** Depends only on the gateway's existing
   DID resolver. Mostly a deployment + fixture exercise.
5. **#6 (Sprint 4 perf).** Should run *after* #7/#8 so the perf
   measurements capture the realistic issuance path (which gets
   heavier once cloud-credential minting is in it).

## Cross-cutting design principles

These principles apply to every item below and are stated once here so
each individual doc can stay focused.

- **Fail closed.** Any new control-plane authorization check (for
  example CA, PIM, or consent) that cannot be evaluated MUST deny
  issuance, not skip the check. This matches the existing
  `condition-registry.ts` posture (see
  `packages/common/src/condition-registry.ts` lines 1–20). By
  contrast, item #9 posture emission is an observability feed and
  must remain best-effort: emitter failures should be audited, but
  MUST NOT block issuance.
- **Config-driven, not code-driven.** Each cloud integration is opt-in
  via configuration. A deployment that only uses Azure must not be
  forced to install AWS / GCP SDKs at runtime — use lazy `import()` at
  the adapter boundary. The existing `azure-signer.ts` /
  `aws-kms-signer.ts` / `gcp-cloudkms-signer.ts` triplet is the
  pattern to follow.
- **Schema parity across clouds.** Where the plan calls for the same
  field names across Azure / AWS / GCP (explicitly required in #9 and
  implicitly in #7 / #8), define the shape **once** in
  `packages/common/src/types.ts` and have every cloud adapter emit
  records of that shape. Per-cloud-only fields go under a
  `cloudSpecific` sub-object.
- **No new top-level dependencies without justification.** Re-use
  `@azure/identity`, `@aws-sdk/*`, `@google-cloud/*` packages that are
  already in the issuer's `package.json` wherever possible. New SDKs
  must be lazy-imported.
- **Backwards compatible.** Every new field on
  `IssueCapabilityResponse`, `CapabilityConstraint`, etc., must be
  optional. Existing tokens, audit logs, and gateway code paths must
  continue to work unchanged when a feature is disabled.
- **Auditable.** Every new decision point (CA/PIM evaluation, SAS
  minting, DB token minting, posture emission) emits an audit log
  entry via the existing `auditLogger` pipeline so the gateway and
  SIEM see it.

## Out of scope for these docs

- Web/UI changes for posture dashboards (deferred to Sprint 5).
- Migration tooling for already-issued tokens — these features only
  affect *new* issuances.
- Production cloud account setup (Defender for Cloud, Security Hub,
  SCC enablement) — assumed to be done by the operator.
