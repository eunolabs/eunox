# Enterprise Federation Threat Model Addendum

> **Status: Placeholder — to be completed in Task 1.**
>
> This document is referenced by `docs/stage-5-design.md` and
> `public/packages/common/src/agt-guard.ts` as a future deliverable.
> It will be produced, reviewed, and signed off as part of **Task 1**
> (see `docs/stage5executionplan.md` §5 and §"Phase A — Pre-flight").
> No partner-federation code (Task 3), SCIM code (Task 10), or SOC2
> export code (Task 6) may merge to `main` until this document reaches
> "approved" status.

## Questions to be answered (required by §5 of the execution plan)

The following questions from `docs/stage5executionplan.md` §5 must be
answered verbatim in this document before Task 1 is complete:

- **Partner DID compromise** — blast radius, detection path, revocation path.
- **DID document spoofing** — `did:web` MiTM/domain-hijack scenario;
  pin-attestation workflow (`verifyPinAttestation`).
- **SCIM bearer token exposure** — rotation cadence, storage requirements,
  consequence of exposure.
- **SCIM privilege escalation** — approval workflow for mapping a SCIM group
  to an elevated role.
- **Cross-chain anchor tampering** — what an attacker with the HMAC secret
  can do; ACL backend vs. per-replica-postgres impact.
- **SOC2 export endpoint exposure** — authorization model, rate limit, cursor
  expiry, data-residency implications.
- **DB credential blast radius** — minimum-privilege DB role, credential TTL
  constraint, connection-level audit trail.
- **In-process guard bypass** — explicit statement that the AGT guard is a
  soft guard, not a security boundary.
- **Air-gapped key management** — file-based EC key permissions (`0400`), key
  derivation, offline backup requirements, multi-tenant cloud restriction.

## Sign-off (required before Tasks 3 / 6 / 10 merge)

| Reviewer | Role | Date | Notes |
|---|---|---|---|
| _(name)_ | Engineer | _(date)_ | |
| _(name)_ | Engineer | _(date)_ | |
| _(name)_ | Security | _(date)_ | |
