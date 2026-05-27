---
title: "Building for SOC 2: mapping CC6 and CC7 controls to an AI governance platform"
description: "security architects, compliance engineers, and CISOs who need to demonstrate AI agent governance in a SOC 2 audit"
pubDate: "2026-06-16"
---

_Audience: security architects, compliance engineers, and CISOs who need to demonstrate AI agent governance in a SOC 2 audit_

---

SOC 2 is one of those standards that looks approachable from the outside and turns out to be more nuanced than it appears once you're actually preparing an audit package. The Trust Services Criteria are intentionally broad — they're designed to cover a wide range of systems — which means the real work is in the mapping: taking what your system actually does and explaining, with evidence, how it satisfies each criterion.

I've been through this mapping exercise with eunox a couple of times now, and the two criteria that generate the most questions are CC6 (Logical and Physical Access Controls) and CC7 (System Operations). CC6 because auditors immediately ask "how do you know only authorised agents can call these tools?", and CC7 because the question "how do you know something went wrong?" requires you to explain your monitoring, anomaly detection, and incident response posture.

This post is a practical walkthrough of how eunox's architecture maps to those two criteria, what the specific controls look like in the platform, and how to extract the evidence you need for an audit package. I'm going to reference the underlying technical details covered in earlier posts — particularly [the capability tokens post](./09-capability-tokens.md), [the reference monitor post](./10-tool-gateway-reference-monitor.md), and [the audit log post](../docs/blog/11-tamper-evident-audit-logs.md) — and focus here on connecting those mechanisms to the control language auditors actually use.

---

## What CC6 is actually asking

CC6 covers logical and physical access. The physical half is mostly about your hosting infrastructure — data centres, hardware, etc. — and if you're on a major cloud provider, your CSP's own SOC 2 report covers most of that. What CC6 is really asking about, in the context of an AI platform, is:

- **CC6.1**: Who can access which resources, and how is that access managed?
- **CC6.2**: How are user accounts managed, provisioned, and deprovisioned?
- **CC6.3**: How are access rights reviewed and modified over time?
- **CC6.6**: How are logical access boundaries enforced at the network layer?
- **CC6.7**: How are transmissions protected?
- **CC6.8**: What prevents unauthorised software or malicious content from being introduced?

For a traditional web application, these map reasonably cleanly to your IAM setup, your VPC/firewall rules, your TLS configuration. For an AI agent platform, you have an additional layer that most auditors aren't familiar with yet: the question of what an AI agent is allowed to do once it's authenticated. A service account that can call your gateway is a valid principal, but "this service account exists and has a valid API key" doesn't tell you anything about which tool calls that agent is authorised to make, under what conditions, or what happens when it tries to exceed those bounds.

This is the gap that eunox's capability token model fills, and it's worth explaining to an auditor explicitly rather than assuming they'll see the connection.

---

## CC6.1 — Logical access controls and the capability token

CC6.1 is the core access control criterion. The auditor wants to know: for any given resource, how do you decide whether a request is authorised?

The eunox answer has several components.

**Identity establishment.** Before any tool call is evaluated, the agent session must present a valid JWT capability token. That token is signed by a KMS-backed key held by the capability issuer service — either Azure Key Vault, AWS KMS, or GCP Cloud KMS depending on your deployment. The token carries a `sub` claim that identifies the agent principal, an `iss` claim that identifies the issuer, and an `aud` claim that scopes the token to a specific gateway instance. A token that was not issued by a trusted issuer, or that was issued for a different gateway, fails signature verification and is denied. There is no path to tool access that bypasses this verification step.

**Capability scoping.** The token's `capabilities` array encodes the specific resources and actions this session is authorised for. A capability entry looks like this:

```json
{
  "resource": "db://analytics/**",
  "actions": ["read"],
  "conditions": [
    { "type": "allowedOperations", "operations": ["SELECT"] },
    { "type": "maxCalls", "count": 100, "windowSeconds": 3600 }
  ]
}
```

This is not a broad permission grant — it's a narrow, per-session specification of exactly what this agent invocation is authorised to do. The gateway evaluates this against every tool call the agent makes. If the call doesn't match a capability entry: deny. If it matches but a condition fails: deny.

**Evidence for auditors.** The `GET /api/v1/audit/export` endpoint returns structured OCSF-formatted records for every tool call — allowed and denied — with the token identity, the matched capability, the conditions evaluated, and the decision. For CC6.1, you can produce an export that shows: here are all the tool calls made in this period, here is the identity of the agent making each call, here is the capability that authorised or denied the call. The decision rationale is in the record, not reconstructed from logs.

**What to present.** For a CC6.1 finding, I'd present:

1. The capability issuer service's architecture (JWT signing with KMS-backed key, JWKS endpoint, token lifetime)
2. A sample decoded token showing the `capabilities` structure
3. A redacted audit export showing the decision fields per call
4. The enforcement pipeline documentation showing each verification step and its fail-closed behaviour

The fail-closed property is worth emphasising explicitly. Some auditors will ask "what happens when your verification step can't reach the JWKS endpoint?" The answer — deny — is the right one for CC6.1, and it distinguishes eunox from systems that fall back to permit during partial outages.

---

## CC6.2 — Provisioning, deprovisioning, and SCIM

CC6.2 is about the lifecycle of access: how is access granted, how is it modified, and how is it removed?

For traditional systems this is your Joiner/Mover/Leaver process — user joins the organisation, gets provisioned in the directory; user changes role, permissions are updated; user leaves, access is revoked. For AI agents, the equivalent process involves API keys, capability templates, and revocation.

**Provisioning.** API keys for agent deployments are created through the minter service (`POST /admin/v1/keys`). Each key is associated with a tenant and a policy template. The request is authenticated with operator credentials and logged to the audit ledger with the `operatorId` who issued it. The key ID and policy association are retrievable from the admin API for audit purposes.

**Deprovisioning.** There are two deprovisioning mechanisms. First, token expiry: JWT capability tokens are short-lived (five minutes or less in hosted mode). An agent session that isn't actively making calls will naturally lose its active token. Second, explicit revocation: `DELETE /admin/v1/keys/{prefix}` immediately revokes the API key in the minter, so future key-authenticated requests and fresh token minting attempts fail. Existing capability tokens remain bounded by their normal TTL, and JTI-based revocation remains a separate gateway-side incident-response control when you need to invalidate a specific token immediately.

**SCIM integration.** For enterprise deployments, the SCIM 2.0 provisioning integration connects eunox to your identity provider's Joiner/Mover/Leaver process directly. When a user is offboarded in your IdP, the SCIM deprovision event triggers capability template cleanup for any agents associated with that user. The SCIM bridge (described in detail in [the SCIM post](./27-scim-for-ai-agents.md)) handles group-to-capability-template mapping, so you can say "members of the data-analysts group get read-only analytics capabilities" and have that applied and revoked automatically when group membership changes.

**Evidence for auditors.** The admin audit log records every provisioning and deprovisioning event with timestamp, operator identity, and the key/token affected. For CC6.2, you can produce:

1. Admin audit log exports showing key creation and revocation events
2. SCIM event logs showing deprovision triggers and their effect on capability templates
3. A demonstration of the revocation path (issue a key, revoke it, show that subsequent key-authenticated requests or token-minting attempts fail immediately, then pair that with short TTLs or JTI revocation for already-issued tokens)

---

## CC6.3 — Access reviews

CC6.3 asks whether you periodically review access rights and whether stale or excessive access is recertified or removed.

For AI agent platforms, the access review question is different from the human-access version. You're not reviewing whether user Alice still needs access to application B. You're reviewing whether agent deployment X still needs the capability set encoded in policy template Y, and whether any drift has occurred between what the policy says and what the agent is actually doing.

**Policy review.** Capability policy templates are version-controlled YAML files (or database records if you're using the hosted policy store). Any change to a policy goes through your normal code review process — pull request, approval, deployment. This naturally produces an audit trail of when the policy changed, who changed it, and why. For access reviews, you can point to the policy's git history.

**Usage analysis.** The audit evidence APIs give you the raw decision data for access reviews: `GET /api/v1/audit/records` is the tenant-scoped query surface, and `GET /api/v1/audit/export` is the admin export surface. In practice you aggregate those records in your SIEM or warehouse by capability, decision, or `conditionType` over the review window. If a capability is in the token but has never been used, that's a candidate for removal during access review. If a capability is being used at rates significantly below its `maxCalls` limit, the limit might be reducible. This data-driven review is something traditional RBAC systems rarely support — you can't easily tell from a permission grant whether the permission is actually being exercised.

**Token lifetime as a control.** Short-lived tokens mean that any access rights effectively expire automatically. A capability token with a five-minute TTL means the maximum window for an unauthorised exercise of access is five minutes — not the six months between your last access review and the next one.

---

## CC7 — System operations and the monitoring story

CC7 is about whether you know when something is wrong. It covers system monitoring, anomaly detection, incident identification, and response. For AI agent deployments, this is the area where most organisations have the largest gap — either because they haven't built structured monitoring for agent behaviour, or because they have monitoring but it's based on server logs rather than structured decision records.

---

## CC7.1 — Vulnerability management

CC7.1 asks whether you have a process for identifying and remediating vulnerabilities. For an AI governance platform, this includes:

- The platform software itself (dependency scanning, CVE tracking, patching schedule)
- The policy configuration (are there capability templates with overly-broad permissions that represent a security risk?)
- The deployment infrastructure (container image scanning, network exposure)

The air-gap deployment covered in [the air-gapped deployment post](./29-air-gapped-ai-governance.md) documents the image inventory approach — all container images are enumerated, pulled to a private registry, and can be scanned with any standard container security tool. The `k8s/air-gap-images.txt` manifest is the inventory.

For policy vulnerabilities, the `GET /api/v1/audit/export` data combined with the conditions analysis can identify policies where the conditions are too permissive — for example, a `maxCalls` limit that's set so high it effectively doesn't constrain anything, or an `allowedOperations` list that includes operations you wouldn't expect an agent to need.

---

## CC7.2 — Monitoring for anomalies

This is where eunox's audit infrastructure pays off directly for compliance. The OCSF API Activity records in the Postgres ledger are structured, queryable data about every decision the enforcement pipeline made. "How do you monitor for anomalies?" has a specific, defensible answer.

**Denial spike alerting.** A spike in denied calls signals that something is being attempted that the policy was designed to prevent. The gateway exposes the Prometheus counter `eunox_gateway_decisions_total{decision="deny"}` for that top-line alert. To break the spike down by `conditionType` or `denialCode`, pivot into the structured audit records from `GET /api/v1/audit/records` or your exported OCSF events. An anomalous cluster of `allowedOperations` denials might mean an agent encountered an adversarial injection and is now attempting SQL operations it shouldn't.

**Call volume anomalies.** `eunox_gateway_decisions_total{decision="allow"}` gives you the baseline allow volume at the gateway. Significant deviations from baseline are worth investigating. For tenant-, agent-, or resource-level drilldown, use the structured audit records rather than relying on Prometheus labels that don't exist on the counter. An agent that normally makes 20 database calls per hour suddenly making 2,000 is a signal — possibly a runaway loop, possibly an agent that's been manipulated.

**Kill-switch state monitoring.** The gateway exports `eunox_gateway_kill_switch_active{global_kill="0"|"1"}` as the primary kill-switch gauge, plus `eunox_gateway_kill_switch_killed_sessions` and `eunox_gateway_kill_switch_killed_agents` counters for scoped actions. If a kill-switch is activated and not cleared within your expected incident response window, that should generate a high-priority alert — either it was intentional and someone should have cleared it, or it was triggered automatically and someone needs to investigate the cause.

**New agent identities.** The `sub` claim in capability tokens identifies the agent principal. Monitoring for new `sub` values that appear in the audit log without a corresponding provisioning event in the admin audit can catch agents that were deployed without going through your standard provisioning process.

**Evidence for auditors.** For CC7.2, present:

1. Your Prometheus dashboard (or alerting rules) showing the metrics you monitor
2. The alert thresholds and escalation paths for each metric
3. An example of an anomaly being detected and the resulting investigation record

---

## CC7.3 — Incident identification and classification

CC7.3 asks whether you can identify security incidents when they occur and whether you can classify their severity.

The OCSF schema that eunox uses for audit records maps naturally to incident classification. API Activity records carry `severity_id`, `status`, and `category_uid` fields. A denial event due to `allowedOperations` violation is OCSF category 6003 (API Activity), severity informational when isolated, severity high when clustered. You can write SIEM rules against the OCSF schema without custom field mapping.

For automated incident identification, the policy violation record includes:

- The full request arguments (subject to `redactFields` obligations)
- The specific condition that failed
- The token identity and session context
- A timestamp accurate to millisecond

This gives an incident responder enough context to reconstruct exactly what the agent attempted, whether the attempt was part of a broader pattern, and whether it represents a policy violation or a genuine attack.

---

## CC7.4 and CC7.5 — Response and recovery

CC7.4 covers incident response and CC7.5 covers recovery. For an AI agent platform, the response mechanisms are:

**Kill-switch activation.** When an agent fleet needs to be stopped immediately, the gateway exposes `POST /admin/kill-switch/global/activate` for a global stop and scoped session/agent routes under `/admin/kill-switch/session/:sessionId/kill` and `/admin/kill-switch/agent/:agentId/kill`. Effect is immediate — the gateway checks kill-switch state on every call. You don't need to find and stop individual agent instances. One API call stops everything in scope.

**Token revocation.** For surgical incident response targeting a specific session, revoke the specific token's JTI. The revocation propagates to all gateway instances via Redis within a single request cycle.

**Audit evidence preservation.** The Postgres ledger is write-once (records are inserted, never updated or deleted by the application layer). The HMAC chain and KMS-signed bundles mean the audit record can be presented as tamper-evident evidence. The `GET /api/v1/audit/export` endpoint returns a JSON bundle with a `records` array and a `verificationUri`, and you pair that with `GET /api/v1/audit/chain-proof` (and, for software signers, `GET /api/v1/audit/signing-keys`) for offline verification. For CC7.4, you need to demonstrate that your incident response doesn't compromise the integrity of your audit evidence — the immutable ledger design addresses this.

---

## Building the audit evidence package

The `GET /api/v1/audit/export` endpoint accepts `scope`, `since`, `until`, `pageSize`, and `cursor`. For SOC 2 audit preparation, you'll typically want:

- **For access review**: full export for the audit period with the relevant `scope` (`soc2-cc6`, `soc2-cc7`, or `all`)
- **For incident evidence**: export for the incident window, then correlate the returned records with `GET /api/v1/audit/records` or your SIEM for session- or agent-level drilldown
- **For chain verification**: fetch `GET /api/v1/audit/chain-proof` separately, and use the `verificationUri` from the export response (typically `/api/v1/audit/signing-keys` for software signers) to retrieve the verification key material

The export format is a JSON object with a `records` array of OCSF events, which is straightforward to hand to an auditor or transform into the format your SIEM expects. The `verificationUri` field in that response tells you where to fetch the public key material needed for offline verification when the gateway is using a software signer.

One thing I've learned through audit cycles: produce the evidence before the auditor asks for it, and produce it in a format they can work with. Auditors who haven't seen the OCSF format before need a brief explanation of the schema, but once they understand it, the structured fields make their review faster, not slower. The alternative — reconstructed narratives from server logs — takes longer and leaves more room for "can you show me where in the logs this happened?"

---

## The tamper-evident chain

One question that comes up reliably in SOC 2 audits: "How do you know these log records are authentic? Could someone on your team modify or delete records after the fact?"

The answer involves three layers. First, every row in the Postgres ledger carries a `previousHash` — the SHA-256 hash of the previous record — and a `signature` — the KMS-signed hash of this record's content. Modifying any record breaks the chain hash for every subsequent record. This is detectable by running the `GET /api/v1/audit/chain-proof` endpoint, which recalculates the chain and reports any breaks.

Second, periodic bundle signatures. The gateway creates periodic signed bundles of audit records — essentially a Merkle-tree commitment to the state of the ledger at a point in time. These bundles are signed by the KMS key and can be stored externally (S3, Azure Blob, etc.) as a point-in-time reference. Even if someone could modify the database, they'd need to also invalidate all the external bundle signatures, which requires access to the KMS key.

Third, cross-chain anchoring for replica chains. In multi-replica deployments, each replica gateway maintains its own audit chain. The cross-chain anchor record in each chain references the other chains' head hashes, so inconsistencies between replicas are detectable.

For auditors, the practical demonstration is: export the audit records, run the chain verification tool, show the result "chain intact, all records verified." The tamper-evident design means you can make this claim with confidence, not just assertion.

---

## What this doesn't solve

No single platform covers all of SOC 2 on its own, and I'd be doing you a disservice by pretending otherwise. CC6 and CC7 have criteria that sit outside what eunox controls:

- Physical security of your hosting infrastructure is your CSP's responsibility
- Identity provider configuration (SSO, MFA for human operators) is outside eunox's scope
- Network-level access controls around the gateway and capability issuer are deployment-specific
- Your incident response process, escalation paths, and communication procedures are yours to define and demonstrate

What eunox provides is the governance layer for agent activity specifically — the tamper-evident evidence that agents were operating within defined policy, the structured audit trail for access reviews, and the kill-switch and revocation mechanisms for incident response. Combined with your baseline cloud security posture and identity management, it fills the AI-agent-specific gap that traditional SOC 2 programs weren't designed to address.

If you're preparing for a SOC 2 Type II audit and have questions about specific criteria mapping, the self-hosting reference in `docs/self-host.md` and the control-mapping guide in `docs/security/soc2-mapping.md` are the current in-repo references for export workflows and auditor questions. And if you're deploying on-premises rather than in the cloud, the air-gapped deployment post covers the infrastructure considerations that come with running this stack in an environment without internet access.
