---
title: "Tamper-Evident Audit Logs: OCSF, HMAC Chaining, and KMS-Signed Evidence"
description: 'Published in the "Architecture deep-dives" series. Read post 10 ("The Tool Gateway as a reference monitor") first if you haven''t seen the enforcement pipeline yet — understanding how the gateway evaluates a tool call is a prerequisite for understanding why the audit record for that call looks the way it does. See [`docs/blog-articles.md`](../blog-articles.md) for the full series index.'
pubDate: "2026-05-30"
---

_Published in the "Architecture deep-dives" series. Read post 10 ("The Tool Gateway as a reference monitor") first if you haven't seen the enforcement pipeline yet — understanding how the gateway evaluates a tool call is a prerequisite for understanding why the audit record for that call looks the way it does. See [`docs/blog-articles.md`](../blog-articles.md) for the full series index._

---

Every time a security audit comes up in a conversation with a potential enterprise customer, the same question surfaces within the first ten minutes: _"Can you prove that those audit logs haven't been tampered with?"_ It's a fair question. A log file that an attacker — or a disgruntled admin with database access — can silently modify is not evidence. It's a story.

Building something that can actually answer that question cleanly took longer than I expected. Here's what I learned.

---

## The problem with conventional logging

Most systems log events by appending rows to a database table or writing lines to a file. Both approaches share the same weakness: anyone with write access to the store can modify or delete records without leaving a trace. In a traditional relational database, `UPDATE` and `DELETE` are first-class operations. There's no structural barrier to "fixing" an inconvenient record.

For a system whose entire value proposition is governance — _your AI agents don't do things they're not supposed to do, and we can prove it_ — this is not a theoretical concern. If an attacker compromises the gateway host, or if a rogue operator wants to cover their tracks, a mutable audit log gives them a clean exit. The absence of evidence becomes the evidence of absence.

The classic answer from the security world is an append-only log with a cryptographic chain. Each entry hashes the previous one; modifying any entry breaks the chain for every entry that follows. This is how certificate transparency logs work, how blockchain systems work at their core, and how we built the eunox audit ledger.

---

## OCSF: choosing the right schema

Before getting into how records are protected, it's worth explaining what they contain.

We chose the [Open Cybersecurity Schema Framework (OCSF)](https://schema.ocsf.io) — specifically the **API Activity** event class (`class_uid: 6003`) for every enforcement decision the gateway makes. I'll be honest: I initially resisted adding a dependency on an external schema when a simple JSON object would have done the job. I was wrong, and here's why.

The first time an enterprise customer's security team asked whether they could ingest our audit events into Splunk, I was glad we'd made the choice. OCSF is what Splunk, Microsoft Sentinel, and most SIEM vendors speak natively. If we'd rolled our own schema, every customer integration would require a custom field-mapping exercise. With OCSF, there's nothing to map — the ingestion pipeline already knows what `class_uid`, `time`, `severity_id`, and `status` mean.

The two event classes we emit:

| Class             | `class_uid` | When it fires                                             |
| ----------------- | ----------- | --------------------------------------------------------- |
| **Authorization** | `3003`      | Token issuance, attenuation, renewal, revocation          |
| **API Activity**  | `6003`      | Every enforcement decision (allow or deny) at the gateway |

A typical allowed tool call produces a record that looks roughly like this:

```json
{
  "class_uid": 6003,
  "category_uid": 6,
  "type_uid": 600301,
  "time": 1746590400000,
  "severity_id": 1,
  "status": "Success",
  "metadata": {
    "version": "1.1.0",
    "product": { "name": "eunox", "vendor_name": "eunox", "version": "5.0.0" },
    "uid": "evt_a3f2b1c4..."
  },
  "actor": { "agent_uid": "agent_abc123", "tenant_id": "tenant_xyz" },
  "api": {
    "operation": "tools/call",
    "request": { "tool": "query_db", "args": { "query": "SELECT ..." } }
  },
  "http_request": { "url": { "path": "/proxy/query_db" } }
}
```

A denial adds `"status": "Failure"`, a `denialCode`, and a `conditionType` that identifies exactly which condition rejected the call. This structured denial shape is important — when you're debugging an agent in production and the audit trail shows 40 allowed calls and then a denial, you want to know immediately whether the denial was a `maxCalls` exhaustion, an `allowedOperations` violation, or a missing capability token entirely. We designed the denial codes to answer that question without requiring a log query.

---

## The HMAC chain: tamper evidence without a distributed ledger

The append-only guarantee is enforced at two levels.

At the database level, the `eunox_audit_ledger` table is write-only from the application perspective: `INSERT` only, no `UPDATE` or `DELETE` in the application code, and in production deployments we recommend a Postgres role with only `INSERT` and `SELECT` grants for the gateway process. This is necessary but not sufficient — a database admin can still run `UPDATE` directly.

The cryptographic layer is what closes that gap. Every row carries a `row_hmac` column computed as:

```
HMAC-SHA256(hmacSecret, seq || ":" || previousHash || ":" || recordHash || ":" || replicaId)
```

Where:

- `seq` is a monotonically increasing per-replica sequence number
- `previousHash` is the SHA-256 of the _previous_ row's canonical JSON in the same replica chain
- `recordHash` is the SHA-256 of this row's canonical JSON
- `replicaId` identifies which gateway instance wrote the row (important in a multi-replica deployment)
- `hmacSecret` is a 256-bit secret provisioned at deployment time, stored in your KMS (Key Vault, AWS Secrets Manager, etc.) — not in the database itself

This is the key design choice: the `hmacSecret` is _separate_ from the database. A database admin who can run arbitrary SQL does not automatically have the HMAC secret. Modifying a row without the secret produces a detectable mismatch. To forge a record, an attacker needs both database write access _and_ the HMAC secret _and_ to recompute the entire chain from the modified record forward — all three simultaneously, under time pressure.

That's not an impenetrable barrier, but it raises the bar substantially. And because we also emit KMS-signed JWTs (more on that below), there's a second, independent layer that doesn't depend on the HMAC secret at all.

---

## Multi-replica chains and cross-chain anchors

A gateway deployment at any reasonable scale runs more than one instance. That breaks the simple "linear chain" model, because records from different replicas are interleaved in the database but each replica maintains its own independent sequence.

The design solution is that each replica maintains its own chain identified by `replicaId`. The `seq` column is per-replica, and the `previousHash` links within a single replica's chain. This means chain continuity verification is done per-replica, not across the full table.

For SOC 2 audit purposes, the export endpoint (`GET /api/v1/audit/export`) returns records sorted by replica and sequence. The auditor can verify each replica chain independently. If you have three gateway replicas running at high availability, you get three chains that can each be verified independently. A record gap in any chain is immediately detectable.

The `replicaId` is set at gateway startup — typically derived from the pod name in Kubernetes (`POD_NAME` env var), which is stable and deterministic within a deployment. If you're rolling a deployment and a pod restarts, the new instance picks up from `seq: 1` in its own chain. The old chain is sealed. Both chains are present in the export and both are independently verifiable.

---

## KMS-signed JWTs: the second layer

HMAC is fast and easy to verify, but it has a property that some auditors push back on: it's symmetric. The same key that was used to _write_ the HMAC can be used to _forge_ it. If an attacker has the `hmacSecret`, they can rewrite history without leaving a trace at the HMAC layer.

This is where the KMS-signed JWT layer comes in. Every audit record in the export bundle includes an `evidenceJwt` field — a JWT signed by the gateway's asymmetric signing key (the same key that signs capability tokens, managed by Key Vault / AWS KMS / GCP Cloud KMS). The JWT payload contains the full OCSF record plus the chain metadata (`seq`, `previousHash`, `replicaId`).

Crucially, this is an _asymmetric_ signature. The private key never leaves the HSM. An auditor can verify the `evidenceJwt` offline using the issuer's published JWKS endpoint — the same verification path they'd use for any JWT issued by the platform — without any access to internal secrets.

This gives you two independent tamper-evidence mechanisms:

1. HMAC chain verification (fast, symmetric, requires secret)
2. KMS JWT verification (asymmetric, offline-verifiable, key never leaves HSM)

To forge a record while defeating both layers, an attacker would need to simultaneously compromise the HMAC secret _and_ the KMS private key. The KMS key never leaves the hardware boundary; compromising it is a different class of attack from SQL injection or database admin access.

---

## The local audit log in `eunox-mcp`

Posts 9 and 10 covered the gateway — the enterprise enforcement path. But the same OCSF schema is also used in `eunox-mcp`, the open-source local proxy.

When you're running `eunox-mcp` locally (no gateway, no Postgres, just a YAML policy file and a stdio process), every tool call still gets logged to `~/.eunox/audit.jsonl`. The format is the same OCSF API Activity shape. The difference is the signer: instead of a KMS-backed asymmetric key, the local log uses a locally-generated HMAC key stored in `~/.eunox/key` (created on first run, mode 0600).

This is a deliberate design choice. The policy format is the same whether you're running locally or against the hosted gateway. The audit record format is the same. When you move from local development to a production gateway deployment, your tooling — log parsers, monitoring scripts, SIEM ingest rules — doesn't need to change. The only thing that changes is the signer and the sink.

If you `tail -f ~/.eunox/audit.jsonl` while running an agent locally, you're reading the same event schema that will end up in your SIEM in production. That observability continuity matters more than I initially appreciated; it's one of those things that seems like a minor implementation detail until the first time you're debugging a production policy issue by replaying the logic locally.

---

## SOC 2 evidence: CC6 and CC7

The practical purpose of all this machinery is producing audit evidence for SOC 2 Type II audits. We map directly to the two control families that auditors care about for an authorization system:

**CC6 (Logical and Physical Access Controls):** every token issuance, attenuation, renewal, and revocation event maps here. An auditor can see, for a given time period, every grant of access (CC6.2), every revocation (CC6.2), and every narrowing of scope through attenuation (CC6.3). The `scope=soc2-cc6` query parameter on the export endpoint returns exactly this set.

**CC7 (System Operations):** every enforcement decision — every allowed and denied tool call — maps here. This is the evidence that your access control policies are actually being enforced in real time (CC6.6), and that anomalies are being detected and logged (CC7.1, CC7.2). The `scope=soc2-cc7` query parameter returns this set.

An auditor can:

1. Export records for the audit period via `GET /api/v1/audit/export?since=...&until=...`
2. Verify each `evidenceJwt` signature offline using the published JWKS
3. Verify chain continuity across all replica chains
4. Map records to specific CC controls using `type_uid`

The full verification script is in `docs/security/soc2-mapping.md §4`. It's not a hypothetical — I ran through it with an actual auditor and it produced clean results.

---

## HMAC secret rotation

One operational concern that came up early: what happens when you need to rotate the HMAC secret? The answer is uncomfortable but honest: rotating the secret invalidates every existing row's HMAC, because the stored value was computed with the old secret. A fresh HMAC check will fail for all pre-rotation records.

There are three strategies, documented in `docs/runbooks/ledger-hmac-rotation.md`:

**Strategy A (recommended):** Create a new table. Configure the backend to write to the new table with the new secret. Keep the old table as a read-only archive, verifiable with the old secret. This is operationally clean and adds no risk to historical integrity.

**Strategy B (emergency):** Backfill all rows with a recomputed HMAC during a maintenance window. This requires an exclusive lock and carries the risk that any tampering between the start of the rotation and the backfill is overwritten and undetectable.

**Strategy C (future):** Per-row secret versioning, where each row stores a `secret_version` column pointing to the correct key for verification. Not yet implemented — it's on the roadmap and would enable rolling rotations without maintenance windows.

The KMS-signed JWTs are unaffected by HMAC rotation, which is another reason the dual-layer approach is worth the added complexity.

---

## What I'd do differently

If I were building this from scratch today, I'd probably reach for per-row secret versioning from day one rather than planning to add it later. The append-only constraint on the application side is worth keeping, but rotating a symmetric secret without a versioning mechanism is a painful operational problem that surfaces exactly when you least want complexity.

I'd also think harder about the cross-chain anchor story for large multi-replica deployments. Right now, an auditor verifies each replica's chain independently. That works, but it doesn't give you a global ordering guarantee across replicas — you can tell that replica A's records are internally consistent, and replica B's records are internally consistent, but interleaving them by `time` gives you an approximate ordering, not a provably consistent one. For most SOC 2 purposes this is fine. For financial-grade transaction integrity it isn't.

But for a governance layer over AI agent tool calls, where the threat model is "prevent and detect unauthorized actions" rather than "achieve Byzantine fault tolerance," the current design is a good trade-off between complexity and assurance.

---

_Next in this series: [post 12 — Pluggable adapters: building a cloud-portable identity and signing layer](./12-pluggable-adapters.md), which covers how eunox swaps between Azure AD + Key Vault, AWS Cognito + KMS, and GCP Cloud Identity + Cloud KMS without touching the enforcement core._
