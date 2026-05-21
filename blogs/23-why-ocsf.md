# Why OCSF? Choosing a Schema for AI Agent Audit Events

*First post in the "Technology choices" series. [Post 11](./11-tamper-evident-audit-logs.md) covers how the audit records are protected with HMAC chaining and KMS signatures. [Post 10](./10-tool-gateway-pdp.md) explains when and why each record is emitted. If you haven't read those, they provide the "what" behind the records this post explains the shape of. See [`docs/blog-articles.md`](../blog-articles.md) for the full series index.*

---

There's a moment in every non-trivial platform project where you have to decide how to structure your audit data. The shape of an audit record sounds like a minor implementation detail. In my experience it's one of the decisions with the longest tail — it affects SIEM integration, SOC 2 audit scope, incident response tooling, customer buy-in, and your own ability to query what happened in production. Getting it wrong means either re-designing the schema under load or carrying technical debt through every audit report and integration you ever ship.

For euno, I chose the [Open Cybersecurity Schema Framework (OCSF)](https://schema.ocsf.io). This post explains why, how the mapping works in practice, where the friction is, and what I'd tell someone starting from scratch today.

---

## The problem with rolling your own schema

When I started designing the audit log, my instinct was to write something minimal and purpose-built. Something like:

```json
{
  "ts": "2024-03-15T14:23:11Z",
  "agent": "sales-research-bot",
  "tool": "query_db",
  "result": "deny",
  "reason": "maxCalls exceeded"
}
```

Clean, readable, easy to produce. I could have shipped that in two days. The first version did ship something very close to that.

The problems surfaced quickly.

The first enterprise customer to run a security review asked for SIEM integration. Their Splunk team wanted to know the field names so they could write an ingestion pipeline. I sent them the custom schema. They sent back a list of questions: Is `ts` epoch millis or ISO 8601? Does `result` always use these exact string values? What's the unique record identifier? Is there a version field? Do you have an event class taxonomy?

I answered the questions. Then the next customer asked roughly the same questions, slightly differently. And their Splunk configuration was different, so the field names I'd chosen conflicted with their existing normalization rules. Their team asked if I could rename `agent` to `actor_name`. No big deal for one customer. The second customer then asked if I could rename it back.

This is the inevitable path when you roll your own event schema for a security product. Every enterprise security team has existing normalization infrastructure, and every piece of that infrastructure was designed around standard schemas. When your format is bespoke, you become a one-off translation problem for every single customer.

---

## What OCSF actually is

OCSF was open-sourced in 2022 by Splunk, AWS, and a consortium of other security vendors. It's a normalization framework — a set of event class definitions with strongly typed, named fields and a controlled vocabulary for values. The key design decision that makes it useful is that it doesn't try to be everything to everyone. It has a core schema that all events share (a `metadata` object, a `severity_id`, a `time`, a `status`), and then event-class-specific extensions that add fields relevant to the specific event type.

The framework ships with categories and classes for the most common security event types:

- **Category 3: Identity & Access Management** — authentication events, token issuance, authorization decisions
- **Category 6: Application Activity** — API calls, database queries, file access

For euno, the two classes we emit are:

| Class | `class_uid` | Used for |
|---|---|---|
| **Authorization** | `3003` | Token issuance, attenuation, renewal, revocation |
| **API Activity** | `6003` | Every enforcement decision at the gateway or local proxy |

When I say "emit," I mean we produce JSON records conforming to these class definitions, with all mandatory fields populated. When a SIEM vendor says "we support OCSF," they mean their ingestion pipeline knows these field names and class UIDs without requiring a customer-specific mapping configuration.

---

## Mapping a tool call enforcement decision to API Activity

The actual mapping work is where the details live. Let me walk through what a real enforcement decision looks like as an OCSF `class_uid: 6003` record.

An agent calls the `query_db` tool with a SQL query. The gateway evaluates the capability manifest, runs condition evaluation, and allows the call. The resulting audit record:

```json
{
  "class_uid": 6003,
  "category_uid": 6,
  "type_uid": 600301,
  "time": 1710509991000,
  "start_time": 1710509990982,
  "end_time": 1710509991003,
  "severity_id": 1,
  "severity": "Informational",
  "status": "Success",
  "status_id": 1,
  "metadata": {
    "version": "1.1.0",
    "product": {
      "name": "euno",
      "vendor_name": "euno",
      "version": "5.0.0"
    },
    "uid": "evt_a3f2b1c4d5e6f7a8",
    "log_name": "euno-audit",
    "log_provider": "euno-gateway"
  },
  "actor": {
    "user": {
      "uid": "agent_abc123",
      "type": "System",
      "type_id": 2
    },
    "session": {
      "uid": "sess_xyz789",
      "created_time": 1710509000000
    },
    "policy": {
      "name": "sales-research-bot-policy",
      "uid": "capability-manifest:sales-research-bot:v3"
    }
  },
  "api": {
    "operation": "tools/call",
    "request": {
      "uid": "req_deadbeef",
      "flags": ["tool_call"],
      "data": {
        "tool": "query_db",
        "arguments": { "query": "SELECT id, name FROM customers WHERE region = 'EMEA'" }
      }
    },
    "response": {
      "flags": ["allowed"],
      "message": "OK"
    },
    "service": {
      "name": "postgres-mcp-server",
      "uid": "upstream://localhost:5432"
    }
  },
  "http_request": {
    "url": {
      "path": "/proxy/tools/call",
      "hostname": "gateway.internal"
    },
    "http_method": "POST",
    "version": "2"
  },
  "dst_endpoint": {
    "hostname": "localhost",
    "port": 5432,
    "svc_name": "postgres-mcp-server"
  },
  "unmapped": {
    "tenantId": "acme-corp",
    "conditionEvaluations": [],
    "obligationsApplied": ["log"]
  }
}
```

That's considerably more verbose than the minimal schema I almost shipped. Let me explain the non-obvious fields and why they're worth the verbosity.

**`type_uid: 600301`** is OCSF's way of encoding `class_uid * 100 + activity_id`. `600301` means "API Activity (6003), Create (01)." The OCSF activity taxonomy for API Activity includes Create, Read, Update, Delete, and Other. Tool calls are mapped to Create (an invocation is a creation event in OCSF's taxonomy). This distinction matters for SIEM alerting — you can build a rule that fires on `type_uid in [600302, 600303, 600304]` (Read/Update/Delete) for specific API endpoints without having to enumerate tool names.

**`actor.policy`** is an extension to the standard actor structure. OCSF's API Activity class defines an `actor` object but doesn't mandate a policy field. We add it because the capability manifest that governed the enforcement decision is critical context for any audit query. "Which policy version was active when this call happened?" is the first question in many incident response investigations.

**`unmapped`** is OCSF's escape hatch for extension fields that don't fit the standard schema. The standard advises putting non-standard fields here rather than inventing top-level keys. `tenantId`, `conditionEvaluations`, and `obligationsApplied` live here. They show up in SIEM ingestion as extended fields and are fully queryable, but the ingestion pipeline knows not to try to normalize them against the standard schema.

---

## The denial record and why its structure matters

An allowed call is interesting. A denied call is the record that actually gets scrutinized. Here's what a denial looks like:

```json
{
  "class_uid": 6003,
  "status": "Failure",
  "status_id": 2,
  "severity_id": 3,
  "severity": "Medium",
  "api": {
    "operation": "tools/call",
    "request": {
      "data": {
        "tool": "delete_file",
        "arguments": { "path": "/etc/passwd" }
      }
    },
    "response": {
      "flags": ["denied"],
      "error": "ALLOWED_OPERATIONS_VIOLATION",
      "error_message": "Tool delete_file is not in allowedOperations for resource read_file"
    }
  },
  "unmapped": {
    "tenantId": "acme-corp",
    "denialCode": "ALLOWED_OPERATIONS_VIOLATION",
    "conditionType": "allowedOperations",
    "matchedResource": "read_file"
  }
}
```

The `status: "Failure"` with `status_id: 2` is OCSF standard. The `api.response.error` field is the normalized denial code. The `severity_id: 3` (Medium) on denials is a deliberate choice — not every denial is an attack; agents probe boundaries naturally during normal operation. But denials cluster analysis in a SIEM benefits from having some severity attached. A single denial is informational; twenty denials in thirty seconds from the same session is worth a page.

The `unmapped.conditionType` and `unmapped.denialCode` fields are the most useful for euno-specific queries. If you're investigating "why did the agent fail?" in your SIEM, filtering on `unmapped.conditionType = "maxCalls"` vs `unmapped.conditionType = "allowedOperations"` immediately partitions the investigation space.

---

## The Authorization class: token lifecycle events

Not every event is a tool call. The Authorization class (`class_uid: 3003`) covers the token lifecycle: issuance, attenuation, renewal, revocation, and partner DID registry changes.

```json
{
  "class_uid": 3003,
  "type_uid": 300301,
  "status": "Success",
  "metadata": { "uid": "evt_b2c3d4e5f6a7b8c9" },
  "actor": {
    "user": { "uid": "operator:alice@example.com", "type": "User", "type_id": 1 }
  },
  "policy": {
    "name": "sales-research-bot-policy",
    "uid": "capability-manifest:sales-research-bot:v3"
  },
  "unmapped": {
    "eventType": "TOKEN_ISSUED",
    "tenantId": "acme-corp",
    "jti": "cap_token_abc123",
    "agentId": "sales-research-bot",
    "tokenTtlSeconds": 900
  }
}
```

The SOC 2 CC6 scope query (`?scope=soc2-cc6`) returns exactly these records for a given time period — every grant and revocation of access authority, with the operator identity that initiated each action. This is the CC6.2 requirement: logical access changes are logged with the identity that made the change.

---

## OCSF profile extensions: the AI agent gap

OCSF as of version 1.1.0 does not have an "AI agent" profile. The framework was designed with human-initiated API activity in mind, and some fields don't have natural AI equivalents. The `actor.user` field has `type_id` values like `System`, `User`, `Unknown` — there's no `Agent` type. We use `type_id: 2` (System) for agent actors, which is accurate but loses the semantic distinction between a human operator running an API call and an autonomous LLM-driven agent running a tool call.

I've been watching the OCSF working group discussions and there's active interest in an AI/ML event profile. When that lands, euno will have a migration to do. The `type_uid` namespace will extend cleanly; the `actor` structure is the part I'm least confident about. But forward compatibility with a schema that has a proper standards body behind it is vastly better than forward compatibility with something I wrote myself.

For now, the `unmapped` fields fill the gap. Every AI-specific attribute (agent framework, model identifier, prompt hash, session turn number) lives in `unmapped`. When the OCSF AI profile exists, we'll migrate those fields to first-class schema positions. The SIEM queries that currently filter on `unmapped.agent_framework` will need updates, but the records will all be there, queryable both ways during a transition period.

---

## Ingestion in practice: Splunk, Microsoft Sentinel, and the commodity case

The payoff comes at ingestion time. When I send an OCSF `class_uid: 6003` record to a Splunk SIEM configured with the OCSF technology add-on, no field mapping configuration is required. `time`, `severity_id`, `status`, `actor.user.uid`, `api.operation` — these are recognized. The customer security team can immediately write detection rules using the same field names they use for all their other OCSF sources, without reading our documentation.

Microsoft Sentinel has had native OCSF ingestion support since 2023. The Advanced SIEM Information Model (ASIM) normalization tables accept OCSF events with minimal transformation. This matters for Microsoft-heavy customers, who make up a substantial portion of enterprise deployments — their SIEM is already configured to ingest OCSF from their Azure services; euno just becomes another source in the same stream.

The commodity case — "ingest logs into any S3-compatible store and query with Athena or BigQuery" — also benefits. OCSF has Parquet schema definitions maintained by AWS that map directly to Athena external table definitions. If a customer is aggregating security events into a data lake, the euno records land in the same table format as their CloudTrail and GuardDuty events. The query you write to ask "show me all authorization failures in the last 30 days across all event sources" works with euno records without modification.

---

## What the OCSF discipline costs

It's not free. The verbosity is real — a minimal custom audit record might be 400 bytes; a full OCSF record with all mandatory fields is 2-4KB. At 10,000 tool calls per minute (not unusual for a busy gateway deployment), that's meaningful storage impact. We mitigate this with configurable summarization: the `AUDIT_VERBOSITY=compact` setting omits the redundant metadata fields (gateway version, product name, hostname) that are the same for every record in a deployment and writes them once in a header record instead. The full record is always emitted for denials and authorization events; only allowed tool calls get compacted.

The schema discipline also requires discipline in the team. Every new event type, every new field, goes through a mapping exercise: does this fit in an existing OCSF field, or does it go into `unmapped`? Getting that wrong in either direction is a problem. Over-mapping (forcing something into a standard field where it doesn't fit) creates confusion for security teams who see a familiar field name with a non-standard meaning. Under-mapping (putting everything in `unmapped` because it's easier) undermines the integration value entirely.

The rule I use: if a field has a direct semantic equivalent in the OCSF schema, use the OCSF field. If it's AI-specific or euno-specific and has no OCSF equivalent, put it in `unmapped` using our existing camelCase extension naming. Keeping that naming consistent makes it immediately clear, in any SIEM query, which fields are OCSF standard and which are euno-specific extensions.

---

## Would I make the same choice again?

Yes, with two things I'd do differently.

First, I'd decide earlier to use `unmapped` for AI-specific fields and stick to it. The early codebase had some AI fields stuffed into OCSF `actor.process` and `api.request.flags` in ways that technically fit but made the records harder to read. Cleaning that up mid-stream is fine but takes time.

Second, I'd document the OCSF class UIDs and field mapping as a first-class deliverable in the README, not an afterthought in the security docs. Every conversation with a security team starts with "show me the event schema" — having a one-page reference for the mapping accelerates those conversations substantially. The mapping is now in `docs/security/soc2-mapping.md` and it's genuinely one of the first things I send to security teams evaluating the platform.

The bottom line: OCSF adds verbosity and schema discipline overhead. What it gives you in return — SIEM compatibility without customer-specific mapping work, a forward-compatible path to AI-specific event classes, and a standard vocabulary for SOC 2 evidence — is worth the cost for any security platform that expects enterprise customers.

---

*Next in this series: [post 24 — W3C DIDs in production: lessons from building a partner federation layer](./24-w3c-dids-in-production.md), which covers `did:web` and `did:ion` resolution in detail including the reliability challenges we didn't anticipate. [Post 11](./11-tamper-evident-audit-logs.md) covers how the OCSF records described here are protected with HMAC chaining and KMS signatures.*
