---
title: "W3C DIDs in Production: Lessons from Building a Partner Federation Layer"
description: "Second post in the \"Technology choices\" series. [Post 13](./13-partner-did-federation.md) covers the federation architecture in depth — the two-eyes approval workflow, pin attestation, circuit breakers, and the trust model. This post is about the lower-level operational and reliability experience of actually running `did:web` and `did:ion` resolution in a production gateway. Read post 13 first if you haven't. See [`docs/blog-articles.md`](../blog-articles.md) for the full series index."
pubDate: "2026-06-12"
---

*Second post in the "Technology choices" series. [Post 13](./13-partner-did-federation.md) covers the federation architecture in depth — the two-eyes approval workflow, pin attestation, circuit breakers, and the trust model. This post is about the lower-level operational and reliability experience of actually running `did:web` and `did:ion` resolution in a production gateway. Read post 13 first if you haven't. See [`docs/blog-articles.md`](../blog-articles.md) for the full series index.*

---

I spent several weeks in early production with our partner federation feature dealing with reliability issues I hadn't fully anticipated. That's not unusual — distributed systems always have surprises. What struck me about W3C DID resolution specifically is how the failure modes differ from the other network dependencies in the gateway (JWKS endpoints, Redis, Postgres), and how easy it is to get the fault/error classification wrong in ways that create real security problems.

This post is a collection of those lessons. It's a companion to the architectural overview in post 13; where that post explains what the system is designed to do, this one explains where the real-world edge cases are.

---

## `did:web` is HTTPS with extra specification

Let me start with the basics, because the gap between "this sounds simple" and "this has surprising failure modes" is widest here.

A `did:web` resolution is, at its core, an HTTPS GET request. If the DID is `did:web:partner.example.com`, you fetch `https://partner.example.com/.well-known/did.json`. If it's `did:web:partner.example.com:department:security`, you fetch `https://partner.example.com/department/security/did.json`. The DID document comes back as JSON, you parse out the `verificationMethod` array, and you use the key to verify JWT signatures.

That sounds straightforward. Here are the failure modes I've encountered in production:

**Inconsistent JSON Canonicalization.** The `did.json` file returned by one partner's server was different every request — not in meaningful fields, but in key ordering. They were generating it dynamically rather than serving a static file, and their serializer didn't guarantee field ordering. This broke our pin attestation: we computed `jcsSha256(didDocument)` on the first fetch, stored the hash, and then every subsequent fetch produced a different hash because JCS requires a specific canonical form. JCS (JSON Canonicalization Scheme, RFC 8785) is defined, but the spec is only as useful as the implementation on the other end. We had to add a pre-canonicalization normalization step that re-serializes the fetched document through our JCS serializer before hashing, which defeats the point if the serializer introduces any information loss. The fix was to require partners to serve a static `did.json` rather than a dynamic one. That's the right requirement; it's just not one I had anticipated needing to document.

**Redirects.** The HTTPS fetch for `did:web` should follow HTTP 301/302 redirects, but the DID spec is ambiguous about whether redirect following is allowed and, if so, how many hops. We encountered a partner whose server did a 301 redirect from HTTP to HTTPS (they had an HTTP endpoint for LB health checks that redirected everything). The redirect was to a different hostname. Should we accept the redirected DID document? The spec says the authority of the DID document must match the DID's web origin. A redirect to a different hostname technically violates this. We chose to reject cross-origin redirects and allow same-origin redirects only. This is more restrictive than what some other DID resolvers do, but it prevents a class of DNS-level attacks where a compromised resolver can redirect the DID resolution to an attacker-controlled endpoint.

**Stale OCSP / TLS certificate issues.** Two partners went through certificate rotation events where their new certificate's OCSP responder was slow to propagate. For about 4 hours after each rotation, TLS handshakes to their DID endpoint were failing at the certificate validation layer. This showed up as authentication errors, not network errors — technically, the TLS failure is a transport authentication failure. Our initial classification had these as "fault" errors that counted against the circuit breaker. After the second incident we reclassified TLS auth failures as a separate category: "transport error, exponential backoff with a long window, does not count against circuit breaker." The reasoning: TLS certificate issues are recoverable without operator intervention and tend to self-resolve within hours. Tripping the circuit breaker — and then having the circuit stay open until a human resets it — is worse than backing off aggressively and waiting.

---

## The fault vs. non-fault classification problem

Post 13 mentions the circuit breaker's fault/non-fault split briefly. I want to expand on this because it took me longer to get right than I expected, and the consequences of getting it wrong are non-obvious.

The rule is: **a fault is a problem with the infrastructure path, not with the data on the path.** If the network is broken, the DNS is broken, the server is down, the server returns a 5xx — those are faults. If the server is reachable and returns a well-formed DID document, but the document doesn't match the pinned hash, or the JWT signature is invalid, or the DID document is missing the expected key — those are errors, not faults.

Why does this matter so much? Because circuit breakers protect against infrastructure instability, not data integrity failures. If we trip the circuit on a pin mismatch, an attacker can knock out a partner's token acceptance by sending a single forged token that causes a pin check failure. If the circuit is now open, every subsequent token from that partner is rejected immediately without a resolution attempt. The attacker has achieved a denial of service against a legitimate partner relationship at the cost of one bad request.

Conversely, if we count every network error as a permanent ban rather than a circuit breaker, a partner with an intermittently flaky server (which is real; enterprise infrastructure is messy) would lose their federation access until an operator intervened. That's a usability problem that erodes confidence in the system.

The state machine I ended up with has four error categories with different handling:

| Error type | Examples | Circuit breaker impact |
|---|---|---|
| **Fault** | DNS failure, TCP timeout, HTTP 5xx | Counts against failure threshold |
| **Transport error** | TLS failure, connection reset | Exponential backoff, no circuit breaker |
| **Auth error** | Pin mismatch, signature invalid, malformed document | Does not count; immediately logged as security event |
| **Soft error** | HTTP 429, HTTP 503 with Retry-After | Respects Retry-After header; no circuit breaker |

The security event logging on auth errors is important. A single signature verification failure might be a one-off bad token. A stream of signature verification failures on the same session is an active attack. Logging these as separate events (not just incrementing the circuit breaker counter) means the SIEM alerting logic can see the pattern.

---

## ION: the operational reality

`did:ion` is a different animal. Instead of a simple HTTPS fetch, resolution involves querying the ION network — a Sidetree implementation that anchors DID state transitions on the Bitcoin blockchain. The resolution path is:

1. Contact an ION node (Microsoft's public resolver or a self-hosted node)
2. The ION node reconstructs the DID document from the Sidetree operations anchored in Bitcoin transactions
3. Return the DID document

The latency profile is fundamentally different from `did:web`. A `did:web` resolution is a single HTTPS round trip to a server that's presumably geo-replicated and fast — typically 20-80ms. An ION resolution through the public Microsoft endpoint can be 200-600ms cold, or near-instant if the ION node has the DID cached. The tail latency is worse than `did:web` because ION node availability depends on the public endpoint's operational health, which is outside your control.

In our key cache design (caching resolved keys for `PARTNER_DID_CACHE_TTL_SECONDS`, default 5 minutes), ION's resolution latency is a one-time cost paid on cache miss. For a gateway handling 1,000 req/s with 20 active partner relationships and a 5-minute cache TTL, you're paying the ION resolution cost at most once every 5 minutes per DID — roughly once every 300,000 requests per relationship. That's manageable.

Where ION resolution latency becomes a real problem is on gateway cold start (all cache is empty) or after a cache invalidation event (operator triggered a refresh or the cache was cleared). We added a pre-warming mechanism: at startup, the gateway asynchronously kicks off resolution for all active partner DIDs in the registry, so the cache is populated before the first live traffic hits. This trades a slower startup for a fast first request after startup. For Kubernetes deployments, where cold starts happen frequently (rolling updates, pod rescheduling), this matters.

**Self-hosted ION for air-gapped deployments.** The air-gapped Helm chart includes an ION sidecar — a bundled ION node that ships as a container. The ION node syncs the relevant portions of the Bitcoin blockchain through a bundled Bitcoin pruned node (about 10GB of chain state at the time of writing, growing slowly). This adds operational overhead, but for customers who cannot make any outbound internet calls from the gateway host, it's the only option for `did:ion`. The DID resolution path in the air-gapped configuration points to `http://ion-sidecar:3000` instead of `https://discover.did.microsoft.com/1.0/identifiers/`.

I'll be honest: the air-gapped ION sidecar is complex to operate. It needs to stay synchronized. The Bitcoin pruned node needs disk space. If the ION sidecar falls behind, DID documents for recent key rotations may not be resolvable until it catches up. For most air-gapped deployments, `did:web` with pin attestation is the pragmatic choice unless the security model specifically requires the Bitcoin-anchored immutability guarantee of `did:ion`.

---

## Negative caching: when not to cache

The positive key cache is discussed in post 13. Let me cover the negative cache, which is less obvious but equally important.

A negative cache entry is created when a DID resolution fails — not because the network timed out (that's a fault, handled by the circuit breaker), but because the DID does not exist, the DID document is malformed, or the expected key is not present. If we don't cache the negative result, we'll retry the resolution on every incoming token with that `iss` — potentially hammering a partner's server with resolution attempts for a DID that we already know is broken.

The negative cache TTL is significantly shorter than the positive cache TTL. We use `PARTNER_DID_NEGATIVE_CACHE_TTL_SECONDS` (default 30 seconds) for negative entries. The reasoning: a negative result might indicate a transient problem on the partner's side (they're deploying a new DID document) rather than a permanent state. We want to notice when the problem is fixed without having to wait 5 minutes. But we also don't want every bad token to trigger a fresh network call.

There's an edge case that took some thought: **what happens when a DID document is temporarily replaced with a fraudulent one?** If an attacker hijacks `partner.example.com` and we cached the positive result 4 minutes ago, we'll accept their fraudulent tokens until the cache expires. The pin attestation system (described in post 13) is the defense here: if the new document doesn't match the pinned hash, the cache is not updated with the fraudulent key. The attacker gets the negative cache response for 60 seconds, then we re-fetch, fail pin attestation again, and cache another negative for 60 seconds. The attack is continuously denied. Meanwhile, the pin mismatch is logging as an auth error (see the fault table above), which should be triggering SIEM alerts within seconds of the first mismatch.

---

## The `did:key` shortcut that saved our integration test suite

When we were building the integration tests for the federation feature, the obvious approach would be to run a real HTTP server serving a `did.json` file. That works but it adds infrastructure setup to the test harness, introduces network dependencies, and makes tests flaky in environments where ports are restricted.

`did:key` is a DID method where the public key is encoded directly in the DID identifier — no resolution required. A `did:key:z6Mk...` identifier is a multibase-encoded public key. The resolver extracts the key directly from the identifier string without any network call.

Our integration test fixtures use `did:key` throughout. The `partner-issuer-sim` test package generates a `did:key` identifier from a freshly-generated key pair at test initialization. The gateway's DID resolver for `did:key` never touches the network. Tests are fast, deterministic, and offline-capable.

The limitation for production is obvious: `did:key` has no update path. If the corresponding private key is compromised, you can't rotate by updating a document somewhere. The DID and the key are permanently bound. For test fixtures this is fine; for production partner relationships it's not acceptable.

One design question that came up: should `did:key` be allowed in production partner registrations? Operationally, we treat `did:key` as a test/development shortcut and `did:web` / `did:ion` as production methods because they support rotation and hosted trust metadata. The current registry path does not enforce this with an `ALLOW_DID_KEY_PARTNERS` flag, so if you need a hard production policy you should enforce it in your deployment guardrails and onboarding process.

---

## Lessons for anyone building DID resolution

**Don't conflate the DID spec with the implementation ecosystem.** The W3C DID spec is well-defined. The `did:web` method spec is simpler than you'd expect. The hard part is that every implementation detail that the spec leaves open (redirect handling, cache-control headers, non-canonical JSON) is a potential source of interoperability friction. Test against multiple real partners early, not just your own test fixtures.

**Circuit breakers need careful thought in security contexts.** The canonical circuit breaker pattern (from Nygard's "Release It!") is designed for reliability in distributed systems. Applying it to a security-relevant path requires additional thought about whether circuit breaker state can be influenced by an adversary. The fault/non-fault split described above is the specific adaptation required when the "network dependency" is also an authentication step.

**Plan for key rotation from day one.** The two-eyes approval workflow for updating partner pins (post 13) was designed up front, but the tooling to make that workflow fast took longer than the circuit breaker. When a partner rotates their key, an operator needs to go through the two-eyes flow to update the pin. If that workflow takes 24 hours because of organizational process, partner tokens are broken for 24 hours. Make the rotation workflow as fast and low-friction as possible — the security property is the two-eyes requirement, not the length of time it takes.

**Air-gapped ION is a significant operational commitment.** If any of your customers are in air-gapped environments and want `did:ion` for their partner relationships, be ready to support a full ION sidecar deployment including the pruned Bitcoin node. If they can live with `did:web` plus pin attestation, that's a much simpler operational story. In practice, every air-gapped customer we've worked with has been satisfied with `did:web` + pin attestation. The Bitcoin-anchored immutability guarantee of `did:ion` is compelling theoretically but rarely drives the decision in a real deployment.

---

## What I monitor in production

After a few months running partner federation in production, this is the short list of signals I watch:

**Circuit breaker state changes.** Any transition from `closed` to `open` on a partner DID is an immediate-attention alert. A `half-open` to `open` transition (probe attempt failed during recovery) is also alert-worthy but lower urgency. The Prometheus gauge `euno_partner_did_circuit_breaker_state{did="...", state="open"}` == 1 is the primary alert condition.

**Pin mismatch count.** Any pin mismatch above zero in a 5-minute window is a security alert. This can be a legitimate partner key rotation (and they forgot to tell us to update the pin), or it can be an active substitution attack. Either way, someone needs to look at it immediately.

**Negative cache hit rate.** If the negative cache hit rate climbs for a specific partner DID, it means resolution is repeatedly failing. Combined with the circuit breaker state, this distinguishes between "circuit is open, all requests are hitting negative cache" (expected) and "circuit is closed but resolution is consistently failing" (unexpected, investigate).

**Key cache miss rate.** A sudden spike in cache misses for a specific DID (without a corresponding operator-initiated refresh) can indicate the positive cache is being exhausted somehow — either through very high traffic volume hitting the same DID from different tenants, or something else going wrong with the caching layer.

None of these signals require custom instrumentation if you already have the Prometheus gateway running. They're all dimensioned by DID, so you can see at a glance which partner is causing problems.

---

*Previous: [post 23 — Why OCSF? Choosing a schema for AI agent audit events](./23-why-ocsf.md). Next: [post 25 — KMS-backed JWT signing: trade-offs between Azure Key Vault, AWS KMS, and GCP Cloud KMS](./25-kms-backed-jwt-signing.md).*
