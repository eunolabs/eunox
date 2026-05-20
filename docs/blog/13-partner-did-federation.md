# Partner DID Federation: Cross-Org Trust Without Shared Secrets

*Part of the "Architecture deep-dives" series. [Post 12](./12-pluggable-adapters.md) covered the pluggable identity and signing adapters. This post goes into the cross-organization federation scenario — what happens when the agent presenting a capability token was issued by a *different* organization's issuer, not your own.*

---

Here's a scenario that comes up in enterprise accounts more often than I expected: two companies want their AI agents to collaborate. Company A runs its own euno capability issuer. Company B runs its own. An agent from Company B needs to make tool calls against a resource that Company A's gateway protects. How does Company A's gateway trust Company B's tokens?

The naive answer is: exchange API keys. Give Company B a credential that Company A's gateway accepts. This works for a pilot. It falls apart at scale — key rotation becomes a coordination problem, a compromised key at Company B is Company A's problem too, and the blast radius of any single leaked credential spans both organizations.

The right answer is: use W3C Decentralized Identifiers. Each organization's issuer has a DID that resolves to a DID document containing their public key. Company A's gateway verifies tokens from Company B by resolving Company B's DID, fetching their public key, and checking the JWT signature. No shared secrets. No key distribution problem. Rotation happens by updating the DID document; the gateway fetches the new key on the next resolution cycle.

That's the theory. The practice involves several layers that are worth explaining carefully.

---

## What a DID actually is

If you haven't worked with W3C DIDs before, the concept is simpler than the spec documents make it appear. A DID is a URI that looks like this:

```
did:web:partner.example.com
```

or:

```
did:ion:EiDPx5LKpLf...
```

The `did:web` method means: resolve this identifier by fetching `https://partner.example.com/.well-known/did.json`. That URL returns a **DID document** — a JSON object that contains, among other things, a `verificationMethod` array listing the public keys associated with this DID. When the gateway sees a JWT with `iss: "did:web:partner.example.com"`, it resolves the DID, extracts the appropriate public key, and verifies the JWT signature.

The `did:ion` method is different. Instead of DNS-based resolution, `did:ion` uses the ION network — a Sidetree-based DID implementation anchored to the Bitcoin blockchain. Resolution requires either a public ION node or a locally-run ION node (important for air-gapped deployments — more on that in the deployment docs). The security properties are different from `did:web`: ION identifiers are content-addressed and immutable, so a domain hijack can't substitute a fraudulent DID document. The trade-off is resolution latency and the operational dependency on an ION node.

We support both, and most enterprise customers start with `did:web` (simpler, faster, no infrastructure dependency) before considering `did:ion` for their highest-sensitivity federation relationships.

---

## The two-eyes approval workflow

Even if the cryptography is correct, you don't want a single operator to be able to unilaterally add a partner DID to the trust registry. A compromised admin account, a social engineering attack, or just a mistake should not result in an untrusted organization's tokens being silently accepted.

The partner DID registration workflow requires two operators — a proposer and a separate approver. This is enforced in the code, not just documented as a policy:

```
POST /admin/partner-dids/proposals
X-Admin-Api-Key: <key>
X-Admin-Operator: alice@example.com
Body: { "did": "did:web:partner.example.com" }
```

This creates the proposal but does *not* activate it. A different operator (different identity from `alice@example.com`) must then approve:

```
POST /admin/partner-dids/proposals/did:web:partner.example.com/approve
X-Admin-Api-Key: <key>
X-Admin-Operator: bob@example.com
```

If `bob` and `alice` are the same identity, the approval throws `TwoEyesViolationError`. The `approver !== entry.proposer` check is in the `PartnerDidRegistry` implementation and has its own test coverage. This isn't a "nice to have" — it's the minimum separation of duties that enterprise security teams require for external trust decisions.

The audit log emits a `PARTNER_DID_APPROVED` or `PARTNER_DID_REVOKED` event (OCSF `class_uid: 3003`, Authorization) for every registry change. Any modification outside a change-management window should trigger an operator alert.

---

## Pin attestation: locking the DID document

Here's the threat model for `did:web` that keeps me up at night: what happens if Company B's domain gets hijacked?

If an attacker takes over `partner.example.com`, they can host a different `did.json` file containing their own public key. The gateway's DID resolution would fetch this fraudulent document, extract the attacker's key, and start accepting tokens the attacker minted. From the gateway's perspective, the `iss` is still `did:web:partner.example.com` and the signature is valid.

Pin attestation addresses this. At proposal time, the gateway fetches the current DID document and computes `pinnedDocSha256 = jcsSha256(didDocument)` — a SHA-256 hash of the DID document in its JCS (JSON Canonicalization Scheme) serialized form. This hash is stored in the `PartnerDidEntry`.

On every subsequent DID resolution, the gateway checks whether the fetched DID document's hash matches the pinned hash. If it doesn't match — because the domain was hijacked, the certificate was replaced, or someone modified the document — the resolution fails with an authentication error. The circuit breaker opens (more on that below). An alert fires.

The pin is not automatically updated. If Company B legitimately rotates their key and updates their DID document, their DID document hash will change, and partner tokens will stop working until an operator updates the pin through the two-eyes approval workflow. This is intentional. An automatic pin update would defeat the protection — you'd be back to "trust whatever the domain serves," which is the threat model we're trying to address.

Pin attestation is **mandatory for production partner registrations**. Development and test registrations can omit it, but the gateway logs a warning on every resolution for an unpinned partner DID.

---

## Per-DID circuit breakers

DID resolution involves a network call — fetching the `did.json` over HTTPS, or querying an ION node. Like any network call, it can fail. An upstream partner's server might be slow, their DNS might have a TTL anomaly, the ION node might be unreachable. None of these failure modes should cause euno's gateway to start accepting everything (fail-open) or rejecting everything (fail-closed gateway for all tenants).

The solution is a per-DID circuit breaker. Each partner DID has its own circuit breaker state (`closed`, `open`, `half-open`) tracked independently. When a DID resolution fails:

- If the failure looks like a **fault** (network timeout, DNS failure, HTTP 5xx from the DID hosting server) — it counts against the circuit breaker failure threshold. After `PARTNER_DID_CB_FAILURE_THRESHOLD` failures within `PARTNER_DID_CB_WINDOW_MS`, the circuit opens. While open, resolution fails immediately without a network call, and tokens with that `iss` are rejected.

- If the failure looks like a **non-fault error** (signature verification failed, pin mismatch, malformed DID document) — it does *not* count against the circuit breaker. This is a deliberate design choice.

That second rule is important, so let me explain the reasoning. A signature verification failure means the DID document resolved successfully but the token's signature is invalid. That's not a flaky network — that's either a legitimate rejection or an active attack. Tripping the circuit breaker on signature failures would let an attacker knock out a partner's token acceptance by sending a stream of malformed tokens. The circuit breaker is a reliability mechanism against infrastructure instability, not a rate limiter for bad tokens.

The circuit breaker state is exported as a Prometheus gauge:

```
euno_partner_did_circuit_breaker_state{did="did:web:partner.example.com", state="closed"} 1
euno_partner_did_circuit_breaker_state{did="did:web:partner.example.com", state="open"} 0
```

An alert on `state="open"` persisting for more than one minute is a reasonable starting threshold. You want to know about it; you also don't want to page someone for a transient blip that the circuit breaker recovers from on its own.

---

## Caching and the positive key cache

DID resolution on every token verification would add 50-200ms of latency per tool call, depending on whether the DID is `did:web` (an HTTPS fetch) or `did:ion` (an ION node query). That's not acceptable in the enforcement hot path.

The gateway maintains a positive key cache: once a DID document is successfully resolved and its public key extracted, the key is cached for `PARTNER_DID_CACHE_TTL_SECONDS` (default 5 minutes). Subsequent token verifications for the same `iss` use the cached key without a network call.

The cache TTL is the gap between "partner rotates their key" and "gateway starts using the new key." In practice this means: after a partner rotates, it takes up to 5 minutes before their new tokens are accepted by all gateway instances. This is the same trade-off you see in any JWKS key caching setup — the `max-age` on a JWKS endpoint creates an identical window. 5 minutes is a reasonable default for most federation scenarios.

During an incident (suspected key compromise), an operator can flush the positive key cache for a specific partner immediately:

```
POST /admin/partner-dids/did:web:partner.example.com/refresh
X-Admin-Api-Key: <key>
X-Admin-Operator: <operator-identity>
```

This forces a fresh resolution on the next token verification for that partner. Combined with the revocation path (below), it gives operators a fast-path for compromised partner situations.

---

## What happens when a partner key is compromised

This is the scenario that comes up in every security review, and it's worth walking through explicitly.

Suppose Company B's private signing key is compromised. An attacker can now mint tokens with `iss: "did:web:company-b.example.com"` and a valid signature. Those tokens will be accepted by Company A's gateway until:

1. Company B rotates their key and updates their DID document.
2. Company A's gateway flushes its positive key cache (either naturally after 5 minutes, or immediately via the refresh endpoint).
3. Any in-flight sessions whose tokens were issued before the compromise expire. Tokens have a maximum TTL enforced by the gateway; the default is 15 minutes.

The audit trail tells you exactly which sessions were active during the compromise window — filter by `iss = "did:web:company-b.example.com"` and the time range. If you have specific `jti` values for tokens you know were forged, you can add them to the revocation list immediately:

```
POST /admin/revoke
X-Admin-Api-Key: <key>
Body: { "jti": "jti_of_forged_token", "tenantId": "..." }
```

The blast radius of a partner key compromise is bounded to tokens with that `iss`. Platform-issued tokens (signed by the platform's own KMS key) are unaffected. Other partners are unaffected. The two-tier architecture — platform issuer for first-party tokens, partner DID federation for cross-org tokens — provides meaningful isolation.

---

## `did:web` vs `did:ion` in production

I've seen both deployed in production at this point. The practical differences:

**`did:web`** is simpler to set up and maintain. If you already have a domain and TLS, you're hosting a JSON file. Key rotation is a matter of updating the file and (if using pin attestation) going through the two-eyes workflow to update the pin. The dependency is on your domain's HTTPS availability — which, for any reasonable company, is high.

The risk with `did:web` is domain-level attacks: domain hijacking, fraudulent TLS certificates from a compromised CA. Pin attestation mitigates this substantially. For partners you trust and have a relationship with, and where you're monitoring the Prometheus circuit breaker and audit alerts, `did:web` is pragmatic.

**`did:ion`** is stronger because the DID document history is anchored on Bitcoin. Domain hijacking doesn't help an attacker because the DID document content is cryptographically committed in the chain. The downside is the ION infrastructure dependency. In air-gapped deployments, you need to run a bundled ION sidecar; the hosted Microsoft ION resolver is publicly accessible but adds a network dependency on a third party.

My recommendation: start with `did:web`, add pin attestation, set up the circuit breaker alerts, and revisit `did:ion` if your risk model requires it. Most enterprise federation relationships don't need the stronger model; the combination of HTTPS + pin attestation + two-eyes approval + circuit breaker + audit trail is sufficient for SOC 2 and most security team sign-offs.

---

## Revocation

Partner DID entries can be revoked at any time by an operator:

```
DELETE /admin/partner-dids/did:web:partner.example.com
X-Admin-Api-Key: <key>
X-Admin-Operator: <operator-identity>
```

A revoked entry fails the trust check immediately — before any key cache lookup. New tokens with the revoked `iss` are rejected without a network call. In-flight sessions continue until their tokens expire (the stateless JWT model doesn't allow retroactive invalidation without adding the specific JTIs to the revocation list, which is always an option for tokens whose identifiers appear in the audit log).

The audit event for a revocation fires a `PARTNER_DID_REVOKED` record in the OCSF Authorization class. Combined with the Prometheus alert on circuit breaker state changes, this gives operators two independent signals when a partner relationship transitions.

---

## The non-goal: transitive trust

One design decision I want to be explicit about, because it's occasionally pushed back on: euno's partner federation model does not support transitive trust.

If Company A trusts Company B, and Company B trusts Company C, that does *not* mean Company A's gateway trusts Company C. Company C must be explicitly registered in Company A's `PartnerDidRegistry` through the two-eyes workflow. There is no automatic inference of trust.

This is intentional and it has a clear security property: the set of trusted issuers is always explicit, auditable, and requires deliberate human action to expand. There is no path by which an attacker who compromises a trusted partner can use that relationship to bootstrap trust for an additional entity. See [post 17 in this series](../blog-articles.md#design-principles) for a longer treatment of why declarative-not-transitive is the right model for cross-org AI agent governance.

---

## A note on `did:key` for development

There's a third DID method we support: `did:key`. These are self-describing DIDs where the public key is encoded directly in the identifier — no resolution required. They look like `did:key:z6Mk...` and are created locally from a key pair.

`did:key` is not suitable for production partner federation (no resolution means no update path if the key is compromised), but it's extremely useful for development and testing. The `partner-issuer-sim` test fixture uses `did:key` to produce tokens that the gateway can verify without any external network call, which makes integration tests fast, deterministic, and offline-capable.

---

*Previous: [post 12 — Pluggable adapters: building a cloud-portable identity and signing layer](./12-pluggable-adapters.md). Next: [post 14 — AGT: defense in depth inside the agent process](./14-agt-defense-in-depth.md).*
