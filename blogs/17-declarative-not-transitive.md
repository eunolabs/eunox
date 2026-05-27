# Declarative, Not Transitive: The Partner Federation Trust Model

_Third post in the "Design principles" series. [Post 13](./13-partner-did-federation.md) in the architecture series covered the mechanics of partner DID federation: how DID documents are resolved, how the two-eyes approval workflow enforces separation of duties, how per-DID circuit breakers protect you from flaky resolution endpoints. This post is different — it's about the explicit design decision not to support transitive trust, and why that decision produces a significantly stronger security model than the alternative. See [`docs/blog-articles.md`](../blog-articles.md) for the full series index._

---

I've been in security architecture long enough to have watched the following pattern play out multiple times: a system starts with a small, carefully curated set of trust relationships. Each one is reviewed, approved, and documented. Over time, the set grows — new partners, new integrations, new contexts — and someone builds a feature that makes it easier to add trust relationships without going through the full review. Often this feature is called "delegation" or "inheritance" or "federated trust" and it sounds like pure convenience. More often than not, it becomes the most-exploited feature in the system.

The pattern is transitive trust. And it's why eunox's partner federation model explicitly doesn't support it.

---

## What transitive trust would look like

If eunox had transitive trust, the model would work like this: if Company A's gateway trusts Company B as a partner issuer, and Company B explicitly trusts Company C as _their_ partner, then Company A would automatically trust Company C without requiring a separate registration.

This has a certain logical appeal. It mirrors how web PKI works for domain certificates — if you trust a root CA, you automatically trust everything that root CA has signed. It mirrors how Kerberos works for Kerberos realms — realm A trusts realm B, realm B trusts realm C, and cross-realm tickets can traverse the path A → B → C.

Those systems have transitive trust because it solves a real scalability problem. If you're operating a public TLS infrastructure and you need every user's browser to trust every website's certificate, you need a hierarchy that doesn't require every user to explicitly approve every certificate issuer. The transitive chain through root CAs is the only practical solution at that scale.

Enterprise AI agent governance is not that problem.

---

## The trust graph in enterprise AI governance

In the partner federation scenario, the entities are organizations. Company A decides to allow AI agents from Company B to make tool calls against Company A's resources. This is a business relationship, not a technical convenience. The decision involves:

- Legal review (what data are we exposing to Company B's agents?)
- Security review (how does Company B manage their private keys? What's their incident response process?)
- Business review (is this relationship appropriate? Under what circumstances might it be revoked?)

That review process — the two-eyes approval workflow described in [post 13](./13-partner-did-federation.md) — is the correct human gate for this kind of trust decision. It exists because the consequences of getting it wrong are significant: you're authorizing external agents to call your internal tools.

With transitive trust, that review becomes a formality. Company A approves Company B. Company B approves Company C, Company D, Company E, and Company F — partners of their own that Company A has never heard of and certainly hasn't reviewed. Company A's gateway now accepts tokens from Company C through F, all on the strength of a decision that Company A made about Company B specifically.

The security property is broken. Company A can no longer answer "which organizations' agents can make tool calls on our gateway?" with a list they control. The answer is "Company B and everyone Company B has approved and everyone those entities have approved and..."

---

## Why this matters specifically for compromised partners

Let me make the threat concrete.

Suppose Company B's private signing key is compromised. An attacker now has the ability to mint tokens with `iss: "did:web:company-b.example.com"`. In the non-transitive model:

- Company A can revoke Company B's DID from its `PartnerDidRegistry` immediately
- The blast radius is limited to tokens with Company B's `iss`
- Company C, which is in Company A's registry under its own DID, is unaffected
- Company D, which Company A has never registered, could never present tokens that Company A's gateway would accept regardless of what Company B did

In a transitive model, Company B's compromised key gives the attacker the ability to mint tokens that pass _through_ Company B's trust relationship to reach Company A. The attacker can't directly mint tokens with Company B's key that claim Company C's `iss` — but they can create a token chain where a forged Company B token authorizes a Company C sub-token, if the system supports that kind of delegation.

More practically: if Company B can approve new partner DIDs and Company A inherits those approvals transitively, the attacker who controls Company B's key can register a new "Company G" DID (attacker-controlled), approve it as a Company B partner, and then have Company A's gateway accept tokens from Company G. The attack works entirely at the federation layer; no SQL injection, no network intrusion, no key compromise of Company A is required.

The non-transitive model simply doesn't have this attack path. Company A's gateway checks its own registry. Company G is not in it. Done.

---

## What declarative trust actually means

"Declarative" means the trust relationships are explicit, enumerable, and fully within the operator's control.

At any moment, an operator at Company A can call:

```
GET /admin/partner-dids
```

And receive the complete, current list of partner DIDs that Company A's gateway trusts. That list is the ground truth. Every entry was created through the two-eyes approval workflow (proposer + separate approver). Every entry has a timestamp, an audit record, and optionally a pinned DID document hash.

There's no hidden inheritance. There's no "also these DIDs because Company B approved them." The list is the list.

This property is valuable during security reviews and audits. An auditor asks: "Who can present capability tokens that your gateway will accept?" The answer is a list that fits on a page — the platform's own issuer DID, plus the explicitly registered partner DIDs. That's it. No transitive derivations to compute, no partner-of-partner graphs to enumerate, no "well it depends on what Company B has configured."

---

## The security properties of the non-transitive model

Let me enumerate the specific properties that the non-transitive design gives you:

**Explicit trust decisions.** Every trust relationship in the system was created by a human, through the two-eyes workflow, at a specific point in time. There are no implicit trust relationships that emerged from combining other relationships.

**Bounded blast radius.** A compromised partner affects only the tool calls that used that partner's tokens on your gateway. It cannot be leveraged to escalate to additional trust relationships you didn't create.

**Revocability without side effects.** Revoking a partner DID affects only that partner's ability to present tokens. It has no effect on other partners that may have independent trust relationships with either party.

**No transitive revocation cascades.** In a transitive trust system, revoking an intermediate trust anchor can invalidate all downstream relationships. In a non-transitive system, each relationship is independent and revocable independently.

**Auditability.** The complete trust graph is always explicit in the registry. You can enumerate it, audit it, and compare it against your approved partner list without needing to recursively traverse relationships.

---

## The pushback I hear

The most common pushback when I explain this model is: "But what if we have fifty partners? You're saying we have to go through the approval workflow fifty times?"

Yes. That's exactly what I'm saying.

The approval workflow is O(n) in the number of partnerships. That's intentional. Each partnership is a distinct trust decision. The cost of the workflow — two operators reviewing, proposing, and approving a specific partner DID — scales with the number of decisions you're making. That's the correct scaling behavior for a security-critical process.

Compare to a transitive model where you approve one "hub" partner and implicitly inherit trust for their entire partner network. That's O(1) work for you but it's also O(1) visibility — you've made one decision and inherited N consequences that you haven't reviewed. The work you didn't do doesn't disappear; it becomes implicit risk.

There's also a process observation: if your security team is telling you that fifty individual partner approvals is too much work and you should find a way to batch them, that's a signal that the approvals aren't getting the attention they deserve. The friction in the approval workflow is doing work. Remove the friction and you remove the attention.

---

## Hub-and-spoke without transitivity

There's a pattern that sometimes emerges in large deployments that looks like transitive trust but isn't: a central "identity hub" organization that acts as a common reference point.

Company A runs an identity hub. Companies B, C, D, E all register the hub as a partner DID. The hub issues tokens on behalf of each company (with those companies' DIDs as the `iss` claim via attenuation chains). Every company's gateway accepts tokens from the hub.

This looks like "Company A approves the hub, therefore Company A accepts tokens from B through E." But it's not transitive trust — it's direct trust with additional complexity. Each gateway that accepts hub tokens has explicitly registered the hub DID. Each company has deliberately chosen to trust the hub's issuance decisions. The hub is auditable and revocable by any company independently.

The difference from transitive trust: if Company B leaves the hub arrangement, Company A's gateway doesn't automatically stop accepting tokens with Company B's DID. Company A has to explicitly update its registry (revoke the hub DID if applicable, or add Company B's own DID if they've moved to direct federation). The trust state is always a function of what's in Company A's registry, not what any external party has decided.

This hub pattern is legitimate. It just requires each participant to explicitly register the hub and understand what they're trusting. No magic inference.

---

## Comparison with the SPIFFE/SVID model

If you've worked with cloud-native identity (particularly SPIFFE, the Secure Production Identity Framework For Everyone), you might recognize some of the same concerns about transitive trust.

SPIFFE's trust bundles are also explicit and non-transitive. If Service A's SPIFFE Verifiable Identity Document (SVID) is issued by SPIFFE Trust Domain `company-a.example.com`, and Service B's SVID is issued by `company-b.example.com`, then company A's workloads won't accept connections from company B unless company A has explicitly imported company B's CA bundle. There's no automatic trust derivation from "we both use SPIFFE."

The SPIFFE design principle here is the same as eunox's: **trust domains are explicitly federated, not implicitly derived**. The spec explicitly warns against transitive trust because it makes trust graphs non-auditable and creates implicit paths that don't correspond to intentional decisions.

Eunox's partner federation model follows the same logic applied to AI agent tokens rather than workload identity certificates. The technical mechanisms are different (DIDs instead of X.509 CA hierarchies, JWT tokens instead of mTLS), but the structural principle is identical: explicit, auditable, non-transitive.

---

## What happens when you need to revoke a partner

One thing the non-transitive model makes much simpler: revoking a partner relationship.

In a transitive trust system, revoking a trust relationship might cascade to relationships you didn't intend to affect. If Company A revokes its trust in Company B, and Company B was the transitive trust anchor for Companies C and D, then Companies C and D's relationships are also affected — even if you intended to only revoke Company B.

In the non-transitive model, revocation is surgical:

```
DELETE /admin/partner-dids/did:web:company-b.example.com
X-Admin-Api-Key: <key>
X-Admin-Operator: <operator-identity>
```

This revokes Company B's DID from Company A's registry. Company C and Company D, which have their own separate entries in the registry, are unaffected. The security team can take exactly the action they intend without worrying about collateral effects.

The audit log records the revocation with a `PARTNER_DID_REVOKED` event. The audit trail for the period after revocation will show rejections for tokens with `iss: "did:web:company-b.example.com"` — clear evidence that the revocation took effect. Company C and D's tokens continue to be accepted — also clearly visible in the audit trail.

This is the kind of clean incident response narrative that security teams need to present to regulators: "At time T, we revoked trust for Company B. Here is the audit evidence showing no tokens from Company B were accepted after that time. Here is the evidence showing that Company C and D were not affected."

---

## The `did:key` development exception revisited

[Post 13](./13-partner-did-federation.md) mentioned `did:key` as a DID method that's suitable for development and testing but not production partner federation. I want to add a relevant note here: `did:key` also doesn't have a useful notion of federation at all, which is another reason it's only for development.

A `did:key` DID is self-describing — the public key is encoded directly in the DID string. There's no resolution required, no DID document hosted anywhere. This means there's no mechanism for "Company B's `did:key` trusts Company C" — `did:key` doesn't have that concept. It's just a bare key.

For production partner federation, the registered DIDs are `did:web` or `did:ion` because those methods have resolvable documents that can carry metadata and can be updated in a controlled way. The pin attestation mechanism (from [post 13](./13-partner-did-federation.md)) provides change detection on top of `did:web`'s mutability. The ION blockchain anchoring provides immutability for `did:ion`.

Neither of these methods supports anything resembling transitive trust at the protocol level. The explicit-registry model in eunox is consistent with the design of the DID methods it uses.

---

## Looking at the graph from the other direction

I've been describing this from Company A's perspective (the gateway operator deciding what to trust). Let me briefly consider Company B's perspective (the partner whose tokens are being presented).

Company B's tokens are accepted by exactly the gateways that have explicitly registered Company B's DID. Company B doesn't have a way to "add themselves" to additional gateways — that requires an action on the gateway side. Company B doesn't benefit from their own federation relationships for purposes of accessing Company A's resources.

This is also a security property. In a transitive trust model, Company B could potentially expand its access to Company A's resources by creating a trust relationship with Company C, if Company A happens to trust Company C and the transitive chain applies. In the non-transitive model, Company A's access grants are entirely under Company A's control. Company B cannot manipulate them.

The principle: **a party cannot extend their own access by manipulating the trust graph**. Access can only be granted by the resource owner making an explicit, reviewed decision.

---

## Consistency with the fail-closed principle

The non-transitive model is also consistent with the fail-closed principle from [post 15](./15-fail-closed-not-fail-open.md). "Not recognized" in the trust registry means "denied." There is no "maybe this is a transitive trust path I should evaluate" branch. The lookup either succeeds (DID is in the registry) or it fails (DID is not in the registry, deny).

The code path is direct:

```go
entry, ok := registry.Get(issClaim)
if !ok || !registry.IsApproved(issClaim) {
    return enforcement.DenyResult("partner_did_not_registered")
}
_ = entry
```

No graph traversal, no transitive lookup, no "check if any registered DID trusts this one." The registry is a flat map from DID string to registration record. If the DID isn't a key in that map, the token is rejected.

This simplicity is a security feature. Complex logic is where bugs hide. The trust check is as simple as a hash map lookup. The simplicity is part of why the implementation is correct and why it's easy to audit.

---

## The question I keep coming back to

When I'm evaluating security architecture decisions, the question I keep coming back to is: "In five years, when something goes wrong, will we be able to explain clearly what happened and show that our controls worked as intended?"

With non-transitive, explicitly-declared partner trust, the answer to that question is yes. The registry is the complete record of trust decisions. Every entry was created through the approval workflow and is in the audit log. Every token acceptance is verifiable against the registry. If a trust relationship needs to be revoked, the registry update is the single correct action and its effect is bounded and verifiable.

With transitive trust, the answer to that question is much harder. You'd need to explain which transitive path the attacker exploited, which intermediate trust anchor allowed them through, and why the trust chain led to Company A accepting tokens from an entity they never approved. That's a much harder conversation to have with a regulator who wants to understand your access controls.

The boring answer — explicit list, manual approval, no inheritance — is the answer that ages well.

---

_Previous: [post 16 — Schema parity over version drift: keeping the YAML format honest](./16-schema-parity-over-version-drift.md). Next: [post 18 — Defense-in-depth for SQL injection through an LLM](./18-defense-in-depth-sql-injection.md). See [`docs/blog-articles.md`](../blog-articles.md) for the full series index._
