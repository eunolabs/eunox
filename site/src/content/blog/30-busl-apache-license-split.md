---
title: "The BUSL / Apache split: open-source AI security with a sustainable license model"
description: "developers evaluating euno for integration or deployment, and anyone curious about how AI infrastructure companies think about licensing"
pubDate: "2026-06-18"
---

*Audience: developers evaluating euno for integration or deployment, and anyone curious about how AI infrastructure companies think about licensing*

---

Licensing is one of those topics that developers historically avoided until it became unavoidable. Then HashiCorp relicensed Terraform. Redis changed its license. Elasticsearch sued Amazon. Suddenly everyone started reading the license file.

If you've looked at euno's repository structure and noticed that parts of the codebase are Apache 2.0 and other parts are BUSL-1.1, you might have questions. What does the split mean? What can you do with each part? Why did we structure it this way? And what does "non-competing use" actually mean in practice?

This post is the honest answer to those questions. I'll explain the decision, the Go monorepo architecture it created, what you can and can't do under each license, and why I think this model is actually better for the ecosystem than the alternatives.

---

## Where this decision came from

Every infrastructure company building AI tooling is facing the same tension right now. On one side: open source wins adoption. Developers trust open-source software more. They can audit it, contribute to it, fork it if they disagree with the direction, and build on it without being locked into a vendor relationship. For a security product in particular — something that sits in front of sensitive tools and makes access control decisions — open source is almost a prerequisite for trust. You can't ask people to trust your policy engine if they can't read it.

On the other side: open core companies that publish everything under a permissive license regularly discover that cloud providers will package their software as a managed service, charge for it, and out-compete the original company at enterprise scale without contributing back. This has happened enough times now that it's not theoretical. It's a documented pattern with a name.

The BUSL (Business Source License) was designed by MariaDB as a response to this specific problem. The idea: the software is available, readable, modifiable, and self-hostable. But you can't offer it as a commercial managed service to third parties — the "production use restriction" — without a commercial licence, until a specified time after each release, at which point it converts to open source anyway.

BUSL is not open source by the OSI definition. I want to be clear about that. It has restrictions that OSI-compliant licenses don't have. But for many use cases — self-hosting, development, research, internal deployment — it behaves exactly like open source. The restriction is narrow and targeted: it specifically prevents hosted-service competition.

The choice of BUSL for the platform components wasn't made lightly. We went back and forth on it. But the thing that resolved it was thinking about what happens to the project if we can't sustain it financially. An euno that isn't maintained, can't hire the people to advance it, and eventually stops responding to security issues is worse for users and the ecosystem than an euno with a license that prevents someone from undercutting us on managed hosting.

---

## The Go monorepo architecture

The license split is reflected directly in the repository structure, but it now shows up as a Go monorepo rather than two top-level folders. The repository is BUSL-1.1 overall, with the `eunox-mcp` OSS tier and public contracts surfaced through `pkg/`. The three relevant top-level directories are:

```
cmd/        ← service entrypoints
internal/   ← private application code
pkg/        ← public Go packages
```

The hosted services live under `cmd/` and `internal/`: the gateway, issuer, minter, DB token service, storage grant service, posture emitter, and the rest of the private platform implementation.

The public contracts live in `pkg/`. That's where the shared capability, policy, crypto, audit, and related Go packages live.

And the developer-facing OSS tier is the `eunox-mcp` binary — the local enforcement client you run alongside your agent. The split is no longer "everything in `public/` versus everything in `eunox/`"; it's "public contracts and the OSS local client versus the hosted platform services."

---

## Why the core types must be open

The most important decision in the whole licensing structure is this: the shared `pkg/` Go packages are Apache 2.0.

These packages contain the types that define the capability manifest schema — `AgentCapabilityManifest`, `Capability`, `Condition`, the condition interfaces, the OCSF event types. These are the contract between agents, policies, and enforcement. If you're building an AI agent that consumes capability tokens, or a policy authoring tool, or a SIEM integration, or a third-party gateway, you need these types.

If those shared `pkg/` packages were BUSL, the entire ecosystem would be hamstrung. Every tool that needed to parse a capability manifest would need either a BUSL commercial license or would have to reverse-engineer the schema from documentation. That's a terrible outcome for interoperability, and it would mean euno becomes the only entity that can build things that understand euno policies. That's not a healthy ecosystem, and it would kill adoption.

The Apache 2.0 license on the shared packages means:
- Any developer can import the shared `pkg/` Go packages in their agent code with no restrictions
- Third parties can build compatible policy authoring tools that understand the manifest format
- Academic researchers can work with the schema for analysis and experimentation
- Organisations can build their own enforcement implementations if they choose — the contract is public and reusable

The [schema parity post](../docs/blog/16-schema-parity-over-version-drift.md) explains the design decision to keep `eunox-mcp`, the Go runtime SDK, and the gateway all sharing a single type definition. The Apache license on that shared type is what makes that ecosystem property durable.

---

## What BUSL actually restricts

Let me be specific about what BUSL-1.1 prohibits, because the vague term "competing use" generates a lot of uncertainty.

The BUSL production use grant reads (paraphrased): you may use this software for production purposes as long as you are not offering a commercial product or service to third parties where the substantial value is derived from this software.

What this prohibits:
- Running euno's gateway, capability issuer, or minter as a hosted service and charging customers for access to it
- Packaging euno's platform components as a managed product that you sell to enterprises
- Integrating the BUSL components into a competing hosted AI governance platform

What this does NOT prohibit:
- Deploying euno in your own organisation's infrastructure to govern your own AI agents
- Self-hosting the complete stack on-premises or in your own cloud account
- Using euno to build your own AI products and services (the governance is for your use)
- Contributing to the codebase (PRs welcome)
- Forking for research, evaluation, or testing
- Reading and studying the source code

The practical summary: if you're deploying euno to govern AI agents in your organisation, you're fine under BUSL. If you're AWS and you want to offer "Amazon Euno Gateway" as a managed service to your customers, you need a commercial license.

The "additional use grant" section of the BUSL file in this repository spells out the permitted production use explicitly. Read it — it's short, and it's written to be understood by engineers, not just lawyers.

---

## The conversion timeline

Every BUSL-licensed release specifies a conversion date — the date on which that version of the software automatically becomes Apache 2.0. For euno, the conversion period is four years from each release.

This matters for a few reasons.

First, it means BUSL is not a permanent restriction. Version 1.14.2 of the tool gateway, released today, will be Apache 2.0 in 2030. If euno hypothetically ceased to exist as a company, the software would eventually convert to open source, and anyone could fork and continue it. The community is not permanently locked out.

Second, it means the restriction is calibrated to a reasonable product lifecycle. Four years is long enough that a release is still commercially current by conversion. We're not releasing code that immediately becomes freely distributable as a managed service before we've had any commercial runway from it.

Third, it creates a natural archive of the evolution of the platform. The 2028 versions of euno's gateway will include the 2024 code under open source terms. Researchers and developers who want to understand the design history will have full access.

---

## The `eunox-mcp` binary and what you can do with it

The `eunox-mcp` binary — the OSS local enforcement client you run alongside your agent — is Apache 2.0. Full stop. You can:

- Install it in any application, commercial or not
- Redistribute it in a product you sell
- Modify it and ship the modified version
- Build closed-source products on top of it

This is deliberate. The local enforcement client is the thing that developers install alongside their applications. If there were any license friction at the developer integration layer, adoption would drop off a cliff. The whole point of `eunox-mcp` is to be a zero-friction drop-in. Apache 2.0 is the right license for that.

The commercial restriction only applies to the platform components — the services that operators run to support the hosted governance model. An organisation that self-hosts the gateway for their own use is fine. A company that packages the gateway as a product they sell to others needs the commercial license.

---

## The Go runtime SDK and future adapter situation

The same Apache 2.0 logic applies to the Go runtime SDK and any adapters we publish for specific agent frameworks. The runtime SDK, the upcoming framework-specific adapters, any future integrations — all Apache 2.0. Adapters are developer-facing integration code. They should be unrestricted.

When building on these adapters: you can include them in your commercial product, you can modify them, you can fork them. If you're integrating them with the hosted gateway, the gateway's BUSL terms apply to the gateway service, not to the adapter code itself.

---

## The trust argument for open licensing of the enforcement core

There's a security-specific reason why the `eunox-mcp` binary should be open source, and it goes beyond the commercial adoption argument.

`eunox-mcp` is a security enforcement client. It evaluates policy conditions, makes allow/deny decisions, and writes audit records. These are exactly the kinds of operations where you want an auditable, inspectable codebase.

When an organisation deploys `eunox-mcp` in a sensitive production system, their security team should be able to read the enforcement code and verify that it does what we claim it does. "Trust our documentation" is not a sufficient answer for a security control. "Read the code" is. Apache 2.0 ensures they can always do this, without needing a commercial relationship.

This also applies to security researchers. Responsible disclosure requires that researchers can study the code, find vulnerabilities, and report them. A researcher who discovers a bypass in the condition evaluation logic needs to be able to read the code to understand and document the bypass clearly. Open source enables this.

The BUSL-licensed platform components don't get quite the same benefit — they're also readable (BUSL permits reading and evaluation), but they can't be freely distributed as-is. For the server-side enforcement code, we've decided that readability and self-deployability is the priority, and the commercial restriction is acceptable given that the server is primarily relevant for organisations with the infrastructure to run it.

---

## Practical questions developers ask

**Can I use euno in my startup's product?**

Yes. Install `eunox-mcp` (Apache 2.0) alongside your agent code. Self-host the gateway stack using the BUSL-licensed platform (you're deploying it for your own use, not selling it as a service to others). Build your product. No license issue.

**Can I build a consultancy offering that deploys and operates euno for clients?**

This is a nuanced case. If you're deploying euno on a client's own infrastructure, within their own account, as an implementation service, that's generally fine — you're deploying for them, not offering euno as a service. If you're running the infrastructure yourself and billing clients for API access to it, that's the hosted-service restriction and requires a commercial license. When in doubt, reach out — the commercial license is designed for this case.

**Can I fork the BUSL code and modify it for internal use?**

Yes. You can fork, modify, and deploy modified versions for your own organisation's use. The production use restriction applies to external commercial offering, not internal deployment. Keep the BUSL license notices and conversion dates intact.

**What happens to my deployment when a BUSL-licensed version converts to Apache 2.0?**

Nothing changes practically. You were already licensed to self-host it. The conversion just removes the commercial restriction, so at that point someone else could also offer it as a managed service under Apache 2.0 terms. Your existing deployment continues under whatever license was in effect when you deployed it, or you can choose to operate it under the new Apache terms after conversion.

**Can I contribute code to the BUSL parts?**

Yes, through the standard PR process. Contributions to the platform components are welcome. The repository does not currently include a separate `CONTRIBUTING.md` or CLA file; contributions are governed by the existing license terms in `LICENSE`, including the standard contribution clause there.

---

## What we'd do differently

The main thing I'd reconsider is the communication around this. BUSL is genuinely less well-understood than MIT or Apache, and the first reaction many developers have to "BUSL-1.1" is wariness, even when their actual use case is completely unaffected by the restriction.

We've tried to address this with clear documentation — the `LICENSE` file has the permitted use grant spelled out, and this blog post is an attempt to explain the reasoning — but there's a certain amount of friction that just comes from "not MIT" in an industry that's been trained to expect MIT.

If I were doing it again, I'd probably also publish a "License FAQ" document in the repo root that answers the common deployment scenarios explicitly (is my use case covered?), because the abstract language of license documents creates uncertainty that concrete Q&A can resolve.

The underlying decision — Apache for the types and client, BUSL for the platform — I still think is right. The alternative, pure open source with no commercial restriction, would mean any well-capitalised cloud provider could package our platform as a managed service tomorrow, and the investment we've made in security architecture, compliance features, and enterprise deployment support would essentially become a free R&D service for them. That's not sustainable, and an unsustainable security infrastructure project is bad for everyone who depends on it.

---

## The broader context

The license debate in infrastructure software isn't going away. There are now multiple BUSL-licensed projects (HashiCorp's tools, parts of Elasticsearch's codebase), multiple projects that tried pure open source and changed (Redis, Confluent), and multiple projects that chose a different model entirely (Grafana, which went AGPL for some components).

Each of these represents a different answer to the same question: how do you build financially sustainable open infrastructure without either closing it entirely or watching it get captured by hyperscalers?

BUSL is one answer. It's not the only answer, and it's not universally correct. For euno, given the specific risk (a well-resourced entity offering our governance platform as a managed service that competes directly with our hosted offering) and the specific requirement (the enforcement client must be genuinely open for developer trust and security auditing), the split model makes sense.

As the AI agent governance space matures and more organisations need this infrastructure, we'll revisit the model. If the BUSL restriction is preventing legitimate adoption, we'll know from the questions we're getting. If the conversion timeline needs to move, we can adjust. Licenses aren't eternal commitments — they're decisions made in context, subject to revision as context changes.

For now, the principle is straightforward: the contract is open, the client is open, and the platform is source-available with a commercial hosting restriction. Developers get the auditing and trust properties they need. The company gets the commercial protection it needs to continue investing in the platform. Users get a security infrastructure that's funded to be maintained and improved.

That's the deal. I think it's a fair one.
