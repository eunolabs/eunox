---
title: "Apache 2.0 + BUSL-1.1: a dual-license strategy for open-source AI security"
description: "How and why eunox splits cmd/mcp under Apache 2.0 (free tier, no restrictions) and the platform under BUSL-1.1 — and what each license means for your deployment."
pubDate: "2026-06-18"
---

_Audience: developers evaluating eunox for integration or deployment, and anyone curious about how AI infrastructure companies think about licensing_

---

Licensing is one of those topics that developers historically avoided until it became unavoidable. Then HashiCorp relicensed Terraform. Redis changed its license. Elasticsearch sued Amazon. Suddenly everyone started reading the license file.

If you've looked at eunox's repository, you'll notice two licenses. `cmd/mcp/` — the `eunox-mcp` local enforcement proxy — is **Apache 2.0**. The rest of the platform — the gateway, issuer, minter, and shared packages — is **BUSL-1.1**. This post explains the reasoning, what each license covers, and what it means for your use case.

---

## Where this decision came from

Every infrastructure company building AI tooling is facing the same tension right now. On one side: open source wins adoption. Developers trust open-source software more. They can audit it, contribute to it, fork it if they disagree with the direction, and build on it without being locked into a vendor relationship. For a security product in particular — something that sits in front of sensitive tools and makes access control decisions — open source is almost a prerequisite for trust. You can't ask people to trust your policy engine if they can't read it.

On the other side: open core companies that publish everything under a permissive license regularly discover that cloud providers will package their software as a managed service, charge for it, and out-compete the original company at enterprise scale without contributing back. This has happened enough times now that it's not theoretical. It's a documented pattern with a name.

The dual-license model is our answer to this tension. `eunox-mcp` is fully open — Apache 2.0, no restrictions, use it however you want. The platform services that require significant infrastructure investment to operate are BUSL-1.1. Developers get the open-source tool they need to evaluate, trust, and adopt. The company gets the commercial protection it needs to sustain investment in the platform.

---

## The repository structure

The repository is a Go monorepo. The license split maps directly to directory boundaries:

```
cmd/
  mcp/          ← Apache 2.0 (eunox-mcp binary — the free tier)
  gateway/      ← BUSL-1.1
  issuer/       ← BUSL-1.1
  minter/       ← BUSL-1.1
  db-token-svc/ ← BUSL-1.1
  ...
internal/       ← BUSL-1.1
pkg/            ← BUSL-1.1
```

`cmd/mcp/` has its own `LICENSE` file containing the full Apache 2.0 text. All other files carry a `SPDX-License-Identifier: BUSL-1.1` header. The `cmd/mcp/` files carry `SPDX-License-Identifier: Apache-2.0`.

---

## Why `eunox-mcp` is the free tier

`eunox-mcp` is the component most developers interact with first. It's a local enforcement proxy that wraps any MCP server and enforces your policy YAML before tool calls reach the upstream. No server. No sign-up. No cloud account. One binary, runs on your machine.

Making this Apache 2.0 is a deliberate decision to lower the adoption barrier to zero. There is no license friction, no "what does BUSL mean for my use case" conversation, no question about whether embedding it in your product is allowed. Apache 2.0 means yes, unambiguously, to all of those questions.

The adoption argument is also a trust argument. `eunox-mcp` is a security enforcement client — it evaluates policy conditions, makes allow/deny decisions, and writes audit records. Security teams and developers evaluating it need to be able to read, audit, and verify the code. Apache 2.0 guarantees that with no caveats. You can fork it, modify it, redistribute it, include it in commercial products — all of it, without restriction.

---

## What BUSL-1.1 covers and what it restricts

The platform components — gateway, issuer, minter, shared `pkg/` packages, and all other services — are BUSL-1.1.

BUSL is not open source by the OSI definition. I want to be clear about that. It has restrictions that OSI-compliant licenses don't have. But for many use cases — self-hosting, development, research, internal deployment — it behaves exactly like open source. The restriction is narrow and targeted: it specifically prevents **hosting the platform as a commercial managed service to third parties** without a commercial license.

**What BUSL-1.1 prohibits:**

- Running eunox's gateway, capability issuer, or minter as a hosted service and charging customers for access to it
- Packaging eunox's platform components as a managed product you sell to enterprises
- Integrating the BUSL components into a competing hosted AI governance platform

**What BUSL-1.1 does NOT prohibit:**

- Deploying eunox in your own organisation's infrastructure to govern your own AI agents
- Self-hosting the complete stack on-premises or in your own cloud account
- Using eunox to build your own AI products and services (the governance is for your use)
- Contributing to the codebase (PRs welcome)
- Forking for research, evaluation, or testing
- Reading and studying the source code

The practical summary: if you're deploying eunox to govern AI agents in your organisation, you're fine under BUSL. If you're AWS and you want to offer "Amazon Eunox Gateway" as a managed service to your customers, you need a commercial license.

---

## The `eunox-mcp` binary and what you can do with it

`eunox-mcp` is Apache 2.0. Full stop. You can:

- Install it and run it anywhere, for any purpose
- Embed it in your own applications and redistribute it
- Modify and fork it — for internal use or for distribution
- Include it in commercial products without restriction
- Study and audit the source code

There are no restrictions. Apache 2.0 is one of the most permissive licenses in existence.

The one thing Apache 2.0 requires: preserve the copyright notice and license text when distributing. That's it.

---

## The shared `pkg/` packages

The Go packages under `pkg/` — which define the `AgentCapabilityManifest` schema, condition types, audit events, and enforcement interfaces — are BUSL-1.1.

This matters for the schema parity guarantee: every component that processes policy YAML imports from the same `pkg/` source, so the types and validators are identical across `eunox-mcp`, the gateway, the issuer, and the runtime adapters. The [schema parity post](./16-schema-parity-over-version-drift.md) explains this in detail.

For most integration purposes — reading types, understanding the manifest format, building tooling that parses the YAML — the BUSL terms apply and permit this use. The restriction only kicks in if you package those packages as part of a commercial hosted-service offering to third parties.

---

## The conversion timeline

Every BUSL-licensed release specifies a conversion date — the date on which that version automatically becomes Apache 2.0. For eunox, the conversion period is four years from each release.

This means the restriction is not permanent. Version 1.14.2 of the gateway, released today, will be Apache 2.0 in 2030. If eunox hypothetically ceased to exist as a company, the software would eventually convert to open source, and anyone could fork and continue it. The community is not permanently locked out.

`eunox-mcp`, being Apache 2.0 from day one, has no conversion period — it's already fully open.

---

## Practical questions developers ask

**Can I use `eunox-mcp` in my startup's product?**

Yes. `eunox-mcp` is Apache 2.0 — embed it, redistribute it, build on it, no restrictions. If you also want to self-host the gateway stack, that's BUSL-1.1: you're deploying it for your own use, not selling it as a service to others. No license issue.

**Can I build a consultancy that deploys and operates eunox for clients?**

This is a nuanced case. If you're deploying eunox on a client's own infrastructure, within their own account, as an implementation service, that's generally fine — you're deploying for them, not offering eunox as a service. If you're running the infrastructure yourself and billing clients for API access to it, that's the hosted-service restriction and requires a commercial license. When in doubt, reach out — the commercial license is designed for this case.

**Can I fork `eunox-mcp` and distribute a modified version?**

Yes, without restriction. Apache 2.0. Keep the copyright notice and license text, that's all.

**Can I fork the BUSL code and modify it for internal use?**

Yes. You can fork, modify, and deploy modified platform versions for your own organisation's use. The production use restriction applies to external commercial offering, not internal deployment. Keep the BUSL license notices and conversion dates intact.

**Can I contribute code to either part?**

Yes, through the standard PR process. Contributions to both the Apache 2.0 `cmd/mcp/` and the BUSL platform components are welcome.

---

## Why this split, not some other split

The alternative we considered was making the shared `pkg/` types Apache 2.0 and keeping only `cmd/` services BUSL. We decided against it for a practical reason: the `pkg/` packages contain the condition evaluators that implement enforcement semantics — not just types, but executable logic. If you extract `pkg/` under Apache 2.0, you have enough to build a complete competing enforcement gateway without the BUSL restriction.

The split at `cmd/mcp/` keeps the developer-facing tool — the one developers actually install and use day-to-day — fully open, while preserving the commercial protection around the assembled platform. The enforcement contract is readable and auditable in `pkg/` under BUSL (which permits reading and self-deployment), and `eunox-mcp` itself is Apache 2.0 with no restrictions.

If the split creates friction for a specific legitimate use case you have, reach out. Licenses are decisions made in context, not eternal commitments, and the intent is to be the most developer-friendly split we can sustain.

---

## The broader context

The license debate in infrastructure software isn't going away. There are now multiple BUSL-licensed projects (HashiCorp's tools, parts of Elasticsearch's codebase), multiple projects that tried pure open source and changed (Redis, Confluent), and multiple projects that chose a different model entirely (Grafana, which went AGPL for some components).

Each represents a different answer to the same question: how do you build financially sustainable open infrastructure without either closing it entirely or watching it get captured by hyperscalers?

The dual-license model is one answer. The Apache 2.0 free tier drives recognition and adoption by removing every barrier for the tool developers touch first. The BUSL-1.1 platform protects the commercial investment that funds continued development. Users get a security infrastructure that's genuinely open at the developer layer and sustainably funded at the platform layer.

That's the deal. I think it's a fair one.
