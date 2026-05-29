<!-- Copyright 2026 Eunox Authors -->
<!-- SPDX-License-Identifier: BUSL-1.1 -->

# Licensing FAQ

Eunox uses a **dual-license model**. The quick answer for most people:

> **Running eunox for your own use (personal, employer, or client) is free.**
> Building a commercial product that wraps or resells the eunox platform
> as a service requires a commercial licence.

---

## Quick Reference

| Component | License | Use freely | Embed in your product | Host as a service for third parties |
|---|---|---|---|---|
| `cmd/mcp/` (`eunox-mcp` binary) | Apache 2.0 | ✅ | ✅ | ✅ |
| Gateway, Issuer, Minter, DB Token Svc, Storage Grant Svc | BUSL-1.1 | ✅ | ✅ (internal use) | ❌ requires commercial licence |
| `pkg/` and `internal/` | BUSL-1.1 | ✅ | ✅ (internal use) | ❌ requires commercial licence |
| `eunox-python` (planned) | Apache 2.0 | ✅ | ✅ | ✅ |

All BUSL-licensed components **automatically convert to Apache 2.0** four years
after the official project launch date. The conversion is permanent and irrevocable.

---

## Individual Developer Questions

### "I want to evaluate eunox on my laptop. Is that free?"

Yes, completely. Download, run, experiment — no restrictions.

### "I'm building an internal tool for my company using eunox. Is that free?"

Yes. Deploying eunox to protect your own internal agents and services — even at
enterprise scale — is covered by the BUSL non-production / own-use permission.
You pay nothing.

### "I contribute to an open-source project that could use eunox. Can I include it?"

Yes, for projects where eunox is infrastructure for the project's own agents or
services. If the open-source project's commercial offering would host eunox as a
service on behalf of its users, that's competing use and requires a commercial
licence.

### "I want to write a blog post / conference talk about eunox."

Go ahead. Nothing in the licence restricts discussion, criticism, or
comparison.

---

## Organisation Questions

### "We want to deploy eunox to enforce AI agent policies across our 500-person engineering org."

That's the primary use case. Free.

### "We're a consulting firm. We want to set up eunox for our client and hand it over."

Fine — you're setting it up for them to run. "Hosting as a service" means
operating it on their behalf on an ongoing basis; one-time deployment and
handover is not that.

### "We're building a SaaS product where our customers log in and get a managed eunox gateway."

That's competing use. You need a commercial licence.
[Contact us](mailto:legal@eunolabs.com) — we're pragmatic and the process is fast.

### "We're a cloud provider and want to bundle eunox as a managed service."

Commercial licence required. [Contact us](mailto:legal@eunolabs.com).

### "We want to fork eunox and build our own competing product."

The BUSL allows you to fork and self-host. Offering the fork as a competing
hosted AI governance service requires a commercial licence until the BUSL
conversion date.

---

## BUSL Conversion Timeline

The BUSL conversion clock starts on the **official project launch date**, not on
the date of any pre-launch git tag or commit. We will announce the launch date
publicly; that date becomes the Change Date for all BUSL-licensed components
released up to and including that point.

From the launch date, the conversion schedule is:

- **Launch date + 4 years** — all BUSL-licensed code released on or before
  launch converts to Apache 2.0 automatically and permanently.
- **Post-launch releases** — each subsequent release carries its own Change Date
  of four years from that release's publication date.

This is:

- **Public** — the launch date will be announced and archived; the per-release
  Change Date is recorded in each release's `LICENSE` file.
- **Irrevocable** — once converted, the code is Apache 2.0 forever.
- **Automatic** — the BUSL itself specifies the conversion; no action is required
  on our side or yours.

If you are evaluating eunox today and your primary concern is long-term licence
risk: the conversion is a firm commitment, and the clock starts at launch.

---

## The `eunox-mcp` Binary

`cmd/mcp/` (the `eunox-mcp` binary — the MCP proxy) is **Apache License 2.0**
with no use restrictions. You can:

- Embed it in any product, open-source or commercial.
- Host it as a service.
- Fork and redistribute.

The Apache 2.0 licence file is at [`cmd/mcp/LICENSE`](../cmd/mcp/LICENSE).

---

## `eunox-python` (Planned)

The planned `eunox-python` PyPI package will be released under **Apache 2.0**.
This is a firm commitment, not a "we intend to." The rationale: Python agent
frameworks (LangChain, LangGraph, AutoGen) are themselves Apache 2.0; forcing
BUSL on the client library creates friction with no benefit to eunox. The
enforcement logic and platform services remain BUSL-1.1.

---

## What Is "Competing Use"?

The BUSL-1.1 prohibits use in a **production environment** that is a **Competing
Use**. For eunox, competing use means:

> Offering a commercial product or service that provides the same core
> functionality as the eunox platform — that is, a hosted AI agent governance,
> policy enforcement, or zero-trust enforcement service — where third parties
> pay for or derive commercial value from access to that service.

Running eunox to protect your own AI agents is **not** competing use.
Building a product where *your customers* use the hosted eunox platform is.

---

## Commercial Licences

Commercial licences are available for:

- SaaS or managed service deployments
- OEM embedding in third-party products
- White-labelling

[Email us](mailto:legal@eunolabs.com) with a brief description of your use
case. Turnaround is typically under 48 hours for standard cases.

---

## Still not sure?

Open a [GitHub Discussion](https://github.com/eunolabs/eunox/discussions) and
describe your use case. We'll give you a clear answer publicly so others with
the same question can find it.
