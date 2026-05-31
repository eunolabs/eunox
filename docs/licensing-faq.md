<!-- Copyright 2026 Eunolabs, LLC -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Licensing FAQ

Eunox uses a **dual-license model**. The quick answer for most people:

> **Running eunox for your own use (personal, employer, or client) is free.**
> Building a commercial product that wraps or resells the eunox platform
> as a service requires a commercial licence.

---

## Quick Reference

| Component                        | License    | Use freely | Embed in your product | Host as a service for third parties |
| -------------------------------- | ---------- | ---------- | --------------------- | ----------------------------------- |
| `cmd/mcp/` (`eunox-mcp` binary)  | Apache 2.0 | ✅         | ✅                    | ✅                                  |
| `pkg/` and `internal/`           | Apache 2.0 | ✅         | ✅                    | ✅                                  |
| `eunox-python` (planned)         | Apache 2.0 | ✅         | ✅                    | ✅                                  |

All code in this repository is **Apache License 2.0**.

---

## Individual Developer Questions

### "I want to evaluate eunox on my laptop. Is that free?"

Yes, completely. Download, run, experiment — no restrictions.

### "I'm building an internal tool for my company using eunox. Is that free?"

Yes. Deploying eunox to protect your own internal agents and services — even at
enterprise scale — is completely free under the Apache 2.0 licence.

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

Apache 2.0 permits this. You can fork, modify, and redistribute — including in
commercial and competing products — provided you retain copyright notices and the
licence file.

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

---

## Still not sure?

Open a [GitHub Discussion](https://github.com/eunolabs/eunox/discussions) and
describe your use case. We'll give you a clear answer publicly so others with
the same question can find it.
