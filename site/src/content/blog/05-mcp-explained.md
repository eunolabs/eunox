---
title: "MCP explained: the USB-C moment for AI tooling"
description: "developers and technical leads evaluating AI agent infrastructure"
pubDate: "2026-05-24"
---

*Audience: developers and technical leads evaluating AI agent infrastructure*

---

Here's the thing nobody really talks about when they demo an AI agent: somebody had to write a custom integration for every tool that agent uses. A function that takes natural language intent and turns it into an API call for Slack. A different function for GitHub. A different one for your database. A different one for your CRM. And if you want to switch from Claude to GPT-4o or Gemini, you might have to rewrite all of them, because each model has a subtly different way of defining tools and receiving results.

Before MCP, building agents was an N×M problem. N models, M tools, potentially N×M adapters to write and maintain. You picked a model and built around it. The tools were bespoke to your stack. Swapping anything out was painful in proportion to how many integrations you'd accumulated.

That's the problem MCP solves. Not the only problem with agents, not the hardest problem — but a real one, and it's worth understanding what the protocol actually does and doesn't cover before you build on top of it.

---

## What MCP actually is

Anthropic published the Model Context Protocol spec in November 2024. It's an open protocol — the spec is public, there's no licence fee, and several major tools have adopted it. The core idea is simple enough to fit in two sentences: standardise how AI models communicate with the tools they use, and standardise how tools advertise what they can do.

There are three roles in the protocol:

The **MCP Host** is the application that contains the model — Claude Desktop, Cursor, your custom agent framework. It manages the model and the user interaction.

The **MCP Client** speaks the protocol on behalf of the host. It connects to MCP Servers and handles the protocol mechanics — discovery, tool invocation, result handling.

The **MCP Server** is the thing that exposes tools. Your GitHub integration is an MCP Server. Your database query tool is an MCP Server. A Slack connector is an MCP Server. The server describes what tools it offers and handles the actual execution.

The elegant part: one MCP Server works with any MCP Client. One MCP Client works with any MCP Server. The N×M matrix collapses to N+M. Write a server once and it works with every client that speaks the protocol. Write a client once and it can connect to every server. This is genuinely useful, and it's why adoption has been faster than most protocol proposals in this space.

---

## The USB-C analogy is accurate, including the annoying parts

USB-C standardises the connector, not what flows through it. A USB-C cable that charges your laptop doesn't necessarily work for your monitor. A cable that does 20Gbps data doesn't necessarily deliver 100W of power. The connector is the same. The capabilities vary. And the transition took years — there's still plenty of micro-USB and Lightning hardware around, the ecosystem is uneven, and people have been burned by cheap cables that look right but don't work.

MCP is similar. A genomics database server and a Slack integration server look identical to the protocol layer — they both expose tools over the same transport, with the same discovery mechanism. The protocol doesn't know or care what the tools actually do. That's a feature — the abstraction is clean. It's also where the analogy gets slightly uncomfortable.

Just like USB-C, the transition is uneven. As of mid-2025, Claude Desktop and Cursor have native MCP support. OpenAI's models don't natively speak MCP — you can adapt, but there's no built-in integration. The community server ecosystem has grown fast, but fast growth and quality control don't always travel together. There's no trust certification for MCP servers in the main registry. "MCP-compatible" tells you the server speaks the protocol. It tells you nothing about whether it's secure, well-maintained, or won't start doing unexpected things with the data it receives.

And just like USB-C created new failure modes the old approach didn't have — people plugging in cables that fry their hardware because they trusted the connector shape — standardisation creates new security failure modes too. We'll get to those.

---

## What the protocol actually covers

**Transport.** MCP defines two transport mechanisms. STDIO runs the MCP Server as a subprocess — the client spawns it, communicates over standard input/output, and the server has no network surface. Simple, clean, great for local development and bundled integrations. HTTP+SSE (Server-Sent Events for streaming) is the network model — the server is a hosted service, the client connects over HTTP, and you can have one server instance serving many clients. In practice, local dev tools tend to use STDIO; production multi-user deployments want HTTP.

**Three capability types.** Tools are callable functions — the model invokes them by name with typed arguments and gets a result. Resources are data sources the model can read — files, database records, knowledge base entries. Prompts are reusable templates with parameters that let servers offer pre-built interaction patterns. Most of the interesting governance discussion is about tools, because tools are the ones that do things with consequences.

**Discovery.** The protocol defines a handshake where the client asks the server what it offers, and the server responds with a list of capabilities and their schemas. This is what lets a generic agent framework work with an arbitrary server without being pre-programmed with knowledge of that server's tools.

That's mostly it for what MCP specifies. Clean, minimal, useful.

---

## What MCP deliberately does not cover

This is the part where people sometimes feel misled, so it's worth being direct: MCP does not define authentication, authorisation, rate limiting, audit logging, or prompt injection defences. Not an oversight — this is intentional scoping. The protocol maintainers made a deliberate call to keep the spec focused and let implementers handle these concerns.

That's a reasonable design decision for a protocol. It's just not the whole picture of what you need to run agents safely in production.

"MCP-compatible" is not the same as "production-ready for enterprise." A server that speaks perfect MCP with no auth, no rate limiting, and no logging is MCP-compatible. It's also a problem if you point a production agent at it. The protocol gives you interoperability. Security and governance are layers you have to add.

---

## The security gap is real

There's a specific risk that MCP introduces that's worth understanding: the tool description is a trust surface.

When an MCP Server tells the client what tools it offers, those descriptions go into the model's context. The model uses those descriptions to decide when and how to call the tools. An honest server describes `backup_files` as what it actually does. A malicious or compromised server could describe `backup_files` as "saves your work to ensure nothing is lost" while the actual implementation exfiltrates data to an external endpoint. The model, reading the description, has no way to verify it against the implementation. It trusts the description because descriptions are what it has.

This is a real attack vector. It's not theoretical. It means you need to think carefully about which MCP servers you allow your agents to connect to, and ideally you want an intermediate layer that validates tool call arguments against what's actually permitted — not what the server claims.

Prompt injection is also amplified in an MCP context. Tool results come back as content that lands directly in the model's context window. A tool that returns a document, an email, or a web page is returning content that the model will process as part of its reasoning. If that content contains instructions — put there by whoever produced the content, not by your system prompt — the model will see those instructions alongside everything else. [The prompt injection post](./01-prompt-injection-policy-layer.md) has a detailed treatment of how this works and how a policy layer can intercept it, but the key point here is that MCP's clean separation of protocol and content doesn't protect you from injection that happens through the content.

---

## Where the ecosystem is right now

Claude Desktop has supported MCP natively since late 2024. Cursor added it quickly after. VS Code's Copilot has an extension model that's compatible. There are several hundred community-built MCP servers covering everything from GitHub and Linear to genomics databases and local filesystem access. The quality varies enormously — some are well-engineered, maintained, and tested; others are proof-of-concept repos with no auth and minimal error handling.

OpenAI's models don't natively speak MCP as of mid-2025. You can build adapters, and there's active community work in this direction, but it's an extra step. Whether this changes depends partly on whether OpenAI decides to adopt the spec or push their own tooling standard, and that's genuinely unclear.

The thing missing from the ecosystem is trust infrastructure. There's no process for verifying that a published MCP server does what its description says, no security review requirement for servers in community registries, no trust label that means "this server has been audited." That's not a criticism — it's a protocol in its first year of real adoption. But it's something you should account for when evaluating servers for production use.

---

## Where things are going

The spec is actively evolving. The directions that seem most concrete as of mid-2025:

**Streamable HTTP** is replacing the older SSE model — cleaner streaming semantics, better support for long-running tool calls, and more natural for the kind of back-and-forth that complex tool chains produce.

**Tool annotations** will let servers communicate metadata about tools beyond just their input/output schema — things like whether a tool is read-only or has side effects, what rate limits apply, what data categories it handles. This is the right direction for building policy layers on top of MCP, because right now policy systems have to infer this information from tool names and descriptions, which is fragile.

**Auth integration** — there's work happening on how MCP should interact with OAuth and other standard auth flows. This would let MCP servers express their auth requirements in a standardised way, which is better than the current state where each server does auth differently or not at all.

None of this changes the fundamental picture: MCP is the plumbing, and governance is a separate layer. The protocol is getting better at expressing the metadata that governance systems need, but the enforcement is still your responsibility.

---

MCP solves the integration matrix problem and it does it well. If you're building agents that need to connect to multiple tools, or you want to reuse tool integrations across different models and frameworks, the protocol is worth adopting. The ecosystem support is real, the spec is stable enough to build on, and the abstraction is clean.

But the moment your agents are calling tools with real consequences — sending emails, querying customer data, executing code — you need to think about what sits between the model and the tool. The protocol doesn't do it. That's what a policy proxy is for. [Building a policy proxy for MCP](./06-mcp-policy-proxy.md) covers what that looks like in practice.
