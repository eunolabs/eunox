# MCP explained: the USB-C moment for AI tooling

*Audience: developers and technical leads evaluating AI agent infrastructure*

---

## A standardisation problem hiding in plain sight

Imagine you are building an AI agent. The agent needs to search the web, query your internal database, read files from a shared drive, and post updates to Slack. You go to implement each of these capabilities and quickly discover that you need to write four entirely different integration layers: a custom search API client, a database connector with a specific driver and query interface, an authentication flow for the file system API, and a Slack webhook handler. Each one speaks a different protocol, uses a different authentication scheme, and returns data in a different format.

Now imagine you want to swap out the AI model. The model you built against has its own way of describing available tools, its own format for tool call requests, and its own way of consuming tool results. Your competitor's model does it differently. The open-source model you might use for cost reasons does it a third way. Every model change requires re-integrating every tool.

This is the integration matrix problem that the AI tooling ecosystem has faced since the first wave of agent deployments in 2023. N models times M tools equals N×M custom integrations. Every player in the ecosystem — model providers, tool developers, framework authors, application builders — was building incompatible adapters for the same underlying problem.

The Model Context Protocol is the attempt to collapse this matrix. It is the USB-C moment for AI tooling: a single standard interface that works across the full diversity of the ecosystem on both sides.

---

## What MCP actually is

The Model Context Protocol is an open specification, published by Anthropic in November 2024, that defines a standard protocol for communication between AI models (or the systems that orchestrate them) and the external tools and data sources those models use.

The core idea is a three-role architecture:

**MCP Host**: the application that contains or orchestrates the AI model. This might be a chat interface like Claude Desktop, an IDE plugin like Cursor, an agent framework like LangChain, or a custom application you have built. The host manages the overall conversation and decides when to invoke tools.

**MCP Client**: a component, embedded in or alongside the host, that speaks the MCP protocol. The client maintains a connection to one or more MCP servers and translates the host's tool invocation requests into MCP protocol messages.

**MCP Server**: a process that exposes tools, resources, and prompts over the MCP protocol. An MCP server for file system access exposes tools like `read_file`, `write_file`, `list_directory`. An MCP server for a database exposes tools like `execute_query`, `list_tables`. The server implements the MCP protocol on one side and the actual backend integration on the other.

The result: a model (or host) that supports MCP can connect to any MCP server without custom integration code. An MCP server, once written, works with any MCP-compatible host. The N×M integration matrix collapses to N+M implementations.

---

## The USB-C analogy unpacked

The USB-C comparison is apt in ways that go beyond the obvious "universal connector" angle.

**USB-C standardises the physical connection, not the capability**. A USB-C port can carry USB 2.0 data, USB 3.2 data, Thunderbolt 4, DisplayPort video, or just power. The physical interface is the same; what flows through it varies enormously. MCP standardises the connection protocol — the message framing, the capability discovery handshake, the request/response format — without constraining what tools can do. A file system MCP server and a genomics database MCP server look identical to the protocol layer; their functional capabilities are entirely different.

**USB-C solved a real, frustrating problem with real adoption resistance**. The transition to USB-C was not instant; it required device manufacturers to adopt the new port, cable manufacturers to produce the cables, and users to replace their adapters. The standard succeeded because the ecosystem benefits were large enough to overcome the transition costs. MCP faces the same dynamics: model providers, tool developers, framework authors, and application builders all need to adopt it for the network effects to materialise. Adoption is happening, but it is still a work in progress.

**USB-C created new failure modes**. The USB-C ecosystem has seen problems that USB-A never had: cables that look identical but have vastly different capabilities, chargers that damage devices, protocols that interfere with each other on the same port. Standardisation makes interoperability possible, but it also creates a surface area for new categories of problems. MCP has analogous dynamics in the security domain, which we will come to.

---

## What MCP standardises

Understanding MCP's scope requires understanding exactly what the specification covers and what it leaves to implementers.

### The transport layer

MCP supports two transport mechanisms:

**STDIO transport**: the MCP server runs as a subprocess of the MCP client. The client and server communicate over standard input and standard output, using newline-delimited JSON-RPC 2.0 messages. This is the local process model: the server runs on the same machine as the client, launched by the client when needed. It is simple, has no network surface area, and is the natural deployment model for local development tools — an IDE plugin launching a local file system server, for example.

**HTTP with Server-Sent Events**: the MCP server runs as a separate HTTP server. The client sends requests as HTTP POST requests with JSON-RPC payloads, and the server sends responses and notifications over Server-Sent Events (SSE), a one-directional streaming mechanism over HTTP. This is the network model: the server runs as a hosted service that clients connect to over the network, appropriate for deployed agents calling shared tool infrastructure.

The two transport models have different security properties, which we will explore in the follow-on post on building a policy proxy.

### The capability model

MCP defines three types of capabilities that servers can expose:

**Tools**: callable functions with defined input schemas. A tool invocation is a request from the client (on behalf of the model) to the server to perform some action and return a result. Tools are the primary mechanism for AI agents to take actions and retrieve information. Each tool has a name, a description (used by the model to understand when to invoke it), and a JSON Schema defining the expected parameters.

**Resources**: read-only data that the server makes available to the model's context. A resource might be a specific file, a database record, a configuration value. Resources are not invoked like tools; they are exposed to the model as context that it can reference in its reasoning. The distinction between tools and resources maps roughly to the distinction between actions and read-only data access.

**Prompts**: reusable prompt templates that the server makes available to the host. These are pre-written instructions or workflows that the host can inject into the model's context. A prompts capability lets tool developers ship guidance about how their tools should be used alongside the tools themselves.

### The discovery handshake

When a client connects to a server, it performs a capability discovery handshake: the server declares what tools, resources, and prompts it exposes, along with their schemas and descriptions. The client provides this capability manifest to the host, which uses it to inform the model of what tools are available.

This discovery mechanism is what makes the N+M integration possible: a model does not need to be pre-configured with knowledge of specific tools. It receives the tool descriptions at runtime, in a standardised format, and can reason about how to use them.

### What MCP does not standardise

MCP is deliberately scoped. It does not standardise:

- **Authentication**: how the client authenticates to the server is out of scope for the core protocol. Different servers use different authentication mechanisms. The specification notes that authentication is an area for future work or local convention.
- **Authorisation**: whether the requesting model or user is permitted to invoke a specific tool, with specific arguments, is entirely outside the protocol. This is left to the server to implement as it sees fit.
- **Rate limiting and resource governance**: there is no standard mechanism for servers to declare usage limits or for clients to respect them.
- **Audit logging**: no standard format or requirement for logging tool invocations.

These omissions are intentional and reasonable: a protocol specification should standardise the minimum necessary for interoperability, not attempt to solve every problem. But they create a significant gap between "MCP-compatible" and "production-ready for enterprise AI agents."

---

## The ecosystem as of mid-2025

In the eighteen months since MCP's publication, adoption has been substantial, though uneven.

### Model and framework support

Anthropic's Claude models support MCP natively in the Claude Desktop application. Cursor (the AI-powered IDE) added MCP support in early 2025 and has become one of the most visible deployment environments for developer-facing MCP servers. The open-source ecosystem has produced MCP clients for most major agent frameworks: LangChain, LlamaIndex, AutoGen, and others.

OpenAI's GPT models have their own tool-calling protocol, which differs from MCP at the API level. Bridges and adapters exist, but native MCP support is not currently available in the OpenAI API. This represents the most significant adoption gap: a large fraction of AI agent deployments use OpenAI models that do not natively speak MCP. The ecosystem is actively working on reconciliation.

Google's Gemini models have a function-calling protocol that is similar in concept but different in detail. Again, adapters exist; native MCP support is partial.

### Server ecosystem

The MCP server ecosystem has grown rapidly. Anthropic maintains a curated registry of official and community MCP servers. As of mid-2025, there are hundreds of public MCP servers covering:

- File system and local compute tools (the most common category)
- Version control systems (GitHub, GitLab, Bitbucket)
- Databases (PostgreSQL, MySQL, SQLite, various cloud databases)
- Communication platforms (Slack, Microsoft Teams, email)
- Project management tools (Linear, Jira, Asana, GitHub Issues)
- Web browsing and search
- Cloud infrastructure (AWS, Azure, GCP)
- Developer tools (code execution environments, testing frameworks)

The quality and security posture of these servers varies enormously. Official servers from established vendors are generally better tested and maintained. Community-built servers range from polished, well-maintained implementations to experimental tools that have never been reviewed for security.

### The registry problem

There is currently no standardised trust or security certification for MCP servers in the public registry. An MCP server that is listed in the community registry has been reviewed only for basic functionality, not for security properties. A malicious or vulnerable MCP server that gains a developer's trust via the registry could potentially execute arbitrary code in the developer's environment, exfiltrate credentials, or — more subtly — manipulate the AI model's behaviour by providing misleading tool descriptions.

This is an active area of concern in the MCP ecosystem and the subject of ongoing work, both in the specification itself and in the tooling around it.

---

## The security gap MCP leaves open

MCP solves the integration problem. It does not solve the security problem. In fact, by making it dramatically easier to connect AI models to powerful tools, MCP amplifies the security surface area that responsible AI deployments need to address.

### The tool call is still a security event

An AI model invoking an MCP tool is an AI agent taking an action in the world — reading data, writing data, sending messages, executing code. The fact that the invocation uses a standardised protocol does not change its security significance. A `execute_query` tool call that runs `DROP TABLE users` is just as dangerous whether it comes from a custom integration or from an MCP-compatible client.

MCP standardises the *mechanism* of tool invocation. It does not provide the *governance* of what tool invocations are permitted. The policy question — "should this agent, at this moment, be allowed to call this tool with these arguments?" — is entirely outside the scope of the protocol.

### The tool description is a trust surface

MCP servers describe their tools in natural language, and those descriptions are provided to the AI model to help it understand when and how to use the tools. This creates a trust surface that did not exist in manually-written tool integration code: the model's understanding of a tool's purpose is mediated by the server's natural language description, which the operator may not have reviewed.

A malicious MCP server could provide a tool called `backup_files` whose description says "saves your current work to a safe location" but whose implementation exfiltrates the files to an attacker-controlled server. The model, trusting the description, invokes the tool without suspicion.

This is a specific instance of the supply chain risk that MCP introduces: the server is a dependency, and like any dependency, it can be malicious, compromised, or simply buggy in ways that have security consequences.

### Prompt injection is amplified

Prompt injection attacks — where adversarial content in data retrieved by the agent attempts to manipulate the agent's behaviour — are discussed in detail in [The prompt injection problem: why every AI agent needs a policy layer](./01-prompt-injection-policy-layer.md). MCP amplifies this attack surface in a specific way.

When an MCP server returns tool results to the model, those results become part of the model's context. An attacker who can influence the content returned by an MCP tool has a direct channel into the model's reasoning process. A `read_file` tool that returns a file containing adversarial instructions, a `web_search` tool that returns a result page containing a prompt injection payload, a `list_issues` tool that returns a GitHub issue with hidden instructions — all of these are prompt injection vectors through MCP tools.

The MCP protocol does not provide any mechanism for the client to sanitise or inspect tool results before they reach the model. The governance of what results are acceptable, and what happens when they appear adversarial, is entirely up to the application layer built around MCP.

### The missing governance layer

The security gap left by MCP can be summarised as: MCP standardises the plumbing, but not the governance. It answers "how does the model call this tool?" It does not answer:

- Is this model/agent/user permitted to call this tool right now?
- With these specific arguments?
- At this rate?
- And what is the audit record for this call?

These questions need answers before MCP-connected agents are suitable for production enterprise deployments. The policy proxy pattern — sitting between the MCP client and the MCP server, enforcing governance on every tool call — is the architectural response to this gap. This is covered in depth in [Building a policy proxy for MCP: design choices and trade-offs](./06-mcp-policy-proxy.md).

---

## Comparing MCP to what came before

To appreciate what MCP provides, it helps to understand the alternatives it replaces.

### Custom tool integrations

Before MCP, every AI framework had its own tool abstraction. LangChain's `BaseTool`, OpenAI's function-calling JSON Schema, AutoGen's function registration, Semantic Kernel's plugin model. Each had a different API, different serialisation format, and different lifecycle management. Writing a tool once meant either targeting a specific framework or writing multiple adapters.

MCP's advantage over custom integrations: write the server once, work with any MCP-compatible client. The tooling burden shifts from O(frameworks) per tool to O(1) per tool.

### Plugin systems

Several AI products have implemented plugin systems: OpenAI's now-deprecated plugin marketplace, various IDE extensions. These are generally tighter in scope — plugins for a specific product rather than a cross-ecosystem protocol — and have varying governance properties.

MCP's advantage: an open standard that is not owned by a single product vendor, enabling a genuinely interoperable ecosystem rather than a platform-specific extension mechanism.

### Custom API integrations

The simplest approach: the agent calls APIs directly, handling authentication, error handling, and response parsing in application code. No protocol layer, no mediation.

MCP's disadvantage relative to this: adding a protocol layer adds complexity. The advantage: the tool implementation is separated from the agent, can be developed and deployed independently, and works across agent implementations.

---

## What MCP is not a substitute for

MCP is a significant and useful standardisation effort. It is worth being clear about what it does not provide:

**It is not a security layer**. As discussed above, MCP says nothing about whether any given tool invocation is authorised. Security must be added by the application using MCP, by a proxy layer around MCP, or by both.

**It is not an observability layer**. MCP does not standardise logging of tool invocations. Auditability must be added by the implementation.

**It is not a policy language**. There is no MCP-native way to express "this tool can only be called with arguments matching this pattern" or "this agent can call this tool at most twenty times per hour." Policy must be implemented outside the protocol.

**It is not a trust framework**. Connecting to an MCP server does not imply any security properties about that server. There is no certificate authority for MCP servers, no standardised attestation that an MCP server behaves as described.

**It is not a solution to prompt injection**. An MCP server that returns adversarial content as tool results has not violated the MCP protocol. The protocol carries whatever the server sends; the safety properties of that content are outside its scope.

These are not criticisms of MCP — they are accurate descriptions of its scope. The protocol does what it is designed to do: standardise the communication interface between AI models and tools. The gap between that interface and a production-grade AI agent governance layer is real, significant, and the subject of the follow-on post.

---

## The trajectory

MCP is evolving rapidly. The specification has seen several revisions since its November 2024 launch, and the rate of change means that any specific detail in this post may be superseded. The areas of active development that are most relevant to production deployments:

**Authentication integration**: the specification is actively developing guidance for standard authentication flows between MCP clients and servers, likely building on OAuth 2.0. This will be important for enterprise deployments where servers need to verify that the requesting principal is authorised.

**Streamable HTTP transport**: the SSE-based HTTP transport is being revised to a more bidirectional streaming approach that addresses some of the limitations of the current server-sent events model.

**Tool annotations**: a mechanism for servers to declare additional metadata about tools, including safety hints that can inform client-side policy decisions. This is a step toward the governance layer that the protocol currently lacks, though it will still require enforcement infrastructure to be useful.

**Sampling**: a mechanism for MCP servers to request that the host perform AI inference, enabling more sophisticated server-side behaviours. This raises its own security considerations and is still being worked through.

The trend is toward a more capable and more production-ready protocol. The gap between the protocol and a comprehensive governance layer is narrowing, but it remains real. For organisations deploying AI agents today, that gap needs to be filled by tooling built around the protocol — a policy proxy, an audit layer, a capability governance system.

Understanding MCP is the foundation for understanding where governance tooling fits. The MCP-aware policy proxy pattern is the subject of the next post: [Building a policy proxy for MCP: design choices and trade-offs](./06-mcp-policy-proxy.md).
