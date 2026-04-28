# Framework Adapters

> **Status:** ✅ Implemented (all three adapters shipped on top of
> `@euno/agent-runtime`). This document is the design reference that was
> previously missing — `execution-plan.md` calls out the framework
> adapters as a Sprint-2 deliverable but no design doc had been written
> for them.

## Implementation reference

- **Shared runtime:** `packages/agent-runtime/src/runtime.ts`
- **Shared adapter types and errors:** `packages/framework-adapters/src/types.ts`
- **LangChain adapter:** `packages/framework-adapters/src/langchain.ts`
- **Microsoft Agent Framework adapter:** `packages/framework-adapters/src/maf.ts`
- **CrewAI adapter:** `packages/framework-adapters/src/crewai.ts`
- **Test evidence:** `packages/framework-adapters/tests/{langchain,maf,crewai}.test.ts`

## Problem

Application teams adopt Euno from inside agent frameworks they have
already chosen — most commonly **LangChain**, **Microsoft Agent
Framework (MAF)**, and **CrewAI**. Asking those teams to rewrite their
agent business logic against a Euno-specific SDK is a non-starter; the
governance system has to meet the framework where it already lives.

The goal of `@euno/framework-adapters` is therefore to provide
framework-native middleware that:

1. **Acquires and refreshes** the agent's capability token transparently.
2. **Intercepts every tool call** the framework dispatches and routes it
   through the Tool Gateway (`/api/v1/tools/invoke`) so the gateway —
   not the LLM — is the policy decision point.
3. **Surfaces denials** as structured framework-native errors so the
   agent's planner can react (e.g. choose a different tool, ask the
   user, abort the task).
4. **Emits a stable correlation ID** on every call so the framework's
   trace lines up 1:1 with the audit log produced by the gateway.

These four obligations are spelled out in the Sprint-1 / Sprint-2
acceptance criteria of [`execution-plan.md`](./execution-plan.md).

## Scope (and non-scope)

In scope:

- LangChain, MAF, and CrewAI adapters with a **single shared error
  shape and correlation-ID contract**.
- A thin, structural runtime interface (`CapabilityRuntime`) so the
  adapters never reach into framework-specific or cloud-specific state.
- Test parity: the same three behavioural scenarios run against every
  adapter (no token / expired token / gateway denial).

Out of scope:

- Inventing a new agent framework. The adapters are middleware, not a
  competing SDK.
- Re-implementing identity or signing. Those live in
  `@euno/capability-issuer` (see [`ADAPTER_PATTERN.md`](./ADAPTER_PATTERN.md)).
- LLM provider abstraction. The adapters do not know or care which
  model the framework is calling.

## Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                      Agent process                            │
│                                                               │
│  ┌────────────┐    ┌────────────────────────────────────────┐ │
│  │   LLM /    │    │       Framework runtime                │ │
│  │  Planner   │◄──►│   (LangChain | MAF | CrewAI)           │ │
│  └────────────┘    │                                        │ │
│                    │   ┌──────────────────────────────┐     │ │
│                    │   │    Euno framework adapter    │     │ │
│                    │   │  (langchain.ts / maf.ts /    │     │ │
│                    │   │   crewai.ts)                 │     │ │
│                    │   └──────────────┬───────────────┘     │ │
│                    └──────────────────┼─────────────────────┘ │
│                                       ▼                       │
│                       ┌────────────────────────────┐          │
│                       │   @euno/agent-runtime      │          │
│                       │   (CapabilityRuntime)      │          │
│                       └──────────────┬─────────────┘          │
└──────────────────────────────────────┼────────────────────────┘
                                       ▼
                          ┌─────────────────────────┐
                          │     Tool Gateway        │
                          │  /api/v1/tools/invoke   │
                          └─────────────────────────┘
```

The shared substrate is `@euno/agent-runtime`. All three adapters depend
only on a **structural** interface from that package
(`CapabilityRuntime`, with `invokeTool` and `isTerminated`) so:

- Tests can inject a stub runtime without standing up a real gateway.
- The adapters cannot accidentally couple to cloud-specific state
  (Azure / AWS / GCP wiring lives behind the runtime, not in front of
  it).

## Public API

| Adapter       | Entry points                                                                                              | Source                                |
| ------------- | --------------------------------------------------------------------------------------------------------- | ------------------------------------- |
| **LangChain** | `wrapAsLangChainTool`, `wrapAsLangChainTools`, `EunoLangChainCallbackHandler`                             | `packages/framework-adapters/src/langchain.ts` |
| **MAF**       | `createEunoFunctionToolMiddleware`, `createEunoAgentRunMiddleware` (`UnknownToolPolicy = 'pass-through' \| 'deny'`) | `packages/framework-adapters/src/maf.ts`        |
| **CrewAI**    | `wrapAsCrewAITool`, `wrapAsCrewAITools`, `EunoCrewAITaskLifecycle`                                        | `packages/framework-adapters/src/crewai.ts`     |

The shared types — `CapabilityRuntime`, `ToolBinding` (mapping
`frameworkToolName → gatewayTool + gatewayResource`), the audit-event
shape — live in `packages/framework-adapters/src/types.ts`.

## Shared correlation-ID and error-shape contract

Every adapter:

1. Generates (or accepts) a `correlationId` per tool call and threads it
   through both the gateway request and the framework's own trace /
   callback surface.
2. Translates a gateway `403` denial into a framework-native
   `CapabilityDenialError` (exported from `@euno/framework-adapters`)
    whose payload includes `statusCode`, `errorCode`, `message`,
    `correlationId`, and `tool` (and optionally `resource`). Concretely:

    ```typescript
    interface CapabilityDenialError extends Error {
      name: 'CapabilityDenialError';
      statusCode: number;
      errorCode: string;
      tool: string;
      resource?: string;
      correlationId: string;
      details?: unknown;
    }
    ```

    - **LangChain:** the wrapped tool throws / returns a structured
     `CapabilityDenialError` that the agent sees in its scratchpad;
     the callback handler also fires an `EunoCallbackEvent`.
   - **MAF:** the function-tool middleware short-circuits before the
     model sees the result on a denial (per the Sprint-2 acceptance
     criterion), and the agent-run middleware emits a structured
     `MAFAuditEvent`.
   - **CrewAI:** the wrapped tool fails the *owning task* without
     crashing the crew, and `EunoCrewAITaskLifecycle` emits a
     `CrewAITaskAuditEvent`.

This is what lets a single gateway log line be reconciled against three
different framework traces without per-framework reconciliation code in
the SIEM.

## Acceptance scenarios (CI matrix)

Each adapter ships with the same three-scenario suite, executed in CI
for every PR (per `execution-plan.md` §"Framework Adapter Acceptance"):

| Scenario | Expected behaviour |
| -------- | ------------------ |
| Tool call **without** a token | Adapter raises a structured denied-error; the framework planner sees a typed error rather than a runtime exception. |
| Tool call with an **expired** token | Adapter triggers a refresh-and-retry through `AgentRuntime`; on success the call proceeds, on persistent failure the denial path runs. |
| Gateway returns a denial | Adapter surfaces it in the framework's trace **with the same correlation ID** that the gateway emitted to the audit log. |

Plus framework-specific assertions:

- **MAF:** the function-tool middleware short-circuits before the model
  sees the result on a denial.
- **CrewAI:** a denied tool call fails the owning task without crashing
  the rest of the crew.

The implementations of these scenarios live alongside the source in
`packages/framework-adapters/tests/` (`langchain.test.ts`,
`maf.test.ts`, `crewai.test.ts`) and are part of the workspace
`npm test` run.

## Developer ergonomics: CLI scaffolding

To make adoption a one-line operation,
`packages/cli/src/index.ts::init` accepts a
`--framework {langchain|maf|crewai}` flag (per `execution-plan.md`
Sprint-4 criterion). When set, `euno init` writes both:

1. The standard `agent-capability.yaml` manifest.
2. A starter wiring file for the chosen framework (`euno-langchain.ts`,
   `euno-maf.ts`, or `euno-crewai.ts`) that imports the appropriate
   adapter and shows the minimum code needed to construct an
   `AgentRuntime`, declare a `ToolBinding` table, and hand the wrapped
   tools to the framework.

The scaffolding is intentionally minimal — it is a starting point, not
a copy/paste production solution.

## Cross-references

- [`execution-plan.md`](./execution-plan.md) — Sprint-1 / Sprint-2
  acceptance criteria and the underlying motivation.
- [`ADAPTER_PATTERN.md`](./ADAPTER_PATTERN.md) — adapter pattern for
  identity / signing (different layer, same idea).
- [`enforcement.md`](./enforcement.md) — why the gateway, not the
  framework, is the policy decision point.
- [`IMPLEMENTATION.md`](./IMPLEMENTATION.md) — overall component
  inventory.
