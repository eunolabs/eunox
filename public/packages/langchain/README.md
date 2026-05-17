# @euno/langchain

LangChain companion package for **euno capability-native agent governance**.

Wraps any LangChain tool or tool-like function with the same condition
enforcement engine used by the `euno-mcp` proxy — no separate process, no
network hop, no Redis required.

**License:** Apache-2.0

---

## Why

LangChain agents run tools in-process. Without governance, a model can call
`query_db` with `DROP TABLE users` and nothing stops it.

`@euno/langchain` places the same `AgentCapabilityManifest` enforcement that
guards the MCP transport *inside* the LangChain tool wrapper:

```ts
// BEFORE — unguarded
const queryTool = new DynamicTool({
  name: 'query_db',
  func: async (sql) => db.query(sql),
});

// AFTER — governed
import { createLocalRuntime, wrapAsLangChainTool } from '@euno/langchain';

const runtime = await createLocalRuntime({
  policyFile: './euno.policy.yaml',
});

const queryTool = wrapAsLangChainTool(runtime, {
  name:        'query_db',
  description: 'Run a read-only SQL query on the analytics database',
  schema: {
    type: 'object',
    required: ['sql'],
    properties: { sql: { type: 'string' } },
  },
  handler: async ({ sql }) => db.query(String(sql)),
});
```

Now if the model produces `{ sql: 'DROP TABLE users' }`, the wrapper
intercepts it **before** calling `db.query`:

```
CapabilityDenialError: Tool call 'query_db' was denied by policy
  errorCode:     OPERATION_NOT_ALLOWED
  conditionType: allowedOperations
  statusCode:    403
```

---

## Installation

```bash
npm install @euno/langchain
```

Requires `@euno/mcp` and `@euno/common-core` as peer workspace packages.

---

## Policy file

The same YAML format accepted by `euno-mcp proxy --policy`:

```yaml
agentId: my-analytics-agent
name:    Analytics Agent
version: 0.1.0

requiredCapabilities:
  - resource: query_db
    actions:  [call]
    argumentSchema:
      type: object
      required: [sql]
      properties:
        sql: { type: string }
    conditions:
      - type: allowedOperations
        operations: [SELECT, SHOW]
      - type: maxCalls
        count: 100
        windowSeconds: 3600

  - resource: send_email
    actions:  [call]
    conditions:
      - type: recipientDomain
        domains: [company.com]
```

---

## API

### `createLocalRuntime(opts)`

```ts
const runtime = await createLocalRuntime({
  policyFile:       './euno.policy.yaml', // required
  auditLog:         `${os.homedir()}/.euno/audit.jsonl`, // optional; tilde (~) is expanded automatically
  rotateSizeBytes:  100 * 1024 * 1024,    // optional, default 100 MiB
  sessionId:        'my-session-id',      // optional, auto-generated if absent
});
```

Returns a `LocalCapabilityRuntime` that enforces the manifest on every
`invokeTool()` call and appends a signed OCSF record to the audit log.

### `wrapAsLangChainTool(runtime, definition)`

```ts
const tool = wrapAsLangChainTool(runtime, {
  name:         'query_db',
  description:  'Run a SQL query',
  schema:       { type: 'object', properties: { sql: { type: 'string' } } },
  handler:      async ({ sql }) => db.query(String(sql)), // optional
  transformArgs: (raw) => ({ sql: String(raw) }),         // optional
  sourceIp:     '10.0.0.1',                              // optional, for ipRange conditions
  resource:     'mcp-tool://query_db',                   // optional
});
```

Returns a `LangChainCompatibleTool` with `invoke()`, `call()`, and `func()`
entry points — plug it into any LangChain agent unchanged.

- **On allow**: calls `handler(args)` and returns the result as a string.
- **On deny**: throws `CapabilityDenialError` with `errorCode`, `statusCode`,
  `conditionType`, and `correlationId`.

### `wrapAsLangChainTools(runtime, definitions)`

Bulk wrapper for registering many tools at once.

### `EunoLangChainCallbackHandler`

A structural `BaseCallbackHandler` that emits correlation-tagged audit events:

```ts
const handler = new EunoLangChainCallbackHandler((event) => {
  if (event.phase === 'tool-error' && event.errorCode) {
    myMonitoring.recordDenial(event);
  }
});

await agent.invoke(input, { callbacks: [handler] });
```

Events carry `phase`, `toolName`, `runId`, `correlationId`, `ts`, and (on
error) `errorCode`, `statusCode`, `conditionType`, and `errorMessage`.

### `CapabilityDenialError`

```ts
try {
  await tool.invoke({ sql: 'DROP TABLE users' });
} catch (err) {
  if (err instanceof CapabilityDenialError) {
    console.error(err.errorCode);     // 'OPERATION_NOT_ALLOWED'
    console.error(err.conditionType); // 'allowedOperations'
    console.error(err.statusCode);    // 403
  }
}
```

---

## Denial codes

| `errorCode`                 | `statusCode` | Trigger                           |
|-----------------------------|-------------|-----------------------------------|
| `KILL_SWITCH`               | 503         | `runtime.terminate()` was called  |
| `MAX_CALLS_EXCEEDED`        | 429         | `maxCalls` condition              |
| `TIME_WINDOW_DENIED`        | 403         | `timeWindow` condition            |
| `OPERATION_NOT_ALLOWED`     | 403         | `allowedOperations` condition     |
| `EXTENSION_NOT_ALLOWED`     | 403         | `allowedExtensions` condition     |
| `TABLE_NOT_ALLOWED`         | 403         | `allowedTables` condition         |
| `IP_RANGE_DENIED`           | 403         | `ipRange` condition               |
| `RECIPIENT_DOMAIN_DENIED`   | 403         | `recipientDomain` condition       |
| `POLICY_BACKEND_DENIED`     | 403         | `policy` condition                |
| `ARGUMENT_VALIDATION_FAILED`| 422         | `argumentSchema` violation        |
| `CAPABILITY_DENIED`         | 403         | Generic policy denial             |

---

## Audit log

Every enforcement decision is written to a tamper-evident JSONL file
(same OCSF API Activity schema as `euno-mcp`). Read with:

```bash
euno-mcp stats --log ~/.euno/audit.jsonl
```
