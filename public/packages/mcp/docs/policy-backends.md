# Custom Policy Backends

`@euno/mcp` ships a set of built-in condition types for local enforcement
(`maxCalls`, `timeWindow`, `allowedOperations`, `ipRange`, `recipientDomain`, …).
For cases that require an external policy engine — Open Policy Agent, Cedar,
a custom rules database, or any other service — the `policy` condition type
lets you delegate enforcement to a pluggable backend.

This document covers:

1. [The `policy` condition type](#1-the-policy-condition-type)
2. [Writing a backend module](#2-writing-a-backend-module)
3. [Registering a backend at proxy start](#3-registering-a-backend-at-proxy-start)
4. [The `PolicyBackend` interface](#4-the-policybackend-interface)
5. [Worked example — OPA HTTP](#5-worked-example--opa-http)
6. [Error handling and startup failures](#6-error-handling-and-startup-failures)
7. [Stage-3 compatibility](#7-stage-3-compatibility)

---

## 1. The `policy` condition type

In a capability manifest (`.yaml` or `.json`), a `policy` condition names a
backend by the string key it was registered under:

```yaml
agentId: my-agent
name: My Agent
version: 1.0.0
requiredCapabilities:
  - resource: "mcp-tool://send_payment"
    actions: [call]
    conditions:
      # Delegate enforcement to the backend registered as 'opa-http'.
      - type: policy
        backend: opa-http
        # Optional: backend-specific config passed verbatim to validate/enforce.
        config:
          package: authz.payments
          rule: allow
        # Optional: per-call input merged with the runtime context.
        input:
          environment: production
```

`backend` (required) — the name under which the backend is registered.  
`config` (optional) — static, operator-supplied configuration passed verbatim to
`enforce()`. The manifest loader does **not** call `validate()` — validation
happens at enforcement time via the condition registry.  
`input` (optional) — additional input merged into the enforcement context.

If a manifest references a backend that is not registered at proxy start,
**every** call governed by that condition is denied with:

```
POLICY_BACKEND_DENIED: unrecognized policy backend 'opa-http'
```

---

## 2. Writing a backend module

A backend module is a plain Node.js file (TypeScript or JavaScript) that
exports a default **registrar function**.  The registrar receives the registry
API and calls `registerPolicyBackend` once for each backend it provides.

```ts
// my-opa-backend.ts
import type { PolicyBackend } from '@euno/common-core';

const opaBackend: PolicyBackend = {
  validate(config: unknown): void {
    // Called when the condition is evaluated (enforcement time).
    // Throw if `config` is missing required fields.
    const c = config as { package?: string };
    if (!c?.package) throw new Error('opa-http: config.package is required');
  },

  async enforce(
    config: unknown,
    input: unknown,
    ctx,           // ConditionContext from @euno/common-core
  ) {
    const c = config as { package: string; rule?: string };
    const rule = c.rule ?? 'allow';
    const url = `http://localhost:8181/v1/data/${c.package.replace(/\./g, '/')}/${rule}`;

    const body = {
      input: {
        ...(typeof input === 'object' && input !== null ? input : {}),
        sourceIp: ctx.sourceIp,
        recipients: ctx.recipients,
      },
    };

    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });

    if (!res.ok) {
      // Fail closed: treat OPA errors as denial.
      return { allow: false, reason: `OPA request failed: HTTP ${res.status}` };
    }

    const data = (await res.json()) as { result?: boolean };
    if (data.result === true) {
      return { allow: true };
    }
    return { allow: false, reason: `OPA policy ${c.package}/${rule} returned false` };
  },
};

// The default export is the registrar function.
export default function register(api: {
  registerPolicyBackend: (name: string, backend: PolicyBackend) => void;
}): void {
  api.registerPolicyBackend('opa-http', opaBackend);
}
```

The registrar function may be **async**:

```ts
export default async function register(api) {
  const config = await loadConfig();      // any async setup
  api.registerPolicyBackend('my-backend', buildBackend(config));
}
```

---

## 3. Registering a backend at proxy start

Pass `--policy-backend <path>` to the `proxy` subcommand.  The flag is
**repeatable** — supply it once per module.

```bash
# Load one backend
euno-mcp proxy \
  --policy ./euno.policy.yaml \
  --policy-backend ./my-opa-backend.js \
  -- node ./upstream-server.js

# Load two backends from different modules
euno-mcp proxy \
  --policy ./euno.policy.yaml \
  --policy-backend ./opa-backend.js \
  --policy-backend ./cedar-backend.js \
  -- node ./upstream-server.js
```

**Path resolution** follows Node.js `import()` rules:

| Path form | Resolved relative to |
|-----------|----------------------|
| `./relative/path.js` | `process.cwd()` (where you invoke `euno-mcp`) |
| `/absolute/path.js`  | Filesystem root |
| `my-npm-package`     | `node_modules` |

Both `.js` (CommonJS or ESM) and compiled `.js` output from TypeScript modules
are accepted.  If you want to pass a `.ts` file directly without a compile
step, run the proxy through `ts-node`:

```bash
npx ts-node -e "require('@euno/mcp/dist/cli')" -- proxy \
  --policy ./euno.policy.yaml \
  --policy-backend ./my-policy-backend.ts \
  -- node ./upstream-server.js
```

In production, pre-compile your backend to `.js` and pass the compiled path.

On successful load, `euno-mcp` writes a confirmation line to `stderr`:

```
[euno-mcp] registered policy backend: opa-http
```

---

## 4. The `PolicyBackend` interface

```ts
// From @euno/common-core
export interface PolicyBackend {
  /**
   * Called at enforcement time (each tools/call) to validate the static
   * `config` field before delegating to `enforce()`.  In the local proxy
   * context, `validate()` is **not** called at manifest-load time — it is
   * invoked by the condition registry during enforcement.
   * Throw a descriptive error if `config` is structurally invalid.
   */
  validate(config: unknown): void;

  /**
   * Called for each tools/call that matches a constraint with a `policy`
   * condition referencing this backend.
   *
   * @param config  - The static `config` field from the condition (may be undefined).
   * @param input   - The static `input` field from the condition (may be undefined).
   * @param ctx     - Runtime context: sourceIp, recipients, counterStore, etc.
   *
   * Return `{ allow: true }` to permit the call, or
   * `{ allow: false, reason: '...' }` to deny it.
   * The `reason` string is forwarded to the MCP client as a denial message.
   */
  enforce(
    config: unknown,
    input: unknown,
    ctx: ConditionContext,
  ): ConditionResult | Promise<ConditionResult>;

  /**
   * Optional response post-processor.  Called after the upstream returns a
   * result — not yet implemented in this Stage; reserved for Stage 3.
   */
  redact?(config: unknown, input: unknown, body: unknown): unknown;
}

export type ConditionResult =
  | { allow: true; reason?: string }
  | { allow: false; reason: string };
```

The `ConditionContext` available to `enforce()` includes:

| Field | Type | Description |
|-------|------|-------------|
| `now` | `Date` | Wall-clock time of the request |
| `sourceIp` | `string \| undefined` | Client IP (HTTP transport only) |
| `recipients` | `string[] \| undefined` | Extracted from `to`, `cc`, `bcc`, `recipients` args |
| `operation` | `string \| undefined` | SQL verb (SELECT, INSERT, …) from `sql`/`query` arg |
| `filePath` | `string \| undefined` | From `filePath`, `path`, `file`, `filename` arg |
| `tables` | `Array<{table, columns?}> \| undefined` | From `table`/`tables` args |
| `counterStore` | `CallCounterStore` | Increment-and-get counter (for rate-limit backends) |
| `counterKey` | `string` | Scoped counter key: `<sessionId>\|<toolName>\|<resource>` |

---

## 5. Worked example — OPA HTTP

This end-to-end example wires a running [OPA](https://www.openpolicyagent.org/)
instance as the policy backend.

**OPA policy (`authz/payments.rego`)**

```rego
package authz.payments

default allow = false

allow if {
    input.sourceIp != null
    net.cidr_contains("10.0.0.0/8", input.sourceIp)
}
```

**Backend module (`opa-backend.js`)**

```js
async function enforce(config, _input, ctx) {
  const pkg = config?.package ?? 'authz.payments';
  const rule = config?.rule ?? 'allow';
  const url = `http://localhost:8181/v1/data/${pkg.replace(/\./g, '/')}/${rule}`;

  const res = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ input: { sourceIp: ctx.sourceIp } }),
  });

  if (!res.ok) return { allow: false, reason: `OPA HTTP ${res.status}` };
  const { result } = await res.json();
  return result === true
    ? { allow: true }
    : { allow: false, reason: 'OPA policy denied' };
}

module.exports = function register(api) {
  api.registerPolicyBackend('opa-http', {
    validate(config) {
      if (config != null && typeof config.package !== 'string') {
        throw new Error('opa-http: config.package must be a string');
      }
    },
    enforce,
  });
};
```

**Policy manifest (`euno.policy.yaml`)**

```yaml
agentId: payments-agent
name: Payments Agent
version: 1.0.0
requiredCapabilities:
  - resource: "mcp-tool://initiate_payment"
    actions: [call]
    conditions:
      - type: policy
        backend: opa-http
        config:
          package: authz.payments
          rule: allow
```

**Running the proxy**

```bash
euno-mcp proxy \
  --transport http --port 3000 \
  --policy ./euno.policy.yaml \
  --policy-backend ./opa-backend.js \
  -- node ./payment-mcp-server.js
```

---

## 6. Error handling and startup failures

Errors in backend modules fail **fast** — before the proxy starts serving:

| Failure mode | What happens |
|---|---|
| Module path not found | `[euno-mcp] Failed to load policy backend module '…': …` + exit 1 |
| Default export is not a function | `[euno-mcp] Policy backend module '…' must export a default function …` + exit 1 |
| Registrar throws | `[euno-mcp] Error registering policy backends from '…': …` + exit 1 |

This means a mis-typed `--policy-backend` path or a backend module that
throws during registration will prevent the proxy from starting, giving
operators immediate, actionable feedback rather than silent misbehaviour at
request time.

---

## 7. Stage-3 compatibility

Backends registered via `registerPolicyBackend` from `@euno/common-core` land
in the **same shared registry** that the Stage-3 hosted gateway uses.  A
backend written today for `euno-mcp` local-proxy is usable unchanged in a
Stage-3 multi-tenant deployment — pass the same module path in the gateway
configuration instead of on the CLI.

The registry is process-global by design; concurrent calls to `enforce()` from
different sessions must be safe (stateless or internally synchronised).
