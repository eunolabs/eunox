# Custom conditions in `@euno/mcp`

`@euno/mcp` can load custom condition handlers at proxy startup.

Use one or more `--custom-condition <module>` flags:

```bash
npx -y @euno/mcp proxy \
  --policy ./euno.policy.yaml \
  --custom-condition ./custom-conditions/deny-external.js \
  -- node ./my-mcp-server.js
```

## Module contract

A custom-condition module must default-export a function:

- Input: `{ registerCustomCondition }`
- Behavior: call `registerCustomCondition(name, handler)` for each custom handler
- Return: `void` or `Promise<void>`

If the module cannot be loaded, or its default export is not a function, startup fails fast.

## Handler contract

Handlers are registered by name and must implement:

- `validate(config)` — throw on invalid condition config
- `enforce(config, ctx)` — return `{ allow: true }` or `{ allow: false, reason }`
- optional `redact(config, body)` — response-time redaction

If a policy references `type: custom` with a `name` that was not registered, proxy startup preflight fails and points to `--custom-condition`.

## Worked example

Policy:

```yaml
agentId: email-agent
name: Email Agent
version: 0.1.0
requiredCapabilities:
  - resource: "send_email"
    actions: [call]
    conditions:
      - type: custom
        name: denyBlockedRecipient
        config:
          blockedDomain: "blocked.test"
```

Handler module (`./custom-conditions/deny-blocked-recipient.js`):

```js
exports.default = ({ registerCustomCondition }) => {
  registerCustomCondition('denyBlockedRecipient', {
    validate(config) {
      if (!config || typeof config.blockedDomain !== 'string' || config.blockedDomain.length === 0) {
        throw new Error("blockedDomain must be a non-empty string");
      }
    },
    enforce(config, ctx) {
      const recipients = Array.isArray(ctx.recipients) ? ctx.recipients : [];
      const blocked = recipients.some((r) => String(r).toLowerCase().endsWith(`@${config.blockedDomain.toLowerCase()}`));
      return blocked
        ? { allow: false, reason: `recipient is blocked by custom condition (${config.blockedDomain})` }
        : { allow: true };
    },
  });
};
```
