# Policy Hot-Reload

> **Audience:** Platform operators and developers managing capability
> policies in eunox issuer deployments.

---

## Table of Contents

1. [Overview](#overview)
2. [Policy File Format](#policy-file-format)
3. [Loading Mechanism](#loading-mechanism)
4. [Hot-Reload Architecture](#hot-reload-architecture)
5. [Validation and Safety](#validation-and-safety)
6. [Admin API for Policy Management](#admin-api-for-policy-management)
7. [Policy Hash and Token Binding](#policy-hash-and-token-binding)
8. [Operational Procedures](#operational-procedures)
9. [Monitoring](#monitoring)
10. [Troubleshooting](#troubleshooting)
11. [Configuration Reference](#configuration-reference)

---

## Overview

The eunox issuer supports **file-based hot-reload** of role capability
policies. When the policy file changes on disk, the issuer automatically
detects the modification and atomically applies the new policies — without
requiring a restart or dropping in-flight requests.

Hot-reload is safe by design:

- **Atomic swap:** New policies are fully validated before replacing the
  active set
- **Low-blocking:** Read operations (token issuance) use an `RWMutex` and
  are only briefly blocked during the atomic swap
- **Fail-safe:** If the new file is malformed, the previous policies remain
  active and an error is logged

---

## Policy File Format

Policies are defined in a JSON file referenced by `ROLE_POLICY_FILE`:

```json
{
  "version": "1",
  "policies": [
    {
      "role": "developer",
      "description": "Standard developer access",
      "maxTTLSeconds": 3600,
      "capabilities": [
        {
          "resource": "tool:code-*",
          "actions": ["invoke", "read"],
          "conditions": [
            {
              "type": "timeWindow",
              "params": {
                "startHour": 8,
                "endHour": 18,
                "timezone": "UTC"
              }
            }
          ]
        }
      ],
      "allowedActions": ["invoke", "read", "list"],
      "maxCalls": 1000
    },
    {
      "role": "admin",
      "description": "Full administrative access",
      "maxTTLSeconds": 900,
      "capabilities": [
        {
          "resource": "*",
          "actions": ["*"]
        }
      ],
      "allowedActions": ["*"]
    }
  ]
}
```

### Policy Fields

| Field            | Type   | Required | Description                                               |
| ---------------- | ------ | -------- | --------------------------------------------------------- |
| `role`           | string | Yes      | Role name (matched against user's identity token roles)   |
| `description`    | string | No       | Human-readable description                                |
| `maxTTLSeconds`  | int    | No       | Maximum token TTL for this role (default: engine default) |
| `capabilities`   | array  | Yes      | Capability constraints granted to this role               |
| `allowedActions` | array  | No       | Whitelist of actions (for display/documentation)          |
| `maxCalls`       | int    | No       | Maximum API calls per token (enforced via call counter)   |
| `conditions`     | array  | No       | Additional conditions applied to all capabilities         |

### Capability Constraint Fields

| Field            | Type   | Description                                            |
| ---------------- | ------ | ------------------------------------------------------ |
| `resource`       | string | Resource pattern (exact, glob `*`, or prefix `tool:*`) |
| `actions`        | array  | Permitted actions on the resource                      |
| `conditions`     | array  | Conditions that must be satisfied at enforcement time  |
| `argumentSchema` | object | JSON Schema for permitted arguments (optional)         |

### Supported Condition Types

| Type                | Parameters                         | Description                                                                                                                                      |
| ------------------- | ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `timeWindow`        | `startHour`, `endHour`, `timezone` | Restrict to time-of-day window                                                                                                                   |
| `ipRange`           | `cidrs` (array of CIDR strings)    | Restrict to IP address ranges                                                                                                                    |
| `allowedOperations` | `operations` (array)               | Restrict to specific operation names                                                                                                             |
| `allowedExtensions` | `extensions` (array)               | Restrict file extensions                                                                                                                         |
| `allowedTables`     | `tables` (array)                   | Restrict database table access                                                                                                                   |
| `maxCalls`          | `limit` (int)                      | Maximum invocations per token (enforcement-time check; distinct from the policy-level `maxCalls` field which sets the default limit at issuance) |
| `recipientDomain`   | `domains` (array)                  | Restrict email/messaging recipients                                                                                                              |
| `redactFields`      | `fields` (array)                   | Fields that must be redacted in responses                                                                                                        |
| `policy`            | `policyId` (string)                | Reference to named policy                                                                                                                        |
| `custom`            | `key`, `value`                     | Arbitrary key-value condition                                                                                                                    |

---

## Loading Mechanism

### Startup Sequence

```
cmd/issuer/main.go
    │
    ▼
policy.New(
    WithPollInterval(30s),
    WithOnReloadError(logError),
)
    │
    ▼
policyEngine.LoadFromFile(cfg.RolePolicyFile)
    │ ← Fails → os.Exit(1) (startup failure)
    │ ← Success
    ▼
policyEngine.StartHotReload()
    │
    ▼
Background goroutine: pollLoop()
```

### Initial Load

On startup, the issuer:

1. Reads the policy file from disk
2. Parses JSON and validates structure
3. Builds internal policy map (role → capabilities)
4. If validation fails, the service **exits** (fail-fast on startup)

### Hot-Reload (Runtime)

After startup, a background goroutine polls for changes:

1. Every `pollInterval` (default: 30 seconds), check file `ModTime()`
2. If `ModTime` is newer than `lastModified`, trigger reload
3. Read and parse the updated file
4. Validate the new policy set
5. If valid: atomically swap the active policies (under write lock)
6. If invalid: log error via `onReloadError` callback, keep old policies

---

## Hot-Reload Architecture

### Thread Safety

```
┌─────────────────────────────────────────────────────┐
│                  PolicyEngine                         │
│                                                      │
│  ┌──────────────────────────────────────────────┐   │
│  │  sync.RWMutex                                 │   │
│  │                                               │   │
│  │  Read path (token issuance):                  │   │
│  │    RLock() → IntersectCapabilities() → RUnlock│   │
│  │                                               │   │
│  │  Write path (hot-reload):                     │   │
│  │    Lock() → swap policies → Unlock()          │   │
│  │                                               │   │
│  └──────────────────────────────────────────────┘   │
│                                                      │
│  pollLoop goroutine:                                 │
│    ticker (30s) → stat file → reload if changed      │
│                                                      │
│  stopCh: channel for graceful shutdown               │
│  sync.Once: ensures Stop() is idempotent             │
└─────────────────────────────────────────────────────┘
```

### Concurrency Guarantees

| Operation                                | Lock Type        | Blocking?                |
| ---------------------------------------- | ---------------- | ------------------------ |
| Token issuance (`IntersectCapabilities`) | RLock            | Never blocked by readers |
| Policy lookup (`MaxTTLForRole`)          | RLock            | Never blocked by readers |
| Hot-reload (swap)                        | Lock (exclusive) | Briefly blocks new reads |
| File stat check                          | None             | Non-blocking             |

### Reload Duration

The exclusive write lock is held only for the pointer swap (~microseconds).
File I/O and parsing happen **before** acquiring the lock. In practice,
token issuance latency is unaffected by hot-reload.

---

## Validation and Safety

### Pre-Swap Validation

Before replacing the active policy set, the engine validates:

1. **JSON syntax:** File must be valid JSON
2. **Parseability into policy structures:** Data must unmarshal into the policy file types

Additional semantic constraints (e.g., role uniqueness, non-empty capabilities, or strict version enforcement) are not currently enforced in `reload()`.

### Failure Modes

| Scenario                          | Behavior                                               | Recovery                                      |
| --------------------------------- | ------------------------------------------------------ | --------------------------------------------- |
| File deleted                      | `os.Stat` fails → error logged, old policies retained  | Restore file                                  |
| File empty                        | JSON parse fails → error logged, old policies retained | Fix file content                              |
| Invalid JSON                      | Parse error → logged, old policies retained            | Fix syntax                                    |
| Missing/weak semantic constraints | File may still load if JSON parses                     | Validate policy content in CI/operator checks |
| Permission denied                 | `os.Open` fails → error logged, old policies retained  | Fix permissions                               |
| Disk full (new file)              | Write may fail → old file still valid                  | Free disk space                               |

### Safe Update Procedure

To update policies without risk:

```bash
# 1. Write new policy to a temporary file
cat > /etc/eunox/policies.json.new << 'EOF'
{ "version": "1", "policies": [...] }
EOF

# 2. Validate syntax
jq . /etc/eunox/policies.json.new > /dev/null

# 3. Atomic rename (same filesystem)
mv /etc/eunox/policies.json.new /etc/eunox/policies.json
```

Using `mv` (rename) ensures the file is never partially written when the
poller reads it. The poller sees either the old file or the new file — never
a truncated intermediate state.

---

## Admin API for Policy Management

The issuer also supports runtime policy management via admin endpoints.
These changes are **in-memory only** and are lost on restart unless the
policy file is also updated.

### Create or Update a Role Policy

```bash
POST /admin/role-policy/{role}
Content-Type: application/json
X-Admin-Api-Key: {key}

{
  "description": "Updated developer policy",
  "maxTTLSeconds": 1800,
  "capabilities": [
    {"resource": "tool:*", "actions": ["invoke"]}
  ]
}
```

**Response (201 Created):**

```json
{ "role": "developer", "status": "created" }
```

### List All Policies

```bash
GET /admin/role-policy
X-Admin-Api-Key: {key}
```

**Response:**

```json
{
  "policies": [
    {"role": "developer", "maxTTLSeconds": 1800, ...},
    {"role": "admin", "maxTTLSeconds": 900, ...}
  ]
}
```

### Delete a Role Policy

```bash
DELETE /admin/role-policy/{role}
X-Admin-Api-Key: {key}
```

**Response (200 OK):**

```json
{ "role": "developer", "status": "deleted" }
```

### Admin vs File Priority

| Source      | Persistence              | Restart Behavior              |
| ----------- | ------------------------ | ----------------------------- |
| Policy file | Durable (disk)           | Reloaded on startup           |
| Admin API   | In-memory                | Lost on restart               |
| Hot-reload  | Overwrites admin changes | File always wins on next poll |

**Recommendation:** Use the admin API for temporary testing or emergency
changes. Use the policy file for persistent configuration. If both are used,
the file's content will overwrite admin API changes on the next poll cycle.

---

## Policy Hash and Token Binding

When a token is issued, the issuer computes a **policy hash** from the
granted capabilities:

```
policy_hash = base64url(SHA-256(JSON(capabilities))[:16])
```

This hash is embedded in the token payload. It serves two purposes:

1. **Audit correlation:** Links enforcement decisions back to the specific
   policy version that authorized the token
2. **Drift detection:** If policies change after issuance, the hash in
   existing tokens identifies them as issued under a previous policy version

**Note:** Policy changes do NOT invalidate existing tokens. Tokens remain
valid until expiration or explicit revocation. The policy hash is
informational only.

---

## Operational Procedures

### Deploying a Policy Change

```bash
# 1. Prepare the new policy file
vim /etc/eunox/policies.json.new

# 2. Validate (optional — use jq or a custom validator)
jq '.policies | length' /etc/eunox/policies.json.new

# 3. Deploy atomically
mv /etc/eunox/policies.json.new /etc/eunox/policies.json

# 4. Verify reload (check logs within poll interval)
kubectl logs -l app=eunox-issuer --tail=5 | grep -i policy

# 5. Test issuance with new policy
curl -X POST https://issuer:3001/api/v1/issue \
  -H "Authorization: ******" \
  -d '{"role": "developer", "capabilities": [{"resource": "tool:new-tool", "actions": ["invoke"]}]}'
```

### Kubernetes ConfigMap Reload

When using ConfigMaps for policy files:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: eunox-issuer-policies
data:
  policies.json: |
    {"version": "1", "policies": [...]}
---
# In the Deployment spec:
volumes:
  - name: policies
    configMap:
      name: eunox-issuer-policies
volumeMounts:
  - name: policies
    mountPath: /etc/eunox
    readOnly: true
```

**Important:** Kubernetes ConfigMap volume mounts use symlinks. The policy
engine's `os.Stat()` correctly detects the `ModTime` change when Kubernetes
updates the symlink target (typically within 60–90 seconds of ConfigMap
update, plus the poll interval).

### Rolling Back a Policy Change

```bash
# Option 1: Restore from git
git checkout HEAD~1 -- policies.json
mv policies.json /etc/eunox/policies.json

# Option 2: Use admin API for immediate effect
curl -X POST https://issuer:3001/admin/role-policy/developer \
  -H "X-Admin-Api-Key: $KEY" \
  -d '{"capabilities": [{"resource": "tool:*", "actions": ["invoke"]}]}'
```

---

## Monitoring

### Key Metrics

| Signal                        | Source                       | Indicates                            |
| ----------------------------- | ---------------------------- | ------------------------------------ |
| Policy reload success         | Log: `"policy reloaded"`     | Healthy reload cycle                 |
| Policy reload failure         | Log: `"policy reload error"` | Malformed file or permission issue   |
| Role not found in policy      | HTTP 403 on `/api/v1/issue`  | Missing role definition              |
| Capability intersection empty | HTTP 400 on `/api/v1/issue`  | Requested capabilities exceed policy |

### Recommended Alerts

| Alert                     | Condition                  | Action                              |
| ------------------------- | -------------------------- | ----------------------------------- |
| Policy reload failures    | Error log > 0 in 5 minutes | Check file permissions and content  |
| High 403 rate on issuance | > 10% of requests          | Verify policy covers expected roles |
| Policy file not modified  | No reload > 24 hours       | May indicate stale ConfigMap mount  |

---

## Troubleshooting

### Policy Not Reloading

1. **Check file permissions:**

   ```bash
   ls -la /etc/eunox/policies.json
   # Must be readable by the issuer process
   ```

2. **Check ModTime is updating:**

   ```bash
   stat /etc/eunox/policies.json
   # Compare with last reload time in logs
   ```

3. **Check for parse errors in logs:**

   ```bash
   kubectl logs -l app=eunox-issuer | grep -i "reload\|policy\|error"
   ```

4. **Verify poll interval:** Default is 30 seconds. Change may take up to
   one interval to be detected.

### Token Issuance Failing After Policy Change

1. **Role removed:** If a role was removed from the policy, tokens for that
   role cannot be issued (403)
2. **Capability mismatch:** Requested capabilities may no longer intersect
   with the updated policy (400)
3. **Check current active policies:**
   ```bash
   curl https://issuer:3001/admin/role-policy \
     -H "X-Admin-Api-Key: $KEY" | jq '.policies[].role'
   ```

---

## Configuration Reference

| Variable            | Default | Description                                               |
| ------------------- | ------- | --------------------------------------------------------- |
| `ROLE_POLICY_FILE`  | —       | Path to policy JSON file (empty = no file-based policies) |
| `DEFAULT_TOKEN_TTL` | `900`   | Default token TTL in seconds                              |
| `MAX_TOKEN_TTL`     | `86400` | Maximum token TTL in seconds                              |

### Engine Options (Code-Level)

| Option                  | Default       | Description                                   |
| ----------------------- | ------------- | --------------------------------------------- |
| `WithPollInterval(d)`   | 30 seconds    | File modification check interval              |
| `WithDefaultMaxTTL(s)`  | 900 seconds   | Default max TTL when role has no explicit max |
| `WithOnReloadError(fn)` | Log to stderr | Callback invoked on reload failure            |
