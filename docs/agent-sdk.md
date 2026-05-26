# Agent Runtime — Token Management and Enforcement

This guide explains how to use the eunox Agent Runtime (`internal/agentruntime`) to manage capability tokens and invoke tools through the enforcement gateway.

---

## Overview

The **Agent Runtime** provides:

1. **Token Lifecycle Management**: Automatic token acquisition, caching, and proactive refresh
2. **DPoP Binding**: Proof-of-possession key generation and management
3. **Tool Invocation**: HTTP transport for calling tools through the gateway
4. **Retry Logic**: Automatic retry with exponential backoff for transient failures

The runtime is the primary entry point for embedding eunox capability governance into Go-based AI agents.

---

## Quick Start

### Basic Usage

```go
package main

import (
    "context"
    "log"

    "github.com/edgeobs/eunox/internal/agentruntime"
)

func main() {
    // Configure the runtime
    cfg := &agentruntime.Config{
        IssuerURL:   "https://issuer.example.com",
        GatewayURL:  "https://gateway.example.com",
        IdentityToken: getIdentityToken(), // Your OIDC/Azure AD token
    }

    // Create runtime instance
    runtime, err := agentruntime.New(cfg)
    if err != nil {
        log.Fatalf("Failed to create runtime: %v", err)
    }

    // Invoke a tool
    ctx := context.Background()
    result, err := runtime.InvokeTool(ctx, &agentruntime.ToolRequest{
        Tool: "database:read",
        Args: map[string]interface{}{
            "table": "users",
            "limit": 100,
        },
    })
    if err != nil {
        log.Fatalf("Tool invocation failed: %v", err)
    }

    log.Printf("Tool result: %+v", result)
}
```

### Configuration Options

```go
cfg := &agentruntime.Config{
    // Required
    IssuerURL:   "https://issuer.example.com",   // Capability issuer endpoint
    GatewayURL:  "https://gateway.example.com",  // Tool gateway endpoint
    IdentityToken: "your-oidc-token",            // OR use IdentityTokenProvider

    // Optional: Dynamic token provider (recommended for long-running agents)
    IdentityTokenProvider: func(ctx context.Context) (string, error) {
        // Refresh your identity token from your IdP
        return getLatestIdentityToken(ctx)
    },

    // Optional: Token refresh behavior
    RefreshBeforeExpiry: 30 * time.Second, // Start refresh 30s before expiry

    // Optional: Retry configuration
    MaxRetries:      3,
    RetryBaseDelay:  100 * time.Millisecond,
    RetryMaxDelay:   5 * time.Second,

    // Optional: HTTP client (default: 30s timeout)
    HTTPClient: &http.Client{Timeout: 60 * time.Second},

    // Optional: Disable DPoP (not recommended for production)
    DPoPEnabled: boolPtr(false),
}
```

---

## Token Management

### Automatic Token Acquisition

The runtime automatically acquires a capability token from the issuer on first use:

```go
runtime, _ := agentruntime.New(cfg)

// First tool invocation triggers token acquisition
result, err := runtime.InvokeTool(ctx, toolReq)
```

### Proactive Token Refresh

The runtime monitors token expiry and proactively refreshes tokens before they expire:

```go
cfg := &agentruntime.Config{
    // ... other config
    RefreshBeforeExpiry: 30 * time.Second, // Refresh 30s before expiry
}
```

When the token is within 30 seconds of expiry, the runtime automatically calls `/api/v1/renew` to get a fresh token.

### Manual Token Management

For advanced use cases, you can manually control token lifecycle:

```go
// Get current token
token, err := runtime.GetToken(ctx)

// Force token refresh
newToken, err := runtime.RefreshToken(ctx)
```

---

## Calling Issuer Endpoints Directly

If you need to call the issuer endpoints (`/api/v1/attenuate`, `/api/v1/renew`) directly without the runtime, use standard HTTP clients:

### Attenuate a Token

Attenuation produces a child token scoped to a narrower set of capabilities. The `cnf.jkt` (DPoP binding) and `region` claims are preserved from the parent.

```bash
curl -X POST https://issuer.example.com/api/v1/attenuate \
  -H "Authorization: Bearer <parent-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "requestedCapabilities": [
      { "resource": "api://myservice/readonly", "actions": ["read"] }
    ]
  }'
```

Response:

```json
{
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...",
  "tokenID": "cap_abc123",
  "expiresAt": 1735689600
}
```

### Renew a Token

Renewal extends the expiry of an existing token without changing its capabilities. `cnf.jkt`, `region`, and `policyHash` are preserved.

```bash
curl -X POST https://issuer.example.com/api/v1/renew \
  -H "Authorization: Bearer <current-token>" \
  -H "Content-Type: application/json" \
  -d '{}'
```

Response:

```json
{
  "token": "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9...",
  "tokenID": "cap_xyz789",
  "expiresAt": 1735693200
}
```

---

## Error Handling

The runtime returns structured errors. Common error scenarios:

### Token Acquisition Failures

```go
runtime, err := agentruntime.New(cfg)
if err != nil {
    // Configuration validation failed
    log.Fatalf("Invalid config: %v", err)
}

result, err := runtime.InvokeTool(ctx, toolReq)
if err != nil {
    // Check error type
    if errors.Is(err, agentruntime.ErrUnauthorized) {
        log.Println("Identity token invalid or expired")
    } else if errors.Is(err, agentruntime.ErrForbidden) {
        log.Println("Identity lacks permission for requested capabilities")
    } else {
        log.Printf("Tool invocation failed: %v", err)
    }
}
```

### Rate Limiting

When rate limited (HTTP 429), the runtime automatically retries with exponential backoff (if `MaxRetries > 0`):

```go
cfg := &agentruntime.Config{
    // ... other config
    MaxRetries:     3,
    RetryBaseDelay: 100 * time.Millisecond,
    RetryMaxDelay:  5 * time.Second,
}
```

For manual handling:

```bash
# Rate limit response includes Retry-After header
HTTP/1.1 429 Too Many Requests
Retry-After: 42
Content-Type: application/json

{
  "error": "rate_limit_exceeded",
  "message": "Too many requests. Retry after 42 seconds."
}
```

---

## HTTP Error Reference

| Status | Meaning | Action |
|--------|---------|--------|
| 200 | Success | Use response token/result |
| 401 | Invalid/expired bearer token | Re-authenticate, get new identity token |
| 403 | Token lacks permission | Check capabilities or request broader scope |
| 422 | Invalid request body | Fix capability format or tool arguments |
| 429 | Rate limited | Wait `Retry-After` seconds (runtime handles automatically) |
| 500 | Service internal error | Retry with exponential backoff (runtime handles automatically) |

---

## DPoP (Proof-of-Possession)

The runtime automatically generates an ephemeral DPoP key pair and includes proof-of-possession proofs in all requests to the issuer and gateway.

### What is DPoP?

DPoP binds capability tokens to a specific client key pair. Even if a token is stolen, it cannot be used without the corresponding private key.

### Disabling DPoP (Not Recommended)

```go
cfg := &agentruntime.Config{
    // ... other config
    DPoPEnabled: boolPtr(false), // Only for testing/debugging
}
```

**Security Warning**: Disabling DPoP removes proof-of-possession binding. Only disable for local testing.

---

## Adapters for Tool Invocation

The runtime supports different tool invocation patterns through adapters:

### HTTP Adapter (Default)

Calls tools via HTTP POST to the gateway:

```go
result, err := runtime.InvokeTool(ctx, &agentruntime.ToolRequest{
    Tool: "http:post:api.example.com/data",
    Args: map[string]interface{}{"query": "users"},
})
```

### Function Call Adapter

For tools that are function calls (e.g., OpenAI function calling, Anthropic tool use):

```go
// The runtime can be extended with custom adapters
// See internal/agentruntime/adapters/ for examples
```

---

## Issuance Hints

Provide hints to the issuer for policy evaluation:

```go
cfg := &agentruntime.Config{
    // ... other config
}

runtime, _ := agentruntime.New(
    cfg,
    agentruntime.WithHintsProvider(func(ctx context.Context) (map[string]interface{}, error) {
        return map[string]interface{}{
            "environment": "production",
            "region":      "us-west-2",
            "agentVersion": "1.2.3",
        }, nil
    }),
)
```

These hints are included in the `/api/v1/issue` request and can be used by custom policy engines for authorization decisions.

---

## Advanced: Custom HTTP Client

Provide a custom HTTP client for mTLS, custom timeouts, or proxy support:

```go
import (
    "crypto/tls"
    "net/http"
)

// Configure mTLS
tlsConfig := &tls.Config{
    Certificates: []tls.Certificate{clientCert},
    RootCAs:      rootCAs,
}

cfg := &agentruntime.Config{
    // ... other config
    HTTPClient: &http.Client{
        Timeout: 60 * time.Second,
        Transport: &http.Transport{
            TLSClientConfig: tlsConfig,
        },
    },
}
```

---

## See Also

- [docs/ARCHITECTURE.md](./ARCHITECTURE.md) — System architecture overview
- [docs/openapi/capability-issuer.yaml](./openapi/capability-issuer.yaml) — Issuer API specification
- [docs/openapi/tool-gateway.yaml](./openapi/tool-gateway.yaml) — Gateway API specification
- [docs/enforcement.md](./enforcement.md) — Policy enforcement guarantees
- [internal/agentruntime/runtime.go](/internal/agentruntime/runtime.go) — Runtime implementation

---

## Helper Function

```go
func boolPtr(b bool) *bool {
    return &b
}
```
