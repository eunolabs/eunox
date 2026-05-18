# @euno/cli

Command-line interface for the Euno capability-issuer and agent governance platform.

## Installation

```bash
npm install -g @euno/cli
```

## Commands

### `euno init`
Scaffold a new capability manifest.
```bash
euno init --agent "My Agent" --output manifest.yaml
euno init --agent "My Agent" --framework langchain --cloud azure
```

### `euno validate <file>`
Validate a capability manifest.
```bash
euno validate manifest.yaml
```

### `euno request`
Request a capability token from the issuer (Bearer-token path).
```bash
euno request --agent my-agent --token $AZURE_AD_TOKEN
euno request --agent my-agent --token $TOKEN --manifest manifest.yaml
```

Refresh a stored token:
```bash
euno request --refresh --agent-id my-agent
```

### `euno validate-token [token]`
Verify a capability token's signature and expiry against the issuer JWKS. Enforces the `aud` claim (default: `tool-gateway`) and the `iss` claim. Pass `--aud` and `--iss` to override the defaults.
```bash
euno validate-token eyJ...
euno validate-token --agent-id my-agent
euno validate-token eyJ... --jwks-url https://issuer.example.com/.well-known/jwks.json
euno validate-token eyJ... --iss did:web:issuer.example.com --aud tool-gateway
```

### `euno revoke <jti>`
Revoke a capability token by its JTI via the **gateway** admin API (`POST /admin/revoke`).
```bash
euno revoke <jti> --admin-key $EUNO_ADMIN_API_KEY
euno revoke <jti> --admin-key $KEY --gateway-url https://gateway.example.com
```

### `euno config set <key> <value>`
Persist CLI configuration to `~/.euno/config`.
```bash
euno config set issuerUrl https://issuer.example.com
euno config set idpAuthUrl https://login.microsoftonline.com/<tenant>/oauth2/v2.0/authorize
euno config set idpTokenUrl https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token
euno config set idpClientId <client-id>
euno config set defaultAgentId my-agent
```

### `euno config show`
Print current configuration.

### `euno config dump-template --service <name>`
Print an `.env.example` for a named service.

### `euno schema-version`
Manage capability token schema versions.
```bash
euno schema-version check
euno schema-version plan 1.0 1.1
euno schema-version validate-token <token>
euno schema-version validate-token <token> --against-jwks <url>
```

## Configuration File

`~/.euno/config` (JSON, mode 0600):
```json
{
  "issuerUrl": "https://issuer.example.com",
  "idpAuthUrl": "https://login.microsoftonline.com/.../authorize",
  "idpTokenUrl": "https://login.microsoftonline.com/.../token",
  "idpClientId": "...",
  "agentId": "my-agent"
}
```

## Token Storage

Tokens are stored at `~/.euno/tokens/<agent-id>.jwt` with mode 0600.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `EUNO_ISSUER_URL` | Issuer URL (fallback when not in config) |
| `AZURE_AD_TOKEN` | Bearer token for `request` command |

## License

Apache-2.0
