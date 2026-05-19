# @euno/cli

Command-line interface for the Euno capability-issuer and agent governance platform.

## Installation

```bash
npm install -g @euno/cli
```

## Stage 4: Hosted Issuer + Identity Provider

With the Stage-4 hosted issuer, `euno request` and `euno validate-token`
connect to a live token-issuance service that authenticates users through
your identity provider (Entra ID, AWS Cognito, or GCP Cloud Identity) and
issues JWT capability tokens bound to the requesting user's identity.

### Quick setup

```bash
# Persist your issuer and IdP configuration
euno config set issuerUrl        https://issuer.euno.example
euno config set idpAuthUrl       https://login.microsoftonline.com/<tenant>/oauth2/v2.0/authorize
euno config set idpTokenUrl      https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token
euno config set idpClientId      <client-id>
euno config set defaultAgentId   my-agent

# Request a capability token (opens a browser for the PKCE flow)
euno request --agent my-agent

# Validate the stored token
euno validate-token --agent-id my-agent

# Renew an expiring token without re-authenticating
euno request --refresh --agent-id my-agent
```

See [`docs/quickstart-stage-4.md`](../../../../docs/quickstart-stage-4.md)
for the complete setup guide, and
[`docs/issuer-idp-setup.md`](../../../../docs/issuer-idp-setup.md) for
per-IdP configuration recipes.

---

## Stage 5: Enterprise Features

Stage 5 promotes four previously quarantined packages to GA and adds
partner DID federation, cross-chain audit anchoring, SOC 2 export, and
SCIM 2.0 provisioning.

### Partner DID federation

Trust tokens issued by a partner organisation whose identity is anchored
in a W3C DID (`did:web` or `did:ion`).

```bash
# Validate a partner-issued capability token
euno validate-token eyJ... \
  --iss did:web:partner.example.com \
  --jwks-url https://partner.example.com/.well-known/jwks.json \
  --aud tool-gateway

# Validate against a did:ion DID (resolved automatically via ION_RESOLVER_URL)
euno validate-token eyJ... \
  --iss did:ion:EiA...
```

### SOC 2 audit export

Export a cursor-paginated, cryptographically signed OCSF evidence bundle
from the gateway audit ledger, suitable for submission to an auditor.

```bash
# Export all CC7 (Logical and Physical Access) records
euno audit export \
  --gateway-url https://gateway.euno.example \
  --admin-key $EUNO_ADMIN_API_KEY \
  --scope soc2-cc7 \
  --out ./audit-soc2-cc7.jsonl

# Export all records (CC6 + CC7)
euno audit export \
  --gateway-url https://gateway.euno.example \
  --admin-key $EUNO_ADMIN_API_KEY \
  --scope all \
  --from 2026-01-01 --to 2026-03-31 \
  --out ./audit-q1-2026.jsonl

# Verify the cryptographic signatures in an exported bundle
euno verify-bundle ./audit-soc2-cc7.jsonl \
  --jwks-url https://issuer.euno.example/.well-known/jwks.json
```

### Service discovery

Inspect the Stage-5 discovery document to confirm which enterprise
features your issuer has enabled.

```bash
euno discover --issuer-url https://issuer.euno.example
```

The document reports `partnerFederation`, `scim`, `auditExport`, and
`capabilities` fields (schema version 1.0.0).

See [`docs/self-host.md §12`](../../../../docs/self-host.md) for the
complete Stage-5 operator guide.

---

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
