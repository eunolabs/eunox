# Quickstart: Stage 4 — First Issued Capability Token

This guide walks you from a clean machine to a verified capability token using the Euno CLI.

## Prerequisites

- Node.js 18+
- A registered IdP app (Entra ID, AWS Cognito, or GCP Cloud Identity) with a redirect URI of `http://127.0.0.1:<any-port>/callback`
- Access to a running Euno capability issuer (hosted or self-hosted)

## 1. Install the CLI

```bash
npm install -g @euno/cli
euno --version
```

## 2. Configure the CLI

Point the CLI at your issuer and IdP:

```bash
euno config set issuerUrl https://issuer.example.com
euno config set idpAuthUrl https://login.microsoftonline.com/<tenant>/oauth2/v2.0/authorize
euno config set idpTokenUrl https://login.microsoftonline.com/<tenant>/oauth2/v2.0/token
euno config set idpClientId <your-client-id>
euno config set agentId my-agent
```

Config is persisted to `~/.euno/config` (mode 0600).

## 3. Request a Capability Token

If you have an Azure AD / IdP token already:
```bash
euno request --agent-id my-agent --token $AZURE_AD_TOKEN
```

The token is printed to stdout and saved to `~/.euno/tokens/my-agent.jwt`.

## 4. Verify the Token

```bash
euno validate-token --agent-id my-agent
```

Expected output:
```
✓ Token is VALID
  Issuer:  did:web:issuer.example.com
  Subject: user@example.com
  Agent:   my-agent
  Token ID (jti): <uuid>
  Expires: 2027-...
  Capabilities: 3
```

## 5. Renew the Token (before expiry)

```bash
euno request --refresh --agent-id my-agent
```

## 6. Revoke the Token

Token revocation is an admin operation handled by the gateway (not the issuer). Use the gateway admin API with your admin API key:

```bash
euno revoke <jti> --admin-key $EUNO_ADMIN_API_KEY --gateway-url https://gateway.example.com
```

## Troubleshooting

| Error | Fix |
|-------|-----|
| `✗ Azure AD bearer token is required` | Pass `--token $TOKEN` or set `AZURE_AD_TOKEN` |
| `✗ No stored token found` | Run `euno request` first |
| `✗ Token has expired` | Run `euno request --refresh --agent-id <id>` |
| `✗ Signature verification FAILED` | Ensure `--iss` matches the token's issuer and `issuerUrl` JWKS is reachable |
| HTTP 429 | Wait and retry; rate limit is 20 requests / 60 seconds |
