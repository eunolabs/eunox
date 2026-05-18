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

## 3. Request a Capability Token (PKCE browser flow — recommended)

The primary path uses the browser-based PKCE flow. The CLI opens your default
browser to your IdP's authorisation endpoint, receives the authorization code
on a loopback callback, exchanges it with the issuer, and writes the capability
token to disk. **No credentials ever appear in a URL or shell history.**

```bash
euno request --agent-id my-agent
```

The CLI will:
1. Open your browser at your IdP's authorisation page.
2. Complete the PKCE exchange automatically when you authenticate.
3. Write the capability token to `~/.euno/tokens/my-agent.jwt` (mode 0600).

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

## Non-interactive / CI use

> **⚠ Security note:** The `--token` flag bypasses the PKCE browser flow and
> **skips nonce binding and PKCE state tracking**, which are the primary
> defences against authorization-code and token-replay attacks. Use this flag
> **only** in non-interactive CI environments where a browser cannot be launched,
> and ensure the token is injected via a secrets manager (not plain-text env
> vars in logs).

In a CI pipeline where you pre-obtain an IdP token through a machine-identity
credential exchange (e.g. GitHub OIDC → `aws sts assume-role-with-web-identity`
→ Cognito federation), pass the resulting token directly:

```bash
euno request --agent-id my-agent --token "$IDP_TOKEN"
```

The token is printed to stdout and saved to `~/.euno/tokens/my-agent.jwt`.

## Troubleshooting

| Error | Fix |
|-------|-----|
| `✗ Could not start loopback server: …` | Port conflict or firewall; retry or use the non-interactive `--token` path |
| `Authorization timed out after 2 minutes` | You did not complete the browser sign-in; run `euno request` again |
| `✗ Authorization failed: …` | The IdP returned an error; check `idpAuthUrl`, `idpClientId`, and redirect URI registration |
| `✗ No stored token found` | Run `euno request` first |
| `✗ Token has expired` | Run `euno request --refresh --agent-id <id>` |
| `✗ Signature verification FAILED` | Ensure `--iss` matches the token's issuer and `issuerUrl` JWKS is reachable |
| HTTP 429 | Wait and retry; rate limit is 20 requests / 60 seconds |
