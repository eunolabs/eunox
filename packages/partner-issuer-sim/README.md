# `@euno/partner-issuer-sim`

Simulated "partner organization" capability issuer used by the cross-org
trust harness (`docs/sprint-3-4-gaps/05-cross-org-trust-harness.md`,
Sprint 4 → Team DP, item #5).

This package is **not** published to any registry. It exists in the
monorepo solely to drive the cross-org integration tests in
`packages/integration-tests/tests/cross-org.test.ts` and the
`infra/docker-compose.cross-org.yml` harness.

## Endpoints

- `GET  /healthz`              — liveness probe.
- `GET  /.well-known/did.json` — DID document for the partner DID.
- `POST /issue`                — mints an EdDSA-signed JWT for a partner
  agent. Body: `{ partnerAgentId, capabilities, ttl?, audience? }`.
- `POST /validate`             — accepts a JWT minted by *us* and reports
  whether the partner accepts it. Used by the harness to prove outbound
  trust from our side. Body: `{ token, action, resource }`.

## Configuration

| Env var | Default | Purpose |
| --- | --- | --- |
| `PORT` | `4001` | Listening port. |
| `PARTNER_ISSUER_DID` | `did:web:partner-sim.local%3A4001` | Partner DID. |
| `PARTNER_AUDIENCE` | `tool-gateway` | `aud` claim in minted tokens. |
| `PARTNER_TOKEN_TTL` | `900` | Token TTL (seconds). |
| `PARTNER_SEED` | _(none)_ | 32-byte hex / base64url seed for deterministic key derivation. **Set this in CI.** |
| `PARTNER_KEY_DIR` | _(none)_ | Optional directory to persist the key pair. |
| `PARTNER_TRUSTED_ISSUER_DIDS` | _(empty)_ | Comma-separated issuer DIDs the partner accepts on `/validate`. |

## Local development

```bash
npm run dev --workspace=@euno/partner-issuer-sim
curl http://localhost:4001/.well-known/did.json
```

For the full three-service docker-compose harness see
`infra/docker-compose.cross-org.yml`.
