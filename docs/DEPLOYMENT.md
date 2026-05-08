# Deployment Notes

Stage 1 does not require deployment: `@euno/mcp` runs locally as a stdio or
HTTP MCP proxy and writes local audit evidence under `~/.euno/`.

The hosted platform services are frozen during Stages 1–2 and are not the
recommended entry point for new users. When deploying the platform for an
internal design partner, use the current workspace paths:

| Service | Workspace | Default port |
| --- | --- | --- |
| Capability Issuer | `euno-platform/packages/capability-issuer` | 3001 |
| Tool Gateway | `euno-platform/packages/tool-gateway` | 3002 |
| Shared infra implementations | `euno-platform/packages/common-infra` | n/a |
| Public shared contract | `public/packages/common` | n/a |

## Build and validation

From the repository root:

```bash
npm install
npm run lint
npm run test
npm run build
```

## Configuration

Generate service-specific environment templates with the CLI:

```bash
npm run build -w @euno/cli
euno config dump-template --service issuer > euno-platform/packages/capability-issuer/.env.example
euno config dump-template --service gateway > euno-platform/packages/tool-gateway/.env.example
```

Production deployments need an issuer signing key, a gateway verifier
configuration, a protected backend URL, and the selected optional backing stores
(Redis/Postgres/KMS) configured through the typed config schema in
`public/packages/common/src/config/schema.ts` and the implementations in
`euno-platform/packages/common-infra`.

## Containerization

There are no maintained Dockerfiles in the repository today. If a design partner
needs containers before the hosted platform is productized, build from the root
workspace so `@euno/common-core`, `@euno/common-infra`, and the target service are
compiled together. Do not resurrect old `packages/*` Dockerfile snippets; they
predate the two-folder split and are intentionally removed from this guide.
