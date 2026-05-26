# OpenAPI Specifications

This directory contains OpenAPI 3.0 specifications for eunox's HTTP services.
The specs are hand-maintained; keep them in sync when changing the routes in
the corresponding Go source files under `internal/`.

| File | Service | Source |
| ---- | ------- | ------ |
| [`capability-issuer.yaml`](./capability-issuer.yaml) | Capability Issuer (default port 3001) | `internal/issuer/app.go` |
| [`capability-issuer-discovery.yaml`](./capability-issuer-discovery.yaml) | Issuer JWKS/Discovery | `internal/issuer/app.go` |
| [`tool-gateway.yaml`](./tool-gateway.yaml)           | Tool Gateway (default port 3002)      | `internal/gateway/app.go` and `internal/gateway/admin.go` |

## Viewing the specs

The YAML files are valid OpenAPI 3.0 documents and can be browsed with any
OpenAPI viewer, for example:

```bash
# Swagger UI in Docker
docker run -p 8080:8080 \
  -e SWAGGER_JSON=/spec/capability-issuer.yaml \
  -v "$(pwd)/docs/openapi:/spec" \
  swaggerapi/swagger-ui

# Or with redoc-cli
npx @redocly/cli preview-docs docs/openapi/tool-gateway.yaml
```

## Validating the specs

```bash
# Lint with redocly
npx @redocly/cli lint docs/openapi/capability-issuer.yaml
npx @redocly/cli lint docs/openapi/tool-gateway.yaml
```

## Generating clients

The specs can be used to generate clients in any language supported by
`openapi-generator`:

```bash
npx @openapitools/openapi-generator-cli generate \
  -i docs/openapi/tool-gateway.yaml \
  -g typescript-axios \
  -o clients/tool-gateway-ts
```
