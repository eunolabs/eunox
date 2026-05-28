<p align="center">
  <img src="https://github.com/edgeobs/eunox/blob/main/site/public/eunolabs.png?raw=true" alt="eunox" height="160">
</p>

<h1 align="center">eunox</h1>

<p align="center">
  <strong>Zero-trust enforcement gateway for AI agents</strong><br>
  A single YAML policy file defines and enforces every action an agent is permitted to take, validating each tool call before it reaches your backend and producing a tamper‑evident audit trail.
</p>

<p align="center">
  <a href="https://github.com/edgeobs/eunox/blob/main/LICENSE"><img alt="License: BUSL-1.1" src="https://img.shields.io/badge/license-BUSL--1.1-blue.svg"></a>
  <a href="https://go.dev/"><img alt="Go 1.25+" src="https://img.shields.io/badge/go-%E2%89%A51.25-00ADD8"></a>
  <a href="https://spec.modelcontextprotocol.io/"><img alt="MCP" src="https://img.shields.io/badge/MCP-supported-7c3aed"></a>
</p>

---

## What is eunox?

Eunox — from Eunomia, the Greek goddess of law and order — is a zero-trust enforcement gateway for AI agents. Every tool call is authorized against a cryptographically signed, time-limited capability token before it reaches your backend. No ambient authority, no implicit trust, no exceptions — and a tamper-evident audit trail your compliance team can actually use.

## Services

| Service               | Path                     | Description                                                         |
| --------------------- | ------------------------ | ------------------------------------------------------------------- |
| Gateway               | `cmd/gateway/`           | Enforcement gateway — policy evaluation, rate limiting, kill switch |
| Issuer                | `cmd/issuer/`            | Capability token issuance, IdP integration                          |
| Minter                | `cmd/minter/`            | API-key lifecycle, admin auth, anomaly detection                    |
| DB Token Service      | `cmd/db-token-svc/`      | Short-lived DB credentials (AWS RDS, Azure SQL, GCP Cloud SQL)      |
| Storage Grant Service | `cmd/storage-grant-svc/` | Presigned URLs (AWS S3, Azure Blob, GCP GCS)                        |
| Posture Emitter       | `cmd/posture-emitter/`   | Security posture reporting                                          |

## Project Structure

```
eunox/
├── cmd/                    # Service entry points
│   ├── gateway/
│   ├── issuer/
│   ├── minter/
│   ├── db-token-svc/
│   ├── storage-grant-svc/
│   └── posture-emitter/
├── internal/               # Private application code
├── pkg/                    # Public importable packages
├── migrations/             # SQL migrations
├── k8s/                    # Kubernetes manifests & Helm charts
├── infra/                  # Infrastructure (Docker Compose, Terraform, etc.)
├── docs/                   # Documentation
├── site/                   # Astro site (landing page, blog, docs hub)
├── blogs/                  # Blog content
├── Makefile
├── go.mod
└── go.sum
```

## Development

### Prerequisites

- Go 1.25+
- golangci-lint v2.1.6+

### Commands

```bash
# Run all tests with race detector
make test

# Run linter (go vet + golangci-lint)
make lint

# Build all packages
make build

# Generate coverage report
make coverage

# Check BSL license headers
make check-license

# Clean build artifacts
make clean
```

## Deployment

### Quick Start — Production

```bash
# 1. Build gateway binary
go build -o ./bin/gateway ./cmd/gateway

# 2. Set minimum production environment
export GATEWAY_NODE_ENV=production
export GATEWAY_PORT=3002
export GATEWAY_ADMIN_PORT=3003
export GATEWAY_ADMIN_HOST=127.0.0.1
export GATEWAY_ADMIN_API_KEY=$(openssl rand -hex 32)
export GATEWAY_TENANT_ID="my-tenant"
export GATEWAY_REDIS_URL="redis-sentinel://sentinel1:26379,sentinel2:26379/0?sentinel_master_name=mymaster"
export GATEWAY_ISSUER_JWKS_URL="https://issuer.internal/.well-known/jwks.json"

# 3. Run
./bin/gateway
```

### Kubernetes (Helm)

```bash
helm install eunox k8s/helm/eunox/ \
  --namespace eunox-system --create-namespace \
  -f k8s/helm/eunox/values.yaml
```

See [`docs/deployment.md`](./docs/deployment.md) for the full configuration
reference, [`docs/deploy-eks.md`](./docs/deploy-eks.md) for EKS, and
[`docs/deploy-gke.md`](./docs/deploy-gke.md) for GKE.

### Other Targets

- **Docker Compose** (dev/pilot): `infra/docker-compose.yml`
- **Air-gapped**: `k8s/air-gap-images.txt` + `scripts/pull-air-gap-images.sh`
- **Self-hosted**: [`docs/self-host.md`](./docs/self-host.md)

## Documentation

- 🌐 **Website:** [`site/`](./site/) — landing page, quick start, features, deploy guides
- 🏗 **Architecture:** [`docs/architecture.md`](./docs/architecture.md)
- 🚀 **Deployment:** [`docs/deployment.md`](./docs/deployment.md)
- 🔧 **Self-hosting:** [`docs/self-host.md`](./docs/self-host.md)

## License

Business Source License 1.1 — See [LICENSE](./LICENSE) for details.
