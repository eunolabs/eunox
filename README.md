<p align="center">
  <img src="https://github.com/user-attachments/assets/c1bf707c-85dd-4f5d-aeff-a77188af871e" alt="eunox" height="96">
</p>

<h1 align="center">eunox</h1>

<p align="center">
  <strong>Policy proxy for AI agents — Go implementation.</strong><br>
  One YAML file enforces what every agent is allowed to do —
  <em>before</em> the tool call reaches your backend.
</p>

<p align="center">
  <a href="https://github.com/edgeobs/eunox/blob/main/LICENSE"><img alt="License: BUSL-1.1" src="https://img.shields.io/badge/license-BUSL--1.1-blue.svg"></a>
  <a href="https://go.dev/"><img alt="Go 1.25+" src="https://img.shields.io/badge/go-%E2%89%A51.25-00ADD8"></a>
  <a href="https://spec.modelcontextprotocol.io/"><img alt="MCP" src="https://img.shields.io/badge/MCP-supported-7c3aed"></a>
</p>

---

## What is eunox?

eunox is the **Go reimplementation** of the Euno Platform enterprise services.
It provides a policy proxy for AI agents that speak the
[Model Context Protocol](https://spec.modelcontextprotocol.io/), delivering
improved performance, lower memory usage, and simplified deployment.

## Services

| Service | Path | Description |
|---------|------|-------------|
| Gateway | `cmd/gateway/` | Enforcement gateway — policy evaluation, rate limiting, kill switch |
| Issuer | `cmd/issuer/` | Capability token issuance, IdP integration |
| Minter | `cmd/minter/` | API-key lifecycle, admin auth, anomaly detection |
| DB Token Service | `cmd/db-token-svc/` | Short-lived DB credentials (AWS RDS, Azure SQL, GCP Cloud SQL) |
| Storage Grant Service | `cmd/storage-grant-svc/` | Presigned URLs (AWS S3, Azure Blob, GCP GCS) |
| Posture Emitter | `cmd/posture-emitter/` | Security posture reporting |

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
├── web/                    # Static website
├── site/                   # Astro blog/site
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

See [`k8s/`](./k8s/) for Kubernetes manifests and Helm charts,
and [`infra/`](./infra/) for Docker Compose and Terraform configurations.

For detailed deployment instructions, see [`docs/DEPLOYMENT.md`](./docs/DEPLOYMENT.md).

## Documentation

- 🌐 **Website:** [`web/`](./web/) — landing page, quick start, features
- 🏗 **Architecture:** [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md)
- 🚀 **Deployment:** [`docs/DEPLOYMENT.md`](./docs/DEPLOYMENT.md)
- 🔧 **Self-hosting:** [`docs/self-host.md`](./docs/self-host.md)

## License

Business Source License 1.1 — See [LICENSE](./LICENSE) for details.
