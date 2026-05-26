# Repository Structure

eunox is a single Go module containing all platform services.

## Module

```
github.com/edgeobs/eunox
```

## Package Organization

| Directory | Purpose | License |
|-----------|---------|---------|
| `cmd/` | Service entry points (main packages) | BUSL-1.1 |
| `internal/` | Private application logic | BUSL-1.1 |
| `pkg/` | Public importable library packages | BUSL-1.1 |
| `migrations/` | SQL schema migrations | BUSL-1.1 |
| `k8s/` | Kubernetes manifests and Helm charts | BUSL-1.1 |
| `infra/` | Docker Compose, Terraform, cloud configs | BUSL-1.1 |
| `docs/` | Documentation | BUSL-1.1 |
| `web/` | Static website | BUSL-1.1 |
| `site/` | Astro blog/site | BUSL-1.1 |
| `blogs/` | Blog content | BUSL-1.1 |

## Services

| Service | Binary | Description |
|---------|--------|-------------|
| Gateway | `cmd/gateway` | Policy enforcement proxy |
| Issuer | `cmd/issuer` | Capability token issuance |
| Minter | `cmd/minter` | API-key lifecycle management |
| DB Token Service | `cmd/db-token-svc` | Short-lived database credentials |
| Storage Grant Service | `cmd/storage-grant-svc` | Presigned storage URLs |
| Posture Emitter | `cmd/posture-emitter` | Security posture reporting |
