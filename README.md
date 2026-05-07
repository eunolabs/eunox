# Euno - Capability-Native Agent Governance System

A production-quality capability-based agent governance system with Azure integration.

## Project status

Euno is in **Stage 0** of a [staged execution plan](docs/mvp.md).  The
codebase contains a substantial Stage-5 infrastructure (multi-cloud KMS,
Redis-backed kill switches, cross-chain audit anchors, partner DID
resolution) built ahead of Stage-1 buyers.  Stage 0 exists to stop that
drift: core packages (`tool-gateway`, `capability-issuer`, `common`,
`agent-runtime`, `framework-adapters`) are **feature-frozen** — accepting
only security fixes, dependency bumps, and design-partner-driven changes —
while engineering focus shifts to building the lightweight MCP-based wedge
product targeted at individual developers.  See
[`docs/stage-0-freeze.md`](docs/stage-0-freeze.md) for the freeze policy
and PR-review checklist, and [`docs/mvp.md`](docs/mvp.md) for the full
staged plan.

## Overview

Euno provides a zero-trust security framework for AI agents, combining decentralized identity (DID) with capability-based authorization. The system ensures that AI agents operate with explicitly granted, time-limited, and cryptographically verifiable permissions.

## Architecture

### Components

1. **Capability Issuer** (`packages/capability-issuer`)
   - Issues JWT-based capability tokens
   - Integrates with Azure AD for user authentication
   - Uses Azure Key Vault, AWS KMS, or GCP Cloud KMS for cryptographic signing
   - Implements policy-driven issuance based on user roles
   - Token renewal and capability attenuation

2. **Tool Gateway** (`packages/tool-gateway`)
   - Validates capability tokens
   - Enforces fine-grained action permissions
   - Provides audit logging for all access decisions
   - Acts as a proxy for backend services
   - Session-scoped kill switch for emergency shutdowns

3. **Common** (`packages/common`)
   - Shared types, interfaces, and utilities
   - Logging infrastructure
   - Cryptographic utilities
   - Adapter pattern for pluggable identity and signing providers

4. **CLI Tool** (`packages/cli`)
   - Command-line interface for capability management
   - Initialize and validate agent manifests
   - Request and manage capability tokens

## Key Features

- **Zero-Trust Architecture**: Every agent action requires explicit capability validation
- **Azure Integration**: Native support for Azure AD, Key Vault, and managed identities
- **W3C Standards**: JWT tokens compatible with W3C Verifiable Credentials
- **Pluggable Identity**: Abstracted identity provider interface for multi-vendor support
- **Comprehensive Audit**: All issuance and enforcement decisions are logged
- **Production Ready**: Full TypeScript implementation with comprehensive tests
- **Capability Delegation**: Attenuate tokens to create child capabilities with reduced scope
- **Token Renewal**: Refresh tokens without re-authentication
- **DID Integration**: W3C DID Document support (did:web, did:ion, did:key)
- **Developer CLI**: Tools for manifest creation and token management
- **Enhanced Audit**: Parent-child capability tracking in audit logs
- **Sandbox Hardening**: Production-grade container security
  - Non-privileged user execution (UID 1001/1002)
  - AppArmor/SELinux profiles blocking dangerous syscalls
  - CPU/memory limits via cgroups
  - Read-only root filesystem with tmpfs for temporary files
  - Environment variable scrubbing (secrets via Kubernetes Secrets)
  - Network policies with default-deny egress
  - Pod Security Standards (restricted mode)
  - Resource quotas and limit ranges

## Getting Started

### Prerequisites

- Node.js >= 18.0.0
- npm >= 9.0.0
- Azure subscription with:
  - Azure AD tenant
  - Azure Key Vault
  - Appropriate permissions for key operations

### Installation

```bash
# Install dependencies
npm install

# Build all packages
npm run build

# Run tests
npm run test
```

### Configuration

#### Capability Issuer

1. Copy the environment template:
   ```bash
   cd packages/capability-issuer
   cp .env.example .env
   ```

2. Configure your Azure resources in `.env`:
   - Set `AZURE_KEYVAULT_URL` to your Key Vault URL
   - Set `AZURE_AD_TENANT_ID` and `AZURE_AD_CLIENT_ID`
   - Configure authentication credentials

3. Create a signing key in Azure Key Vault:
   ```bash
   az keyvault key create --vault-name <your-vault> --name capability-signing-key --kty RSA --size 2048
   ```

#### Tool Gateway

1. Copy the environment template:
   ```bash
   cd packages/tool-gateway
   cp .env.example .env
   ```

2. Set `ISSUER_PUBLIC_KEY_URL` to point to your Capability Issuer instance

### Running Locally

```bash
# Terminal 1: Start Capability Issuer
cd packages/capability-issuer
npm run dev

# Terminal 2: Start Tool Gateway
cd packages/tool-gateway
npm run dev
```

## Usage

### Issuing a Capability Token

```bash
# Obtain an Azure AD token for your user
# (use Azure CLI or MSAL library)

# Request a capability token
curl -X POST http://localhost:3001/api/v1/issue \
  -H "Authorization: Bearer <azure-ad-token>" \
  -H "Content-Type: application/json" \
  -d '{
    "agentId": "my-agent-001",
    "requestedCapabilities": [
      {
        "resource": "api://service/endpoint",
        "actions": ["read", "write"]
      }
    ]
  }'
```

### Using the Token

```bash
# Make a request through the Tool Gateway
curl -X GET http://localhost:3002/proxy/service/endpoint \
  -H "Authorization: Bearer <capability-token>"
```

## Role-Based Capabilities

The system maps Azure AD roles to capability constraints:

| Role | Capabilities |
|------|-------------|
| **SalesManager** | Read/write access to CRM customers, read reports, read/write sales data |
| **Viewer** | Read-only access to CRM customers, reports, and sales data |
| **DataScientist** | Read/write analytics APIs, read datasets, execute ML models |
| **Administrator** | Full access to all APIs and storage |

## Security Features

### Cryptographic Signing

- Tokens are signed using RSA-2048 or EC keys stored in Azure Key Vault, AWS KMS, or GCP Cloud KMS
- Hash locally, sign remotely pattern (cloud KMS best practice)
- Public key available via `/api/v1/public-key` endpoint
- Supports multiple signing algorithms: RS256, RS384, RS512, ES256, ES384, ES512

### Token Validation

- Signature verification using public key
- Expiration check (default: 15 minutes)
- Audience validation
- Revocation support (in-process by default; configure `REDIS_URL` to share revocations across gateway replicas — see `docs/DISTRIBUTED_STATE.md`)

### Audit Logging

All capability operations are logged with:
- Timestamp
- Agent/session ID
- User ID
- Action and resource
- Decision (allow/deny)
- Reason for denial (if applicable)

## API Reference

### Capability Issuer

#### `POST /api/v1/issue`

Issue a new capability token.

**Headers:**
- `Authorization: Bearer <azure-ad-token>` (required)

**Request Body:**
```json
{
  "agentId": "string (required)",
  "requestedCapabilities": [
    {
      "resource": "string",
      "actions": ["read", "write", ...]
    }
  ]
}
```

**Response:**
```json
{
  "token": "string (JWT)",
  "expiresAt": "number (Unix timestamp)",
  "tokenId": "string (UUID)",
  "capabilities": [...]
}
```

#### `POST /api/v1/attenuate` **NEW Sprint 3**

Create a child capability token with reduced scope.

**Headers:**
- `Authorization: Bearer <parent-capability-token>` (required)

**Request Body:**
```json
{
  "requestedCapabilities": [
    {
      "resource": "string",
      "actions": ["read"]  // Must be subset of parent
    }
  ],
  "ttl": 300  // Optional, max is parent expiration
}
```

**Response:** Same as `/issue`

#### `POST /api/v1/renew` **NEW Sprint 3**

Renew an existing capability token with fresh expiration.

**Headers:**
- `Authorization: Bearer <current-capability-token>` (required)

**Request Body:**
```json
{
  "ttl": 900  // Optional, defaults to 15 minutes
}
```

**Response:** Same as `/issue` with new token and expiration

#### `GET /api/v1/public-key`

Get the public key for token verification.

**Response:**
```json
{
  "publicKey": "string (PEM format)"
}
```

#### `GET /.well-known/did.json`

Get the DID document for the issuer.

### Tool Gateway

#### `POST /api/v1/validate`

Validate a capability token for a specific action (testing endpoint).

**Headers:**
- `Authorization: Bearer <capability-token>` (required)

**Request Body:**
```json
{
  "action": "read | write | delete | execute | admin",
  "resource": "string (resource identifier)"
}
```

**Response:**
```json
{
  "allowed": "boolean",
  "reason": "string (if denied)",
  "matchedCapability": {...}
}
```

#### `* /proxy/*`

Proxy requests to backend services with capability validation.

All requests under `/proxy/*` are validated and forwarded to the configured backend service.

## CLI Tool **NEW Sprint 3**

The Euno CLI provides developer tools for capability management.

### Installation

```bash
# From the CLI package directory
cd packages/cli
npm install
npm run build

# Or use npx from the root
npx euno --help
```

### Commands

#### `euno init`

Initialize a new agent capability manifest.

```bash
euno init --agent "MyAgent" --output ./manifest.yaml
```

Creates a template manifest file with:
- Agent ID and metadata
- Example capability constraints
- Customizable resource patterns

#### `euno validate`

Validate a capability manifest file.

```bash
euno validate ./manifest.yaml
```

Checks for:
- Required fields (agentId, name, version)
- Valid capability structure
- Proper action types

#### `euno request`

Request a capability token from the issuer (documentation only - use curl for actual requests).

```bash
euno request --agent my-agent --token $AZURE_AD_TOKEN
```

#### `euno config`

Show current CLI configuration and environment variables.

```bash
euno config
```

## Testing

### Unit Tests

```bash
# Run all tests
npm run test

# Run tests for a specific package
cd packages/common
npm test

# Run tests with coverage
npm test -- --coverage
```

### Integration Testing

See the test files in each package's `tests/` directory for examples of:
- Token issuance flows
- Token verification
- Action enforcement
- Role mapping

## Deployment

### Docker Deployment (Sprint 3 Hardened)

The system includes hardened Dockerfiles with Sprint 3 security controls:

```bash
# Build hardened images
docker build -f packages/capability-issuer/Dockerfile -t euno/capability-issuer:latest .
docker build -f packages/tool-gateway/Dockerfile -t euno/tool-gateway:latest .

# Images include:
# - Non-privileged user (UID 1001/1002)
# - Read-only root filesystem
# - Memory limits (--max-old-space-size)
# - Health checks
```

### Kubernetes Deployment (Sprint 3 Sandbox Hardening)

Full production deployment with Sprint 3 security hardening:

```bash
# 1. Create namespace with Pod Security Standards
kubectl apply -f k8s/pod-security-standards.yaml

# 2. Install AppArmor profiles (on each node)
sudo cp k8s/security-policies/apparmor-profile.conf /etc/apparmor.d/euno-restricted
sudo apparmor_parser -r /etc/apparmor.d/euno-restricted

# 3. Create secrets
kubectl create secret generic issuer-secrets \
  --from-literal=azure-client-secret="YOUR_SECRET" \
  --namespace=euno-system

kubectl create secret generic gateway-secrets \
  --from-literal=admin-api-key="YOUR_API_KEY" \
  --namespace=euno-system

# 4. Apply network policies
kubectl apply -f k8s/network-policies.yaml

# 5. Deploy services
kubectl apply -f k8s/capability-issuer-deployment.yaml
kubectl apply -f k8s/tool-gateway-deployment.yaml

# 6. Verify security hardening
kubectl get pods -n euno-system -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.securityContext.runAsUser}{"\n"}{end}'
```

**Security Features Enforced:**
- ✅ Non-privileged user (runAsNonRoot)
- ✅ AppArmor/SELinux profiles
- ✅ Resource limits (CPU/memory)
- ✅ Read-only root filesystem
- ✅ Network policies (default deny)
- ✅ Pod Security Standards (restricted)
- ✅ Capability drop (ALL)
- ✅ Seccomp profile (RuntimeDefault)

See `k8s/SECURITY.md` for complete deployment and security validation guide.

### Azure Kubernetes Service (AKS)

1. Build Docker images:
   ```bash
   docker build -f packages/capability-issuer/Dockerfile -t euno/capability-issuer:latest .
   docker build -f packages/tool-gateway/Dockerfile -t euno/tool-gateway:latest .
   ```

2. Deploy to AKS with Managed Identity:
   - Enable pod identity
   - Grant Key Vault access to the managed identity
   - Deploy using provided Kubernetes manifests

### Environment Variables

Required environment variables for production:
- Set `NODE_ENV=production`
- Use Managed Identity (`AZURE_CREDENTIAL_TYPE=managed-identity`)
- Configure appropriate logging destinations
- Set secure `ISSUER_DID` (e.g., `did:web:your-domain.com`)

## Future Enhancements

Planned improvements include:

- [ ] Self-service web UI for capability requests and pilot dashboards (`web/`)
- [ ] Dynamic policy engine (OPA / Cedar) plugged in via the existing condition registry
- [ ] Multi-region active/active issuer
- [ ] Federated trust to a partner organization (see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) cross-org section)
- [ ] Continuous evidence-chain verification job
- [ ] OpenTelemetry tracing across issuer → gateway → backend
- [ ] Submit the capability JWT profile as an IETF Internet-Draft

## Implementation Status

All core capabilities have shipped:

- ✅ Foundation, sandbox baseline, gateway enforcement, audit logging
- ✅ DID support (did:web, did:ion, did:key), delegation, renewal, distributed kill switch & revocation, framework adapters
- ✅ Production pilot deployment (Bicep IaC, Sentinel analytics, HA/HPA)
- ✅ Pilot stabilization, multi-cloud parity (AWS / GCP), manifest cookbook

## Production Deployment Checklist

Before deploying Euno to production, ensure all items below are completed:

### Security Configuration

- [ ] **Environment Variables**: Set `NODE_ENV=production` for all services
- [ ] **CORS Configuration**: Set `ALLOWED_ORIGINS` to whitelist only trusted domains
  ```bash
  ALLOWED_ORIGINS=https://your-app.com,https://admin.your-app.com
  ```
- [ ] **Rate Limiting**: Configure appropriate rate limits
  ```bash
  RATE_LIMIT_WINDOW_MS=60000
  RATE_LIMIT_MAX_REQUESTS=100  # Adjust based on expected load
  ```
- [ ] **Admin API Key**: Set strong admin API key for tool-gateway
  ```bash
  ADMIN_API_KEY=$(openssl rand -hex 32)
  ```
- [ ] **Secrets Management**: All secrets stored in a secrets manager (Azure Key Vault) or Kubernetes Secrets — never committed to the repository; inject at runtime via environment variables or mounted files
- [ ] **TLS/HTTPS**: Enable TLS for all external endpoints
- [ ] **Network Policies**: Apply Kubernetes Network Policies (see `k8s/network-policies.yaml`)

### Identity & Signing

- [ ] **Azure Key Vault**: Signing key created and accessible via Managed Identity
  ```bash
  az keyvault key create --vault-name <vault> --name capability-signing-key --kty RSA --size 2048
  ```
- [ ] **Azure AD App Registration**: Application registered with correct permissions
- [ ] **Managed Identity**: Enabled for capability-issuer and tool-gateway pods
- [ ] **DID Configuration**: Set production `ISSUER_DID` (e.g., `did:web:your-domain.com`)
- [ ] **Public Key Endpoint**: Ensure `/.well-known/did.json` is publicly accessible

### Kubernetes Security

- [ ] **Pod Security Standards**: Applied restricted mode (see `k8s/pod-security-standards.yaml`)
- [ ] **AppArmor Profiles**: Installed on all nodes
  ```bash
  sudo cp k8s/security-policies/apparmor-profile.conf /etc/apparmor.d/euno-restricted
  sudo apparmor_parser -r /etc/apparmor.d/euno-restricted
  ```
- [ ] **Non-Root Users**: All containers run as UID 1001/1002
- [ ] **Read-Only Filesystem**: Root filesystem read-only with tmpfs mounts
- [ ] **Resource Limits**: CPU and memory limits configured
- [ ] **Security Context**: `allowPrivilegeEscalation: false`, `runAsNonRoot: true`

### High Availability

- [ ] **Multiple Replicas**: At least 2 replicas for each service
- [ ] **Distributed Revocation**: Redis deployed for token revocation (see `docs/DISTRIBUTED_STATE.md`)
  ```bash
  REDIS_URL=redis://euno-redis:6379
  ```
- [ ] **Distributed Kill Switch**: Redis deployed so kills (global / session / agent) propagate across every gateway replica (see `docs/DISTRIBUTED_STATE.md`). The same `REDIS_URL` configured for distributed revocation is reused; without it a kill issued on one pod is **not** honoured on the others.
- [ ] **Health Checks**: Liveness and readiness probes configured
- [ ] **Horizontal Pod Autoscaler**: Configured for automatic scaling

### Monitoring & Observability

- [ ] **Azure Monitor**: Log Analytics workspace configured
- [ ] **Application Insights**: Enabled for performance monitoring
- [ ] **Audit Logging**: All capability operations logged to Azure Monitor
- [ ] **Alerts**: Configured for:
  - High denied action rate (potential attack)
  - Kill switch activations
  - Service health failures
  - Redis connection errors
  - Rate limit exceeded events
- [ ] **Dashboards**: Operational dashboards created

### Testing

- [ ] **Load Testing**: Tested with expected production load
- [ ] **Security Testing**: Penetration testing completed
- [ ] **Disaster Recovery**: Backup and restore procedures tested
- [ ] **Incident Response**: Team trained on runbook (see `docs/INCIDENT_RESPONSE_RUNBOOK.md`)

### Documentation

- [ ] **Deployment Guide**: `docs/DEPLOYMENT.md` reviewed
- [ ] **Production Checklist**: `docs/PRODUCTION_DEPLOYMENT_CHECKLIST.md` completed top-to-bottom
- [ ] **Pilot Playbook**: `docs/PILOT_PLAYBOOK.md` reviewed
- [ ] **API Documentation**: OpenAPI specs in `docs/openapi/` published
- [ ] **Architecture Diagrams**: Up to date
- [ ] **Runbooks**: Incident response procedures documented

### Validation

- [ ] **All Tests Passing**: `npm test` passes with 100% success rate
- [ ] **Build Successful**: `npm run build` completes without errors
- [ ] **Lint Clean**: `npm run lint` reports no issues
- [ ] **Security Scan**: No critical vulnerabilities in `npm audit`
- [ ] **Token Issuance**: End-to-end token issuance tested
- [ ] **Token Validation**: Gateway correctly validates and enforces tokens
- [ ] **Token Revocation**: Revocation works across all gateway instances (requires `REDIS_URL`; see `docs/DISTRIBUTED_STATE.md`)
- [ ] **Kill Switch**: Global, session, and agent kill switches tested across all gateway instances (requires `REDIS_URL`; see `docs/DISTRIBUTED_STATE.md`)

### Performance Targets

- [ ] Gateway latency < 5ms (p95)
- [ ] Token issuance < 500ms (p95)
- [ ] Supports 50+ concurrent agents
- [ ] Handles 1000+ requests/minute per gateway instance

### Post-Deployment

- [ ] **Monitoring Active**: All alerts and dashboards operational
- [ ] **Team On-Call**: Incident response team assigned
- [ ] **Rollback Plan**: Procedure documented and tested
- [ ] **Communication Plan**: Stakeholders notified of deployment

## Contributing

See [`docs/README.md`](docs/README.md) for the documentation index and contribution guidelines.

Code ownership and review responsibilities are formalized in [`CODEOWNERS`](CODEOWNERS).

## License

ISC

## References

- [Building an Auditable Security Layer for Agentic AI](https://azurefeeds.com/2026/04/22/building-an-auditable-security-layer-for-agentic-ai/)
- [Zero-Trust Agents: Adding Identity and Access to Multi-Agent Workflows](https://techcommunity.microsoft.com/blog/azure-ai-foundry-blog/zero-trust-agents-adding-identity-and-access-to-multi-agent-workflows/4427790)
- [Microsoft Entra Verified ID Architecture](https://learn.microsoft.com/en-us/entra/verified-id/introduction-to-verifiable-credentials-architecture)
- [W3C Decentralized Identifiers (DIDs)](https://www.w3.org/TR/did-core/)
- [W3C Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/)