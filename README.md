# Euno - Capability-Native Agent Governance System

A production-quality capability-based agent governance system with Azure integration, implementing Milestone 1 Sprints 1-3 of the execution plan.

## Overview

Euno provides a zero-trust security framework for AI agents, combining decentralized identity (DID) with capability-based authorization. The system ensures that AI agents operate with explicitly granted, time-limited, and cryptographically verifiable permissions.

## Architecture

### Components

1. **Capability Issuer** (`packages/capability-issuer`)
   - Issues JWT-based capability tokens
   - Integrates with Azure AD for user authentication
   - Uses Azure Key Vault for cryptographic signing
   - Implements policy-driven issuance based on user roles
   - **NEW Sprint 3**: Token renewal and capability attenuation

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

4. **CLI Tool** (`packages/cli`) **NEW Sprint 3**
   - Command-line interface for capability management
   - Initialize and validate agent manifests
   - Request and manage capability tokens

## Key Features

### Core Capabilities (Sprints 1-2)
- **Zero-Trust Architecture**: Every agent action requires explicit capability validation
- **Azure Integration**: Native support for Azure AD, Key Vault, and managed identities
- **W3C Standards**: JWT tokens compatible with W3C Verifiable Credentials
- **Pluggable Identity**: Abstracted identity provider interface for multi-vendor support
- **Comprehensive Audit**: All issuance and enforcement decisions are logged
- **Production Ready**: Full TypeScript implementation with comprehensive tests

### Sprint 3 Enhancements
- **Capability Delegation**: Attenuate tokens to create child capabilities with reduced scope
- **Token Renewal**: Refresh tokens without re-authentication
- **DID Integration**: W3C DID Document support (did:web format)
- **Developer CLI**: Tools for manifest creation and token management
- **Enhanced Audit**: Parent-child capability tracking in audit logs
- **Sandbox Hardening**: Production-grade container security (NEW)
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
   cp .env.template .env
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
   cp .env.template .env
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

- Tokens are signed using RSA-2048 keys stored in Azure Key Vault
- Hash locally, sign remotely pattern (Azure best practice)
- Public key available via `/api/v1/public-key` endpoint

### Token Validation

- Signature verification using public key
- Expiration check (default: 15 minutes)
- Audience validation
- Revocation support

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
```

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

## Future Enhancements (Sprint 4+)

- [ ] Full W3C Verifiable Credentials support
- [ ] DID:ION integration for decentralized identifiers
- [ ] Advanced constraints (rate limiting, data redaction)
- [ ] Microsoft Sentinel integration
- [ ] Cross-organization trust
- [ ] File system enforcement with Azure SAS tokens
- [ ] Database query enforcement with token-based auth
- [ ] External HTTP request monitoring

## Sprint 3 Implementation Status

### Completed Features ✓

1. **Capability Delegation (/attenuate endpoint)**
   - Child tokens validated as strict subsets of parent capabilities
   - Expiration cannot exceed parent token's expiration
   - Parent-child relationships tracked in audit logs via `parentCapabilityId`

2. **Token Renewal (/renew endpoint)**
   - Extends token lifetime without re-authentication
   - Maintains all original capabilities
   - Creates audit trail linking renewed tokens

3. **Developer CLI Tool**
   - Manifest initialization and validation
   - Configuration management
   - Extensible command structure for future features

4. **Enhanced Capability Types**
   - Resource patterns support wildcards (e.g., `api://service/*`)
   - `file_access`: Use resource pattern `storage://container/path`
   - `api_invoke`: Use resource pattern `api://service/endpoint`
   - Conditions field available for advanced constraints

5. **DID Integration**
   - `did:web` format fully supported
   - DID Document endpoint at `/.well-known/did.json`
   - W3C standards-compliant structure
   - Ready for `did:ion` extension

6. **Sandbox Hardening (Sprint 3 Security Requirements)**
   - **Non-privileged User Execution**
     - Capability Issuer runs as UID 1001
     - Tool Gateway runs as UID 1002
     - Both enforce `runAsNonRoot: true`
   - **AppArmor/SELinux Profiles**
     - Blocks ptrace, mount, sys_admin, sys_module
     - Prevents privilege escalation
     - Profile: `k8s/security-policies/apparmor-profile.conf`
   - **Resource Limits (cgroups)**
     - CPU: 250m-1000m per container
     - Memory: 512Mi-2Gi per container
     - Node.js: `--max-old-space-size=512`
   - **Environment Scrubbing**
     - No secrets in environment variables
     - Kubernetes Secrets for sensitive data
     - ConfigMaps for non-sensitive config
   - **Read-Only Root Filesystem**
     - Only tmpfs mounts writable (/tmp, /app/.npm)
     - Persistent volumes quota: 0
   - **Network Policies**
     - Default deny all ingress/egress
     - Allowlist-only egress to necessary services
     - DNS, Azure services, backend only
   - **Pod Security Standards**
     - Restricted mode enforced
     - Capability drop: ALL
     - Seccomp: RuntimeDefault
     - No host namespaces

### Production Readiness

- ✓ All 26 existing tests passing
- ✓ TypeScript compilation with strict mode enabled
- ✓ Zero compiler errors or warnings
- ✓ Comprehensive audit logging
- ✓ Kill switch mechanisms (global, session, agent-scoped)
- ✓ Cryptographic evidence generation
- ✓ Role-based capability mapping

### Design Principles

- **Security**: Token validation at every gateway interaction
- **Auditability**: Complete audit trail with parent-child relationships
- **Extensibility**: Adapter pattern for pluggable identity and signing
- **Standards Compliance**: W3C DIDs, JWT/VC compatibility
- **Zero Trust**: No implicit trust, always verify

## Contributing

This project follows the Azure-Integrated Hybrid Execution Plan for Capability-Native Agent Governance. See `execution-plan.md` for the full roadmap.

## License

ISC

## References

- [Building an Auditable Security Layer for Agentic AI](https://azurefeeds.com/2026/04/22/building-an-auditable-security-layer-for-agentic-ai/)
- [Zero-Trust Agents: Adding Identity and Access to Multi-Agent Workflows](https://techcommunity.microsoft.com/blog/azure-ai-foundry-blog/zero-trust-agents-adding-identity-and-access-to-multi-agent-workflows/4427790)
- [Microsoft Entra Verified ID Architecture](https://learn.microsoft.com/en-us/entra/verified-id/introduction-to-verifiable-credentials-architecture)
- [W3C Decentralized Identifiers (DIDs)](https://www.w3.org/TR/did-core/)
- [W3C Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/)