# Euno - Capability-Native Agent Governance System

A production-quality capability-based agent governance system with Azure integration, implementing Milestone 1 Sprint 1 of the execution plan.

## Overview

Euno provides a zero-trust security framework for AI agents, combining decentralized identity (DID) with capability-based authorization. The system ensures that AI agents operate with explicitly granted, time-limited, and cryptographically verifiable permissions.

## Architecture

### Components

1. **Capability Issuer** (`packages/capability-issuer`)
   - Issues JWT-based capability tokens
   - Integrates with Azure AD for user authentication
   - Uses Azure Key Vault for cryptographic signing
   - Implements policy-driven issuance based on user roles

2. **Tool Gateway** (`packages/tool-gateway`)
   - Validates capability tokens
   - Enforces fine-grained action permissions
   - Provides audit logging for all access decisions
   - Acts as a proxy for backend services

3. **Common** (`packages/common`)
   - Shared types, interfaces, and utilities
   - Logging infrastructure
   - Cryptographic utilities

## Key Features

- **Zero-Trust Architecture**: Every agent action requires explicit capability validation
- **Azure Integration**: Native support for Azure AD, Key Vault, and managed identities
- **W3C Standards**: JWT tokens compatible with W3C Verifiable Credentials
- **Pluggable Identity**: Abstracted identity provider interface for multi-vendor support
- **Comprehensive Audit**: All issuance and enforcement decisions are logged
- **Production Ready**: Full TypeScript implementation with comprehensive tests

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

## Future Enhancements (Sprint 2+)

- [ ] Full W3C Verifiable Credentials support
- [ ] DID:ION integration for decentralized identifiers
- [ ] Token renewal endpoint
- [ ] Capability delegation and attenuation
- [ ] Advanced constraints (rate limiting, data redaction)
- [ ] Microsoft Sentinel integration
- [ ] Session-scoped kill switch
- [ ] Cross-organization trust

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