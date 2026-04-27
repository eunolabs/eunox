# Euno - Capability-Native Agent Governance System

A production-ready capability-based security system for AI agent governance, built on Azure-native services with support for decentralized identity.

## Overview

Euno implements a **capability-based security model** for AI agents, ensuring that:
- Every agent action is explicitly authorized
- Tokens are cryptographically signed and time-limited
- All access is mediated through a central enforcement gateway
- Comprehensive audit trails track every decision

This implementation follows the **Zero-Trust Agents** pattern documented by Microsoft, treating AI models as untrusted proposers where all decisions are verified by external mechanical enforcement.

## Architecture

The system consists of three main components:

### 1. **Capability Issuer** (`packages/capability-issuer`)
Issues cryptographically signed capability tokens to authorized agents.

**Key Features:**
- Azure AD integration for user authentication
- Azure Key Vault for cryptographic signing
- Policy-driven capability issuance based on user roles
- W3C Verifiable Credentials compatible token format
- DID (Decentralized Identifier) support

### 2. **Tool Gateway** (`packages/tool-gateway`)
Enforces capability constraints on all agent actions.

**Key Features:**
- JWT token verification with signature validation
- Fine-grained action and resource matching
- Kill-switch functionality (global, session, and agent-level)
- Cryptographic audit evidence generation
- Admin API for operational control
- Request proxying to backend services

### 3. **Common Library** (`packages/common`)
Shared types, utilities, and interfaces.

**Key Features:**
- Type-safe capability data models
- Pluggable identity provider interface
- Audit logging utilities
- Kill-switch manager
- Evidence signing framework

## Getting Started

### Prerequisites

- Node.js >= 18.0.0
- npm >= 9.0.0
- Azure subscription (for Key Vault and Azure AD)

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

#### Capability Issuer Setup

1. Copy the example environment file:
```bash
cd packages/capability-issuer
cp .env.example .env
```

2. Configure Azure resources:
   - Create an Azure Key Vault
   - Generate or import an RSA key for signing
   - Create an Azure AD application
   - Set up user roles and permissions

3. Update `.env` with your Azure configuration

#### Tool Gateway Setup

1. Copy the example environment file:
```bash
cd packages/tool-gateway
cp .env.example .env
```

2. Update `.env` with your configuration:
   - Set `ISSUER_PUBLIC_KEY_URL` to your Capability Issuer URL
   - Set `BACKEND_SERVICE_URL` to your protected service URL
   - (Optional) Set `ADMIN_API_KEY` for admin endpoint authentication

### Running the Services

```bash
# Run Capability Issuer
cd packages/capability-issuer
npm run dev

# Run Tool Gateway (in another terminal)
cd packages/tool-gateway
npm run dev
```

## Usage

### Issuing Capability Tokens

```bash
# POST /api/v1/issue
curl -X POST http://localhost:3001/api/v1/issue \
  -H "Authorization: Bearer <Azure-AD-Token>" \
  -H "Content-Type: application/json" \
  -d '{
    "agentId": "my-agent-001",
    "requestedCapabilities": [
      {
        "resource": "api://crm/customers",
        "actions": ["read", "write"]
      }
    ]
  }'
```

### Making Authorized Requests

```bash
# Requests through the Tool Gateway with capability token
curl -X GET http://localhost:3002/proxy/crm/customers \
  -H "Authorization: Bearer <Capability-Token>"
```

### Admin API (Kill-Switch Management)

```bash
# Get kill-switch status
curl http://localhost:3002/admin/kill-switch/status \
  -H "X-Admin-API-Key: <Your-Admin-Key>"

# Activate global kill switch (blocks all agents)
curl -X POST http://localhost:3002/admin/kill-switch/global/activate \
  -H "X-Admin-API-Key: <Your-Admin-Key>"

# Kill a specific session
curl -X POST http://localhost:3002/admin/kill-switch/session/session-123/kill \
  -H "X-Admin-API-Key: <Your-Admin-Key>"

# Kill a specific agent
curl -X POST http://localhost:3002/admin/kill-switch/agent/agent-456/kill \
  -H "X-Admin-API-Key: <Your-Admin-Key>"
```

## Security Features

### Sprint 1 (Foundation)
- ✅ Azure AD integration for user authentication
- ✅ Azure Key Vault integration for cryptographic signing
- ✅ JWT-based capability tokens with W3C VC compatibility
- ✅ Token signature verification
- ✅ Resource and action-based access control
- ✅ Wildcard resource matching
- ✅ Token expiration enforcement
- ✅ Audit logging

### Sprint 2 (System Hardening)
- ✅ Policy-driven capability issuance
- ✅ Live Azure AD role and group membership integration
- ✅ Cryptographic audit evidence with signed records
- ✅ Kill-switch functionality (global, session, agent-level)
- ✅ Admin API for operational control
- ✅ Enhanced monitoring and logging

### Planned (Sprint 3+)
- ⏳ Full DID integration (did:web, did:ion)
- ⏳ Capability delegation and attenuation
- ⏳ Advanced constraints (rate limits, data redaction)
- ⏳ Cross-organization trust
- ⏳ Microsoft Sentinel integration
- ⏳ Evidence verification endpoints

## Development

### Project Structure

```
euno/
├── packages/
│   ├── common/               # Shared types and utilities
│   │   ├── src/
│   │   │   ├── types.ts      # Type definitions
│   │   │   ├── utils.ts      # Utility functions
│   │   │   ├── logger.ts     # Logging utilities
│   │   │   ├── evidence.ts   # Cryptographic audit evidence
│   │   │   └── kill-switch.ts # Kill-switch manager
│   │   └── tests/
│   ├── capability-issuer/    # Token issuance service
│   │   ├── src/
│   │   │   ├── index.ts      # Express server
│   │   │   ├── issuer-service.ts
│   │   │   ├── identity-provider.ts
│   │   │   └── signer.ts     # Azure Key Vault integration
│   │   └── tests/
│   └── tool-gateway/         # Enforcement gateway
│       ├── src/
│       │   ├── index.ts      # Express server
│       │   ├── enforcement.ts # Capability enforcement engine
│       │   ├── verifier.ts   # Token verification
│       │   └── admin-api.ts  # Admin API endpoints
│       └── tests/
├── execution-plan.md         # Detailed implementation plan
└── package.json             # Workspace configuration
```

### Running Tests

```bash
# Run all tests
npm test

# Run tests for a specific package
cd packages/common && npm test
cd packages/capability-issuer && npm test
cd packages/tool-gateway && npm test
```

### Building

```bash
# Build all packages
npm run build

# Build a specific package
cd packages/common && npm run build
```

## API Reference

### Capability Issuer

#### `POST /api/v1/issue`
Issue a capability token for an agent.

**Request:**
- Headers:
  - `Authorization: Bearer <Azure-AD-Token>`
- Body:
  ```json
  {
    "agentId": "string",
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

#### `GET /.well-known/did.json`
Get the DID document for the issuer.

### Tool Gateway

#### `POST /api/v1/validate`
Validate an action request (for testing).

**Request:**
- Headers:
  - `Authorization: Bearer <Capability-Token>`
- Body:
  ```json
  {
    "action": "read|write|execute|delete|admin",
    "resource": "string (e.g., api://service/endpoint)"
  }
  ```

#### `/proxy/*`
Proxy requests to backend services with capability validation.

#### Admin API

All admin endpoints require `X-Admin-API-Key` header if `ADMIN_API_KEY` is configured.

- `GET /admin/kill-switch/status` - Get kill-switch status
- `POST /admin/kill-switch/global/activate` - Activate global kill switch
- `POST /admin/kill-switch/global/deactivate` - Deactivate global kill switch
- `POST /admin/kill-switch/session/:sessionId/kill` - Kill a session
- `POST /admin/kill-switch/agent/:agentId/kill` - Kill an agent
- `POST /admin/kill-switch/session/:sessionId/revive` - Revive a session
- `POST /admin/kill-switch/agent/:agentId/revive` - Revive an agent
- `POST /admin/kill-switch/reset` - Reset all kill switches

## Deployment

### Azure Deployment

This system is designed to run on Azure with the following services:
- **Azure Kubernetes Service (AKS)** or **Azure Container Instances** for hosting
- **Azure Key Vault** for cryptographic key management
- **Azure AD (Entra ID)** for identity and access management
- **Azure API Management** for enhanced gateway capabilities
- **Azure Monitor / Log Analytics** for observability
- **Microsoft Sentinel** for security analytics (optional)

### Environment Variables

See `.env.example` files in each package for required configuration.

## Contributing

This project follows the execution plan defined in `execution-plan.md`. See that document for the roadmap and upcoming features.

## License

ISC

## References

- [Zero-Trust Agents (Microsoft Foundry Blog)](https://techcommunity.microsoft.com/blog/azure-ai-foundry-blog/zero-trust-agents-adding-identity-and-access-to-multi-agent-workflows/4427790)
- [Building an Auditable Security Layer for Agentic AI](https://azurefeeds.com/2026/04/22/building-an-auditable-security-layer-for-agentic-ai/)
- [Microsoft Entra Verified ID Architecture](https://learn.microsoft.com/en-us/entra/verified-id/introduction-to-verifiable-credentials-architecture)
- [W3C Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/)
- [W3C Decentralized Identifiers (DIDs)](https://www.w3.org/TR/did-core/)
