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

The system is split into focused packages under `packages/`:

### 1. **Capability Issuer** (`packages/capability-issuer`)
Issues cryptographically signed capability tokens to authorized agents.

**Key Features:**
- Pluggable identity providers: Azure AD, AWS Cognito, GCP Cloud Identity, W3C DID
- Pluggable signers: Azure Key Vault, AWS KMS, GCP Cloud KMS, DID-bound keys
- Policy-driven capability issuance based on user roles
- Token attenuation (`/api/v1/attenuate`) and renewal (`/api/v1/renew`)
- W3C-compatible token format with versioned schema (`schemaVersion`)
- DID resolution for `did:web`, `did:ion`, and `did:key`
- Discovery endpoints: `/api/v1/public-key`, `/.well-known/did.json`, `/.well-known/capability-issuer`

`/.well-known/capability-issuer` returns issuer metadata for clients and
gateways: issuer DID, service name, supported schema versions, active schema
version, supported signing algorithms, and links to the public key and DID
document endpoints.

### 2. **Tool Gateway** (`packages/tool-gateway`)
Enforces capability constraints on all agent actions.

**Key Features:**
- JWT token verification with signature validation
- Fine-grained, segment-aware action and resource matching
- Typed `CapabilityCondition` enforcement (time windows, IP allowlists, max-call counters, argument schemas, etc.)
- Distributed Redis-backed kill-switch (global, session, agent-level) and revocation list, with in-memory fallback for dev
- Cryptographic audit evidence generation
- Admin API for operational control (kill-switch, revocation)
- Request proxying to backend services (`/proxy/*`)

### 3. **Common Library** (`packages/common`)
Shared types, utilities, and interfaces.

**Key Features:**
- Type-safe capability data models and the `CapabilityCondition` discriminated union
- Pluggable identity / signing adapter base classes and registries
- Audit logging utilities and pluggable log transports
- Distributed kill-switch manager (in-memory + Redis)
- Distributed call counter store for `maxCalls` conditions
- Evidence signing framework
- Specialized validators for file paths, SQL parameters, table / column names, resource patterns
- Role-to-capability mapping helpers

### 4. **Agent Runtime** (`packages/agent-runtime`)
Cloud-agnostic runtime that wraps an agent's tool-call surface and routes
every invocation through the Tool Gateway, attaching the capability
token transparently and surfacing structured denial errors. This is the
substrate the framework adapters sit on top of.

### 5. **Framework Adapters** (`packages/framework-adapters`)
Framework-native middleware so application authors do not need to
rewrite agent business logic to adopt Euno:

- **LangChain** — `wrapAsLangChainTool`, `wrapAsLangChainTools`, `EunoLangChainCallbackHandler`
- **Microsoft Agent Framework (MAF)** — `createEunoFunctionToolMiddleware`, `createEunoAgentRunMiddleware`
- **CrewAI** — `wrapAsCrewAITool`, `wrapAsCrewAITools`, `EunoCrewAITaskLifecycle`

All three share a single correlation-ID and error-shape contract so
observability is identical regardless of framework. See the package source at
`euno-platform/packages/framework-adapters/src/` for the design. (Frozen in Stage 0; activation tracked in [docs/mvp.md](./mvp.md) Stage 3.)

### 6. **CLI** (`packages/cli`)
Developer command-line tool: `euno init` (with `--framework` flag for
LangChain / MAF / CrewAI scaffolding), `validate`, `request`, `config`,
`schema-version`, `check`, `plan`, `validate-token`.

### 7. **Integration Tests** (`packages/integration-tests`)
End-to-end issuer ↔ gateway ↔ agent-runtime test harness.

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

### Sprint 3+ Reconciliation
- ✅ Full DID integration for `did:web`, `did:ion`, and `did:key` (see `packages/capability-issuer/src/did-resolver.ts`)
- ✅ Capability delegation and attenuation (`/api/v1/attenuate`)
- ✅ Token renewal (`/api/v1/renew`)
- ✅ Specialized capability validators and typed conditions, including time windows, IP allowlists, `maxCalls`, and argument schemas
- ✅ Microsoft Sentinel analytics content (`infra/sentinel/analytic-rules.json`)
- ✅ Cryptographic audit evidence generation and verification helpers
- ⚠️ Data redaction remains roadmap/design work and is tracked in `capability-model.md`
- 📚 Cross-organization trust (federation, delegation chains) is future work; see `ARCHITECTURE.md` for the trust-chain design

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
├── docs/                     # Documentation
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

See [`docs/README.md`](../docs/README.md) for the documentation index.

## License

ISC

## References

- [Zero-Trust Agents (Microsoft Foundry Blog)](https://techcommunity.microsoft.com/blog/azure-ai-foundry-blog/zero-trust-agents-adding-identity-and-access-to-multi-agent-workflows/4427790)
- [Building an Auditable Security Layer for Agentic AI](https://azurefeeds.com/2026/04/22/building-an-auditable-security-layer-for-agentic-ai/)
- [Microsoft Entra Verified ID Architecture](https://learn.microsoft.com/en-us/entra/verified-id/introduction-to-verifiable-credentials-architecture)
- [W3C Verifiable Credentials Data Model](https://www.w3.org/TR/vc-data-model/)
- [W3C Decentralized Identifiers (DIDs)](https://www.w3.org/TR/did-core/)
