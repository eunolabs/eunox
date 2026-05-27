# Pluggable Adapters: Identity Providers and Token Signers

The eunox capability governance system implements a clean adapter pattern for identity providers and token signers. This establishes extensible contracts that enable support for multiple implementations — Azure AD + Azure Key Vault, AWS Cognito + AWS KMS, GCP Cloud Identity + GCP Cloud KMS, and W3C Decentralized Identifiers (DIDs) — all behind the same `identity.Provider` / `crypto.Signer` contracts.

---

## Architecture

### Core Components

**Identity Providers** (`pkg/identity/`)

- `identity.Provider` — interface for identity token verification
- `identity.UserContext` — normalized user identity with subject, email, roles, tenant ID
- `identity.ProviderType` — enum for provider types (oidc, cognito, azure-ad, gcp-identity, did)

**Token Signers** (`pkg/crypto/`)

- `crypto.Signer` — interface for signing digests with private keys
- `crypto.Verifier` — interface for verifying signatures with public keys
- `crypto.KeyPair` — combines Signer and Verifier for the same key
- `crypto.Algorithm` — enum for signing algorithms (RS256, ES256, EdDSA, etc.)

### Built-in Implementations

**Identity Providers**

| Type           | Implementation                                        | Package                            |
| -------------- | ----------------------------------------------------- | ---------------------------------- |
| `oidc`         | Generic OIDC provider with JWKS discovery             | `pkg/identity` (`OIDCProvider`)    |
| `azure-ad`     | Azure Active Directory / Microsoft Entra ID           | `pkg/identity` (`AzureADProvider`) |
| `cognito`      | Amazon Cognito user pools                             | `pkg/identity` (`CognitoProvider`) |
| `gcp-identity` | Google Cloud Identity / Workforce Identity Federation | `pkg/identity` (`GCPProvider`)     |
| `did`          | W3C DID Documents (`did:web`, `did:ion`, `did:key`)   | `pkg/identity` (`DIDProvider`)     |

**Token Signers**

| Type          | Implementation                                                 | Package                         |
| ------------- | -------------------------------------------------------------- | ------------------------------- |
| Software keys | In-memory private key signing (RSA, ECDSA, EdDSA)              | `pkg/crypto` (`SoftwareSigner`) |
| AWS KMS       | Remote signing via AWS KMS asymmetric keys                     | `pkg/crypto` (`RealAWSKMSSigner`) |
| Azure Key Vault | Remote signing via Azure Key Vault keys                      | `pkg/crypto` (`RealAzureKeyVaultSigner`) |
| GCP Cloud KMS | Remote signing via GCP Cloud KMS asymmetric keys               | `pkg/crypto` (`RealGCPCloudKMSSigner`) |

---

## Using Built-in Providers

### Generic OIDC Identity Provider

The `OIDCProvider` works with any OIDC-compliant identity provider. It performs automatic JWKS discovery and caches keys for performance.

```go
package main

import (
    "context"
    "log"
    "net/http"
    "time"

    "github.com/edgeobs/eunox/pkg/identity"
)

func main() {
    // Configure OIDC provider
    cfg := &identity.OIDCConfig{
        IssuerURL:      "https://auth.example.com",
        Audience:       "my-service-client-id",
        RequiredScopes: []string{"openid", "profile"},
        RolesClaimPath: "roles", // or "realm_access.roles" for Keycloak
        CacheTTL:       5 * time.Minute,
    }

    // Create provider
    provider, err := identity.NewOIDCProvider(cfg, &http.Client{Timeout: 10 * time.Second})
    if err != nil {
        log.Fatalf("Failed to create OIDC provider: %v", err)
    }

    // Verify a token
    ctx := context.Background()
    userCtx, err := provider.VerifyToken(ctx, idToken)
    if err != nil {
        log.Fatalf("Token verification failed: %v", err)
    }

    log.Printf("Authenticated user: %s (%s)", userCtx.Name, userCtx.Email)
    log.Printf("Roles: %v", userCtx.Roles)
}
```

### Azure AD Identity Provider

The `AzureADProvider` is a specialized wrapper around the OIDC provider with Azure AD-specific claim mappings.

```go
package main

import (
    "context"
    "log"
    "net/http"
    "os"

    "github.com/edgeobs/eunox/pkg/identity"
)

func main() {
    cfg := identity.AzureADConfig{
        TenantID: os.Getenv("AZURE_AD_TENANT_ID"), // e.g., "common" or a specific tenant GUID
        ClientID: os.Getenv("AZURE_AD_CLIENT_ID"),
    }

    provider, err := identity.NewAzureADProvider(cfg, &http.Client{})
    if err != nil {
        log.Fatalf("Failed to create Azure AD provider: %v", err)
    }

    ctx := context.Background()
    userCtx, err := provider.VerifyToken(ctx, idToken)
    if err != nil {
        log.Fatalf("Token verification failed: %v", err)
    }

    log.Printf("Subject: %s, TenantID: %s", userCtx.Subject, userCtx.TenantID)
    log.Printf("Roles: %v, Groups: extracted from 'roles' and 'groups' claims", userCtx.Roles)
}
```

### AWS Cognito Identity Provider

The `CognitoProvider` handles Cognito user pools with automatic JWKS discovery.

```go
package main

import (
    "context"
    "log"
    "net/http"
    "os"

    "github.com/edgeobs/eunox/pkg/identity"
)

func main() {
    cfg := identity.CognitoConfig{
        Region:     os.Getenv("AWS_REGION"),     // e.g., "us-east-1"
        UserPoolID: os.Getenv("USER_POOL_ID"),   // e.g., "us-east-1_ABC123"
        ClientID:   os.Getenv("CLIENT_ID"),      // Cognito app client ID
    }

    provider, err := identity.NewCognitoProvider(cfg, &http.Client{})
    if err != nil {
        log.Fatalf("Failed to create Cognito provider: %v", err)
    }

    ctx := context.Background()
    userCtx, err := provider.VerifyToken(ctx, idToken)
    if err != nil {
        log.Fatalf("Token verification failed: %v", err)
    }

    log.Printf("Cognito user: %s", userCtx.Subject)
    log.Printf("Groups: %v", userCtx.Roles) // Cognito groups mapped to Roles
}
```

### GCP Cloud Identity Provider

The `GCPProvider` verifies Google identity tokens.

```go
package main

import (
    "context"
    "log"
    "net/http"
    "os"

    "github.com/edgeobs/eunox/pkg/identity"
)

func main() {
    cfg := identity.GCPConfig{
        Audience: os.Getenv("GCP_CLIENT_ID"), // Google OAuth 2.0 client ID
    }

    provider, err := identity.NewGCPProvider(cfg, &http.Client{})
    if err != nil {
        log.Fatalf("Failed to create GCP provider: %v", err)
    }

    ctx := context.Background()
    userCtx, err := provider.VerifyToken(ctx, idToken)
    if err != nil {
        log.Fatalf("Token verification failed: %v", err)
    }

    log.Printf("Google user: %s (%s)", userCtx.Name, userCtx.Email)
}
```

### Software Signing Keys

For development and testing, use in-memory software keys. In production, use KMS-backed signers (Azure Key Vault, AWS KMS, GCP Cloud KMS).

```go
package main

import (
    "context"
    "log"

    "github.com/edgeobs/eunox/pkg/crypto"
)

func main() {
    // Generate a new EdDSA key pair
    keyPair, err := crypto.GenerateEdDSAKeyPair("issuer-key-1")
    if err != nil {
        log.Fatalf("Failed to generate key pair: %v", err)
    }

    // Sign a digest
    ctx := context.Background()
    digest := []byte("message to sign")
    signature, err := keyPair.Sign(ctx, digest)
    if err != nil {
        log.Fatalf("Failed to sign: %v", err)
    }

    // Verify the signature
    if err := keyPair.Verify(ctx, digest, signature); err != nil {
        log.Fatalf("Signature verification failed: %v", err)
    }

    log.Printf("Signature verified successfully")
    log.Printf("Algorithm: %s, KeyID: %s", keyPair.Algorithm(), keyPair.KeyID())
}
```

### Generating Keys for Different Algorithms

```go
package main

import (
    "log"

    "github.com/edgeobs/eunox/pkg/crypto"
)

func main() {
    // RSA 2048-bit with RS256
    rsaKey, err := crypto.GenerateRSAKeyPair("rsa-key", 2048)
    if err != nil {
        log.Fatalf("Failed to generate RSA key: %v", err)
    }
    log.Printf("RSA: Algorithm=%s, KeyID=%s", rsaKey.Algorithm(), rsaKey.KeyID())

    // ECDSA P-256 with ES256
    ecdsaKey, err := crypto.GenerateECDSAKeyPair("ecdsa-key", "P-256")
    if err != nil {
        log.Fatalf("Failed to generate ECDSA key: %v", err)
    }
    log.Printf("ECDSA: Algorithm=%s, KeyID=%s", ecdsaKey.Algorithm(), ecdsaKey.KeyID())

    // EdDSA (Ed25519)
    eddsaKey, err := crypto.GenerateEdDSAKeyPair("eddsa-key")
    if err != nil {
        log.Fatalf("Failed to generate EdDSA key: %v", err)
    }
    log.Printf("EdDSA: Algorithm=%s, KeyID=%s", eddsaKey.Algorithm(), eddsaKey.KeyID())
}
```

---

## Creating Custom Adapters

### Custom Identity Provider

Implement the `identity.Provider` interface:

```go
package customidentity

import (
    "context"
    "fmt"

    "github.com/edgeobs/eunox/pkg/identity"
)

// CustomProvider implements identity.Provider for a custom identity system.
type CustomProvider struct {
    apiKey string
    apiURL string
}

func NewCustomProvider(apiURL, apiKey string) (*CustomProvider, error) {
    if apiURL == "" || apiKey == "" {
        return nil, fmt.Errorf("apiURL and apiKey are required")
    }
    return &CustomProvider{
        apiKey: apiKey,
        apiURL: apiURL,
    }, nil
}

// VerifyToken validates a custom token format and returns a UserContext.
func (p *CustomProvider) VerifyToken(ctx context.Context, token string) (*identity.UserContext, error) {
    // 1. Call your custom identity API
    // 2. Validate the token
    // 3. Extract user attributes
    // 4. Return a normalized UserContext

    // Example:
    return &identity.UserContext{
        Subject:  "user-123",
        Email:    "user@example.com",
        Name:     "Custom User",
        Roles:    []string{"admin", "viewer"},
        TenantID: "tenant-1",
        Provider: "custom",
        Claims:   map[string]interface{}{"custom_claim": "value"},
    }, nil
}
```

### Custom Token Signer (HSM Example)

Implement the `crypto.Signer` interface:

```go
package customcrypto

import (
    "context"
    "fmt"

    "github.com/edgeobs/eunox/pkg/crypto"
)

// HSMSigner implements crypto.Signer backed by a hardware security module.
type HSMSigner struct {
    hsmClient HSMClient // your HSM SDK client
    keyID     string
    algorithm crypto.Algorithm
}

func NewHSMSigner(client HSMClient, keyID string, algorithm crypto.Algorithm) (*HSMSigner, error) {
    if client == nil || keyID == "" {
        return nil, fmt.Errorf("hsmClient and keyID are required")
    }
    return &HSMSigner{
        hsmClient: client,
        keyID:     keyID,
        algorithm: algorithm,
    }, nil
}

func (s *HSMSigner) Sign(ctx context.Context, digest []byte) ([]byte, error) {
    // Call your HSM to sign the digest
    signature, err := s.hsmClient.SignDigest(ctx, s.keyID, digest)
    if err != nil {
        return nil, fmt.Errorf("HSM sign failed: %w", err)
    }
    return signature, nil
}

func (s *HSMSigner) Algorithm() crypto.Algorithm {
    return s.algorithm
}

func (s *HSMSigner) KeyID() string {
    return s.keyID
}

// HSMClient is your HSM SDK interface
type HSMClient interface {
    SignDigest(ctx context.Context, keyID string, digest []byte) ([]byte, error)
}
```

---

## Best Practices

### Error Handling

All providers return structured errors. Wrap errors with context when propagating:

```go
userCtx, err := provider.VerifyToken(ctx, token)
if err != nil {
    return fmt.Errorf("verify identity token: %w", err)
}
```

### Lifecycle Management

Providers are stateless and can be reused across requests. Create providers once during application bootstrap and share them:

```go
// In your application setup
var identityProvider identity.Provider

func InitializeApp() error {
    cfg := &identity.OIDCConfig{
        IssuerURL: os.Getenv("OIDC_ISSUER_URL"),
        Audience:  os.Getenv("OIDC_AUDIENCE"),
    }

    var err error
    identityProvider, err = identity.NewOIDCProvider(cfg, &http.Client{})
    if err != nil {
        return fmt.Errorf("create identity provider: %w", err)
    }

    return nil
}

// In your HTTP handler
func HandleRequest(w http.ResponseWriter, r *http.Request) {
    token := extractBearerToken(r)
    userCtx, err := identityProvider.VerifyToken(r.Context(), token)
    if err != nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    // Use userCtx...
}
```

### Configuration Validation

All providers validate configuration at creation time. If configuration is invalid, the constructor returns an error immediately (fail-fast). Never skip error checking during provider creation.

```go
// Good: error is checked
provider, err := identity.NewAzureADProvider(cfg, httpClient)
if err != nil {
    log.Fatalf("Invalid Azure AD configuration: %v", err)
}

// Bad: error ignored (will panic later)
provider, _ := identity.NewAzureADProvider(cfg, httpClient)
```

---

## Partner Federation

Partner federation enables eunox to accept capability tokens issued by external partner organizations using W3C DIDs (`did:web`, `did:ion`, `did:key`). See [docs/architecture.md](./architecture.md) for the full architecture overview.

### Trust Model

1. **DID Registration**: Partner submits DID document URL + attestation pin (two-eye approval required)
2. **Verification**: Operator validates DID document structure and public keys
3. **Circuit Breaker**: Per-partner circuit breaker tracks failure rates and opens/closes based on health
4. **Revocation**: Single-operator revocation for incident response

### DID Provider Usage

```go
package main

import (
    "context"
    "log"
    "net/http"

    "github.com/edgeobs/eunox/pkg/identity"
)

func main() {
    cfg := identity.DIDConfig{
        AllowedDIDMethods: []string{"did:web", "did:key"},
        HTTPClient:        &http.Client{},
    }

    provider, err := identity.NewDIDProvider(cfg)
    if err != nil {
        log.Fatalf("Failed to create DID provider: %v", err)
    }

    // Verify a token issued by a partner with did:web:partner.example.com
    ctx := context.Background()
    userCtx, err := provider.VerifyToken(ctx, partnerToken)
    if err != nil {
        log.Fatalf("Partner token verification failed: %v", err)
    }

    log.Printf("Partner user: %s, DID: %s", userCtx.Subject, userCtx.Claims["iss"])
}
```

---

## KMS-Backed Signers

The `pkg/crypto` package provides production-ready KMS signer implementations that delegate all cryptographic operations to cloud KMS services. Private key material never leaves the KMS boundary.

### Architecture

Each KMS signer follows the same provider/client interface pattern used throughout eunox:

1. **Client interface** — abstracts the cloud SDK's signing API (e.g., `AWSKMSClient`, `AzureKeyVaultClient`, `GCPCloudKMSClient`)
2. **Configuration struct** — holds key identifiers, region/location, algorithm, and client reference
3. **Signer implementation** — implements `crypto.Signer`, delegates to client, handles signature format normalization

This design enables:
- Unit testing with mock clients (no cloud connectivity required)
- Swapping SDK implementations without changing business logic
- Supporting multiple KMS providers in the same deployment

### Supported Algorithms

| Algorithm Family | JOSE IDs | AWS KMS | Azure Key Vault | GCP Cloud KMS |
|-----------------|----------|---------|-----------------|---------------|
| RSA PKCS#1 v1.5 | RS256, RS384, RS512 | ✅ | ✅ | ✅ |
| RSA-PSS | PS256, PS384, PS512 | ✅ | ✅ | ✅ |
| ECDSA | ES256, ES384, ES512 | ✅ | ✅ | ✅ |

> **Note:** EdDSA (Ed25519) and ES256K (secp256k1) are not supported by cloud KMS services. Use `SoftwareSigner` for these algorithms.

### AWS KMS

```go
package main

import (
    "context"
    "log"

    "github.com/edgeobs/eunox/pkg/crypto"
)

func main() {
    // Create your AWS KMS client (wraps aws-sdk-go-v2/service/kms)
    client := NewMyAWSKMSClient(region, credentials)

    signer, err := crypto.NewRealAWSKMSSigner(crypto.RealAWSKMSSignerConfig{
        KeyID:     "arn:aws:kms:us-east-1:123456789:key/mrk-1234abcd",
        Region:    "us-east-1",
        Algorithm: crypto.ES256,
        Client:    client,
    })
    if err != nil {
        log.Fatalf("Failed to create AWS KMS signer: %v", err)
    }

    // Sign a pre-hashed digest
    ctx := context.Background()
    signature, err := signer.Sign(ctx, sha256Digest)
    if err != nil {
        log.Fatalf("Signing failed: %v", err)
    }

    log.Printf("Signed with key %s using %s", signer.KeyID(), signer.Algorithm())
    _ = signature
}
```

### Azure Key Vault

```go
package main

import (
    "context"
    "log"

    "github.com/edgeobs/eunox/pkg/crypto"
)

func main() {
    // Create your Azure Key Vault client (wraps azkeys.Client)
    client := NewMyAzureKeyVaultClient(credential)

    signer, err := crypto.NewRealAzureKeyVaultSigner(&crypto.RealAzureKeyVaultSignerConfig{
        VaultURL:   "https://my-vault.vault.azure.net",
        KeyName:    "signing-key",
        KeyVersion: "abc123", // optional; empty = latest
        Algorithm:  crypto.RS256,
        Client:     client,
    })
    if err != nil {
        log.Fatalf("Failed to create Azure Key Vault signer: %v", err)
    }

    ctx := context.Background()
    signature, err := signer.Sign(ctx, sha256Digest)
    if err != nil {
        log.Fatalf("Signing failed: %v", err)
    }

    log.Printf("Signed with key %s", signer.KeyID())
    _ = signature
}
```

### GCP Cloud KMS

```go
package main

import (
    "context"
    "log"

    "github.com/edgeobs/eunox/pkg/crypto"
)

func main() {
    // Create your GCP Cloud KMS client (wraps kms.KeyManagementClient)
    client := NewMyGCPCloudKMSClient(ctx)

    signer, err := crypto.NewRealGCPCloudKMSSigner(&crypto.RealGCPCloudKMSSignerConfig{
        ProjectID:        "my-project",
        LocationID:       "us-east1",
        KeyRingID:        "my-keyring",
        CryptoKeyID:      "signing-key",
        CryptoKeyVersion: "1",
        Algorithm:        crypto.PS256,
        Client:           client,
    })
    if err != nil {
        log.Fatalf("Failed to create GCP Cloud KMS signer: %v", err)
    }

    ctx := context.Background()
    signature, err := signer.Sign(ctx, sha256Digest)
    if err != nil {
        log.Fatalf("Signing failed: %v", err)
    }

    log.Printf("Signed with key %s", signer.KeyID())
    _ = signature
}
```

### Implementing a KMS Client

To integrate with a specific cloud SDK, implement the corresponding client interface:

```go
// For AWS KMS:
type AWSKMSClient interface {
    Sign(ctx context.Context, input *AWSKMSSignInput) (*AWSKMSSignOutput, error)
}

// For Azure Key Vault:
type AzureKeyVaultClient interface {
    Sign(ctx context.Context, input *AzureKeyVaultSignInput) (*AzureKeyVaultSignOutput, error)
}

// For GCP Cloud KMS:
type GCPCloudKMSClient interface {
    AsymmetricSign(ctx context.Context, input *GCPCloudKMSSignInput) (*GCPCloudKMSSignOutput, error)
}
```

### ECDSA Signature Normalization

Cloud KMS services return ECDSA signatures in different formats:
- **AWS KMS** returns DER/ASN.1 encoded signatures
- **Azure Key Vault** returns JOSE R||S concatenated format
- **GCP Cloud KMS** returns DER/ASN.1 encoded signatures

The signer implementations automatically normalize all ECDSA signatures to the JOSE R||S format (RFC 7518 §3.4) expected by JWT/JOSE consumers. RSA signatures pass through unchanged.

### Legacy Stubs

The original stub signers (`NewAWSKMSSigner`, `NewAzureKeyVaultSigner`, `NewGCPCloudKMSSigner` in `kms_stub.go`) remain available for environments where KMS is not yet configured. They return `ErrKMSNotImplemented` on Sign() calls.

---

## See Also

- [issuer-idp-setup.md](./issuer-idp-setup.md) — Setting up Azure AD, Cognito, GCP for issuance
- [docs/openapi/capability-issuer.yaml](./openapi/capability-issuer.yaml) — Issuer API specification
