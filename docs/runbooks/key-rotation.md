# Runbook: Key Rotation

**Severity**: P2 — Planned Maintenance  
**Last Updated**: 2026-05-26  
**Owner**: Platform Security

## Overview

Cryptographic keys and secrets must be rotated regularly to limit the blast radius of compromise. This runbook covers rotation of all key material in the Eunox platform.

## Key Inventory

| Key | Service | Rotation Frequency | Zero-Downtime |
|-----|---------|-------------------|---------------|
| JWT Signing Key (ECDSA P-256) | Issuer | 90 days | Yes (JWKS overlap) |
| API Key HMAC Pepper | Minter | 180 days | Yes (dual-pepper) |
| Admin API Key | Gateway, Minter | 90 days | Yes (rolling) |
| Audit HMAC Secret | Gateway | 180 days | No (requires maintenance window) |
| TLS Certificates | All | Before expiry | Yes (CertReloader) |

## JWT Signing Key Rotation

The issuer supports overlapping keys via JWKS. The old key remains published for token verification while new tokens use the new key.

### Procedure

```bash
# 1. Generate new key pair
openssl ecparam -genkey -name prime256v1 -noout -out new-signing-key.pem
openssl ec -in new-signing-key.pem -pubout -out new-signing-key-pub.pem

# 2. Store new key in secret manager (example: K8s secret)
kubectl -n euno-system create secret generic euno-issuer-signing-key-v2 \
  --from-file=signing-key.pem=new-signing-key.pem

# 3. Update issuer deployment to reference new key
kubectl -n euno-system set env deployment/euno-issuer \
  SIGNING_KEY_SECRET=euno-issuer-signing-key-v2

# 4. Wait for rollout
kubectl -n euno-system rollout status deployment/euno-issuer

# 5. Verify JWKS endpoint shows both keys
curl -s https://issuer.example.com/.well-known/jwks.json | jq '.keys | length'
# Expected: 2 (old + new)

# 6. After max token lifetime (default 1h), remove old key
kubectl -n euno-system delete secret euno-issuer-signing-key-v1
```

## API Key HMAC Pepper Rotation

The minter supports dual-pepper mode for zero-downtime rotation.

### Procedure

```bash
# 1. Generate new pepper (32 bytes)
NEW_PEPPER=$(openssl rand -hex 32)

# 2. Set as secondary pepper (validation only)
kubectl -n euno-system set env deployment/euno-minter \
  MINTER_PEPPER_HEX_SECONDARY=$NEW_PEPPER

# 3. Wait for rollout
kubectl -n euno-system rollout status deployment/euno-minter

# 4. Promote new pepper to primary (new keys use new pepper)
kubectl -n euno-system set env deployment/euno-minter \
  MINTER_PEPPER_HEX=$NEW_PEPPER \
  MINTER_PEPPER_HEX_SECONDARY=$OLD_PEPPER

# 5. After all old keys expire/are revoked, remove old pepper
kubectl -n euno-system set env deployment/euno-minter \
  MINTER_PEPPER_HEX_SECONDARY-
```

## Admin API Key Rotation

### Procedure

```bash
# 1. Generate new admin key (minimum 32 characters)
NEW_KEY=$(openssl rand -base64 48)

# 2. Update gateway with both keys (comma-separated for rolling support)
kubectl -n euno-system patch secret euno-gateway-secret \
  --type merge -p "{\"stringData\":{\"ADMIN_API_KEY\":\"$NEW_KEY\"}}"

# 3. Restart gateway pods
kubectl -n euno-system rollout restart deployment/euno-gateway

# 4. Update all clients to use new key
# 5. Remove old key from any documentation/configs
```

## TLS Certificate Rotation

TLS certificates are automatically reloaded by the CertReloader (see `pkg/tlsconf`). Simply replace the certificate files and the service will pick up the new certificates within the reload interval (default: 5 minutes).

### Procedure

```bash
# 1. Obtain new certificate from CA
# 2. Update K8s TLS secret
kubectl -n euno-system create secret tls euno-tls \
  --cert=new-cert.pem --key=new-key.pem \
  --dry-run=client -o yaml | kubectl apply -f -

# 3. Verify (no restart needed — CertReloader picks up automatically)
openssl s_client -connect gateway.example.com:443 -brief 2>/dev/null | head -5
```

## Verification

After any key rotation, verify:

1. Service health checks pass: `kubectl -n euno-system get pods`
2. New tokens can be issued and verified end-to-end
3. Existing valid tokens still verify (for signing key rotation)
4. Audit log shows rotation event
5. Monitoring shows no error rate spike
