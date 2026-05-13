# Runbook: Minter Pepper Rotation

> **Applies to:** `ApiKeyVerifier`, `PostgresApiKeyStore`  
> **Environment variables:** `MINTER_PEPPER_HEX`, `MINTER_PEPPER_VERSION`  
> **Related code:** `euno-platform/packages/api-key-minter/src/api-key-verifier.ts`

---

## Overview

The minter uses a **pepper** (a server-side secret mixed into every API-key hash)
as defence-in-depth against offline dictionary attacks on a stolen `api_keys`
table. All stored key hashes are computed as:

```
PBKDF2(rawSecret, pepper || saltHex, iterations, 32)
```

where `pepper` is the `MINTER_PEPPER_HEX` value and `saltHex` is a per-key
random salt stored alongside the hash.

**Rotating the pepper invalidates every existing API-key hash.** After the
rotation, any API key minted under the old pepper will fail verification until
it is re-hashed or re-issued.

---

## When to rotate

Rotate the pepper when any of the following occur:

- The `MINTER_PEPPER_HEX` secret is suspected to have been leaked (e.g. via
  a compromised secrets manager, a git commit, or a build-log artifact).
- A scheduled security review mandates periodic pepper rotation (recommended
  interval: once per year, or after each infrastructure breach investigation).
- An audit requirement specifies a maximum pepper lifetime.

Do **not** rotate the pepper during a live incident response unless key
compromise has been confirmed — the rotation will immediately invalidate all
active API keys and trigger a fleet-wide re-issuance.

---

## Pre-rotation checklist

- [ ] Confirm access to the secrets manager (AWS Secrets Manager / Azure Key
  Vault / HashiCorp Vault) that holds `MINTER_PEPPER_HEX`.
- [ ] Verify you have write access to the `api_keys` table (needed to update
  hashes during the grace period, if using Strategy B).
- [ ] Schedule a maintenance window (Strategy B only — Strategy A is
  zero-downtime for new keys; existing keys see a 401 until re-issued).
- [ ] Notify all tenant administrators that API keys will require re-issuance
  (Strategy A) or that a brief maintenance window is in progress (Strategy B).
- [ ] Confirm the `MINTER_PEPPER_VERSION` variable is set and tracked — the
  version string is stored alongside each hash so the verifier can select the
  correct pepper during a dual-verification grace period.

---

## Generating a new pepper

```bash
# 32 bytes of random entropy, hex-encoded (64 hex characters)
openssl rand -hex 32
# → e.g. 3a1f2b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2
```

Store the new pepper in your key-management system. Never commit it to source
control or expose it in build logs.

---

## Strategy A: Zero-downtime — issue new keys with new pepper (recommended)

New API keys are minted with the new pepper; old API keys remain valid until
each tenant re-issues. This is the lowest-risk approach but requires
coordinating a re-issuance campaign with tenants.

### Steps

1. **Generate the new pepper** (see §Generating above).

2. **Provision the new pepper** alongside the old one in your secrets manager.
   Set the new `MINTER_PEPPER_VERSION` (e.g. increment `v1` → `v2`).

3. **Deploy the updated configuration** to the minter fleet:
   ```bash
   # New pepper for minting
   MINTER_PEPPER_HEX=<new-hex>
   MINTER_PEPPER_VERSION=v2
   ```
   The `ApiKeyVerifier` attempts verification with the current pepper first; if
   that fails it retries with any configured fallback pepper versions (see the
   `peppers` array in `bootstrap.ts`). **To support the grace period, deploy
   both old and new peppers** into the `peppers` array:

   ```typescript
   // In bootstrap.ts during the grace period (multi-pepper mode)
   peppers = [
     { version: 'v2', key: Buffer.from(newPepperHex, 'hex') },  // new (primary)
     { version: 'v1', key: Buffer.from(oldPepperHex, 'hex') },  // old (fallback)
   ];
   ```

4. **Notify tenants** to re-issue their API keys via `POST /admin/keys`.

5. **Monitor the grace period.** Track the proportion of verifications hitting
   the old-pepper fallback path via metrics / audit logs. Once the fallback
   hit-rate drops to zero (all active keys have been re-issued), proceed to
   step 6.

6. **Remove the old pepper** from the `peppers` array and redeploy. The old
   pepper can now be decommissioned in the secrets manager.

7. **Verify** that no old-pepper keys remain in use:
   ```sql
   -- Check for keys still storing the old pepper version
   SELECT COUNT(*) FROM api_keys WHERE pepper_version = 'v1';
   ```
   If the count is non-zero, those tenants have not re-issued their keys.
   Revoke them explicitly or extend the grace period.

---

## Strategy B: Re-hash all existing keys (maintenance window required)

This approach avoids requiring tenants to re-issue keys but requires a
maintenance window and DDL-level write access to the `api_keys` table.

> **Warning:** This strategy requires the minter to be quiesced (no active
> minting or verification requests) during the re-hash step to prevent
> partially-updated keys from failing validation.

### Steps

1. **Generate the new pepper** (see §Generating above).

2. **Open a maintenance window.** Scale down the minter fleet to zero replicas.

3. **Run the re-hash script** against the `api_keys` table:
   ```bash
   node -e "
   const { Pool } = require('pg');
   const { ApiKeyVerifier } = require('@euno/api-key-minter');
   // Script must re-derive each key using the old pepper and re-store
   // using the new pepper. See ApiKeyVerifier.rehashAll() (if available)
   // or implement per-row: SELECT rawSecret from a backup, re-hash, UPDATE.
   "
   ```
   > **Prerequisites:** You must have the raw (pre-hash) API keys available
   > from a secure backup or key-escrow system. If raw keys are not available,
   > use Strategy A (re-issuance) instead — the hash is one-way and cannot be
   > reversed to recover the raw key.

4. **Update the pepper configuration** and **scale the minter fleet back up.**

5. **Remove the old pepper** from the secrets manager once the deployment is
   verified healthy.

### Risk

If raw keys are not available, Strategy B is not feasible. Default to
Strategy A (re-issuance).

---

## Rollback

If the rotation causes unexpected failures:

1. **Immediately re-add the old pepper** as the primary entry in the `peppers`
   array (Strategy A) or revert the `MINTER_PEPPER_HEX` variable (Strategy B).
2. Redeploy the minter fleet.
3. Verify that existing keys pass verification again.
4. File an incident report describing the failure mode before re-attempting.

---

## Verification

After a successful rotation, confirm:

```bash
# Issue a new API key under the new pepper version
curl -s -X POST https://minter.euno.example/admin/keys \
  -H "X-Admin-Key: $MINTER_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"tenantId": "test-tenant"}' | jq .

# Verify the key mints a capability token successfully
curl -s -X POST https://minter.euno.example/api/v1/mint \
  -H "Authorization: Bearer sk-<prefix>.<secret>" \
  -H "Content-Type: application/json" \
  -d '{"agentId": "did:example:test", "sessionId": "s-001"}' | jq .capabilityToken
```

---

## Cross-references

- `euno-platform/packages/api-key-minter/src/api-key-verifier.ts` — `ApiKeyVerifier`, `PepperEntry`
- `euno-platform/packages/api-key-minter/src/bootstrap.ts` — pepper provisioning at startup
- `docs/runbooks/minter-key-rotation.md` — signing key (JWT) rotation procedure
- `docs/security/minter-threat-model.md §4` — pepper threat model
- `docs/architecture-review-2026-05.md §CR-5` — pepper rotation requirement
