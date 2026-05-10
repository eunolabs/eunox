# Capability Token Schema Versioning

## Overview

Capability tokens in euno include a `schemaVersion` field that enables forward and backward compatibility during schema evolution. This document describes the versioning strategy, migration procedures, and compatibility guarantees.

## Current Version

**Version:** `1.0`
**Release Date:** April 2026
**Status:** Current

### Version 1.0 Features

- Typed condition system with discriminated union
- Eight built-in condition types:
  - `timeWindow` - Temporal access restrictions
  - `ipRange` - Network-based access control
  - `allowedOperations` - Sub-action filtering
  - `allowedExtensions` - File extension restrictions
  - `allowedTables` - Database table/column allowlists
  - `maxCalls` - Rate limiting
  - `recipientDomain` - Email recipient restrictions
  - `redactFields` - Response redaction obligations
- Custom condition extensibility via `CustomCondition`
- Optional argument schema validation
- Issuance-time condition validation
- Enforcement-time condition evaluation
- Deny-by-default on unknown condition types

## Compatibility Matrix

| Gateway Version | Supported Token Schema Versions | Notes |
|----------------|--------------------------------|-------|
| 1.0.x          | 1.0                             | Initial release |

## Version Numbering

Schema versions follow a `MAJOR.MINOR` format:

### Major Version (X.0)

**Indicates:** Breaking changes requiring coordinated updates

**Examples:**
- Removing required fields
- Changing field semantics
- Renaming fields
- Changing validation rules

**Compatibility:** Old gateways MUST reject tokens with newer major versions (fail-closed)

### Minor Version (X.Y)

**Indicates:** Backward-compatible additions

**Examples:**
- Adding optional fields
- New condition types
- Additional validation rules (backward-compatible)

**Compatibility:** Minor versions are intended to be backward-compatible, but gateways only accept schema versions explicitly listed as supported. An old gateway that has not been updated will reject tokens with a newer minor version until that exact version is added to the supported set.

## Version Validation

### Issuer Behavior

The capability issuer populates `schemaVersion` in all token creation paths:

1. **Initial Issuance** (`issueCapability`)
   - Sets `schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION`
   - Current value: `"1.0"`

2. **Delegation/Attenuation** (`attenuateCapability`)
   - Preserves the parent token's `schemaVersion`
   - Note: during migrations, this may differ from the issuer's current `CAPABILITY_TOKEN_SCHEMA_VERSION`

3. **Token Renewal** (`renewCapability`)
   - Preserves capabilities from original token
   - Uses current schema version: `"1.0"`

### Gateway Behavior

The tool gateway verifier validates `schemaVersion` on every token verification:

```typescript
// Pseudo-code
if (!token.schemaVersion) {
  throw INVALID_TOKEN("Token missing required schemaVersion field")
}
if (!SUPPORTED_SCHEMA_VERSIONS.has(token.schemaVersion)) {
  throw INVALID_TOKEN(`Unsupported token schema version: ${token.schemaVersion}`)
}
```

**Validation Points:**
- Signature verification
- Revocation check
- Audience validation
- **Schema version validation** ← Added
- Condition enforcement

**Error Handling:**
- Missing `schemaVersion` → `INVALID_TOKEN` (401)
- Unsupported `schemaVersion` → `INVALID_TOKEN` (401)
- Error messages include list of supported versions

## Migration Procedures

### Adding a Minor Version (e.g., 1.0 → 1.1)

**Scenario:** Adding optional fields or new condition types

**Steps:**

1. **Update Gateway** (Week 1-2)
   ```typescript
   // public/packages/common/src/types.ts
   export const SUPPORTED_SCHEMA_VERSIONS: ReadonlySet<string> = new Set([
     '1.0',
     '1.1', // NEW
   ]);
   ```
   - Add new version to `SUPPORTED_SCHEMA_VERSIONS`
   - Implement version-specific logic (if needed)
   - Deploy gateway updates
   - Verify all gateways updated

2. **Update Issuer** (Week 3-4)
   ```typescript
   export const CAPABILITY_TOKEN_SCHEMA_VERSION = '1.1' as const;
   ```
   - Update `CAPABILITY_TOKEN_SCHEMA_VERSION`
   - Deploy issuer updates
   - Monitor token distribution

3. **Validation** (Week 5+)
   - Verify both versions coexist peacefully
   - Monitor for errors or compatibility issues
   - Prepare deprecation plan for 1.0

4. **Deprecation** (3+ months)
   - Announce deprecation timeline
   - Remove 1.0 from `SUPPORTED_SCHEMA_VERSIONS`
   - Deploy gateway updates

### Adding a Major Version (e.g., 1.x → 2.0)

**Scenario:** Breaking changes to schema structure

**Prerequisites:**
- Document breaking changes
- Update gateway code to handle both versions
- Create migration guide for clients

**Steps:**

1. **Preparation Phase** (Week 1-4)
   - Update gateway to support "1.x" and "2.0"
   - Add version-specific parsing/validation logic
   - Deploy gateway updates to ALL instances
   - Verify 100% deployment before proceeding

2. **Transition Phase** (Week 5-8)
   - Update issuer to mint "2.0" tokens
   - Both versions coexist
   - Monitor metrics:
     - Token version distribution
     - Error rates by version
     - Gateway processing times

3. **Validation Phase** (Week 9-12)
   - Ensure no "1.x" tokens in circulation (check TTL)
   - Verify all clients handle "2.0" correctly
   - Address any compatibility issues

4. **Deprecation Phase** (Week 13+)
   - Remove "1.x" from `SUPPORTED_SCHEMA_VERSIONS`
   - Deploy gateway updates
   - Update documentation

**Important:** Never skip the preparation phase. Always deploy gateways before issuers.

## Deployment Order

**Critical Rule:** Gateways MUST be updated before issuers during version changes.

### ✅ Correct Deployment Order

```
1. Update SUPPORTED_SCHEMA_VERSIONS in gateway
2. Deploy gateway updates
3. Verify gateway rollout (100% completion)
4. Update CAPABILITY_TOKEN_SCHEMA_VERSION in issuer
5. Deploy issuer updates
```

### ❌ Incorrect Deployment Order (DO NOT DO THIS)

```
1. Update issuer to mint v1.1 tokens
2. Deploy issuer
3. Update gateway to support v1.1  ← TOO LATE!
```

**Why:** If issuers mint new tokens before gateways support them, requests will fail with `INVALID_TOKEN` errors.

## Backward Compatibility Guarantees

### What is Guaranteed

1. **Gateway Backward Compatibility**
   - Gateway v1.1 can process tokens v1.0 and v1.1
   - No functionality regression for older tokens

2. **Minor Version Tolerance**
   - Optional fields in newer minor versions are ignored by older gateways
   - Core functionality remains intact

3. **Error Messages**
   - Clear indication of version mismatch
   - List of supported versions in error response

### What is NOT Guaranteed

1. **Gateway Downgrade**
   - Downgrading gateway to v1.0 will reject v1.1 tokens
   - This is **intentional** and **safe** (fail-closed)

2. **Major Version Compatibility**
   - Gateway v1.x cannot process v2.x tokens
   - Explicit migration required

3. **Cross-Version Delegation**
   - Cannot attenuate v1.0 token into v2.0 token
   - Child tokens inherit parent's schema version

## Security Considerations

### Fail-Closed by Default

The versioning system prioritizes security over availability:

- Unknown versions → **DENY**
- Missing version → **DENY**
- Parsing errors → **DENY**

**Rationale:** Better to deny access than silently grant incorrect permissions.

### Version Downgrade Attacks

**Threat:** Attacker forces issuer to mint old-version tokens with known vulnerabilities

**Mitigation:**
- Issuer configuration locks to single version
- Only current version should be minted in production
- Monitor for unexpected old-version tokens

### Version String Validation

Version strings are validated via exact match against a static set:

```typescript
SUPPORTED_SCHEMA_VERSIONS.has(token.schemaVersion)
```

**Security Properties:**
- No regex parsing (no ReDoS)
- No semver parsing (no injection)
- Constant-time lookup (no timing attacks)

### Audit Trail

`schemaVersion` is signed into the JWT payload:
- Tamper-evident
- Captured in audit logs
- Enables forensic analysis of version-related issues

## Monitoring and Observability

### Recommended Metrics

Track these metrics for version health:

1. **Token Version Distribution**
   ```
   capability_token.issued{version="1.0"}
   capability_token.issued{version="1.1"}
   ```

2. **Version Validation Outcomes**
   ```
   capability_token.verified{version="1.0", outcome="success"}
   capability_token.verified{version="1.1", outcome="success"}
   capability_token.verified{version="2.0", outcome="rejected"}
   ```

3. **Version Mismatches**
   ```
   capability_token.version_mismatch{expected="1.0", actual="missing"}
   capability_token.version_mismatch{expected="1.0", actual="2.0"}
   ```

### Alerting Thresholds

- **High Priority:** >1% token rejections due to version mismatch
- **Medium Priority:** Old version tokens issued after deprecation
- **Low Priority:** Mixed version distribution during migration window

## FAQ

### Q: Why not use semantic versioning (e.g., 1.2.3)?

**A:** Patch versions don't add value for schema evolution. Changes are either:
- Backward-compatible (minor version)
- Breaking (major version)

A two-part version (MAJOR.MINOR) is simpler and sufficient.

### Q: Can I skip version validation during testing?

**A:** No. Version validation is a security boundary and should always be active. Use test tokens with valid schema versions.

### Q: What happens to tokens in flight during a version migration?

**A:** Tokens have short TTLs (default 15 minutes). During migration:
1. Old tokens expire naturally
2. New tokens are accepted by updated gateways
3. Minimal overlap period

### Q: Can I issue multiple schema versions simultaneously?

**A:** Technically yes (for migration), but:
- Not recommended for steady-state
- Increases complexity
- Issuer should mint single version (current)

### Q: How does schemaVersion relate to kid (key ID)?

**A:** They serve different purposes:
- **`schemaVersion`**: Token structure evolution
- **`kid`**: Key rotation and signing identity

Both are orthogonal. A token can have:
- `schemaVersion: "1.0"` with `kid: "2023-key"`
- `schemaVersion: "1.0"` with `kid: "2024-key"`

## References

- [Capability Model Documentation](./capability-model.md)
- [JWT Best Practices (RFC 8725)](https://datatracker.ietf.org/doc/html/rfc8725)
- [Semantic Versioning](https://semver.org/)

## Change Log

### 2026-04-28
- Initial version (1.0) implemented
- Schema versioning added to all token creation paths
- Gateway validation implemented
- This document created
