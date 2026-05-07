/**
 * Tests for buildProofsVerifierFromEnv — covers the post-review hardening:
 *
 *   - fails fast when REQUIRE_COSIGNATURE_COUNT > number of trusted cosigner
 *     keys (would otherwise reject 100% of tokens at runtime);
 *   - builds an advisory verifier when only the JWKS material is configured
 *     (no REQUIRE_* flag) so unverified proofs surface in audit during a
 *     staged rollout.
 */

import { createLogger, GatewayConfig, SoftwareCosigner } from '@euno/common';
import { buildProofsVerifierFromEnv } from '../src/proofs-verifier-bootstrap';

function baseCfg(overrides: Partial<GatewayConfig> = {}): GatewayConfig {
  // Only the fields buildProofsVerifierFromEnv reads matter; cast through
  // unknown to avoid pulling in the full GatewayConfig surface here.
  return {
    REQUIRE_COSIGNATURE_COUNT: 0,
    REQUIRE_TRANSPARENCY_LOG_PROOF: false,
    ...overrides,
  } as unknown as GatewayConfig;
}

describe('buildProofsVerifierFromEnv', () => {
  const logger = createLogger('proofs-verifier-bootstrap-test');

  it('returns undefined when nothing is configured (back-compat hot path)', () => {
    expect(buildProofsVerifierFromEnv(baseCfg(), logger)).toBeUndefined();
  });

  it('FAILS FAST when REQUIRE_COSIGNATURE_COUNT exceeds trusted key count', async () => {
    const c1 = await SoftwareCosigner.generateEd25519('cosigner-1');
    const jwks = { keys: [await c1.getPublicJwk()] };
    const cfg = baseCfg({
      REQUIRE_COSIGNATURE_COUNT: 2,
      COSIGNER_JWKS_INLINE: JSON.stringify(jwks),
    } as Partial<GatewayConfig>);

    expect(() => buildProofsVerifierFromEnv(cfg, logger)).toThrow(
      /every token would be rejected/,
    );
  });

  it('builds an advisory verifier when JWKS is configured without REQUIRE_* flags', async () => {
    const c1 = await SoftwareCosigner.generateEd25519('cosigner-1');
    const jwks = { keys: [await c1.getPublicJwk()] };
    const cfg = baseCfg({
      // REQUIRE_COSIGNATURE_COUNT stays 0 (advisory mode)
      COSIGNER_JWKS_INLINE: JSON.stringify(jwks),
    } as Partial<GatewayConfig>);

    const v = buildProofsVerifierFromEnv(cfg, logger);
    expect(v).toBeDefined();
    // Advisory: isNoOp() returns true (no strict requirement) BUT the
    // verifier still runs opportunistic checks on tokens that carry proofs.
    expect(v!.isNoOp()).toBe(true);
  });
});
