/**
 * Bootstrap helper — build a {@link ProofsVerifier} from validated env config.
 *
 * Loads cosigner JWKS and per-log JWKS from inline JSON or a file path
 * and constructs the verifier. Returns `undefined` when neither
 * cosignature nor SCT is required (the gateway then runs with a
 * no-op proofs check).
 *
 * Lives in its own module so `bootstrap.ts` keeps its current size.
 */

import * as fs from 'fs';
import {
  GatewayConfig,
  JwkSet,
  Logger,
} from '@euno/common';
import { ProofsVerifier } from './proofs-verifier';

function parseJwkSet(raw: string, source: string): JwkSet {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new Error(`${source}: not valid JSON: ${err instanceof Error ? err.message : 'unknown'}`);
  }
  if (
    !parsed ||
    typeof parsed !== 'object' ||
    !Array.isArray((parsed as { keys?: unknown }).keys)
  ) {
    throw new Error(`${source}: must be a JWKS object {"keys":[...]}`);
  }
  return parsed as JwkSet;
}

function readFile(path: string, label: string): string {
  try {
    return fs.readFileSync(path, 'utf8');
  } catch (err) {
    throw new Error(`${label}: failed to read "${path}": ${err instanceof Error ? err.message : 'unknown'}`);
  }
}

/**
 * Build the {@link ProofsVerifier} from gateway env config. Returns
 * `undefined` only when the gateway has neither strict-mode requirements
 * nor any cosigner/transparency-log JWKS configured — i.e. proofs are
 * fully turned off. When trust material IS configured (even without a
 * `REQUIRE_*` flag) the verifier is built in advisory mode so
 * proof-bearing tokens are still verified opportunistically and
 * unverified proofs surface in the audit log during staged rollouts.
 */
export function buildProofsVerifierFromEnv(
  cfg: GatewayConfig,
  logger: Logger,
): ProofsVerifier | undefined {
  const cosigCount = cfg.REQUIRE_COSIGNATURE_COUNT;
  const requireScts = cfg.REQUIRE_TRANSPARENCY_LOG_PROOF;

  // Load JWKS material whenever it is configured — independent of the
  // REQUIRE_* flags — so advisory verification can run during a staged
  // rollout (deploy keys + issuer cosigning first, observe failures in
  // audit, then flip REQUIRE_COSIGNATURE_COUNT > 0 to enforce).
  const cosignerRaw = cfg.COSIGNER_JWKS_INLINE
    ?? (cfg.COSIGNER_JWKS_FILE ? readFile(cfg.COSIGNER_JWKS_FILE, 'COSIGNER_JWKS_FILE') : undefined);
  const transparencyLogRaw = cfg.TRANSPARENCY_LOG_JWKS_INLINE
    ?? (cfg.TRANSPARENCY_LOG_JWKS_FILE
      ? readFile(cfg.TRANSPARENCY_LOG_JWKS_FILE, 'TRANSPARENCY_LOG_JWKS_FILE')
      : undefined);

  // Fully off — no enforcement and no trust material configured. Skip
  // building the verifier entirely so the hot path stays a no-op.
  if (cosigCount === 0 && !requireScts && !cosignerRaw && !transparencyLogRaw) {
    return undefined;
  }

  let cosignerJwks: JwkSet | undefined;
  if (cosignerRaw) {
    cosignerJwks = parseJwkSet(cosignerRaw, 'COSIGNER_JWKS');
  }
  if (cosigCount > 0) {
    if (!cosignerJwks) {
      // Schema-level cross-field rule already catches this; defensive
      // re-check in case env was mutated post-validation.
      throw new Error(
        'REQUIRE_COSIGNATURE_COUNT > 0 but no COSIGNER_JWKS_FILE / COSIGNER_JWKS_INLINE supplied',
      );
    }
    if (cosignerJwks.keys.length < cosigCount) {
      // Fail fast: with fewer trusted cosigner keys than the threshold,
      // the gateway can NEVER accept any token. Letting this reach
      // production is a 100%-reject-rate misconfiguration; surface it
      // at boot like every other "would always reject" invariant
      // (e.g. requireTransparencyLogProof=true with empty log set).
      throw new Error(
        `COSIGNER_JWKS contains ${cosignerJwks.keys.length} key(s) but REQUIRE_COSIGNATURE_COUNT=${cosigCount} — every token would be rejected`,
      );
    }
  }

  let logJwksByLogId: Map<string, JwkSet> | undefined;
  if (transparencyLogRaw) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(transparencyLogRaw);
    } catch (err) {
      throw new Error(
        `TRANSPARENCY_LOG_JWKS: not valid JSON: ${err instanceof Error ? err.message : 'unknown'}`,
      );
    }
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error(
        'TRANSPARENCY_LOG_JWKS: must be an object mapping logId -> JWKS, e.g. {"log-id":{"keys":[...]}}',
      );
    }
    const map = new Map<string, JwkSet>();
    for (const [logId, jwks] of Object.entries(parsed as Record<string, unknown>)) {
      if (!jwks || typeof jwks !== 'object' || !Array.isArray((jwks as { keys?: unknown }).keys)) {
        throw new Error(
          `TRANSPARENCY_LOG_JWKS: entry for logId="${logId}" must be a JWKS object {"keys":[...]}`,
        );
      }
      map.set(logId, jwks as JwkSet);
    }
    if (map.size > 0) {
      logJwksByLogId = map;
    }
  }
  if (requireScts) {
    if (!logJwksByLogId || logJwksByLogId.size === 0) {
      throw new Error(
        'REQUIRE_TRANSPARENCY_LOG_PROOF=true but no TRANSPARENCY_LOG_JWKS_FILE / TRANSPARENCY_LOG_JWKS_INLINE supplied',
      );
    }
  }

  const verifier = new ProofsVerifier({
    requireCosignatureCount: cosigCount,
    requireTransparencyLogProof: requireScts,
    ...(cosignerJwks ? { cosignerJwks } : {}),
    ...(logJwksByLogId ? { logJwksByLogId } : {}),
    logger,
  });
  logger.info('Issuance proofs enforcement enabled', {
    requireCosignatureCount: cosigCount,
    requireTransparencyLogProof: requireScts,
    cosignerKeyCount: cosignerJwks?.keys.length ?? 0,
    transparencyLogCount: logJwksByLogId?.size ?? 0,
    advisoryOnly: cosigCount === 0 && !requireScts,
  });
  return verifier;
}
