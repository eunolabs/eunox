/**
 * Wiring helpers for multi-issuer trust hardening — load cosigners and
 * transparency logs from the validated env-config and hand them to the
 * {@link CapabilityIssuerService} constructor.
 *
 * Lives in its own module so the orchestrator (`index.ts`) stays focused
 * on top-level service composition.
 *
 * Inputs:
 *   - `COSIGNERS` (JSON array) — see schema.ts for the per-element shape.
 *   - `TRANSPARENCY_LOG_*` — toggles + key material for the in-process
 *     log. Cross-field validation in the schema guarantees that every
 *     required field is present when the toggle is on.
 *
 * Both loaders fail loudly on bad input: an issuer that boots with a
 * misconfigured cosigner / log would degrade silently to the previous
 * single-signer trust model, which is exactly the regression this whole
 * feature exists to prevent.
 */

import * as fs from 'fs';
import {
  Cosigner,
  IssuerConfig,
  Logger,
  SoftwareCosigner,
  TransparencyLog,
  InMemoryTransparencyLog,
} from '@euno/common';

interface CosignerSpec {
  kid: string;
  alg?: string;
  keyPem?: string;
  keyPemFile?: string;
}

/**
 * Parse the `COSIGNERS` env var into a list of {@link Cosigner}s.
 *
 * Format: JSON array of `{ kid, alg?, keyPem | keyPemFile }`. Each
 * spec produces a {@link SoftwareCosigner} loaded from the supplied
 * private key. `alg` is inferred from the key material when omitted
 * (EdDSA for Ed25519/Ed448, ES{256,384,512} for P-{256,384,521}).
 *
 * Returns an empty array (no cosignature) when `COSIGNERS` is unset.
 */
export async function loadCosignersFromEnv(
  cfg: IssuerConfig,
  logger: Logger,
): Promise<Cosigner[]> {
  const raw = cfg.COSIGNERS;
  if (!raw) return [];

  let specs: CosignerSpec[];
  try {
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) {
      throw new Error('COSIGNERS must be a JSON array');
    }
    specs = parsed as CosignerSpec[];
  } catch (err) {
    throw new Error(
      `COSIGNERS is not valid JSON: ${err instanceof Error ? err.message : 'unknown error'}`,
    );
  }

  if (specs.length === 0) return [];

  const cosigners: Cosigner[] = [];
  const seenKids = new Set<string>();
  for (let i = 0; i < specs.length; i += 1) {
    const spec = specs[i]!;
    if (!spec.kid || typeof spec.kid !== 'string') {
      throw new Error(`COSIGNERS[${i}].kid is required and must be a non-empty string`);
    }
    if (seenKids.has(spec.kid)) {
      throw new Error(
        `COSIGNERS[${i}].kid="${spec.kid}" is a duplicate; cosigner kids must be unique`,
      );
    }
    seenKids.add(spec.kid);

    let pem: string;
    if (spec.keyPem) {
      pem = spec.keyPem;
    } else if (spec.keyPemFile) {
      try {
        pem = fs.readFileSync(spec.keyPemFile, 'utf8');
      } catch (err) {
        throw new Error(
          `COSIGNERS[${i}] (kid="${spec.kid}"): failed to read keyPemFile "${spec.keyPemFile}": ${err instanceof Error ? err.message : 'unknown error'}`,
        );
      }
    } else {
      throw new Error(
        `COSIGNERS[${i}] (kid="${spec.kid}"): exactly one of keyPem / keyPemFile is required`,
      );
    }

    try {
      const cosigner = await SoftwareCosigner.fromPemPrivateKey({
        kid: spec.kid,
        pem,
        ...(spec.alg ? { alg: spec.alg } : {}),
      });
      cosigners.push(cosigner);
    } catch (err) {
      throw new Error(
        `COSIGNERS[${i}] (kid="${spec.kid}"): failed to load: ${err instanceof Error ? err.message : 'unknown error'}`,
      );
    }
  }

  logger.info('Issuance cosignature enabled', {
    count: cosigners.length,
    kids: cosigners.map((c) => c.getKid()),
  });
  return cosigners;
}

/**
 * Build the configured transparency log from env (or return `[]` when
 * disabled). The schema guarantees every required field is present
 * before this runs.
 */
export async function loadTransparencyLogsFromEnv(
  cfg: IssuerConfig,
  logger: Logger,
): Promise<TransparencyLog[]> {
  if (!cfg.TRANSPARENCY_LOG_ENABLED) return [];

  const logId = cfg.TRANSPARENCY_LOG_ID!;
  const kid = cfg.TRANSPARENCY_LOG_KEY_KID!;
  let pem: string;
  if (cfg.TRANSPARENCY_LOG_KEY_PEM) {
    pem = cfg.TRANSPARENCY_LOG_KEY_PEM;
  } else {
    try {
      pem = fs.readFileSync(cfg.TRANSPARENCY_LOG_KEY_FILE!, 'utf8');
    } catch (err) {
      throw new Error(
        `TRANSPARENCY_LOG_KEY_FILE: failed to read "${cfg.TRANSPARENCY_LOG_KEY_FILE}": ${err instanceof Error ? err.message : 'unknown error'}`,
      );
    }
  }

  const log = await InMemoryTransparencyLog.fromPemPrivateKey({
    logId,
    kid,
    pem,
    ...(cfg.TRANSPARENCY_LOG_KEY_ALG ? { alg: cfg.TRANSPARENCY_LOG_KEY_ALG } : {}),
  });
  logger.info('Issuance transparency log enabled', {
    logId,
    kid,
    note:
      'In-process software log: for production-grade independence run an out-of-process log ' +
      'with its own KMS key and load only its public JWKS into the gateway.',
  });
  return [log];
}
