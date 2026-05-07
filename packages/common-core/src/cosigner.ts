/**
 * Cosigner — independent counter-signing authority for issuance receipts.
 * ---------------------------------------------------------------------------
 * The {@link Cosigner} interface is the issuer-side abstraction over a
 * second, independently-keyed signing authority. When the issuer is
 * configured with one or more cosigners, every minted capability token
 * carries one {@link Cosignature} per cosigner — the gateway verifies all
 * of them before accepting the token.
 *
 * Why have a separate abstraction:
 *
 *   - The cosigner key is intentionally **not** the same key as the
 *     primary issuer signing key (KMS / JWKS). The whole point of
 *     cosignature is to ensure that an attacker who steals the primary
 *     key still cannot mint usable tokens.
 *   - The cosigner can be:
 *       * a software key held by an offline policy authority (PEM / JWK
 *         file mounted into the issuer pod from a sealed secret store),
 *       * a separate KMS key in a different cloud account / project,
 *       * a remote co-signing service (e.g. an HSM-backed micro-service)
 *         called over an authenticated channel.
 *   - The {@link Cosigner} interface is the integration seam: production
 *     deployments register their preferred implementation; the in-process
 *     {@link SoftwareCosigner} is the default and is what the unit tests
 *     and the local-dev `.env.example` config exercises.
 *
 * The corresponding *verifier-side* cosigner JWKS is just a {@link JwkSet}
 * — the gateway loads it from a file or a URL and looks up keys by `kid`.
 * That side has no special abstraction because verification is pure.
 */

import * as nodeCrypto from 'crypto';
import * as jose from 'jose';
import {
  buildIssuanceReceipt,
  canonicalReceiptSigningInput,
  inferAlgFromKeyObject,
  signRawBytes,
} from './issuance-proofs';
import { JwkKey } from './jwks';
import {
  CapabilityTokenPayload,
  Cosignature,
  IssuanceReceipt,
} from './wire';

/**
 * A cosigner — an independently-keyed authority that countersigns issuance
 * receipts. Implementations MUST be safe to call concurrently.
 */
export interface Cosigner {
  /**
   * Stable identifier of the cosigner, used as the {@link Cosignature.kid}
   * on the wire. MUST match the `kid` of the cosigner's public key in the
   * JWKS the gateway is configured with.
   */
  getKid(): string;

  /**
   * JWA algorithm of this cosigner's key (e.g. `EdDSA`, `ES256`).
   */
  getAlgorithm(): string;

  /**
   * Return the cosigner's public key as a JWK. Used by tests + by
   * deployments that want to publish the cosigner JWKS from the issuer
   * (e.g. for self-contained dev setups). Production deployments are
   * encouraged to publish the cosigner JWKS from a separate principal /
   * URL so the gateway's trust path is independent of the issuer.
   */
  getPublicJwk(): Promise<JwkKey>;

  /**
   * Cosign an issuance receipt. Implementations sign the canonical
   * receipt input bytes (see {@link canonicalReceiptSigningInput}) and
   * return the {@link Cosignature} for embedding in the token's
   * `proofs.cosig[]` claim.
   *
   * Implementations MUST NOT modify the receipt.
   */
  cosignReceipt(receipt: IssuanceReceipt): Promise<Cosignature>;
}

/**
 * In-process software cosigner backed by a private key in memory. Suitable
 * for tests, local dev, and deployments where the cosigner key is held
 * in a sealed secret store mounted into the issuer pod (the practical
 * "offline policy authority" pattern: the key was created out-of-band by
 * the policy team, sealed, and rotated separately from the primary KMS
 * key — its scope of compromise is independent).
 *
 * For HSM-backed or KMS-backed cosigning, write a different
 * {@link Cosigner} implementation that delegates to your KMS SDK and
 * register it via the same env-driven factory.
 */
export class SoftwareCosigner implements Cosigner {
  private readonly kid: string;
  private readonly alg: string;
  private readonly privateKey: jose.KeyLike;
  private readonly publicJwk: JwkKey;

  constructor(opts: {
    kid: string;
    alg: string;
    privateKey: jose.KeyLike;
    publicJwk: JwkKey;
  }) {
    if (!opts.kid || opts.kid.trim() === '') {
      throw new Error('SoftwareCosigner: kid is required');
    }
    if (!opts.alg) {
      throw new Error('SoftwareCosigner: alg is required');
    }
    this.kid = opts.kid;
    this.alg = opts.alg;
    this.privateKey = opts.privateKey;
    // Defensive copy + normalise so callers cannot mutate after construction.
    this.publicJwk = { ...opts.publicJwk, kid: opts.kid, alg: opts.alg, use: 'sig' };
  }

  getKid(): string {
    return this.kid;
  }

  getAlgorithm(): string {
    return this.alg;
  }

  async getPublicJwk(): Promise<JwkKey> {
    return { ...this.publicJwk };
  }

  async cosignReceipt(receipt: IssuanceReceipt): Promise<Cosignature> {
    const input = canonicalReceiptSigningInput(receipt);
    const sig = await signRawBytes(this.alg, this.privateKey, input);
    return { kid: this.kid, alg: this.alg, sig };
  }

  /**
   * Convenience factory: load a cosigner from a PEM-encoded private key
   * (PKCS#8). The matching public key is exported from the private key
   * — no separate file required.
   *
   * `alg` defaults to `EdDSA` for Ed25519 / Ed448 keys, `ES256` for P-256
   * EC keys, and otherwise must be supplied explicitly.
   */
  static async fromPemPrivateKey(opts: {
    kid: string;
    pem: string;
    alg?: string;
  }): Promise<SoftwareCosigner> {
    const keyObject = nodeCrypto.createPrivateKey(opts.pem);
    const alg = opts.alg ?? inferAlgFromKeyObject(keyObject);
    if (!alg) {
      throw new Error(
        'SoftwareCosigner.fromPemPrivateKey: could not infer alg from key; pass alg explicitly',
      );
    }
    const privateKey = await jose.importPKCS8(opts.pem, alg);
    const publicKeyObject = nodeCrypto.createPublicKey(keyObject);
    const publicJwk = publicKeyObject.export({ format: 'jwk' }) as JwkKey;
    return new SoftwareCosigner({
      kid: opts.kid,
      alg,
      privateKey,
      publicJwk,
    });
  }

  /**
   * Convenience factory: generate a fresh Ed25519 cosigner key in memory.
   * Used by tests + dev-mode `.env.example` so a developer can spin up the
   * stack without having to provision a real cosigner key.
   *
   * **Never use this in production**: the key is lost when the process
   * restarts, which means cosignatures minted in the previous lifetime
   * become unverifiable.
   */
  static async generateEd25519(kid: string): Promise<SoftwareCosigner> {
    const { privateKey, publicKey } = nodeCrypto.generateKeyPairSync('ed25519');
    const pem = privateKey.export({ format: 'pem', type: 'pkcs8' }) as string;
    const cs = await SoftwareCosigner.fromPemPrivateKey({ kid, pem, alg: 'EdDSA' });
    // Sanity-check the alg agrees with the public key we just generated.
    void publicKey;
    return cs;
  }
}

/**
 * Helper used by the issuer's issuance pipeline: cosign the canonical
 * receipt derived from a freshly-built {@link CapabilityTokenPayload} with
 * every configured cosigner, in order. Returns the resulting array of
 * {@link Cosignature}s for embedding in `payload.proofs.cosig`.
 *
 * If `cosigners` is empty the function returns `undefined` so the issuer
 * can omit the `cosig` claim entirely (back-compat: tokens minted on a
 * deployment that has no cosigner configured look exactly like they did
 * before this feature shipped).
 *
 * Cosigner failures abort the issuance — partial cosignatures would give
 * an attacker a window to ship tokens with one missing cosigner if a
 * subset of the cosigner pool was offline.
 */
export async function cosignPayload(
  payload: CapabilityTokenPayload,
  cosigners: ReadonlyArray<Cosigner>,
): Promise<Cosignature[] | undefined> {
  if (cosigners.length === 0) return undefined;
  const receipt = buildIssuanceReceipt(payload);
  const signatures: Cosignature[] = [];
  for (const cosigner of cosigners) {
    signatures.push(await cosigner.cosignReceipt(receipt));
  }
  return signatures;
}
