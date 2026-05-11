import * as jose from 'jose';
import { CapabilityTokenPayload, IssuanceContext } from '@euno/common';

export interface LocalTokenSignerOptions {
  privateKeyPem: string;
  publicKeyPem: string;
  keyId?: string;
  algorithm?: 'RS256' | 'ES256';
}

export class LocalTokenSigner {
  private readonly privateKeyPem: string;
  private readonly publicKeyPem: string;
  private readonly keyId: string;
  private readonly algorithm: 'RS256' | 'ES256';
  /** Lazily cached imported private key to avoid re-parsing on every sign(). */
  private cachedPrivateKey: jose.KeyLike | null = null;

  constructor(opts: LocalTokenSignerOptions) {
    this.privateKeyPem = opts.privateKeyPem;
    this.publicKeyPem = opts.publicKeyPem;
    this.keyId = opts.keyId ?? 'minter-local-key';
    this.algorithm = opts.algorithm ?? 'RS256';
  }

  static async generate(algorithm: 'RS256' | 'ES256' = 'RS256'): Promise<LocalTokenSigner> {
    const { publicKey, privateKey } = algorithm === 'ES256'
      ? await jose.generateKeyPair('ES256')
      : await jose.generateKeyPair('RS256');
    const privateKeyPem = await jose.exportPKCS8(privateKey);
    const publicKeyPem = await jose.exportSPKI(publicKey);
    return new LocalTokenSigner({ privateKeyPem, publicKeyPem, algorithm });
  }

  async sign(payload: CapabilityTokenPayload, _context?: IssuanceContext): Promise<string> {
    // Import the private key lazily on first use and cache it for subsequent calls
    // to avoid the cost of PKCS8 parsing on every token mint.
    if (!this.cachedPrivateKey) {
      this.cachedPrivateKey = await jose.importPKCS8(this.privateKeyPem, this.algorithm);
    }
    return new jose.SignJWT(payload as unknown as jose.JWTPayload)
      .setProtectedHeader({ alg: this.algorithm, kid: this.keyId })
      .sign(this.cachedPrivateKey);
  }

  async getPublicKey(): Promise<string> {
    return this.publicKeyPem;
  }

  async getKeyId(): Promise<string> {
    return this.keyId;
  }

  getAlgorithm(): string {
    return this.algorithm;
  }
}
