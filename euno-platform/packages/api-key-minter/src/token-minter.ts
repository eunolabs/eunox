import {
  CapabilityTokenPayload,
  CapabilityConstraint,
  CAPABILITY_TOKEN_SCHEMA_VERSION,
  TokenSigner,
  generateId,
  getCurrentTimestamp,
} from '@euno/common';

export const MINTER_DEFAULT_TTL_SECONDS = 300;
export const MINTER_MAX_TTL_SECONDS = 300;

export interface MintTokenInput {
  tenantId: string;
  agentId: string;
  sessionId: string;
  capabilities: CapabilityConstraint[];
  apiKeyPrefix: string;
  scopes: string[];
  policyId: string;
}

export interface MintTokenResult {
  capabilityToken: string;
  expiresAt: number;
  jti: string;
}

export interface TokenMinterOptions {
  signer: TokenSigner;
  issuerDid: string;
  gatewayAudience?: string;
  ttlSeconds?: number;
}

export class TokenMinter {
  private readonly signer: TokenSigner;
  private readonly issuerDid: string;
  private readonly gatewayAudience: string;
  private readonly ttlSeconds: number;

  constructor(opts: TokenMinterOptions) {
    this.signer = opts.signer;
    this.issuerDid = opts.issuerDid;
    this.gatewayAudience = opts.gatewayAudience ?? 'tool-gateway';

    // Validate and cap ttlSeconds.  Fail fast on NaN/Infinity/<=0 so that
    // a misconfigured minter does not silently mint tokens with invalid `exp`.
    const raw = opts.ttlSeconds ?? MINTER_DEFAULT_TTL_SECONDS;
    if (!Number.isFinite(raw) || !Number.isInteger(raw) || raw <= 0) {
      throw new Error(
        `TokenMinter: invalid ttlSeconds ${raw}. Must be a finite positive integer.`,
      );
    }
    this.ttlSeconds = Math.min(raw, MINTER_MAX_TTL_SECONDS);
  }

  async mintToken(input: MintTokenInput): Promise<MintTokenResult> {
    const now = getCurrentTimestamp();
    const expiresAt = now + this.ttlSeconds;
    const jti = generateId();

    const payload: CapabilityTokenPayload = {
      iss: this.issuerDid,
      sub: input.agentId,
      aud: this.gatewayAudience,
      iat: now,
      exp: expiresAt,
      jti,
      schemaVersion: CAPABILITY_TOKEN_SCHEMA_VERSION,
      capabilities: input.capabilities,
      authorizedBy: {
        userId: input.apiKeyPrefix,
        roles: input.scopes,
        tenantId: input.tenantId,
      },
    };

    payload.vc = {
      '@context': [
        'https://www.w3.org/2018/credentials/v1',
        'https://schemas.euno.dev/capability-credential/v1',
      ],
      id: `urn:uuid:${jti}`,
      type: ['VerifiableCredential', 'CapabilityCredential'],
      credentialSubject: {
        id: input.agentId,
        capabilities: input.capabilities,
        authorizedBy: payload.authorizedBy,
      },
    };

    const capabilityToken = await this.signer.sign(payload);

    return { capabilityToken, expiresAt, jti };
  }
}
