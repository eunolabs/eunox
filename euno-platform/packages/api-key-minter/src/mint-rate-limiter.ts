export interface MintRateLimiterOptions {
  maxMintsPerWindow: number;
  windowSeconds: number;
}

export interface MintRateLimiter {
  check(tenantId: string): Promise<{ allowed: boolean; retryAfterSeconds?: number }>;
}

export class InMemoryMintRateLimiter implements MintRateLimiter {
  private readonly counts = new Map<string, { count: number; windowStart: number }>();
  private readonly maxMints: number;
  private readonly windowMs: number;

  constructor(opts: MintRateLimiterOptions = { maxMintsPerWindow: 100, windowSeconds: 60 }) {
    if (!Number.isFinite(opts.maxMintsPerWindow) || !Number.isInteger(opts.maxMintsPerWindow) || opts.maxMintsPerWindow <= 0) {
      throw new Error(
        `InMemoryMintRateLimiter: invalid maxMintsPerWindow ${opts.maxMintsPerWindow}. Must be a finite positive integer.`,
      );
    }
    if (!Number.isFinite(opts.windowSeconds) || !Number.isInteger(opts.windowSeconds) || opts.windowSeconds <= 0) {
      throw new Error(
        `InMemoryMintRateLimiter: invalid windowSeconds ${opts.windowSeconds}. Must be a finite positive integer.`,
      );
    }
    this.maxMints = opts.maxMintsPerWindow;
    this.windowMs = opts.windowSeconds * 1000;
  }

  async check(tenantId: string): Promise<{ allowed: boolean; retryAfterSeconds?: number }> {
    const now = Date.now();
    const entry = this.counts.get(tenantId);

    if (!entry || now - entry.windowStart >= this.windowMs) {
      this.counts.set(tenantId, { count: 1, windowStart: now });
      return { allowed: true };
    }

    if (entry.count >= this.maxMints) {
      const retryAfterMs = this.windowMs - (now - entry.windowStart);
      return { allowed: false, retryAfterSeconds: Math.ceil(retryAfterMs / 1000) };
    }

    entry.count++;
    return { allowed: true };
  }
}
