# Distributed Token Revocation

## Overview

Token revocation is currently implemented using an in-memory JTI (JWT Token ID) store. While sufficient for single-instance deployments or development, production deployments with multiple gateway instances require a distributed revocation list to ensure revoked tokens are immediately recognized across all instances.

## Current Implementation

Location: `/packages/tool-gateway/src/verifier.ts`

The current implementation stores revoked token IDs in an in-memory `Map` keyed by JTI with the token expiry time as the value. Stale entries (whose expiry has passed) are pruned on each new revocation to keep memory usage bounded:

```typescript
export class JWTTokenVerifier {
  private revokedTokens: Map<string, number> = new Map(); // jti → expiry (Unix seconds)
  // ...
}
```

**Limitations:**
- Revocation on one gateway instance is not visible to other instances
- Revocations are lost on service restart
- No persistence for audit or recovery

## Production Architecture: Redis-Based Revocation

### Architecture Diagram

```
┌─────────────────┐     ┌─────────────────┐
│   Gateway       │     │   Gateway       │
│   Instance 1    │     │   Instance 2    │
└────────┬────────┘     └────────┬────────┘
         │                       │
         │  Check/Add Revoked   │
         └──────────┬────────────┘
                    │
         ┌──────────▼──────────┐
         │                     │
         │   Redis Cluster     │
         │  (Revoked Tokens)   │
         │                     │
         └─────────────────────┘
```

### Implementation Steps

#### 1. Add Redis Client Dependencies

Update `packages/tool-gateway/package.json`:

```json
{
  "dependencies": {
    "ioredis": "^5.3.2"
  },
  "devDependencies": {
    "@types/ioredis": "^5.0.0"
  }
}
```

#### 2. Create Redis Revocation Store

Create `packages/tool-gateway/src/redis-revocation-store.ts`:

```typescript
import Redis from 'ioredis';
import { Logger } from '@euno/common';

export interface RevocationStore {
  isRevoked(tokenId: string): Promise<boolean>;
  revoke(tokenId: string, expiresAt: number): Promise<void>;
}

export class RedisRevocationStore implements RevocationStore {
  private client: Redis;
  private logger: Logger;

  constructor(redisUrl: string, logger: Logger) {
    this.client = new Redis(redisUrl, {
      retryStrategy: (times) => {
        const delay = Math.min(times * 50, 2000);
        return delay;
      },
    });
    this.logger = logger;

    this.client.on('connect', () => {
      this.logger.info('Connected to Redis revocation store');
    });

    this.client.on('error', (err) => {
      this.logger.error('Redis connection error', { error: err.message });
    });
  }

  async isRevoked(tokenId: string): Promise<boolean> {
    try {
      const exists = await this.client.exists(`revoked:${tokenId}`);
      return exists === 1;
    } catch (error) {
      this.logger.error('Failed to check token revocation status', {
        tokenId,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      // Fail closed - treat as revoked if Redis is unavailable
      return true;
    }
  }

  async revoke(tokenId: string, expiresAt: number): Promise<void> {
    try {
      const key = `revoked:${tokenId}`;
      const now = Math.floor(Date.now() / 1000);
      const ttl = Math.max(expiresAt - now, 0);

      if (ttl > 0) {
        await this.client.setex(key, ttl, '1');
        this.logger.info('Token revoked in Redis', { tokenId, ttlSeconds: ttl });
      } else {
        this.logger.warn('Token already expired, skipping revocation', { tokenId });
      }
    } catch (error) {
      this.logger.error('Failed to revoke token in Redis', {
        tokenId,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      throw error;
    }
  }

  async close(): Promise<void> {
    await this.client.quit();
  }
}

// In-memory fallback for development
export class InMemoryRevocationStore implements RevocationStore {
  private revokedTokens: Set<string> = new Set();

  async isRevoked(tokenId: string): Promise<boolean> {
    return this.revokedTokens.has(tokenId);
  }

  async revoke(tokenId: string, _expiresAt: number): Promise<void> {
    this.revokedTokens.add(tokenId);
  }

  async close(): Promise<void> {
    this.revokedTokens.clear();
  }
}
```

#### 3. Update Verifier to Use RevocationStore

Modify `packages/tool-gateway/src/verifier.ts`:

```typescript
import { RevocationStore } from './redis-revocation-store';

export class JWTTokenVerifier {
  private publicKey: string;
  private revocationStore: RevocationStore;

  constructor(publicKey: string, revocationStore: RevocationStore) {
    this.publicKey = publicKey;
    this.revocationStore = revocationStore;
  }

  async verify(token: string): Promise<CapabilityToken> {
    // ... existing verification logic ...

    // Check revocation status
    const tokenId = payload.jti;
    if (tokenId && await this.revocationStore.isRevoked(tokenId)) {
      throw new CapabilityError(
        ErrorCode.AUTHENTICATION_FAILED,
        'Token has been revoked',
        401
      );
    }

    // ... rest of verification ...
  }

  async revokeToken(tokenId: string, expiresAt: number): Promise<void> {
    await this.revocationStore.revoke(tokenId, expiresAt);
  }
}
```

#### 4. Configure Redis in Deployment

Add to environment configuration:

```bash
# Redis configuration for distributed revocation
REDIS_URL=redis://redis-cluster:6379
# Or for Redis Cluster
REDIS_CLUSTER_NODES=redis-node1:6379,redis-node2:6379,redis-node3:6379
```

Kubernetes ConfigMap example:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: gateway-config
  namespace: euno-system
data:
  REDIS_URL: "redis://euno-redis:6379"
  NODE_ENV: "production"
```

#### 5. Deploy Redis

Example Redis deployment for Kubernetes:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: euno-redis
  namespace: euno-system
spec:
  replicas: 1  # Use 3+ for Redis Cluster in production
  selector:
    matchLabels:
      app: euno-redis
  template:
    metadata:
      labels:
        app: euno-redis
    spec:
      containers:
      - name: redis
        image: redis:7-alpine
        ports:
        - containerPort: 6379
        resources:
          limits:
            cpu: 500m
            memory: 512Mi
          requests:
            cpu: 250m
            memory: 256Mi
        volumeMounts:
        - name: redis-data
          mountPath: /data
      volumes:
      - name: redis-data
        persistentVolumeClaim:
          claimName: redis-pvc
---
apiVersion: v1
kind: Service
metadata:
  name: euno-redis
  namespace: euno-system
spec:
  selector:
    app: euno-redis
  ports:
  - port: 6379
    targetPort: 6379
```

## Alternative Implementations

### Azure Cache for Redis

For Azure deployments, use Azure Cache for Redis:

```bash
REDIS_URL=redis://euno-cache.redis.cache.windows.net:6379
REDIS_PASSWORD=your-access-key
```

Connection string in code:

```typescript
const redis = new Redis({
  host: 'euno-cache.redis.cache.windows.net',
  port: 6379,
  password: process.env.REDIS_PASSWORD,
  tls: {
    servername: 'euno-cache.redis.cache.windows.net',
  },
});
```

### AWS ElastiCache

For AWS deployments:

```bash
REDIS_URL=redis://euno-cache.abc123.use1.cache.amazonaws.com:6379
```

### Database-Based Revocation

For smaller deployments, use PostgreSQL or MySQL:

```typescript
export class DatabaseRevocationStore implements RevocationStore {
  private pool: Pool; // pg or mysql2 pool

  async isRevoked(tokenId: string): Promise<boolean> {
    const result = await this.pool.query(
      'SELECT EXISTS(SELECT 1 FROM revoked_tokens WHERE token_id = $1 AND expires_at > NOW())',
      [tokenId]
    );
    return result.rows[0].exists;
  }

  async revoke(tokenId: string, expiresAt: number): Promise<void> {
    await this.pool.query(
      'INSERT INTO revoked_tokens (token_id, expires_at) VALUES ($1, TO_TIMESTAMP($2)) ON CONFLICT DO NOTHING',
      [tokenId, expiresAt]
    );
  }
}
```

Database schema (PostgreSQL):

```sql
CREATE TABLE revoked_tokens (
  token_id VARCHAR(255) PRIMARY KEY,
  revoked_at TIMESTAMP DEFAULT NOW(),
  expires_at TIMESTAMP NOT NULL
);

CREATE INDEX idx_revoked_tokens_expires ON revoked_tokens (expires_at);

-- Cleanup job (run periodically)
DELETE FROM revoked_tokens WHERE expires_at < NOW();
```

## Migration Strategy

### Phase 1: Dual Write (Backward Compatible)

1. Deploy Redis alongside existing gateways
2. Update code to write to both in-memory and Redis
3. Read from in-memory first, fallback to Redis

### Phase 2: Redis Primary

1. Update code to use Redis as primary
2. Keep in-memory as local cache with TTL

### Phase 3: Redis Only

1. Remove in-memory store entirely
2. Full distributed revocation

## Testing

### Unit Tests

```typescript
describe('RedisRevocationStore', () => {
  let store: RedisRevocationStore;
  let redis: Redis;

  beforeAll(async () => {
    redis = new Redis('redis://localhost:6379');
    store = new RedisRevocationStore('redis://localhost:6379', logger);
  });

  afterAll(async () => {
    await store.close();
    await redis.quit();
  });

  it('should revoke token', async () => {
    const tokenId = 'test-token-123';
    const expiresAt = Math.floor(Date.now() / 1000) + 3600;

    await store.revoke(tokenId, expiresAt);
    const isRevoked = await store.isRevoked(tokenId);

    expect(isRevoked).toBe(true);
  });

  it('should expire revoked token', async () => {
    const tokenId = 'test-token-expire';
    const expiresAt = Math.floor(Date.now() / 1000) + 2; // 2 seconds

    await store.revoke(tokenId, expiresAt);
    await new Promise(resolve => setTimeout(resolve, 3000));

    const isRevoked = await store.isRevoked(tokenId);
    expect(isRevoked).toBe(false);
  });
});
```

### Integration Tests

Test multi-instance scenario:

```typescript
describe('Multi-Gateway Revocation', () => {
  it('should propagate revocation across instances', async () => {
    const gateway1 = new JWTTokenVerifier(publicKey, redisStore1);
    const gateway2 = new JWTTokenVerifier(publicKey, redisStore2);

    const tokenId = 'test-multi-instance';
    await gateway1.revokeToken(tokenId, expiresAt);

    // Wait for Redis propagation
    await new Promise(resolve => setTimeout(resolve, 100));

    const isRevokedOnGateway2 = await redisStore2.isRevoked(tokenId);
    expect(isRevokedOnGateway2).toBe(true);
  });
});
```

## Monitoring

### Metrics to Track

1. **Revocation Latency**: Time to propagate revocation across instances
2. **Redis Connection Health**: Connection errors, retry attempts
3. **Cache Hit Rate**: Percentage of revocation checks served from local cache
4. **Revoked Token Count**: Total number of active revocations

### Example Prometheus Metrics

```typescript
const revocationLatency = new prometheus.Histogram({
  name: 'euno_revocation_latency_seconds',
  help: 'Latency of token revocation operations',
});

const redisErrors = new prometheus.Counter({
  name: 'euno_redis_errors_total',
  help: 'Total Redis connection errors',
});
```

## Security Considerations

1. **Encryption in Transit**: Use TLS for Redis connections in production
2. **Access Control**: Redis AUTH password or Redis ACL
3. **Network Isolation**: Deploy Redis in private subnet
4. **Backup**: Regular Redis snapshots for audit trail
5. **Fail-Closed**: If Redis is unavailable, treat tokens as revoked

## Performance Optimization

1. **Local Caching**: Cache revocation status locally with short TTL (5-10 seconds)
2. **Batch Checks**: Check multiple tokens in single Redis pipeline
3. **Redis Cluster**: Use Redis Cluster for horizontal scaling
4. **Key Expiration**: Let Redis handle automatic cleanup of expired tokens

## Summary

For production deployments with multiple gateway instances:

- ✅ Use Redis for distributed revocation storage
- ✅ Implement fail-closed behavior (treat as revoked if Redis unavailable)
- ✅ Use key expiration to automatically clean up expired tokens
- ✅ Monitor Redis health and revocation propagation latency
- ✅ Test multi-instance scenarios in staging environment

This ensures consistent revocation behavior across all gateway instances and provides a production-ready token revocation system.
