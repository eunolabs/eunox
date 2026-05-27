# Redis as a Shared Enforcement Substrate: Call Counters, Kill-Switch, and DPoP Replay

_Fourth post in the "Technology choices" series. [Post 10](./10-tool-gateway-pdp.md) covers the enforcement pipeline at a high level. [Post 21](./21-operator-tooling.md) covers the operator-facing kill-switch and revocation commands that Redis backs. This post goes into the Redis data model and explains the failure modes — what happens to enforcement decisions when Redis is unavailable. See [`docs/blog-articles.md`](../blog-articles.md) for the full series index._

---

When you run a governance proxy in a single process on a developer machine, enforcement state is trivial. The `maxCalls` counter lives in memory. The kill-switch state lives in memory. DPoP nonce replay prevention is an in-memory set. Everything is fast, local, and consistent.

The moment you run more than one gateway instance — and at any production scale, you will — enforcement state becomes a distributed systems problem. A `maxCalls` counter that lives in the memory of one gateway replica is not shared with the other replicas. An agent that's been kill-switched through one replica's in-memory state can make tool calls through a different replica that doesn't know about the switch. A DPoP nonce that was seen by one replica can be replayed against another.

Redis is the answer to all three of these problems, and it's worth explaining exactly how, because the data model and the failure semantics interact with the security model in non-obvious ways.

---

## Why Redis specifically

I evaluated several options before committing to Redis.

**A relational database (Postgres)** was the first candidate. We already have Postgres for the audit ledger. Adding enforcement state tables would keep the infrastructure footprint small. The problem is latency. A SQL round trip for every tool call enforcement decision — checking `maxCalls`, checking kill-switch state, checking DPoP replay — would add 5-30ms of database latency to the hot path. At 10,000 tool calls per second across a busy gateway cluster, that's 10,000 Postgres queries per second for enforcement alone, on top of audit writes. Postgres is excellent, but it's not designed for this access pattern.

**A distributed cache like Memcached** was the second candidate. Fast key-value operations, low latency, horizontally scalable. The problem is that Memcached lacks atomic counter operations that are essential for `maxCalls` enforcement. Implementing a distributed counter with increment-check-update logic against Memcached requires optimistic locking at the application layer, which is complex and has race conditions under high concurrency.

**Redis** has the right combination: sub-millisecond operation latency for simple key lookups, atomic `INCR` and `INCRBY` for counters, `SET NX EX` for replay prevention, `PUBLISH/SUBSCRIBE` for kill-switch propagation, and a data model that maps naturally to the enforcement state we need. Redis Cluster provides horizontal sharding; Redis Sentinel or Redis Cluster provides HA. The entire enforcement state model fits cleanly in Redis primitives.

The additional operational dependency is the trade-off. Every production gateway deployment now requires a highly-available Redis cluster. This is documented prominently in the deployment guide, and the gateway bootstrap validation enforces Redis HA in production mode — if `REDIS_URL` points to a single-node Redis, the gateway refuses to start.

---

## The `maxCalls` counter

The most frequently-accessed Redis key in the system is the `maxCalls` counter. Here's the data model:

**Key:** `eunox:call:{tenantId}:{tokenJti}:{toolName}`

**Value:** integer (current call count)

**TTL:** expires when the capability token expires (token `exp` claim, derived at key creation time)

The enforcement check happens like this:

```
maxCallsKey = "eunox:call:{tenantId}:{tokenJti}:{toolName}"
currentCount = INCR maxCallsKey
if currentCount == 1:
  TTL = tokenExp - now()
  EXPIRE maxCallsKey TTL
if currentCount > maxCalls:
  return DENY, DENIAL_CODE_MAX_CALLS
```

The `INCR` is atomic. Two gateway replicas can receive simultaneous tool calls from the same agent with the same token; both call `INCR` on the same key; each gets a deterministic, non-overlapping count. There are no races.

The `EXPIRE` is set on first increment (count == 1), not on every increment, because we want to tie the counter TTL to the token expiry, not to the call time. If the counter key somehow survives past the token expiry (which shouldn't happen given the TTL, but defensive programming), a fresh `INCR` would reset it correctly because the key would have expired and been deleted by Redis, and the new `INCR` starts from 1.

One subtlety: the `EXPIRE` call is a separate Redis operation from the `INCR`, which means there's a tiny window (microseconds) where the key exists with no TTL. If the gateway crashes between `INCR` and `EXPIRE`, the key persists indefinitely. We handle this with a safety TTL: every `INCR` that creates a new key (result == 1) also triggers a background `EXPIRE` set asynchronously with a maximum TTL of 24 hours, as a backstop. The explicit TTL from the token expiry overrides this immediately if the `EXPIRE` call succeeds. The 24-hour backstop ensures keys don't accumulate indefinitely in crash scenarios.

**What about bursting?** The `maxCalls` condition is a lifetime cap, not a rate limit. If a token has `maxCalls: 100`, the agent can use all 100 calls in the first second if it wants to. Rate limiting is a separate condition type (`maxCallsPerMinute`) with a different key structure:

**Key:** `eunox:rate:{tenantId}:{tokenJti}:{toolName}:{minuteBucket}`

**Value:** counter

**TTL:** 2 minutes (one minute for the current bucket, one minute for the previous bucket to support spillover queries)

The `{minuteBucket}` is `Math.floor(Date.now() / 60000)`. Rate limiting uses a sliding window over the last 60 seconds by summing the current bucket and the proportional fraction of the previous bucket. The math is slightly more complex than a simple counter, but the implementation is in a well-tested utility function and the Redis operations are the same `INCR`/`EXPIRE` primitives.

---

## The kill-switch

The kill-switch (described from an operator perspective in post 21) is backed by three Redis keys per granularity level:

**Session kill:** `eunox:kill:session:{tenantId}:{sessionId}` — `SET "1" EX {killTTL}`

**Agent kill:** `eunox:kill:agent:{tenantId}:{agentId}` — `SET "1" EX {killTTL}`

**Global kill:** `eunox:kill:global:{tenantId}` — `SET "1"` (no TTL; must be explicitly cleared)

The enforcement check is a three-key lookup on every tool call: `GET` session key, `GET` agent key, `GET` global key. All three are checked; any positive result triggers a deny. The `GET` operations can be pipelined into a single round trip using Redis pipelines, so the overhead is one network round trip regardless of how many kill-switch states are active.

**Why `SET "1" EX {killTTL}` with a TTL?** Session and agent kills have a configurable TTL (default 24 hours) rather than persisting indefinitely. The reasoning is operational: kill-switches that are never cleaned up accumulate in Redis over time, and an operator who forgets to revive a session shouldn't cause permanent enforcement side effects. The 24-hour TTL means a kill-switched session that was abandoned will clear itself. If the intent is a permanent kill (compromised agent that should never run again), the operator should also revoke the underlying tokens, which is a separate operation with a different data model.

The global kill has no TTL because a global kill is an emergency measure that an operator must explicitly clear. An automated cleanup would be dangerous — you don't want a global kill to silently lift itself after 24 hours during an active incident.

**Propagation.** When an operator activates a kill-switch via the admin API, the API writes to Redis immediately. All gateway replicas checking Redis will see the kill-switch state on their next tool call check, which happens within milliseconds. There's no coordination protocol between replicas; they all read from the same Redis cluster, so the state is consistent (modulo Redis replication lag, discussed below).

For performance, the gateway maintains a local in-process cache of kill-switch state with a very short TTL (default 500ms for session/agent, 100ms for global). This means a kill switch takes effect within at most 500ms on any replica, rather than on every tool call. The trade-off between "instant effect" and "reduced Redis load" is configurable via `KILL_SWITCH_LOCAL_CACHE_MS`. For latency-sensitive deployments, set it to 0 to disable local caching; the kill switch takes effect on the next tool call at the cost of an extra Redis lookup per call.

---

## DPoP nonce replay prevention

DPoP (Demonstrating Proof of Possession) is a mechanism that binds an access token to a specific public key, preventing stolen-token replay attacks. When a client presents a capability token, it also presents a DPoP proof JWT — a short-lived JWT signed by the private key associated with the token, containing a unique nonce.

The gateway checks that the nonce has not been seen before. If it has, the request is rejected as a replay attack. This requires storing every nonce the gateway has ever seen (within the token's validity window) and checking each incoming nonce against that set.

**Key:** `eunox:dpop:nonce:{tenantId}:{nonce}`

**Value:** `"1"`

**TTL:** equals the capability token's remaining TTL at nonce creation time

The operation is `SET NX EX {ttl}` — "set this key with a TTL, but only if it doesn't exist." The `NX` flag makes this atomic: two concurrent requests with the same nonce result in one success (returns `OK`) and one failure (returns `nil`). The one that gets `nil` is the replay — it's rejected.

This is one of those cases where Redis's atomic semantics are doing heavy lifting that would be very difficult to replicate with any non-atomic store. The `SET NX EX` operation is the entire replay prevention mechanism; there's no application-level locking required.

**What about nonce flooding?** An attacker who knows the DPoP nonce format could attempt to flood the Redis key space by sending many requests with unique nonces, each creating a Redis key that persists for the token TTL. With a 15-minute token TTL and an attacker generating 10,000 nonces per second, that's 9,000,000 Redis keys in 15 minutes. Each key is small (~100 bytes for the key string plus 1 byte for the value), so the memory impact is about 900MB for this attack.

The mitigation is rate limiting at the API level (before the DPoP check) and enforcing a nonce format that's tied to the gateway's own nonce issuance (not freely chosen by the client). The gateway issues nonces to clients and checks that the presented nonce was one it issued, before checking the replay set. This effectively eliminates the nonce-flooding attack because an attacker can't generate valid nonces without first acquiring them from the gateway at a rate-limited endpoint.

---

## The revocation list

Token revocation (described in post 21) is the fourth enforcement state backed by Redis:

**Key:** `eunox:revoked:{tenantId}:{jti}`

**Value:** ISO timestamp of revocation

**TTL:** equals the token's `exp` - `now()` at revocation time (tokens can't be used after they expire anyway)

The revocation check is a single `GET` on this key. If the key exists, the token is revoked and the request is denied with `REVOKED_TOKEN` denial code. If the key doesn't exist, the token is valid (from a revocation perspective; other checks still apply).

The TTL on revocation entries is important: it means the revocation list self-prunes. A revoked token that has expired will have its revocation entry automatically deleted by Redis when the TTL fires. This keeps the revocation list bounded in size without requiring any explicit cleanup jobs.

---

## What happens when Redis is unavailable

This is the question that matters for the security model, and the answer was the source of more design iteration than any other aspect of the Redis integration.

The options when Redis is unavailable are:

1. **Allow the request** (fail-open): enforcement state (counters, kill-switches, replay nonces) is unavailable, so we proceed as if everything is fine.
2. **Deny the request** (fail-closed): we can't verify enforcement state, so we deny.
3. **Best-effort with degraded guarantees**: some checks fail-open, others fail-closed.

Option 1 is easy to implement and terrible for security. If Redis unavailability causes fail-open behavior, an attacker who can disrupt the Redis connection (network partition, resource exhaustion, targeted DoS) can bypass every Redis-backed enforcement check: call counters don't apply, kill-switches are ignored, revoked tokens work, DPoP replay is not checked. This is completely unacceptable.

Option 3 is tempting because some enforcement failures are less severe than others. Missing a `maxCalls` counter increment is bad (the counter drifts) but it doesn't immediately compromise security in the way that ignoring a revocation does. The problem is that this distinction is hard to communicate to operators, hard to reason about in security reviews, and hard to implement correctly. Partial degradation modes tend to create complexity that leads to bugs.

We chose Option 2: fail-closed. When any Redis call fails (connection refused, timeout, cluster error), the affected enforcement check returns `DENY` with denial code `REDIS_UNAVAILABLE`. The tool call is rejected.

There's one exception: read-only enforcement checks during a planned Redis maintenance window can be backed by a local read-through cache with a longer TTL. This is opt-in via `REDIS_DEGRADED_MODE=read-through-cache-120s`. In degraded mode:

- `maxCalls` counter reads use the last-known cached value (may be slightly stale, up to 120 seconds)
- Kill-switch reads use the last-known cached value
- Revocation reads use the last-known cached value
- DPoP nonce replay checks **always fail-closed** regardless of degraded mode setting

The DPoP exception is deliberate. The entire security property of DPoP replay prevention depends on the atomicity and freshness of the nonce store. A stale cache for nonce checks is no check at all — an attacker can replay any nonce that was used before the cache was populated. Replay prevention is never degraded.

---

## Redis HA requirements

The gateway bootstrap runs `checkProductionRedisHa()` and refuses to start if any configured Redis URL is a single-node instance in production mode. This is a hard check, not a warning.

The reason is that single-node Redis is a single point of failure for every Redis-backed enforcement check. In fail-closed mode, a Redis node failure stops the entire gateway. The HA check ensures that before you ever deploy to production, you've set up Redis Cluster or Redis Sentinel.

The check inspects the URL scheme (or seed-list format) and verifies that it points to a Sentinel or Cluster setup. Accepted HA patterns are `redis+sentinel://`, `rediss+sentinel://`, `redis+cluster://`, `rediss+cluster://`, or comma-separated seed nodes. A plain `redis://host:6379` in production mode causes startup failure with an error. The exact implementation includes the env var name (for example `REDIS_URL`) and reads: `"Gateway refused to start — REDIS_URL appears to point at a single-node Redis instance. In production, all runtime-security state stores ... See docs/deployment.md §\"Redis HA for production\"."`

For testing and development, non-production environments bypass this check. There is no `ALLOW_SINGLE_NODE_REDIS` production override.

The gateway uses separate Redis connection pools for each enforcement subsystem:

- `REDIS_URL`: general state (call counters, session data)
- `REVOCATION_REDIS_URL`: revocation list
- `KILL_SWITCH_REDIS_URL`: kill-switch state
- `CALL_COUNTER_REDIS_URL`: `maxCalls` counters (can be a different cluster to isolate counter write load)

Separating these is optional — all four can point to the same Redis cluster, which is the default. The separation option exists for deployments where different SLA or performance requirements apply to different enforcement subsystems, or where the security team wants to isolate revocation data on a separate cluster with stricter access controls.

---

## Keyspace design and memory estimation

For a production deployment planning exercise, here's how to estimate Redis memory usage:

**Call counters (`maxCalls`):**
`numTokens × numTools × avgCallsPerToken × keySize`

With 10,000 active tokens, 5 tools per token average, and ~100 bytes per key, that's about 5MB. Very modest.

**Rate limit counters:**
`numTokens × numTools × 2 (current + previous minute bucket) × keySize`

At 10,000 tokens × 5 tools × 2 buckets × 100 bytes, that's about 10MB.

**Kill-switch entries:**
Proportional to the number of active kill-switch operations. In normal operations this is zero or near-zero. During an incident with 100 kill-switched sessions, it's about 10KB. Not significant.

**Revocation list:**
Proportional to the number of revoked tokens that haven't yet expired. If tokens have 15-minute TTLs and you revoke 1,000 tokens per day, at steady state you have at most 15/60/24 × 1,000 × keySize ≈ 10 tokens × 150 bytes ≈ 1.5KB in the revocation list at any given moment. Even at 100× that scale, it's negligible.

**DPoP nonce set:**
`requestsPerSecond × tokenTTLSeconds × nonceSizeBytes`

At 1,000 requests/second, 15-minute tokens, and 150 bytes per nonce key: 1,000 × 900 × 150 bytes ≈ 135MB. This is the largest contributor and scales with traffic. At 10,000 requests/second it's 1.35GB — still manageable, but worth knowing about for capacity planning.

Total Redis memory for a 10,000 req/second gateway: approximately 1.5-2GB including key overhead. This is comfortably within the limits of a standard Redis deployment. For higher-traffic deployments, the `CALL_COUNTER_REDIS_URL` and the main Redis URL should be separated to distribute memory and write load.

---

## Monitoring and alerting

The Prometheus metrics I watch most closely for Redis health:

**`eunox_redis_operation_latency_ms`** (histogram, labeled by operation and connection pool): the p99 for Redis operations should be under 5ms in a healthy deployment. If it creeps above 20ms, Redis is either overloaded or there's network latency between the gateway and the Redis cluster.

**`eunox_redis_errors_total`** (counter, labeled by operation and error type): any non-zero delta in Redis errors triggers investigation. Under fail-closed behavior, Redis errors translate directly to denied tool calls, so a spike in Redis errors will appear simultaneously in `eunox_enforcement_denials_total{denial_code="REDIS_UNAVAILABLE"}`.

**`eunox_redis_pool_exhausted_total`** (counter): if the Redis connection pool is exhausted, new requests wait for a free connection. Under fail-closed behavior, a waiting request that times out returns `REDIS_UNAVAILABLE`. Pool exhaustion usually indicates either a connection leak (more rare) or insufficient pool sizing for the traffic volume (more common). The `REDIS_POOL_SIZE` environment variable controls this; the default (50) is appropriate for medium-traffic deployments.

**`eunox_call_counter_top_tokens`** (gauge): the top-N tokens by call count in the last 5 minutes. Not strictly a Redis health metric, but useful for identifying runaway agents before they hit the `maxCalls` limit.

---

## Operational lessons

**Deploy Redis Cluster, not Sentinel, for new deployments.** Redis Sentinel provides high availability through failover but not horizontal scaling — you still have one primary for writes. Redis Cluster provides both HA and sharding. For the write-heavy workload of call counters (every tool call writes a counter increment), horizontal scaling matters.

**Use Redis ACLs to scope each connection pool's permissions.** The revocation list connection pool doesn't need write access to the kill-switch keyspace. The call counter pool doesn't need access to the DPoP nonce set. Fine-grained ACLs reduce the blast radius of a connection pool compromise and make it much easier to audit who wrote what to which keyspace.

**Test your Redis failover path regularly.** The fail-closed behavior on Redis unavailability means a Redis cluster failover will cause a brief outage of tool calls during the election period (typically 15-30 seconds for Redis Sentinel, under 10 seconds for Redis Cluster). Test this at least quarterly in a staging environment. The behavior should be understood and documented in the runbooks before it happens in production. "Gateway returns REDIS_UNAVAILABLE for 10 seconds during Redis primary failover" is the expected behavior; it's not a bug, and your on-call team should know that.

---

_Previous: [post 25 — KMS-backed JWT signing](./25-kms-backed-jwt-signing.md). Next: [post 27 — SCIM 2.0 for AI agents: bringing enterprise directory provisioning to capability tokens](./27-scim-for-ai-agents.md)._
