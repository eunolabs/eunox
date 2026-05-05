/**
 * Horizontal shard index computation for the gateway data-plane.
 *
 * ## Problem
 *
 * In a multi-replica gateway every replica contends on the same shared Redis
 * state: the `maxCalls` call-counter `INCR`, the revocation `EXISTS`, the
 * kill-switch `SMEMBERS`, and the DPoP-replay `SET NX`. At scale the
 * call-counter `INCR` becomes a hot key because every authorized request for
 * every agent hits the same key space in the same Redis cluster.
 *
 * ## Solution
 *
 * Consistent-hash each agent (`sub` claim) to a specific gateway replica.
 * Because ALL traffic for agent A is guaranteed to land on replica 1:
 *
 *   - Agent A's `maxCalls` counter lives in replica 1's memory. No Redis
 *     round-trip, no hot key. The scaling curve changes from "N × Redis QPS"
 *     to "N × local cache" — each additional shard adds capacity without
 *     adding Redis load.
 *   - Replica 1's in-process revocation / kill-switch cache only needs
 *     entries for its assigned agents, so cache churn is proportional to the
 *     per-shard agent population (1/N of the fleet).
 *   - DPoP replay and revocation state continue to use the shared Redis store
 *     for correctness — a proof or revocation issued on any pod must be
 *     visible to all pods. Only the `maxCalls` call-counter moves to local
 *     memory.
 *
 * ## Routing layer
 *
 * The Lua HTTP filter in the Envoy shard router computes the same FNV-1a
 * `% shardCount` and sets an `x-euno-shard-index` header. Envoy routes to
 * the per-pod cluster whose index matches, targeting the stable pod DNS name
 * (`tool-gateway-<N>.tool-gateway-headless`). Any client-supplied
 * `x-euno-shard-index` header is stripped before the filter runs. See
 * `k8s/envoy-shard-router.yaml` and `docs/HORIZONTAL_SHARDING.md`.
 *
 * ## Algorithm
 *
 * FNV-1a 32-bit hash of the raw `sub` string, then `hash % shardCount`.
 * FNV-1a was chosen because:
 *   - It is simple to implement in TypeScript, Lua (Envoy filter), and any
 *     future language without external dependencies.
 *   - It produces a uniform distribution over short strings like DIDs and
 *     UUIDs.
 *   - It is deterministic and stable across Node.js versions — there is no
 *     hash randomisation for this pure-computation function.
 *
 * Using plain modulo means adding a shard invalidates ~1/N of the hash
 * space; for the typical gateway fleet size (< 32 shards) this is
 * acceptable during the brief topology-change window. Operators who need
 * zero-disruption shard addition can layer a rendezvous hash on top, but
 * that is not required for the primary hot-key problem.
 */

/**
 * FNV-1a 32-bit hash of `input`.
 *
 * Reference: http://www.isthe.com/chongo/tech/comp/fnv/#FNV-1a
 *
 * Returns a non-negative integer in [0, 2^32 - 1].  We use a 32-bit
 * implementation (rather than 64-bit) because JavaScript cannot represent
 * 64-bit integers natively without BigInt, which would add overhead and
 * complicate the Lua side implementation.  32 bits is sufficient for the
 * shard-count range this feature targets (≤ 1024 shards).
 */
function fnv1a32(input: string): number {
  let hash = 2166136261; // FNV offset basis (32-bit)
  for (let i = 0; i < input.length; i++) {
    // XOR with the byte value.
    hash = hash ^ input.charCodeAt(i);
    // Multiply by FNV prime (32-bit): 16777619
    // Emulate 32-bit unsigned arithmetic with >>> 0 to prevent sign issues.
    hash = Math.imul(hash, 16777619) >>> 0;
  }
  return hash >>> 0; // ensure unsigned
}

/**
 * Compute the zero-based shard index that owns the agent identified by
 * `sub`.
 *
 * @param sub - The `sub` claim of the capability token (agent DID or
 *   identifier). Must be a non-empty string; an empty string is mapped to
 *   shard 0.
 * @param shardCount - Total number of shards in the fleet. Must be >= 1.
 *   When 1 (single-shard / unsharded deployment), always returns 0.
 * @returns A zero-based shard index in [0, shardCount - 1].
 *
 * @example
 * ```typescript
 * computeAgentShardIndex('did:web:acme.com:agent-1', 4); // → deterministic 0-3
 * computeAgentShardIndex('did:web:acme.com:agent-1', 1); // → always 0
 * ```
 */
export function computeAgentShardIndex(sub: string, shardCount: number): number {
  if (shardCount <= 1) return 0;
  if (!sub) return 0;
  return fnv1a32(sub) % shardCount;
}

/**
 * Returns `true` when the agent identified by `sub` is owned by shard
 * `shardIndex` in a fleet of `shardCount` shards.
 *
 * This is the primary guard used by shard-aware stores to decide whether
 * to use the fast local path (in-memory) or fall back to the shared Redis
 * backend for mis-routed traffic.
 *
 * @param sub - The agent `sub` claim.
 * @param shardIndex - This replica's shard index (0-based). Typically
 *   plumbed from `GATEWAY_SHARD_INDEX`.
 * @param shardCount - Total number of shards. Typically plumbed from
 *   `GATEWAY_SHARD_COUNT`.
 */
export function isOwnedByShard(sub: string, shardIndex: number, shardCount: number): boolean {
  if (shardCount <= 1) return true;
  return computeAgentShardIndex(sub, shardCount) === shardIndex;
}
