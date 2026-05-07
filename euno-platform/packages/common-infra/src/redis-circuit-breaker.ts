/**
 * Redis Circuit Breaker
 * ---------------------------------------------------------------------------
 * A simple three-state circuit breaker (closed → open → half-open → closed)
 * designed for wrapping Redis calls so that a sustained Redis outage does not
 * cause every gateway request to wait for a full TCP/TLS timeout on the hot
 * path.
 *
 * ## States
 *
 *   * **Closed** (normal): calls are forwarded to Redis.  Failures are
 *     counted in a sliding window.  When `failureThreshold` failures
 *     accumulate within `windowMs`, the circuit trips to **open**.
 *
 *   * **Open** (failing fast): calls immediately throw
 *     {@link CircuitOpenError} without touching Redis.  After
 *     `cooldownMs` elapses the circuit transitions to **half-open** on
 *     the next `execute()` call.
 *
 *   * **Half-open** (probing): exactly **one** call is forwarded to Redis.
 *     All other concurrent callers throw {@link CircuitOpenError} until
 *     that probe completes.  If the probe succeeds, the circuit closes.
 *     If it fails, the circuit returns to **open** and the cooldown restarts.
 *
 * ## Usage
 *
 * ```typescript
 * const cb = new RedisCircuitBreaker({ failureThreshold: 5, windowMs: 10_000, cooldownMs: 30_000 });
 *
 * try {
 *   const result = await cb.execute(() => redisClient.get(key));
 * } catch (err) {
 *   if (err instanceof CircuitOpenError) {
 *     // Use fallback — Redis is unavailable.
 *   }
 *   // Other errors: Redis returned an error; circuit has recorded the failure.
 * }
 * ```
 *
 * ## Thread safety
 *
 * Node.js is single-threaded so there is no mutex.  All state mutations
 * happen in-process synchronously between awaits; concurrent `execute()`
 * invocations interleave at microtask boundaries.  The `probeInFlight`
 * flag ensures only one probe runs at a time in half-open state.
 */

/**
 * Observable state of a {@link RedisCircuitBreaker}.
 */
export type CircuitState = 'closed' | 'open' | 'half-open';

/**
 * Thrown by {@link RedisCircuitBreaker.execute} when the circuit is open and
 * the cooldown period has not yet elapsed.  Callers should treat this as
 * "Redis is unavailable – use a local fallback" rather than retrying.
 */
export class CircuitOpenError extends Error {
  constructor() {
    super('Redis circuit breaker is open — call skipped to protect the hot path');
    this.name = 'CircuitOpenError';
  }
}

export interface CircuitBreakerOptions {
  /**
   * Number of failures within `windowMs` needed to trip the circuit to open.
   * Default: 5.
   */
  failureThreshold?: number;

  /**
   * Sliding window width (ms) for failure counting.  Failures older than
   * this value do not count toward the threshold.  Default: 10 000.
   */
  windowMs?: number;

  /**
   * Time (ms) the circuit stays open before transitioning to half-open and
   * allowing a single probe call.  Default: 30 000.
   */
  cooldownMs?: number;

  /**
   * Invoked every time the circuit transitions between states.  Use this to
   * update a Prometheus gauge or emit a log line.
   */
  onStateChange?: (from: CircuitState, to: CircuitState) => void;
}

const DEFAULT_FAILURE_THRESHOLD = 5;
const DEFAULT_WINDOW_MS = 10_000;
const DEFAULT_COOLDOWN_MS = 30_000;

export class RedisCircuitBreaker {
  private state: CircuitState = 'closed';
  /** Timestamps (ms) of recent failures within the sliding window. */
  private readonly failureTimestamps: number[] = [];
  private openedAt = 0;
  /**
   * True while a single probe call is in flight during the half-open state.
   * Any concurrent `execute()` call that arrives while this flag is set
   * immediately throws {@link CircuitOpenError} instead of also probing Redis,
   * which would create a thundering herd when cooldown expires.
   */
  private probeInFlight = false;

  private readonly failureThreshold: number;
  private readonly windowMs: number;
  private readonly cooldownMs: number;
  private readonly onStateChange?: (from: CircuitState, to: CircuitState) => void;

  constructor(options: CircuitBreakerOptions = {}) {
    this.failureThreshold = options.failureThreshold ?? DEFAULT_FAILURE_THRESHOLD;
    this.windowMs = options.windowMs ?? DEFAULT_WINDOW_MS;
    this.cooldownMs = options.cooldownMs ?? DEFAULT_COOLDOWN_MS;
    this.onStateChange = options.onStateChange;
  }

  /** Current state — exposed for metrics / logging. */
  getState(): CircuitState {
    return this.state;
  }

  /**
   * Execute a Redis call through the circuit breaker.
   *
   * @throws {@link CircuitOpenError} when the circuit is open and the
   *   cooldown has not elapsed, or when the circuit is half-open and a probe
   *   is already in flight.
   * @throws The underlying error thrown by `fn` on Redis failure (the
   *   circuit records the failure before re-throwing).
   */
  async execute<T>(fn: () => Promise<T>): Promise<T> {
    if (this.state === 'open') {
      const now = Date.now();
      if (now - this.openedAt >= this.cooldownMs) {
        this.transition('half-open');
        // Fall through to the half-open probe path below.
      } else {
        throw new CircuitOpenError();
      }
    }

    if (this.state === 'half-open') {
      // Only one probe may be in flight at a time.  All other concurrent
      // callers are rejected with CircuitOpenError until the probe resolves.
      if (this.probeInFlight) {
        throw new CircuitOpenError();
      }
      this.probeInFlight = true;
      try {
        const result = await fn();
        // Probe succeeded — close the circuit.
        this.transition('closed');
        return result;
      } catch (error) {
        this.recordFailure();
        throw error;
      } finally {
        this.probeInFlight = false;
      }
    }

    // Normal closed-state path.
    try {
      return await fn();
    } catch (error) {
      this.recordFailure();
      throw error;
    }
  }

  /**
   * Manually record a failure (e.g. from an `'error'` event on the Redis
   * client that occurs outside an `execute()` call).  This lets the
   * circuit breaker trip even for background connection errors.
   *
   * A no-op when the circuit is already `open` — failure history is
   * irrelevant in that state, and skipping the append prevents unbounded
   * growth of the timestamps array when a Redis client emits frequent
   * `'error'` events during a sustained outage.
   */
  recordFailure(): void {
    // Fast-path: already open — circuit state cannot deteriorate further and
    // failure history is unused in this state.
    if (this.state === 'open') return;

    const now = Date.now();
    // Prune failures outside the sliding window.
    const cutoff = now - this.windowMs;
    let i = 0;
    const ts = this.failureTimestamps;
    while (i < ts.length && (ts[i] as number) <= cutoff) {
      i++;
    }
    if (i > 0) {
      this.failureTimestamps.splice(0, i);
    }
    this.failureTimestamps.push(now);

    // Trip the circuit if threshold reached, or if a probe in half-open failed.
    if (this.state === 'half-open' || this.failureTimestamps.length >= this.failureThreshold) {
      this.transition('open');
    }
  }

  private transition(to: CircuitState): void {
    const from = this.state;
    if (from === to) return;
    this.state = to;
    if (to === 'open') {
      this.openedAt = Date.now();
      // Clear failure history so the window starts fresh after cooldown.
      this.failureTimestamps.length = 0;
      // Reset probe flag in case we're transitioning from half-open.
      this.probeInFlight = false;
    }
    this.onStateChange?.(from, to);
  }
}
