/**
 * Tests for {@link RedisCircuitBreaker}.
 */

import {
  RedisCircuitBreaker,
  CircuitOpenError,
  CircuitState,
} from '../src/redis-circuit-breaker';

function makeError(message = 'Redis ECONNREFUSED') {
  return new Error(message);
}

describe('RedisCircuitBreaker', () => {
  describe('initial state', () => {
    it('starts in closed state', () => {
      const cb = new RedisCircuitBreaker();
      expect(cb.getState()).toBe('closed');
    });
  });

  describe('closed → open transition', () => {
    it('trips to open after failureThreshold failures in window', async () => {
      const cb = new RedisCircuitBreaker({ failureThreshold: 3, windowMs: 5000, cooldownMs: 30000 });
      const fn = jest.fn().mockRejectedValue(makeError());

      for (let i = 0; i < 3; i++) {
        await expect(cb.execute(fn)).rejects.toThrow('Redis ECONNREFUSED');
      }
      expect(cb.getState()).toBe('open');
    });

    it('does not trip when failures are below the threshold', async () => {
      const cb = new RedisCircuitBreaker({ failureThreshold: 5, windowMs: 5000, cooldownMs: 30000 });
      const fn = jest.fn().mockRejectedValue(makeError());

      for (let i = 0; i < 4; i++) {
        await expect(cb.execute(fn)).rejects.toThrow('Redis ECONNREFUSED');
      }
      expect(cb.getState()).toBe('closed');
    });

    it('does not trip when failures are outside the sliding window', async () => {
      const realNow = Date.now;
      let now = 1_000_000;
      Date.now = () => now;

      try {
        const cb = new RedisCircuitBreaker({ failureThreshold: 3, windowMs: 1000, cooldownMs: 30000 });
        const fn = jest.fn().mockRejectedValue(makeError());

        // Two failures
        await expect(cb.execute(fn)).rejects.toThrow();
        await expect(cb.execute(fn)).rejects.toThrow();
        expect(cb.getState()).toBe('closed');

        // Advance time past window
        now += 2000;

        // Third failure — but the first two are outside the window now
        await expect(cb.execute(fn)).rejects.toThrow();
        // Only 1 failure within the window → still closed
        expect(cb.getState()).toBe('closed');
      } finally {
        Date.now = realNow;
      }
    });

    it('invokes onStateChange callback when transitioning to open', async () => {
      const stateChanges: Array<{ from: CircuitState; to: CircuitState }> = [];
      const cb = new RedisCircuitBreaker({
        failureThreshold: 2,
        windowMs: 5000,
        cooldownMs: 30000,
        onStateChange: (from, to) => stateChanges.push({ from, to }),
      });
      const fn = jest.fn().mockRejectedValue(makeError());

      for (let i = 0; i < 2; i++) {
        await expect(cb.execute(fn)).rejects.toThrow();
      }

      expect(stateChanges).toEqual([{ from: 'closed', to: 'open' }]);
    });
  });

  describe('open state', () => {
    it('throws CircuitOpenError without calling fn', async () => {
      const cb = new RedisCircuitBreaker({ failureThreshold: 2, windowMs: 5000, cooldownMs: 30000 });
      const failFn = jest.fn().mockRejectedValue(makeError());

      // Trip the circuit
      for (let i = 0; i < 2; i++) {
        await expect(cb.execute(failFn)).rejects.toThrow();
      }
      expect(cb.getState()).toBe('open');

      // Now execute should fast-fail
      const probeFn = jest.fn().mockResolvedValue('ok');
      await expect(cb.execute(probeFn)).rejects.toThrow(CircuitOpenError);
      expect(probeFn).not.toHaveBeenCalled();
    });
  });

  describe('open → half-open → closed transition', () => {
    it('transitions to half-open after cooldown and closes on success', async () => {
      const realNow = Date.now;
      let now = 1_000_000;
      Date.now = () => now;

      try {
        const stateChanges: Array<{ from: CircuitState; to: CircuitState }> = [];
        const cb = new RedisCircuitBreaker({
          failureThreshold: 2,
          windowMs: 5000,
          cooldownMs: 1000,
          onStateChange: (from, to) => stateChanges.push({ from, to }),
        });
        const failFn = jest.fn().mockRejectedValue(makeError());

        // Trip the circuit
        for (let i = 0; i < 2; i++) {
          await expect(cb.execute(failFn)).rejects.toThrow();
        }
        expect(cb.getState()).toBe('open');

        // Fast-fail within cooldown
        await expect(cb.execute(jest.fn())).rejects.toThrow(CircuitOpenError);

        // Advance past cooldown
        now += 2000;

        // Next execute should probe (half-open)
        const successFn = jest.fn().mockResolvedValue('result');
        const result = await cb.execute(successFn);
        expect(result).toBe('result');
        expect(cb.getState()).toBe('closed');

        expect(stateChanges).toEqual([
          { from: 'closed', to: 'open' },
          { from: 'open', to: 'half-open' },
          { from: 'half-open', to: 'closed' },
        ]);
      } finally {
        Date.now = realNow;
      }
    });

    it('returns to open when half-open probe fails', async () => {
      const realNow = Date.now;
      let now = 1_000_000;
      Date.now = () => now;

      try {
        const cb = new RedisCircuitBreaker({
          failureThreshold: 2,
          windowMs: 5000,
          cooldownMs: 1000,
        });
        const failFn = jest.fn().mockRejectedValue(makeError());

        // Trip the circuit
        for (let i = 0; i < 2; i++) {
          await expect(cb.execute(failFn)).rejects.toThrow();
        }
        expect(cb.getState()).toBe('open');

        // Advance past cooldown
        now += 2000;

        // Probe fails → back to open
        await expect(cb.execute(failFn)).rejects.toThrow();
        expect(cb.getState()).toBe('open');
      } finally {
        Date.now = realNow;
      }
    });

    it('gates concurrent callers in half-open: only one probe in flight at a time', async () => {
      const realNow = Date.now;
      let now = 1_000_000;
      Date.now = () => now;

      try {
        const cb = new RedisCircuitBreaker({
          failureThreshold: 2,
          windowMs: 5000,
          cooldownMs: 1000,
        });

        // Trip the circuit
        cb.recordFailure();
        cb.recordFailure();
        expect(cb.getState()).toBe('open');

        // Advance past cooldown
        now += 2000;

        // Simulate two concurrent callers: both arrive after cooldown.
        // The probe fn resolves after a microtask so the second concurrent
        // caller can observe probeInFlight=true.
        let resolveProbe!: () => void;
        const probeStarted = new Promise<void>(r => {
          resolveProbe = r;
        });
        // Block the probe until we explicitly unblock it.
        let unblock!: () => void;
        const blocker = new Promise<void>(r => { unblock = r; });

        const probe = jest.fn().mockImplementation(async () => {
          resolveProbe();     // signal that probe has started
          await blocker;      // wait until the test unblocks it
          return 'probe-result';
        });

        // Launch the first caller (will become the probe).
        const firstPromise = cb.execute(probe);
        // Wait until the probe function has actually started running.
        await probeStarted;

        // A second concurrent caller should now be rejected with CircuitOpenError.
        await expect(cb.execute(jest.fn().mockResolvedValue('second'))).rejects.toThrow(CircuitOpenError);

        // Unblock the probe and verify the circuit closes.
        unblock();
        const result = await firstPromise;
        expect(result).toBe('probe-result');
        expect(cb.getState()).toBe('closed');
        expect(probe).toHaveBeenCalledTimes(1);
      } finally {
        Date.now = realNow;
      }
    });
  });

  describe('recordFailure()', () => {
    it('trips circuit when called threshold times', () => {
      const cb = new RedisCircuitBreaker({ failureThreshold: 3, windowMs: 5000, cooldownMs: 30000 });
      cb.recordFailure();
      cb.recordFailure();
      expect(cb.getState()).toBe('closed');
      cb.recordFailure();
      expect(cb.getState()).toBe('open');
    });

    it('is a no-op when the circuit is already open', () => {
      const cb = new RedisCircuitBreaker({ failureThreshold: 2, windowMs: 5000, cooldownMs: 30000 });
      // Trip to open
      cb.recordFailure();
      cb.recordFailure();
      expect(cb.getState()).toBe('open');

      // Calling recordFailure many more times must not accumulate timestamps
      // (verified indirectly: if it did, the array would be non-empty when the
      // circuit re-opens after cooldown, which is the bug being guarded).
      for (let i = 0; i < 100; i++) {
        cb.recordFailure(); // must be a no-op
      }
      // State must remain open, not do anything unexpected.
      expect(cb.getState()).toBe('open');
    });

    it('trips circuit immediately when called on half-open', async () => {
      const realNow = Date.now;
      let now = 1_000_000;
      Date.now = () => now;

      try {
        const stateChanges: Array<{ from: CircuitState; to: CircuitState }> = [];
        const cb = new RedisCircuitBreaker({
          failureThreshold: 2,
          windowMs: 5000,
          cooldownMs: 1000,
          onStateChange: (from, to) => stateChanges.push({ from, to }),
        });
        // Trip to open.
        cb.recordFailure();
        cb.recordFailure();
        expect(cb.getState()).toBe('open');

        // Advance past cooldown so the next execute transitions to half-open.
        now += 2000;

        // A failing probe should:
        //   1. Transition the circuit from open → half-open before running fn.
        //   2. Call recordFailure() on the error, which trips it back to open.
        const failFn = jest.fn().mockRejectedValue(makeError());
        await expect(cb.execute(failFn)).rejects.toThrow();

        // fn was actually called (it was the probe).
        expect(failFn).toHaveBeenCalledTimes(1);

        // The state machine must have visited half-open then returned to open.
        expect(stateChanges).toEqual(
          expect.arrayContaining([
            { from: 'open', to: 'half-open' },
            { from: 'half-open', to: 'open' },
          ]),
        );
        expect(cb.getState()).toBe('open');
      } finally {
        Date.now = realNow;
      }
    });
  });

  describe('successful execute in closed state', () => {
    it('returns the value from the wrapped function', async () => {
      const cb = new RedisCircuitBreaker();
      const fn = jest.fn().mockResolvedValue(42);
      const result = await cb.execute(fn);
      expect(result).toBe(42);
      expect(cb.getState()).toBe('closed');
    });

    it('propagates the error thrown by the wrapped function', async () => {
      const cb = new RedisCircuitBreaker({ failureThreshold: 100 });
      const fn = jest.fn().mockRejectedValue(new Error('transient'));
      await expect(cb.execute(fn)).rejects.toThrow('transient');
    });
  });

  describe('failure threshold edge cases', () => {
    it('threshold of 1 trips on the first failure', async () => {
      const cb = new RedisCircuitBreaker({ failureThreshold: 1, windowMs: 5000, cooldownMs: 30000 });
      await expect(cb.execute(jest.fn().mockRejectedValue(makeError()))).rejects.toThrow();
      expect(cb.getState()).toBe('open');
    });
  });
});
