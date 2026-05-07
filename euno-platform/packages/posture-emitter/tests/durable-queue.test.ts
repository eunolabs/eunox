/**
 * Unit tests for the SQLite WAL-backed DurableQueue.
 *
 * All tests use the default ':memory:' path so no files are created.
 */
import { DurableQueue } from '../src/durable-queue';

describe('DurableQueue', () => {
  let q: DurableQueue;

  beforeEach(() => {
    q = new DurableQueue(); // ':memory:'
  });

  afterEach(() => {
    q.close();
  });

  // -------------------------------------------------------------------------
  // push / depth

  it('starts empty', () => {
    expect(q.depth()).toBe(0);
    expect(q.oldestInsertedAt()).toBeNull();
  });

  it('push increments depth', () => {
    q.push('observed', '{}');
    expect(q.depth()).toBe(1);
    q.push('revoked', '{}');
    expect(q.depth()).toBe(2);
  });

  it('push returns ascending row-ids', () => {
    const id1 = q.push('observed', '{"a":1}');
    const id2 = q.push('observed', '{"a":2}');
    expect(id2).toBeGreaterThan(id1);
  });

  // -------------------------------------------------------------------------
  // peek

  it('peek returns events whose next_attempt_at <= nowMs', () => {
    const t = 1_000_000;
    q.push('observed', '{"n":1}', t);
    q.push('revoked', '{"n":2}', t);
    const events = q.peek(10, t + 1);
    expect(events).toHaveLength(2);
    expect(events.map((e) => e.type).sort()).toEqual(['observed', 'revoked']);
  });

  it('peek orders oldest first', () => {
    const t = 1_000_000;
    const id1 = q.push('observed', '{"n":1}', t);
    const id2 = q.push('observed', '{"n":2}', t + 1);
    const events = q.peek(10, t + 1_000);
    expect(events[0]!.id).toBe(id1);
    expect(events[1]!.id).toBe(id2);
  });

  it('peek respects next_attempt_at after nack', () => {
    const t = 1_000_000;
    const id = q.push('observed', '{}', t);
    q.nack(id, t + 5_000, 'temporary error');
    // Not yet due.
    expect(q.peek(10, t + 4_999)).toHaveLength(0);
    // Now due.
    expect(q.peek(10, t + 5_000)).toHaveLength(1);
  });

  it('peek respects limit', () => {
    for (let i = 0; i < 5; i++) q.push('observed', `{"n":${i}}`);
    expect(q.peek(3)).toHaveLength(3);
  });

  // -------------------------------------------------------------------------
  // ack

  it('ack removes the event', () => {
    const id = q.push('observed', '{}');
    expect(q.depth()).toBe(1);
    q.ack(id);
    expect(q.depth()).toBe(0);
    expect(q.peek(10)).toHaveLength(0);
  });

  it('ack is idempotent', () => {
    const id = q.push('observed', '{}');
    q.ack(id);
    expect(() => q.ack(id)).not.toThrow();
    expect(q.depth()).toBe(0);
  });

  // -------------------------------------------------------------------------
  // nack

  it('nack increments attempts and updates last_error', () => {
    const t = 1_000_000;
    const id = q.push('observed', '{}', t);
    q.nack(id, t + 1_000, 'boom');
    const events = q.peek(10, t + 2_000);
    expect(events).toHaveLength(1);
    expect(events[0]!.attempts).toBe(1);
    expect(events[0]!.lastError).toBe('boom');
  });

  it('multiple nacks accumulate attempts', () => {
    const t = 1_000_000;
    const id = q.push('observed', '{}', t);
    q.nack(id, t + 100, 'e1');
    q.nack(id, t + 200, 'e2');
    const events = q.peek(10, t + 300);
    expect(events[0]!.attempts).toBe(2);
    expect(events[0]!.lastError).toBe('e2');
  });

  // -------------------------------------------------------------------------
  // oldestInsertedAt / lag

  it('oldestInsertedAt returns the minimum insertedAt', () => {
    const t = 2_000_000;
    q.push('observed', '{}', t + 500);
    q.push('observed', '{}', t + 100);
    q.push('observed', '{}', t + 300);
    expect(q.oldestInsertedAt()).toBe(t + 100);
  });

  it('oldestInsertedAt returns null when queue is empty', () => {
    const id = q.push('observed', '{}');
    q.ack(id);
    expect(q.oldestInsertedAt()).toBeNull();
  });

  it('depth returns 0 and oldestInsertedAt null after all acks', () => {
    const ids = [
      q.push('observed', '{}'),
      q.push('revoked', '{}'),
    ];
    for (const id of ids) q.ack(id);
    expect(q.depth()).toBe(0);
    expect(q.oldestInsertedAt()).toBeNull();
  });

  // -------------------------------------------------------------------------
  // payload round-trip

  it('preserves payload and type on peek', () => {
    const payload = JSON.stringify({ record: { agentId: 'agent-1' } });
    q.push('observed', payload);
    const [event] = q.peek(1);
    expect(event!.type).toBe('observed');
    expect(event!.payload).toBe(payload);
  });

  // -------------------------------------------------------------------------
  // insertedAt

  it('stores insertedAt and exposes it on peek', () => {
    const t = 12345678;
    q.push('observed', '{}', t);
    const [event] = q.peek(1, t + 1);
    expect(event!.insertedAt).toBe(t);
  });
});
