/**
 * Binary min-heap ordered by a numeric `expiry` field.
 *
 * Used internally by {@link InMemoryDpopReplayStore} (dpop.ts) and
 * {@link InMemoryRevocationStore} (revocation-store.ts in @euno/tool-gateway)
 * to prune expired entries in O(k log n) instead of O(n) on every insert.
 *
 * ## Lazy deletion
 * The heap is intentionally kept loosely coupled from the backing Map: when
 * an entry is removed from the Map by a lookup (lazy cleanup) or overwritten
 * by a re-insertion with a different expiry, the corresponding heap node
 * becomes "stale".  Callers detect stale nodes during a drain pass by
 * comparing the popped node's expiry against the current Map value, and simply
 * skip map-deletion when the values differ.  The Map is always the
 * authoritative source of truth.
 */
export class MinHeap {
  private readonly data: Array<{ key: string; expiry: number }> = [];

  push(key: string, expiry: number): void {
    this.data.push({ key, expiry });
    this.bubbleUp(this.data.length - 1);
  }

  peek(): Readonly<{ key: string; expiry: number }> | undefined {
    return this.data[0];
  }

  pop(): { key: string; expiry: number } | undefined {
    if (this.data.length === 0) return undefined;
    const top = this.data[0]!;
    const last = this.data.pop()!;
    if (this.data.length > 0) {
      this.data[0] = last;
      this.siftDown(0);
    }
    return top;
  }

  clear(): void {
    this.data.length = 0;
  }

  /**
   * Rebuild the heap from a Map, discarding any stale entries.
   * O(n) via Floyd's heap-construction algorithm.  Call this when the heap
   * has grown significantly larger than the backing Map (due to lazy-deleted
   * stale entries accumulating after FIFO eviction or lazy cleanup).
   */
  rebuildFrom(map: ReadonlyMap<string, number>): void {
    this.data.length = 0;
    for (const [key, expiry] of map) {
      this.data.push({ key, expiry });
    }
    // Floyd's O(n) bottom-up heap construction.
    for (let i = Math.floor(this.data.length / 2) - 1; i >= 0; i--) {
      this.siftDown(i);
    }
  }

  /** Number of nodes currently in the heap (includes stale lazy-delete nodes). */
  size(): number {
    return this.data.length;
  }

  private bubbleUp(i: number): void {
    while (i > 0) {
      const parent = (i - 1) >> 1; // integer division by 2
      if (this.data[parent]!.expiry <= this.data[i]!.expiry) break;
      const tmp = this.data[parent]!;
      this.data[parent] = this.data[i]!;
      this.data[i] = tmp;
      i = parent;
    }
  }

  private siftDown(i: number): void {
    const n = this.data.length;
    for (;;) {
      let smallest = i;
      const l = 2 * i + 1;
      const r = 2 * i + 2;
      if (l < n && this.data[l]!.expiry < this.data[smallest]!.expiry) smallest = l;
      if (r < n && this.data[r]!.expiry < this.data[smallest]!.expiry) smallest = r;
      if (smallest === i) break;
      const tmp = this.data[smallest]!;
      this.data[smallest] = this.data[i]!;
      this.data[i] = tmp;
      i = smallest;
    }
  }
}
