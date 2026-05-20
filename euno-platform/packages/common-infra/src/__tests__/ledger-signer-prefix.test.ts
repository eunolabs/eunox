import type { ObjectStore } from '../object-store';
import { PerReplicaPostgresLedgerBackend, PostgresLedgerBackend } from '../ledger-signer';

const unusedPool = {
  connect: jest.fn(),
  end: jest.fn().mockResolvedValue(undefined),
} as never;

function makeObjectStore() {
  const put = jest.fn(async () => undefined);
  const store: ObjectStore = { put };
  return { store, put };
}

function makeEntries(replicaId: string) {
  return [
    {
      seq: 1,
      previousHash: '0'.repeat(64),
      recordHash: 'a'.repeat(64),
      replicaId,
      signedEvidence: {} as never,
      ts: new Date().toISOString(),
    },
  ];
}

describe('object-store anchor prefixes', () => {
  it('PostgresLedgerBackend uses objectStoresPrefix for object-store keys', async () => {
    const { store, put } = makeObjectStore();
    const backend = new PostgresLedgerBackend(unusedPool, {
      hmacSecret: 'a'.repeat(64),
      objectStores: [store],
      objectStoresPrefix: 'cluster-a/',
    });

    (backend as unknown as { getEntries: (fromSeq: number, toSeq: number) => Promise<unknown[]> }).getEntries =
      async () => makeEntries('rep-1');

    await (
      backend as unknown as {
        triggerObjectStoreAnchor: (fromSeq: number, toSeq: number, replicaId: string) => Promise<void>;
      }
    ).triggerObjectStoreAnchor(1, 1, 'rep-1');

    expect(put).toHaveBeenCalledWith(
      'cluster-a/rep-1/1-1.json',
      expect.any(String),
      'application/json',
    );
  });

  it('PerReplicaPostgresLedgerBackend uses objectStoresPrefix for object-store keys', async () => {
    const { store, put } = makeObjectStore();
    const backend = new PerReplicaPostgresLedgerBackend(unusedPool, 'rep-2', {
      hmacSecret: 'a'.repeat(64),
      objectStores: [store],
      objectStoresPrefix: 'cluster-b/',
    });

    (backend as unknown as { getEntries: (fromSeq: number, toSeq: number) => Promise<unknown[]> }).getEntries =
      async () => makeEntries('rep-2');

    await (
      backend as unknown as {
        triggerObjectStoreAnchor: (fromSeq: number, toSeq: number, replicaId: string) => Promise<void>;
      }
    ).triggerObjectStoreAnchor(1, 1, 'rep-2');

    expect(put).toHaveBeenCalledWith(
      'cluster-b/rep-2/1-1.json',
      expect.any(String),
      'application/json',
    );
  });
});
