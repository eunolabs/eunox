/**
 * Tests for the F-9 continuous evidence-chain verification job and the
 * verify-only software signer it relies on.
 */

import * as crypto from 'crypto';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import {
  createSoftwareEvidenceSigner,
  createSoftwareEvidenceVerifier,
  createSoftwareEvidenceVerifierFromEnv,
  createAuditEvidence,
  type AuditEvidenceSigner,
} from '../src/evidence';
import {
  parseEvidenceBatch,
  runVerifyEvidence,
  main,
} from '../src/verify-evidence-job';
import type { SignedAuditEvidence } from '../src/wire';

function makeKeyPair(): { privatePem: string; publicPem: string } {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  return {
    privatePem: privateKey.export({ type: 'pkcs8', format: 'pem' }) as string,
    publicPem: publicKey.export({ type: 'spki', format: 'pem' }) as string,
  };
}

function makeEvidence() {
  return createAuditEvidence({
    sessionId: 'sess-1',
    userId: 'user-1',
    prompt: 'hello',
    documents: { foo: 'bar' },
    tool: 'read_file',
    args: { path: '/etc/hosts' },
    agentId: 'agent-1',
    resource: 'tool://read_file',
    action: 'read',
    capabilityId: 'cap-1',
    decision: 'allow',
    policyVersion: '1.0.0',
  });
}

async function makeSignedRecord(signer: AuditEvidenceSigner): Promise<SignedAuditEvidence> {
  return signer.signEvidence(makeEvidence());
}

describe('createSoftwareEvidenceVerifier', () => {
  it('verifies signatures produced by createSoftwareEvidenceSigner using only the public key', async () => {
    const { privatePem, publicPem } = makeKeyPair();
    const signer = createSoftwareEvidenceSigner({ privateKeyPem: privatePem, keyId: 'audit-1' });
    const verifier = createSoftwareEvidenceVerifier({ publicKeyPem: publicPem });

    const signed = await makeSignedRecord(signer);
    expect(await verifier.verifyEvidence(signed)).toBe(true);
  });

  it('rejects records with a tampered field even when the public key matches', async () => {
    const { privatePem, publicPem } = makeKeyPair();
    const signer = createSoftwareEvidenceSigner({ privateKeyPem: privatePem });
    const verifier = createSoftwareEvidenceVerifier({ publicKeyPem: publicPem });

    const signed = await makeSignedRecord(signer);
    expect(await verifier.verifyEvidence({ ...signed, action: 'write' })).toBe(false);
  });

  it('rejects records signed by a different key', async () => {
    const a = makeKeyPair();
    const b = makeKeyPair();
    const signer = createSoftwareEvidenceSigner({ privateKeyPem: a.privatePem });
    const verifier = createSoftwareEvidenceVerifier({ publicKeyPem: b.publicPem });

    const signed = await makeSignedRecord(signer);
    expect(await verifier.verifyEvidence(signed)).toBe(false);
  });

  it('pinning keyId rejects records that claim a different kid', async () => {
    const { privatePem, publicPem } = makeKeyPair();
    const signer = createSoftwareEvidenceSigner({ privateKeyPem: privatePem, keyId: 'audit-1' });
    const verifier = createSoftwareEvidenceVerifier({ publicKeyPem: publicPem, keyId: 'expected-kid' });

    const signed = await makeSignedRecord(signer);
    expect(await verifier.verifyEvidence(signed)).toBe(false);
  });

  it('refuses to mint signatures (verify-only)', async () => {
    const { publicPem } = makeKeyPair();
    const verifier = createSoftwareEvidenceVerifier({ publicKeyPem: publicPem });
    await expect(verifier.signEvidence(makeEvidence())).rejects.toThrow(/verify-only/);
  });

  it('throws when neither publicKeyPem nor publicKeyPath is supplied', () => {
    expect(() => createSoftwareEvidenceVerifier({} as { publicKeyPem?: string })).toThrow(
      /publicKeyPem or publicKeyPath/,
    );
  });

  it('throws when both publicKeyPem and publicKeyPath are supplied', () => {
    const { publicPem } = makeKeyPair();
    expect(() =>
      createSoftwareEvidenceVerifier({ publicKeyPem: publicPem, publicKeyPath: '/tmp/x' }),
    ).toThrow(/mutually exclusive/);
  });

  it('throws on key-type / algorithm mismatch', () => {
    const { publicPem } = makeKeyPair();
    expect(() => createSoftwareEvidenceVerifier({ publicKeyPem: publicPem, algorithm: 'ES256' })).toThrow(
      /requires an EC public key/,
    );
  });
});

describe('createSoftwareEvidenceVerifierFromEnv', () => {
  it('returns undefined when no relevant env vars are set', () => {
    expect(createSoftwareEvidenceVerifierFromEnv({})).toBeUndefined();
  });

  it('builds a verifier from EVIDENCE_VERIFY_PUBLIC_KEY_PEM', async () => {
    const { privatePem, publicPem } = makeKeyPair();
    const signer = createSoftwareEvidenceSigner({ privateKeyPem: privatePem });
    const verifier = createSoftwareEvidenceVerifierFromEnv({
      EVIDENCE_VERIFY_PUBLIC_KEY_PEM: publicPem,
    } as NodeJS.ProcessEnv);
    expect(verifier).toBeDefined();
    const signed = await makeSignedRecord(signer);
    expect(await verifier!.verifyEvidence(signed)).toBe(true);
  });

  it('falls back to EVIDENCE_SIGNING_PUBLIC_KEY_PEM', async () => {
    const { privatePem, publicPem } = makeKeyPair();
    const signer = createSoftwareEvidenceSigner({ privateKeyPem: privatePem });
    const verifier = createSoftwareEvidenceVerifierFromEnv({
      EVIDENCE_SIGNING_PUBLIC_KEY_PEM: publicPem,
    } as NodeJS.ProcessEnv);
    const signed = await makeSignedRecord(signer);
    expect(await verifier!.verifyEvidence(signed)).toBe(true);
  });

  it('prefers EVIDENCE_VERIFY_PUBLIC_KEY_PEM and ignores SIGNING fallbacks when both are set (no mutual-exclusivity throw)', async () => {
    // Mixing VERIFY-* (new) with SIGNING-* (legacy) on the same host
    // during a migration must not blow up — verify takes precedence and
    // the SIGNING fallbacks are ignored entirely.
    const verify = makeKeyPair();
    const signing = makeKeyPair();
    const signerVerify = createSoftwareEvidenceSigner({ privateKeyPem: verify.privatePem });
    const signerSigning = createSoftwareEvidenceSigner({ privateKeyPem: signing.privatePem });
    const verifier = createSoftwareEvidenceVerifierFromEnv({
      EVIDENCE_VERIFY_PUBLIC_KEY_PEM: verify.publicPem,
      EVIDENCE_SIGNING_PUBLIC_KEY_FILE: '/does/not/exist.pem',
      EVIDENCE_SIGNING_PUBLIC_KEY_PEM: signing.publicPem,
    } as NodeJS.ProcessEnv);
    expect(verifier).toBeDefined();
    // Records signed under the VERIFY key verify; records signed under
    // the (ignored) SIGNING fallback key do not.
    expect(await verifier!.verifyEvidence(await makeSignedRecord(signerVerify))).toBe(true);
    expect(await verifier!.verifyEvidence(await makeSignedRecord(signerSigning))).toBe(false);
  });

  it('prefers PEM over FILE within the same precedence tier', () => {
    const { publicPem } = makeKeyPair();
    // FILE points at a non-existent path — if precedence were wrong this
    // would throw. With correct precedence the PEM is used and the call
    // succeeds.
    const verifier = createSoftwareEvidenceVerifierFromEnv({
      EVIDENCE_VERIFY_PUBLIC_KEY_PEM: publicPem,
      EVIDENCE_VERIFY_PUBLIC_KEY_FILE: '/does/not/exist.pem',
    } as NodeJS.ProcessEnv);
    expect(verifier).toBeDefined();
  });
});

describe('parseEvidenceBatch', () => {
  it('parses a single JSON object', () => {
    const records = parseEvidenceBatch('{"id":"a"}');
    expect(records).toEqual([{ id: 'a' }]);
  });

  it('parses a JSON array', () => {
    const records = parseEvidenceBatch('[{"id":"a"},{"id":"b"}]');
    expect(records).toEqual([{ id: 'a' }, { id: 'b' }]);
  });

  it('parses JSONL with blank lines', () => {
    const records = parseEvidenceBatch('{"id":"a"}\n\n{"id":"b"}\n');
    expect(records).toEqual([{ id: 'a' }, { id: 'b' }]);
  });

  it('returns an empty array on empty input', () => {
    expect(parseEvidenceBatch('')).toEqual([]);
    expect(parseEvidenceBatch('   \n  ')).toEqual([]);
  });

  it('throws with a line number on malformed JSONL', () => {
    expect(() => parseEvidenceBatch('{"id":"a"}\nnot-json\n')).toThrow(/line 2/);
  });
});

describe('runVerifyEvidence', () => {
  let tmpDir: string;
  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'verify-evidence-'));
  });
  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  function writeBatch(name: string, records: SignedAuditEvidence[], format: 'json' | 'jsonl' = 'jsonl'): string {
    const file = path.join(tmpDir, name);
    const content = format === 'jsonl'
      ? records.map((r) => JSON.stringify(r)).join('\n') + '\n'
      : JSON.stringify(records);
    fs.writeFileSync(file, content);
    return file;
  }

  it('reports every record as verified for an untampered batch', async () => {
    const { privatePem, publicPem } = makeKeyPair();
    const signer = createSoftwareEvidenceSigner({ privateKeyPem: privatePem });
    const verifier = createSoftwareEvidenceVerifier({ publicKeyPem: publicPem });

    const records = [await makeSignedRecord(signer), await makeSignedRecord(signer)];
    const file = writeBatch('batch.jsonl', records);

    const report = await runVerifyEvidence([file], verifier);
    expect(report.total).toBe(2);
    expect(report.verified).toBe(2);
    expect(report.failed).toBe(0);
    expect(report.failures).toEqual([]);
  });

  it('fails fast (default) on the first tampered record', async () => {
    const { privatePem, publicPem } = makeKeyPair();
    const signer = createSoftwareEvidenceSigner({ privateKeyPem: privatePem });
    const verifier = createSoftwareEvidenceVerifier({ publicKeyPem: publicPem });

    const good = await makeSignedRecord(signer);
    const tampered = { ...(await makeSignedRecord(signer)), action: 'write' };
    const stillGood = await makeSignedRecord(signer);
    const file = writeBatch('batch.jsonl', [good, tampered, stillGood]);

    const report = await runVerifyEvidence([file], verifier);
    expect(report.failed).toBe(1);
    // Fail-fast stops at index 1 — total reflects only what was scanned.
    expect(report.total).toBe(2);
    expect(report.failures[0]).toMatchObject({ index: 1, reason: 'signature did not verify' });
    expect(report.failures[0]?.evidenceId).toBe(tampered.id);
  });

  it('reports every failure when failFast=false', async () => {
    const { privatePem, publicPem } = makeKeyPair();
    const signer = createSoftwareEvidenceSigner({ privateKeyPem: privatePem });
    const verifier = createSoftwareEvidenceVerifier({ publicKeyPem: publicPem });

    const good = await makeSignedRecord(signer);
    const tamperedA = { ...(await makeSignedRecord(signer)), action: 'write' };
    const tamperedB = { ...(await makeSignedRecord(signer)), userId: 'attacker' };
    const file = writeBatch('batch.jsonl', [good, tamperedA, tamperedB]);

    const report = await runVerifyEvidence([file], verifier, { failFast: false });
    expect(report.total).toBe(3);
    expect(report.verified).toBe(1);
    expect(report.failed).toBe(2);
    expect(report.failures.map((f) => f.index)).toEqual([1, 2]);
  });

  it('rejects records that are missing required fields with a structural reason', async () => {
    const { publicPem } = makeKeyPair();
    const verifier = createSoftwareEvidenceVerifier({ publicKeyPem: publicPem });
    const file = path.join(tmpDir, 'broken.json');
    fs.writeFileSync(file, JSON.stringify({ id: 'no-signature' }));
    const report = await runVerifyEvidence([file], verifier);
    expect(report.failed).toBe(1);
    expect(report.failures[0]?.reason).toMatch(/missing required fields/);
  });

  it('walks a directory of audit-batch files', async () => {
    const { privatePem, publicPem } = makeKeyPair();
    const signer = createSoftwareEvidenceSigner({ privateKeyPem: privatePem });
    const verifier = createSoftwareEvidenceVerifier({ publicKeyPem: publicPem });

    writeBatch('00.jsonl', [await makeSignedRecord(signer)]);
    writeBatch('01.json', [await makeSignedRecord(signer)], 'json');
    // Non-matching file should be ignored.
    fs.writeFileSync(path.join(tmpDir, 'README.md'), 'ignore me');

    const report = await runVerifyEvidence([tmpDir], verifier, { failFast: false });
    expect(report.total).toBe(2);
    expect(report.verified).toBe(2);
    expect(report.failed).toBe(0);
  });

  it('records a parse failure rather than throwing', async () => {
    const { publicPem } = makeKeyPair();
    const verifier = createSoftwareEvidenceVerifier({ publicKeyPem: publicPem });
    const file = path.join(tmpDir, 'bad.jsonl');
    fs.writeFileSync(file, '{"id":"a"}\nnot-json\n');
    const report = await runVerifyEvidence([file], verifier, { failFast: false });
    expect(report.failed).toBeGreaterThanOrEqual(1);
    const parseFailure = report.failures.find((f) => f.reason.startsWith('parse failed'));
    expect(parseFailure).toBeDefined();
    // File-scoped failures must omit `index` so consumers can treat its
    // presence as "this is a record-scoped failure" without a sentinel.
    expect(parseFailure).not.toHaveProperty('index');
  });
});

describe('main (CLI entry point)', () => {
  let tmpDir: string;
  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'verify-evidence-cli-'));
  });
  afterEach(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  function captureStream(): { stream: NodeJS.WritableStream; data: () => string } {
    const chunks: Buffer[] = [];
    const stream = {
      write(chunk: string | Buffer): boolean {
        chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
        return true;
      },
    } as unknown as NodeJS.WritableStream;
    return { stream, data: () => Buffer.concat(chunks).toString('utf8') };
  }

  it('exits 0 and emits a JSON report for a clean batch', async () => {
    const { privatePem, publicPem } = makeKeyPair();
    const signer = createSoftwareEvidenceSigner({ privateKeyPem: privatePem });
    const file = path.join(tmpDir, 'batch.jsonl');
    fs.writeFileSync(file, JSON.stringify(await makeSignedRecord(signer)) + '\n');

    const stdout = captureStream();
    const stderr = captureStream();
    const code = await main(
      ['node', 'verify-evidence', file],
      { EVIDENCE_VERIFY_PUBLIC_KEY_PEM: publicPem } as NodeJS.ProcessEnv,
      stdout.stream,
      stderr.stream,
    );
    expect(code).toBe(0);
    const report = JSON.parse(stdout.data());
    expect(report.total).toBe(1);
    expect(report.verified).toBe(1);
    expect(report.failed).toBe(0);
  });

  it('exits 1 when any record fails verification', async () => {
    const { privatePem, publicPem } = makeKeyPair();
    const signer = createSoftwareEvidenceSigner({ privateKeyPem: privatePem });
    const tampered = { ...(await makeSignedRecord(signer)), action: 'write' };
    const file = path.join(tmpDir, 'batch.jsonl');
    fs.writeFileSync(file, JSON.stringify(tampered) + '\n');

    const stdout = captureStream();
    const stderr = captureStream();
    const code = await main(
      ['node', 'verify-evidence', file],
      { EVIDENCE_VERIFY_PUBLIC_KEY_PEM: publicPem } as NodeJS.ProcessEnv,
      stdout.stream,
      stderr.stream,
    );
    expect(code).toBe(1);
    const report = JSON.parse(stdout.data());
    expect(report.failed).toBe(1);
  });

  it('exits 2 when no verifier is configured', async () => {
    const file = path.join(tmpDir, 'batch.jsonl');
    fs.writeFileSync(file, '{}\n');
    const stdout = captureStream();
    const stderr = captureStream();
    const code = await main(['node', 'verify-evidence', file], {}, stdout.stream, stderr.stream);
    expect(code).toBe(2);
    expect(stderr.data()).toMatch(/no verifier configured/);
  });

  it('exits 2 when no inputs are supplied', async () => {
    const { publicPem } = makeKeyPair();
    const stdout = captureStream();
    const stderr = captureStream();
    const code = await main(
      ['node', 'verify-evidence'],
      { EVIDENCE_VERIFY_PUBLIC_KEY_PEM: publicPem } as NodeJS.ProcessEnv,
      stdout.stream,
      stderr.stream,
    );
    expect(code).toBe(2);
    expect(stderr.data()).toMatch(/no input files/);
  });

  it('exits 2 on an unknown option', async () => {
    const { publicPem } = makeKeyPair();
    const stdout = captureStream();
    const stderr = captureStream();
    const code = await main(
      ['node', 'verify-evidence', '--bogus', 'file'],
      { EVIDENCE_VERIFY_PUBLIC_KEY_PEM: publicPem } as NodeJS.ProcessEnv,
      stdout.stream,
      stderr.stream,
    );
    expect(code).toBe(2);
    expect(stderr.data()).toMatch(/unknown option/);
  });

  it('--all keeps scanning past failures', async () => {
    const { privatePem, publicPem } = makeKeyPair();
    const signer = createSoftwareEvidenceSigner({ privateKeyPem: privatePem });
    const tamperedA = { ...(await makeSignedRecord(signer)), action: 'write' };
    const tamperedB = { ...(await makeSignedRecord(signer)), userId: 'attacker' };
    const file = path.join(tmpDir, 'batch.jsonl');
    fs.writeFileSync(file, [tamperedA, tamperedB].map((r) => JSON.stringify(r)).join('\n') + '\n');

    const stdout = captureStream();
    const stderr = captureStream();
    const code = await main(
      ['node', 'verify-evidence', '--all', file],
      { EVIDENCE_VERIFY_PUBLIC_KEY_PEM: publicPem } as NodeJS.ProcessEnv,
      stdout.stream,
      stderr.stream,
    );
    expect(code).toBe(1);
    const report = JSON.parse(stdout.data());
    expect(report.total).toBe(2);
    expect(report.failed).toBe(2);
  });

  it('--help exits 0 and prints usage', async () => {
    const stdout = captureStream();
    const stderr = captureStream();
    const code = await main(['node', 'verify-evidence', '--help'], {}, stdout.stream, stderr.stream);
    expect(code).toBe(0);
    expect(stdout.data()).toMatch(/Usage: verify-evidence/);
  });
});
