/**
 * Unit tests for GcsAnchorClientImpl.
 *
 * Uses jest.mock to stub out @google-cloud/storage so the test suite works
 * even when the optional GCP SDK is not available in the test environment.
 */

// jest.mock must be called BEFORE importing the module under test (it is
// hoisted by Babel/ts-jest at transformation time).
jest.mock('@google-cloud/storage', () => {
  return {
    Storage: jest.fn(),
  };
}, { virtual: true });

import { GcsAnchorClientImpl } from '../ledger-signer';
import { Storage } from '@google-cloud/storage';

// Typed handle to the mocked Storage constructor.
const MockStorage = Storage as jest.MockedClass<typeof Storage>;

describe('GcsAnchorClientImpl', () => {
  let setMetadata: jest.Mock;
  let save: jest.Mock;
  let fileMock: jest.Mock;
  let bucketMock: jest.Mock;

  beforeEach(() => {
    MockStorage.mockReset();

    setMetadata = jest.fn().mockResolvedValue(undefined);
    save = jest.fn().mockResolvedValue(undefined);
    fileMock = jest.fn().mockReturnValue({ save, setMetadata });
    bucketMock = jest.fn().mockReturnValue({ file: fileMock });

    // Storage constructor returns an object with `.bucket(name)`.
    MockStorage.mockImplementation(() => ({
      bucket: bucketMock,
    }) as unknown as InstanceType<typeof Storage>);
  });

  it('calls bucket().file().save() with correct args', async () => {
    const client = new GcsAnchorClientImpl({ projectId: 'my-project' });

    await client.putObject({
      bucket: 'my-gcs-bucket',
      key: 'audit-anchor/rep-1/1-1000.json',
      body: '{"schemaVersion":"1.0"}',
      contentType: 'application/json',
    });

    expect(bucketMock).toHaveBeenCalledWith('my-gcs-bucket');
    expect(fileMock).toHaveBeenCalledWith('audit-anchor/rep-1/1-1000.json');
    expect(save).toHaveBeenCalledWith('{"schemaVersion":"1.0"}', {
      resumable: false,
      contentType: 'application/json',
    });
  });

  it('sets temporaryHold by default', async () => {
    const client = new GcsAnchorClientImpl();

    await client.putObject({
      bucket: 'b',
      key: 'k',
      body: '{}',
      contentType: 'application/json',
    });

    expect(setMetadata).toHaveBeenCalledWith({ temporaryHold: true });
  });

  it('skips setMetadata when skipTemporaryHold is true', async () => {
    const client = new GcsAnchorClientImpl({ skipTemporaryHold: true });

    await client.putObject({
      bucket: 'b',
      key: 'k',
      body: '{}',
      contentType: 'application/json',
    });

    expect(save).toHaveBeenCalled();
    expect(setMetadata).not.toHaveBeenCalled();
  });

  it('passes keyFilename to Storage constructor when keyFilePath is provided', async () => {
    const client = new GcsAnchorClientImpl({
      keyFilePath: '/etc/gcp-key.json',
    });

    await client.putObject({
      bucket: 'b',
      key: 'k',
      body: '{}',
      contentType: 'application/json',
    });

    expect(MockStorage).toHaveBeenCalledWith(
      expect.objectContaining({ keyFilename: '/etc/gcp-key.json' }),
    );
  });

  it('passes projectId to Storage constructor when provided', async () => {
    const client = new GcsAnchorClientImpl({ projectId: 'my-gcp-project' });

    await client.putObject({
      bucket: 'b',
      key: 'k',
      body: '{}',
      contentType: 'application/json',
    });

    expect(MockStorage).toHaveBeenCalledWith(
      expect.objectContaining({ projectId: 'my-gcp-project' }),
    );
  });

  it('reuses the same Storage instance across multiple putObject calls (lazy singleton)', async () => {
    const client = new GcsAnchorClientImpl({ projectId: 'proj' });

    await client.putObject({ bucket: 'b', key: 'k1', body: '{}', contentType: 'application/json' });
    await client.putObject({ bucket: 'b', key: 'k2', body: '{}', contentType: 'application/json' });

    // Storage constructor should only be called once (lazy singleton).
    expect(MockStorage).toHaveBeenCalledTimes(1);
  });

  it('propagates errors from file.save()', async () => {
    save.mockRejectedValue(new Error('GCS upload failed'));
    const client = new GcsAnchorClientImpl();

    await expect(
      client.putObject({ bucket: 'b', key: 'k', body: '{}', contentType: 'application/json' }),
    ).rejects.toThrow('GCS upload failed');
  });

  it('propagates errors from file.setMetadata()', async () => {
    setMetadata.mockRejectedValue(new Error('GCS setMetadata failed'));
    const client = new GcsAnchorClientImpl();

    await expect(
      client.putObject({ bucket: 'b', key: 'k', body: '{}', contentType: 'application/json' }),
    ).rejects.toThrow('GCS setMetadata failed');
  });

  it('constructs Storage with no options when neither keyFilePath nor projectId are set', async () => {
    const client = new GcsAnchorClientImpl();

    await client.putObject({ bucket: 'b', key: 'k', body: '{}', contentType: 'application/json' });

    // Should be called with empty config object.
    expect(MockStorage).toHaveBeenCalledWith({});
  });
});
