import {
  generateApiKey,
  parseApiKey,
  isValidApiKeyFormat,
  BASE58_ALPHABET,
  API_KEY_LITERAL_PREFIX,
  API_KEY_PREFIX_LEN,
  API_KEY_SECRET_LEN,
  API_KEY_SEPARATOR,
} from '../src/api-key';
import { CapabilityError } from '@euno/common';

describe('generateApiKey', () => {
  it('returns an object with prefix, secret, and raw', () => {
    const key = generateApiKey();
    expect(typeof key.prefix).toBe('string');
    expect(typeof key.secret).toBe('string');
    expect(typeof key.raw).toBe('string');
  });

  it('prefix has correct length', () => {
    const { prefix } = generateApiKey();
    expect(prefix).toHaveLength(API_KEY_PREFIX_LEN);
  });

  it('secret has correct length', () => {
    const { secret } = generateApiKey();
    expect(secret).toHaveLength(API_KEY_SECRET_LEN);
  });

  it('raw has correct format sk-<prefix>.<secret>', () => {
    const { prefix, secret, raw } = generateApiKey();
    expect(raw).toBe(`${API_KEY_LITERAL_PREFIX}${prefix}${API_KEY_SEPARATOR}${secret}`);
  });

  it('prefix and secret contain only Base58 characters', () => {
    const base58Re = new RegExp(`^[${BASE58_ALPHABET}]+$`);
    const { prefix, secret } = generateApiKey();
    expect(base58Re.test(prefix)).toBe(true);
    expect(base58Re.test(secret)).toBe(true);
  });

  it('two calls produce different keys', () => {
    const a = generateApiKey();
    const b = generateApiKey();
    expect(a.raw).not.toBe(b.raw);
  });
});

describe('parseApiKey', () => {
  it('correctly parses a valid key', () => {
    const { prefix, secret, raw } = generateApiKey();
    const parsed = parseApiKey(raw);
    expect(parsed.prefix).toBe(prefix);
    expect(parsed.secret).toBe(secret);
  });

  it('throws 401 CapabilityError for missing sk- prefix', () => {
    expect(() => parseApiKey('invalid-key')).toThrow(CapabilityError);
    expect(() => parseApiKey('invalid-key')).toThrow(expect.objectContaining({ statusCode: 401 }));
  });

  it('throws for wrong separator position', () => {
    expect(() => parseApiKey('sk-abc.123')).toThrow(CapabilityError);
  });

  it('throws for wrong secret length', () => {
    const fakePrefix = BASE58_ALPHABET.slice(0, API_KEY_PREFIX_LEN);
    const shortSecret = BASE58_ALPHABET.slice(0, 10);
    expect(() => parseApiKey(`sk-${fakePrefix}.${shortSecret}`)).toThrow(CapabilityError);
  });

  it('throws for non-Base58 characters in secret', () => {
    const fakePrefix = BASE58_ALPHABET.slice(0, API_KEY_PREFIX_LEN);
    const badSecret = '0'.repeat(API_KEY_SECRET_LEN); // '0' not in Base58
    expect(() => parseApiKey(`sk-${fakePrefix}.${badSecret}`)).toThrow(CapabilityError);
  });
});

describe('isValidApiKeyFormat', () => {
  it('returns true for a valid generated key', () => {
    const { raw } = generateApiKey();
    expect(isValidApiKeyFormat(raw)).toBe(true);
  });

  it('returns false for empty string', () => {
    expect(isValidApiKeyFormat('')).toBe(false);
  });

  it('returns false for missing sk- prefix', () => {
    expect(isValidApiKeyFormat('sometoken')).toBe(false);
  });

  it('returns false for key without separator', () => {
    expect(isValidApiKeyFormat('sk-' + BASE58_ALPHABET.slice(0, 56))).toBe(false);
  });

  it('returns false for characters outside Base58 alphabet', () => {
    const fakePrefix = BASE58_ALPHABET.slice(0, API_KEY_PREFIX_LEN);
    const badSecret = '0'.repeat(API_KEY_SECRET_LEN);
    expect(isValidApiKeyFormat(`sk-${fakePrefix}.${badSecret}`)).toBe(false);
  });
});
