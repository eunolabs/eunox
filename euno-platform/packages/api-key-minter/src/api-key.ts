import * as crypto from 'crypto';
import { CapabilityError, ErrorCode } from '@euno/common';

export const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
export const API_KEY_SEPARATOR = '.';
export const API_KEY_LITERAL_PREFIX = 'sk-';
export const API_KEY_PREFIX_LEN = 8;
export const API_KEY_SECRET_LEN = 48;
// __dummy__ contains underscores, which are outside the Base58 alphabet,
// so it can never collide with a real prefix.
export const API_KEY_DUMMY_PREFIX = '__dummy__';

export interface ParsedApiKey {
  prefix: string;
  secret: string;
}

function randomBase58Char(): string {
  // Rejection sampling: 256 = 4*64; 4*58=232; reject bytes ≥232 to avoid modulo bias.
  while (true) {
    const byte = crypto.randomBytes(1)[0]!;
    if (byte < 232) return BASE58_ALPHABET[byte % 58]!;
  }
}

function generateBase58String(length: number): string {
  let result = '';
  while (result.length < length) result += randomBase58Char();
  return result;
}

export function encodeBase58(bytes: Buffer): string {
  let result = '';
  for (let i = 0; i < bytes.length; i++) {
    result += BASE58_ALPHABET[bytes[i]! % 58]!;
  }
  return result;
}

export function generateApiKey(): { prefix: string; secret: string; raw: string } {
  const prefix = generateBase58String(API_KEY_PREFIX_LEN);
  const secret = generateBase58String(API_KEY_SECRET_LEN);
  const raw = `${API_KEY_LITERAL_PREFIX}${prefix}${API_KEY_SEPARATOR}${secret}`;
  return { prefix, secret, raw };
}

export function parseApiKey(raw: string): ParsedApiKey {
  if (!isValidApiKeyFormat(raw)) {
    throw new CapabilityError(
      ErrorCode.INVALID_TOKEN,
      'Invalid API key format',
      401,
    );
  }
  const withoutPrefix = raw.slice(API_KEY_LITERAL_PREFIX.length);
  const sepIdx = withoutPrefix.indexOf(API_KEY_SEPARATOR);
  const prefix = withoutPrefix.slice(0, sepIdx);
  const secret = withoutPrefix.slice(sepIdx + 1);
  return { prefix, secret };
}

export function isValidApiKeyFormat(raw: string): boolean {
  if (typeof raw !== 'string') return false;
  if (!raw.startsWith(API_KEY_LITERAL_PREFIX)) return false;
  const withoutPrefix = raw.slice(API_KEY_LITERAL_PREFIX.length);
  const sepIdx = withoutPrefix.indexOf(API_KEY_SEPARATOR);
  if (sepIdx !== API_KEY_PREFIX_LEN) return false;
  const prefix = withoutPrefix.slice(0, sepIdx);
  const secret = withoutPrefix.slice(sepIdx + 1);
  if (secret.length !== API_KEY_SECRET_LEN) return false;
  const base58Re = new RegExp(`^[${BASE58_ALPHABET}]+$`);
  return base58Re.test(prefix) && base58Re.test(secret);
}
