// TRON address helpers: key -> address derivation and Base58Check encoding.
import { keccak_256 } from '@noble/hashes/sha3';
import { sha256 } from '@noble/hashes/sha256';

// Base58 alphabet used by Bitcoin/TRON. Note the missing chars: 0 (zero),
// O (capital o), I (capital i), l (lowercase L).
export const BASE58_ALPHABET =
  '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

const ALPHABET_MAP = new Map(
  [...BASE58_ALPHABET].map((c, i) => [c, i]),
);

// The address payload version byte for TRON mainnet (0x41). This is the
// reason every TRON address starts with the letter "T".
export const TRON_PREFIX_BYTE = 0x41;

/** Encode a byte array to a Base58 string. */
function base58Encode(bytes) {
  // Count leading zero bytes (each maps to a leading "1").
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;

  // Convert the big-endian byte array to base58 via repeated division.
  const digits = [0];
  for (let i = zeros; i < bytes.length; i++) {
    let carry = bytes[i];
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }

  let out = '1'.repeat(zeros);
  for (let i = digits.length - 1; i >= 0; i--) out += BASE58_ALPHABET[digits[i]];
  return out;
}

/** Decode a Base58 string to a byte array (used for validation/tests). */
export function base58Decode(str) {
  let zeros = 0;
  while (zeros < str.length && str[zeros] === '1') zeros++;

  const bytes = [0];
  for (let i = zeros; i < str.length; i++) {
    const value = ALPHABET_MAP.get(str[i]);
    if (value === undefined) throw new Error(`Invalid Base58 char: ${str[i]}`);
    let carry = value;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j] * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }

  const result = new Uint8Array(zeros + bytes.length);
  for (let i = 0; i < bytes.length; i++) result[zeros + i] = bytes[bytes.length - 1 - i];
  return result;
}

/** Base58Check-encode a 21-byte payload (0x41 + 20-byte address hash). */
export function base58CheckEncode(payload21) {
  const checksum = sha256(sha256(payload21)).slice(0, 4);
  const full = new Uint8Array(payload21.length + 4);
  full.set(payload21, 0);
  full.set(checksum, payload21.length);
  return base58Encode(full);
}

/**
 * Convert an uncompressed public key (65 bytes: 0x04 || X || Y) into a TRON
 * Base58Check address string.
 */
export function publicKeyToAddress(uncompressedPubKey) {
  // Drop the 0x04 prefix; hash the 64-byte X||Y with keccak-256.
  const hash = keccak_256(uncompressedPubKey.subarray(1));
  // Address = last 20 bytes of the hash, prefixed with 0x41.
  const payload = new Uint8Array(21);
  payload[0] = TRON_PREFIX_BYTE;
  payload.set(hash.subarray(12), 1);
  return base58CheckEncode(payload);
}

/** True if a string contains only valid Base58 characters. */
export function isValidBase58(str) {
  for (const c of str) if (!ALPHABET_MAP.has(c)) return false;
  return true;
}
