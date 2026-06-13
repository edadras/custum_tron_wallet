// Basic correctness tests for the TRON address derivation.
import assert from 'node:assert';
import * as secp from '@noble/secp256k1';
import { publicKeyToAddress, base58Decode, isValidBase58, BASE58_ALPHABET } from '../src/tron.js';
import { sha256 } from '@noble/hashes/sha256';

let passed = 0;
function check(name, fn) {
  fn();
  passed++;
  console.log(`ok - ${name}`);
}

// 1. Every derived address starts with "T".
check('addresses start with T', () => {
  for (let i = 1; i <= 5; i++) {
    const priv = BigInt(i);
    const pub = secp.ProjectivePoint.BASE.multiply(priv).toRawBytes(false);
    const addr = publicKeyToAddress(pub);
    assert.strictEqual(addr[0], 'T', `address ${addr} should start with T`);
    assert.strictEqual(addr.length, 34, 'address length should be 34');
  }
});

// 2. Base58Check checksum round-trips (decode -> verify checksum).
check('checksum is valid', () => {
  const pub = secp.ProjectivePoint.BASE.multiply(12345n).toRawBytes(false);
  const addr = publicKeyToAddress(pub);
  const raw = base58Decode(addr);
  assert.strictEqual(raw.length, 25, 'decoded payload is 21 + 4 bytes');
  assert.strictEqual(raw[0], 0x41, 'version byte is 0x41');
  const payload = raw.slice(0, 21);
  const checksum = raw.slice(21);
  const expected = sha256(sha256(payload)).slice(0, 4);
  assert.deepStrictEqual([...checksum], [...expected], 'checksum matches');
});

// 3. Known vector: private key = 1.
//    The keccak256 of the pubkey for k=1 yields the well-known Ethereum
//    address 0x7e5f4552091a69125d5dfcb7b8c2659029395bdf; TRON prepends 0x41.
check('known vector for private key = 1', () => {
  const pub = secp.ProjectivePoint.BASE.multiply(1n).toRawBytes(false);
  const addr = publicKeyToAddress(pub);
  const raw = base58Decode(addr);
  const hex = Buffer.from(raw.slice(1, 21)).toString('hex');
  assert.strictEqual(hex, '7e5f4552091a69125d5dfcb7b8c2659029395bdf');
});

// 4. Base58 validation rejects forbidden chars.
check('Base58 validation', () => {
  assert.ok(isValidBase58('RAHN')); // all valid
  assert.ok(isValidBase58('rahino')); // lowercase o and i are valid
  assert.ok(!isValidBase58('RAHINO')); // capital I and O are NOT valid
  assert.ok(!isValidBase58('ISTANBUL')); // contains I
  assert.ok(!isValidBase58('hell0')); // contains 0 (zero)
  assert.ok([...BASE58_ALPHABET].every((c) => 'OIl0'.indexOf(c) === -1));
});

console.log(`\n${passed} tests passed.`);
