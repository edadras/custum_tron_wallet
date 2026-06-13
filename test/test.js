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

// 5. WASM fast engine: addresses must match the k256 reference, and a found
//    key must derive the target address.
import { loadKernel, isWasmAvailable } from '../src/wasm-engine.js';
import { randomBytes } from 'node:crypto';

if (isWasmAvailable()) {
  check('WASM fast path matches k256 reference', () => {
    const k = loadKernel();
    let mism = 0;
    for (let i = 0; i < 8; i++) {
      k.init(randomBytes(32));
      mism += k.selftest(256);
    }
    assert.strictEqual(mism, 0, 'fast affine path must equal the reference');
  });

  check('WASM Base58 matches the independent JS implementation', () => {
    const k = loadKernel();
    for (let i = 0; i < 50; i++) {
      const key = randomBytes(32);
      k.init(key);
      const wasmAddr = k.startAddress();
      const jsAddr = publicKeyToAddress(secp.getPublicKey(Buffer.from(key).toString('hex'), false));
      assert.strictEqual(wasmAddr, jsAddr, 'WASM address must equal the JS address');
    }
  });

  check('WASM prefix range filter equals true startsWith', () => {
    const k = loadKernel();
    let mism = 0;
    for (const pfx of ['TA', 'TRx', 'TEST', 'TKq7']) {
      const tlen = k.setTarget(pfx);
      k.enablePrefixRange(pfx);
      for (let i = 0; i < 4; i++) {
        k.init(randomBytes(32));
        mism += k.selftestPrefix(256, tlen);
      }
    }
    assert.strictEqual(mism, 0, 'range decision must equal full startsWith');
  });

  check('WASM found key derives the target address', () => {
    const k = loadKernel();
    k.init(randomBytes(32));
    const tlen = k.setTarget('kift');
    let idx = -1;
    for (let n = 0; idx < 0 && n < 4e7; n += 200000) idx = k.run(tlen, 'contains', true, 200000);
    assert.ok(idx >= 0, 'should find a match');
    const pk = k.outKeyHex();
    const addr = publicKeyToAddress(secp.getPublicKey(pk, false));
    assert.ok(addr.toLowerCase().includes('kift'), `address ${addr} must contain kift`);
  });
} else {
  console.log('skip - WASM kernel not built');
}

console.log(`\n${passed} tests passed.`);
