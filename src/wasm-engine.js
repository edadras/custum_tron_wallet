// Loader and thin wrapper around the Rust WASM search kernel.
//
// The kernel runs the whole inner loop in WebAssembly. From JS we only seed a
// random start key, then repeatedly ask it to scan a chunk of candidates.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { base58Decode } from './tron.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const WASM_PATH = path.join(__dirname, 'wasm', 'kernel.wasm');

const MODE_CODE = { prefix: 0, suffix: 1, contains: 2 };

/** Load and instantiate the kernel. Returns a small handle object. */
export function loadKernel() {
  const bytes = readFileSync(WASM_PATH);
  const instance = new WebAssembly.Instance(new WebAssembly.Module(bytes), {});
  const e = instance.exports;
  const mem = () => new Uint8Array(e.memory.buffer);
  return {
    /** Seed the (fast) search from a 32-byte private key. */
    init(startKey32) {
      mem().set(startKey32, e.start_key_ptr());
      e.init_fast();
    },
    /** Write the target text (ASCII Base58) into the kernel. */
    setTarget(targetStr) {
      const t = new TextEncoder().encode(targetStr);
      mem().set(t, e.target_ptr());
      return t.length;
    },
    /**
     * Scan up to maxIters candidates with the fast engine.
     * @returns {number} match iteration index, or -1 if none in this chunk.
     */
    run(targetLen, mode, ignoreCase, maxIters) {
      return Number(e.run_fast(targetLen, MODE_CODE[mode], ignoreCase ? 1 : 0, maxIters));
    },
    /**
     * Compare the fast path against the k256 reference for `count` points from
     * the current base. Returns the number of mismatching addresses (0 = good).
     * Requires init() first.
     */
    selftest(count) {
      return e.selftest(count);
    },
    /**
     * Enable the prefix range fast path for a case-sensitive prefix. The prefix
     * maps to a contiguous [min,max] range of 25-byte address values, letting
     * the kernel skip Base58Check for nearly every candidate.
     */
    enablePrefixRange(prefix) {
      const pad = 34 - prefix.length;
      const toRange = (s) => {
        const d = base58Decode(s); // big-endian bytes
        const out = new Uint8Array(25);
        out.set(d.slice(-25), 25 - Math.min(25, d.length));
        return out;
      };
      mem().set(toRange(prefix + '1'.repeat(pad)), e.pref_min_ptr());
      mem().set(toRange(prefix + 'z'.repeat(pad)), e.pref_max_ptr());
      e.set_pref(1);
    },
    /** Prefix-range self-test: disagreements vs the true startsWith (0 = good). */
    selftestPrefix(count, tlen) {
      return e.selftest_prefix(count, tlen);
    },
    /** Base58 address of the current base point (for cross-checking). */
    startAddress() {
      const len = e.dump_start_addr();
      const m = mem();
      const ptr = e.addr_out_ptr();
      let s = '';
      for (let i = 0; i < len; i++) s += String.fromCharCode(m[ptr + i]);
      return s;
    },
    /** Read the 32-byte private key of the last match as hex. */
    outKeyHex() {
      const m = mem();
      const ptr = e.out_key_ptr();
      let s = '';
      for (let i = 0; i < 32; i++) s += m[ptr + i].toString(16).padStart(2, '0');
      return s;
    },
  };
}

export function isWasmAvailable() {
  try {
    readFileSync(WASM_PATH);
    return true;
  } catch {
    return false;
  }
}
