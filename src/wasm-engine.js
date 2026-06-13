// Loader and thin wrapper around the Rust WASM search kernel.
//
// The kernel runs the whole inner loop in WebAssembly. From JS we only seed a
// random start key, then repeatedly ask it to scan a chunk of candidates.
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

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
    /** Seed the search from a 32-byte private key. */
    init(startKey32) {
      mem().set(startKey32, e.start_key_ptr());
      e.init();
    },
    /** Write the target text (ASCII Base58) into the kernel. */
    setTarget(targetStr) {
      const t = new TextEncoder().encode(targetStr);
      mem().set(t, e.target_ptr());
      return t.length;
    },
    /**
     * Scan up to maxIters candidates.
     * @returns {number} match iteration index, or -1 if none in this chunk.
     */
    run(targetLen, mode, ignoreCase, maxIters) {
      return Number(e.run(targetLen, MODE_CODE[mode], ignoreCase ? 1 : 0, maxIters));
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
