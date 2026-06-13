// Worker thread: runs the search loop and reports back to the main thread.
// Uses the fast WASM kernel when available, otherwise the pure-JS generator.
import { parentPort, workerData } from 'node:worker_threads';
import { randomBytes } from 'node:crypto';
import * as secp from '@noble/secp256k1';
import { search } from './generator.js';
import { loadKernel } from './wasm-engine.js';
import { publicKeyToAddress } from './tron.js';

let stop = false;
parentPort.on('message', (msg) => {
  if (msg === 'stop') stop = true;
});

const { mode, target, ignoreCase, reportEvery, engine } = workerData;

if (engine === 'wasm') {
  runWasm();
} else {
  runJs();
}

function runJs() {
  const result = search({
    mode,
    target,
    ignoreCase,
    reportEvery,
    shouldStop: () => stop,
    onProgress: (count) => {
      if (count > 0) parentPort.postMessage({ type: 'progress', count });
    },
  });
  if (result) parentPort.postMessage({ type: 'found', ...result });
  else parentPort.postMessage({ type: 'stopped' });
}

function runWasm() {
  const kernel = loadKernel();
  // Compare against a lower-cased target when ignoring case (kernel lowercases
  // the address, so the target must already be lower-cased to match).
  const needle = ignoreCase ? target.toLowerCase() : target;
  const tlen = kernel.setTarget(needle);
  kernel.init(randomBytes(32));

  const CHUNK = Math.max(2000, reportEvery); // candidates scanned per kernel call
  let done = 0;

  while (!stop) {
    const idx = kernel.run(tlen, mode, ignoreCase, CHUNK);
    if (idx >= 0) {
      const privateKey = kernel.outKeyHex();
      const address = publicKeyToAddress(secp.getPublicKey(privateKey, false));
      parentPort.postMessage({
        type: 'found',
        address,
        privateKey,
        attempts: done + idx + 1,
      });
      return;
    }
    done += CHUNK;
    parentPort.postMessage({ type: 'progress', count: CHUNK });
  }
  parentPort.postMessage({ type: 'stopped' });
}
