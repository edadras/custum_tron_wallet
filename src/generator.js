// Core vanity search loop (optimized for many-core CPUs).
//
// Two speed tricks:
//
// 1. Incremental point addition. Instead of a full elliptic-curve scalar
//    multiplication (private key -> public key) for every candidate, we
//    compute ONE base point and repeatedly ADD the generator point G:
//      pub_{n+1} = pub_n + G   while   priv_{n+1} = priv_n + 1
//
// 2. Batched modular inversion (Montgomery's trick). Turning a projective
//    point into affine (x, y) coordinates needs a modular inverse of Z, which
//    is by far the most expensive field operation. Instead of one inversion
//    per candidate, we collect a whole BATCH of points and invert all their Z
//    values with a SINGLE inversion plus cheap multiplications. This is the
//    main reason this version is several times faster than the naive loop.
import * as secp from '@noble/secp256k1';
import { randomBytes } from 'node:crypto';
import { addressFromPublicXY } from './tron.js';

const N = secp.CURVE.n; // curve order
const P = secp.CURVE.p; // field prime
const { mod, invert, numberToBytesBE } = secp.etc;

// How many points to convert to affine per single inversion. Larger batches
// amortize the inversion better, with diminishing returns past a few hundred.
const BATCH = 256;

/** Pick a random scalar in [2, n-2] so we can safely increment for a while. */
function randomScalar() {
  while (true) {
    const k = BigInt('0x' + randomBytes(32).toString('hex')) % N;
    if (k > 1n) return k;
  }
}

function scalarToPrivHex(scalar) {
  return scalar.toString(16).padStart(64, '0');
}

/**
 * Build a predicate that tests an address against the target text.
 * @param {'prefix'|'suffix'|'contains'} mode
 */
function makeMatcher(mode, target) {
  if (mode === 'suffix') return (addr) => addr.endsWith(target);
  if (mode === 'contains') return (addr) => addr.includes(target);
  return (addr) => addr.startsWith(target); // 'prefix'
}

/**
 * Search for an address whose Base58 form matches the target text.
 *
 * @param {object} opts
 * @param {'prefix'|'suffix'|'contains'} opts.mode  Where the text must appear.
 * @param {string} opts.target        The text to match.
 * @param {boolean} opts.ignoreCase   Case-insensitive matching.
 * @param {number} opts.reportEvery   Report progress every N attempts.
 * @param {() => boolean} opts.shouldStop  Return true to abort the loop.
 * @param {(count:number)=>void} opts.onProgress  Called with attempts since last report.
 * @returns {{address:string, privateKey:string, attempts:number}|null}
 */
export function search({ mode, target, ignoreCase, reportEvery, shouldStop, onProgress }) {
  const needle = ignoreCase ? target.toLowerCase() : target;
  const matches = makeMatcher(mode, needle);
  const G = secp.ProjectivePoint.BASE;

  let scalar = randomScalar();
  let point = G.multiply(scalar); // one full multiplication to seed the run
  let attempts = 0;
  let sinceReport = 0;

  // Reusable scratch buffers for one batch.
  const xs = new Array(BATCH);
  const ys = new Array(BATCH);
  const zs = new Array(BATCH);
  const prefix = new Array(BATCH); // running products of z for batch inversion
  const xy64 = new Uint8Array(64);

  while (true) {
    // --- Collect a batch of consecutive points (projective coords). ---
    for (let i = 0; i < BATCH; i++) {
      xs[i] = point.px;
      ys[i] = point.py;
      zs[i] = point.pz;
      point = point.add(G);
    }

    // --- Batch-invert all Z values with a single modular inversion. ---
    prefix[0] = zs[0];
    for (let i = 1; i < BATCH; i++) prefix[i] = mod(prefix[i - 1] * zs[i], P);
    let acc = invert(prefix[BATCH - 1], P);
    for (let i = BATCH - 1; i >= 0; i--) {
      const zInv = i === 0 ? acc : mod(acc * prefix[i - 1], P);
      acc = i === 0 ? acc : mod(acc * zs[i], P);

      // Affine coordinates -> 64-byte X||Y -> TRON address.
      const x = mod(xs[i] * zInv, P);
      const y = mod(ys[i] * zInv, P);
      xy64.set(numberToBytesBE(x, 32), 0);
      xy64.set(numberToBytesBE(y, 32), 32);
      const address = addressFromPublicXY(xy64);
      const hay = ignoreCase ? address.toLowerCase() : address;

      if (matches(hay)) {
        // scalar currently points just past the batch; recover this key's scalar.
        const keyScalar = scalar + BigInt(i);
        attempts += i + 1;
        return { address, privateKey: scalarToPrivHex(keyScalar), attempts };
      }
    }

    scalar += BigInt(BATCH);
    attempts += BATCH;
    sinceReport += BATCH;

    if (scalar >= N - BigInt(BATCH) - 1n) {
      // Extremely unlikely; reseed to stay safely in range.
      scalar = randomScalar();
      point = G.multiply(scalar);
    }

    if (sinceReport >= reportEvery) {
      onProgress(sinceReport);
      sinceReport = 0;
      if (shouldStop()) {
        onProgress(0);
        return null;
      }
    }
  }
}
