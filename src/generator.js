// Core vanity search loop.
//
// Speed trick: instead of doing a full elliptic-curve scalar multiplication
// (private key -> public key) for every candidate, we compute ONE base point
// and then repeatedly ADD the generator point G. Point addition is far cheaper
// than full multiplication, so this checks many more keys per second.
//
//   pub_{n+1} = pub_n + G   while   priv_{n+1} = priv_n + 1
import * as secp from '@noble/secp256k1';
import { randomBytes } from 'node:crypto';
import { publicKeyToAddress } from './tron.js';

const N = secp.CURVE.n; // curve order

/** Pick a random scalar in [1, n-2] so we can safely increment for a while. */
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
 * Search for an address whose Base58 form starts with `prefix`.
 *
 * @param {object} opts
 * @param {string} opts.prefix        Full prefix the address must start with (e.g. "TRAHINO").
 * @param {boolean} opts.ignoreCase   Case-insensitive matching.
 * @param {number} opts.reportEvery   Report progress every N attempts.
 * @param {() => boolean} opts.shouldStop  Return true to abort the loop.
 * @param {(count:number)=>void} opts.onProgress  Called with attempts since last report.
 * @returns {{address:string, privateKey:string, attempts:number}|null}
 */
export function search({ prefix, ignoreCase, reportEvery, shouldStop, onProgress }) {
  const target = ignoreCase ? prefix.toLowerCase() : prefix;
  const G = secp.ProjectivePoint.BASE;

  let scalar = randomScalar();
  let point = G.multiply(scalar); // one full multiplication to seed the run
  let attempts = 0;
  let sinceReport = 0;

  while (true) {
    const pub = point.toRawBytes(false); // 65-byte uncompressed
    const address = publicKeyToAddress(pub);
    const hay = ignoreCase ? address.toLowerCase() : address;

    attempts++;
    sinceReport++;

    if (hay.startsWith(target)) {
      return { address, privateKey: scalarToPrivHex(scalar), attempts };
    }

    // Advance to the next sequential key.
    point = point.add(G);
    scalar += 1n;
    if (scalar >= N - 1n) {
      // Extremely unlikely; reseed to stay in range.
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
