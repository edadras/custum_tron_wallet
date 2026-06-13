#!/usr/bin/env node
// Vanity TRON address generator — CLI entry point.
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { Worker } from 'node:worker_threads';
import * as secp from '@noble/secp256k1';
import { BASE58_ALPHABET, isValidBase58, publicKeyToAddress } from './tron.js';
import { isWasmAvailable } from './wasm-engine.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function parseArgs(argv) {
  const opts = {
    mode: null, // 'prefix' | 'suffix' | 'contains'
    target: null,
    verify: null, // a private key hex to derive an address from (no search)
    threads: Math.max(1, os.cpus().length),
    ignoreCase: false,
    count: 1,
    engine: null, // 'wasm' | 'js' (auto-detected when null)
    help: false,
  };
  const setMode = (mode, value) => {
    if (opts.mode && opts.mode !== mode) opts.modeConflict = true;
    opts.mode = mode;
    opts.target = value;
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '-p':
      case '--prefix':
        setMode('prefix', argv[++i]);
        break;
      case '-s':
      case '--suffix':
        setMode('suffix', argv[++i]);
        break;
      case '-m':
      case '--contains':
        setMode('contains', argv[++i]);
        break;
      case '-v':
      case '--verify':
        opts.verify = argv[++i];
        break;
      case '-t':
      case '--threads':
        opts.threads = parseInt(argv[++i], 10);
        break;
      case '-i':
      case '--ignore-case':
        opts.ignoreCase = true;
        break;
      case '-c':
      case '--count':
        opts.count = parseInt(argv[++i], 10);
        break;
      case '--engine':
        opts.engine = argv[++i];
        break;
      case '-h':
      case '--help':
        opts.help = true;
        break;
      default:
        // Bare argument => default to prefix mode.
        if (!opts.target && !a.startsWith('-')) setMode('prefix', a);
    }
  }
  return opts;
}

function printHelp() {
  console.log(`
TRON Vanity Address Generator

Usage:
  tron-vanity --prefix <text> [options]
  tron-vanity --contains <text> [options]
  tron-vanity --suffix <text> [options]

Generate a brand-new TRON wallet whose address contains your chosen text.
Every TRON address starts with "T" and is 34 characters long. You can fix a
readable chunk of it (your "advertising" text) while the rest stays random.
You CANNOT fix all 34 characters at once.

Match modes (pick one):
  -p, --prefix <text>    Address starts with the text, e.g. TRAHN...  (after T)
  -m, --contains <text>  Text appears ANYWHERE in the address
  -s, --suffix <text>    Address ends with the text

Other options:
  -t, --threads <n>      Number of CPU worker threads (default: all cores)
  -i, --ignore-case      Case-insensitive match (faster)
  -c, --count <n>        Stop after finding n addresses (default: 1)
      --engine <e>       Compute engine: wasm (fast, default) or js (fallback)
  -v, --verify <hexkey>  Print the address for a private key (no search).
                         Use this to verify a key from any GPU tool offline.
  -h, --help             Show this help

Examples:
  tron-vanity --prefix RAHN
  tron-vanity --contains ESMAEiL -i      # advertising text anywhere, any case
  tron-vanity --suffix 8888

Notes:
  * Valid characters only (Base58). NOT allowed: 0 (zero), O, I, l.
  * Each extra character is ~58x harder. Long text can take days — that's fine,
    just leave it running; a live ETA is shown.
`);
}

// Count how many Base58 symbols match a target char under the chosen mode.
function matchesForChar(ch, ignoreCase) {
  const t = ignoreCase ? ch.toLowerCase() : ch;
  let n = 0;
  for (const s of BASE58_ALPHABET) {
    if ((ignoreCase ? s.toLowerCase() : s) === t) n++;
  }
  return n;
}

// Average number of attempts needed (expected value of a geometric trial).
function expectedAttempts(mode, target, ignoreCase) {
  // For a prefix that starts with "T", the leading "T" is guaranteed by the
  // 0x41 version byte, so it's free and doesn't add difficulty.
  const constrained =
    mode === 'prefix' && target.startsWith('T') ? target.slice(1) : target;
  let perMatch = 1;
  for (const ch of constrained) {
    const m = matchesForChar(ch, ignoreCase) || 1;
    perMatch *= 58 / m;
  }
  // "contains" can match at many positions in the 34-char address, so it is
  // easier than a fixed-position match of the same length.
  if (mode === 'contains') {
    const positions = Math.max(1, 34 - target.length);
    return perMatch / positions;
  }
  return perMatch;
}

function humanTime(seconds) {
  if (!isFinite(seconds)) return '∞';
  if (seconds < 1) return '< 1s';
  const units = [
    ['y', 31557600],
    ['d', 86400],
    ['h', 3600],
    ['m', 60],
    ['s', 1],
  ];
  const parts = [];
  for (const [label, size] of units) {
    if (seconds >= size) {
      const v = Math.floor(seconds / size);
      seconds -= v * size;
      parts.push(`${v}${label}`);
    }
    if (parts.length === 2) break;
  }
  return parts.join(' ') || '< 1s';
}

function humanNum(n) {
  if (n >= 1e12) return (n / 1e12).toFixed(1) + 'T';
  if (n >= 1e9) return (n / 1e9).toFixed(1) + 'B';
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n >= 1e3) return (n / 1e3).toFixed(1) + 'K';
  return String(Math.round(n));
}

// Derive and print the TRON address for a given private key. Useful to verify,
// fully offline, that a key found by any external tool (e.g. a GPU generator)
// really controls the address it claims — before sending funds to it.
function verifyKey(privHex) {
  const clean = privHex.trim().replace(/^0x/, '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(clean)) {
    console.error('\nError: private key must be 64 hex characters (32 bytes).\n');
    process.exit(1);
  }
  let address;
  try {
    address = publicKeyToAddress(secp.getPublicKey(clean, false));
  } catch (e) {
    console.error(`\nError: invalid private key (${e.message}).\n`);
    process.exit(1);
  }
  console.log(`\nPrivate Key: ${clean}`);
  console.log(`Address:     ${address}\n`);
}

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.verify) {
    verifyKey(opts.verify);
    process.exit(0);
  }
  if (opts.help || !opts.target) {
    printHelp();
    process.exit(opts.help ? 0 : 1);
  }

  if (opts.modeConflict) {
    console.error(
      '\nError: choose only ONE match mode (--prefix, --contains, or --suffix).\n',
    );
    process.exit(1);
  }

  // For prefix mode, every TRON address starts with T, so ensure the prefix
  // does too. Other modes use the text exactly as given.
  let target = opts.target;
  if (opts.mode === 'prefix' && !target.startsWith('T')) target = 'T' + target;

  // Validate characters. For a T-prefix, the leading T is fine; validate the
  // rest. For other modes the whole text must be valid Base58.
  const toValidate =
    opts.mode === 'prefix' && target.startsWith('T') ? target.slice(1) : target;
  if (!isValidBase58(toValidate)) {
    console.error(
      `\nError: the text contains characters that don't exist in TRON addresses.\n` +
        `Not allowed: 0 (zero), O (capital o), I (capital i), l (lowercase L).\n` +
        `Allowed alphabet: ${BASE58_ALPHABET}\n`,
    );
    process.exit(1);
  }

  // Pick the engine: WASM (fast) by default when its kernel is present.
  let engine = opts.engine;
  if (engine !== 'js' && engine !== 'wasm') engine = isWasmAvailable() ? 'wasm' : 'js';
  if (engine === 'wasm' && !isWasmAvailable()) {
    console.error('\nError: WASM kernel not found. Build it or use --engine js.\n');
    process.exit(1);
  }

  const where = { prefix: 'starting with', contains: 'containing', suffix: 'ending with' }[opts.mode];
  const exp = expectedAttempts(opts.mode, target, opts.ignoreCase);
  console.log(`\nSearching for TRON addresses ${where}:  ${target}`);
  console.log(`Engine: ${engine.toUpperCase()} | Mode: ${opts.ignoreCase ? 'case-insensitive' : 'case-sensitive'} | Threads: ${opts.threads} | Target count: ${opts.count}`);
  console.log(`Average attempts needed: ~${humanNum(exp)}\n`);

  const reportEvery = 2000;
  const workers = [];
  let totalAttempts = 0;
  let found = 0;
  const startedAt = Date.now();
  let lastPrint = startedAt;

  const finish = () => {
    for (const w of workers) w.terminate();
    const secs = (Date.now() - startedAt) / 1000;
    process.stdout.write('\n');
    console.log(
      `\nDone. Found ${found} address(es) in ${humanTime(secs)} ` +
        `after ${humanNum(totalAttempts)} attempts.`,
    );
    process.exit(0);
  };

  const printProgress = () => {
    const now = Date.now();
    const secs = (now - startedAt) / 1000;
    const rate = totalAttempts / secs;
    const eta = rate > 0 ? exp / rate : Infinity;
    process.stdout.write(
      `\r  tried ${humanNum(totalAttempts)} | ${humanNum(rate)}/s | avg ETA ${humanTime(eta)}   `,
    );
    lastPrint = now;
  };

  function startWorker() {
    const w = new Worker(path.join(__dirname, 'worker.js'), {
      workerData: { mode: opts.mode, target, ignoreCase: opts.ignoreCase, reportEvery, engine },
    });
    w.on('message', (msg) => {
      if (msg.type === 'progress') {
        totalAttempts += msg.count;
        if (Date.now() - lastPrint > 250) printProgress();
      } else if (msg.type === 'found') {
        totalAttempts += msg.attempts;
        found++;
        process.stdout.write('\n');
        console.log('\n✓ Found a match!');
        console.log(`  Address:     ${msg.address}`);
        console.log(`  Private Key: ${msg.privateKey}`);
        console.log('  → Import this Private Key into TronLink / Trust Wallet.\n');
        if (found >= opts.count) {
          finish();
        } else {
          // Restart this worker to keep searching for more matches.
          w.terminate();
          workers[workers.indexOf(w)] = startWorker();
        }
      }
    });
    w.on('error', (err) => console.error('\nWorker error:', err));
    return w;
  }

  for (let i = 0; i < opts.threads; i++) workers.push(startWorker());

  process.on('SIGINT', () => {
    process.stdout.write('\n');
    console.log('\nStopped by user.');
    finish();
  });
}

main();
