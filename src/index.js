#!/usr/bin/env node
// Vanity TRON address generator — CLI entry point.
import os from 'node:os';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import { Worker } from 'node:worker_threads';
import { BASE58_ALPHABET, isValidBase58 } from './tron.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function parseArgs(argv) {
  const opts = {
    prefix: null,
    threads: Math.max(1, os.cpus().length),
    ignoreCase: false,
    count: 1,
    help: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '-p':
      case '--prefix':
        opts.prefix = argv[++i];
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
      case '-h':
      case '--help':
        opts.help = true;
        break;
      default:
        if (!opts.prefix && !a.startsWith('-')) opts.prefix = a;
    }
  }
  return opts;
}

function printHelp() {
  console.log(`
TRON Vanity Address Generator

Usage:
  tron-vanity --prefix <text> [options]
  npm start -- --prefix <text> [options]

The generated address always starts with "T". Your text is matched right after
it, so --prefix RAHN finds addresses like  TRAHN...  (you may also pass the
leading T yourself, e.g. --prefix TRAHN).

Options:
  -p, --prefix <text>   Text the address should start with (required)
  -t, --threads <n>     Number of CPU worker threads (default: all cores)
  -i, --ignore-case     Case-insensitive match (much faster)
  -c, --count <n>       Stop after finding n addresses (default: 1)
  -h, --help            Show this help

Notes:
  * Valid characters only (Base58). NOT allowed: 0 (zero), O, I, l.
  * Each extra character is ~58x harder. 4-5 chars: fast. 6: hours. 7+: very slow.
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
function expectedAttempts(prefix, ignoreCase) {
  // The leading "T" is guaranteed by the 0x41 version byte, so it's free.
  const constrained = prefix.startsWith('T') ? prefix.slice(1) : prefix;
  let attempts = 1;
  for (const ch of constrained) {
    const m = matchesForChar(ch, ignoreCase) || 1;
    attempts *= 58 / m;
  }
  return attempts;
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

async function main() {
  const opts = parseArgs(process.argv.slice(2));
  if (opts.help || !opts.prefix) {
    printHelp();
    process.exit(opts.help ? 0 : 1);
  }

  // Normalise: every TRON address starts with T, so ensure the prefix does too.
  let prefix = opts.prefix;
  if (!prefix.startsWith('T')) prefix = 'T' + prefix;

  // Validate characters (skip the leading T which we just ensured).
  const rest = prefix.slice(1);
  if (!isValidBase58(rest)) {
    console.error(
      `\nError: the text contains characters that don't exist in TRON addresses.\n` +
        `Not allowed: 0 (zero), O (capital o), I (capital i), l (lowercase L).\n` +
        `Allowed alphabet: ${BASE58_ALPHABET}\n`,
    );
    process.exit(1);
  }

  const exp = expectedAttempts(prefix, opts.ignoreCase);
  console.log(`\nSearching for TRON addresses starting with:  ${prefix}`);
  console.log(`Mode: ${opts.ignoreCase ? 'case-insensitive' : 'case-sensitive'} | Threads: ${opts.threads} | Target count: ${opts.count}`);
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
      workerData: { prefix, ignoreCase: opts.ignoreCase, reportEvery },
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
