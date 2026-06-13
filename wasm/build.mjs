// Cross-platform build for the Rust WASM search kernel (works on Windows too).
// Requires the Rust toolchain (https://rustup.rs) with the wasm32 target.
import { execSync } from 'node:child_process';
import { copyFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const dir = path.dirname(fileURLToPath(import.meta.url));

// Ensure the wasm32 target is installed (ignore errors if already present).
try {
  execSync('rustup target add wasm32-unknown-unknown', { stdio: 'ignore' });
} catch {
  /* rustup may be unavailable; cargo will report a clearer error below. */
}

execSync('cargo build --release --target wasm32-unknown-unknown', {
  cwd: dir,
  stdio: 'inherit',
});

const built = path.join(dir, 'target', 'wasm32-unknown-unknown', 'release', 'tron_vanity_wasm.wasm');
const dest = path.join(dir, '..', 'src', 'wasm', 'kernel.wasm');
mkdirSync(path.dirname(dest), { recursive: true });
copyFileSync(built, dest);
console.log('Built src/wasm/kernel.wasm');
