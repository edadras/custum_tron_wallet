#!/usr/bin/env bash
# Build the Rust WASM search kernel and copy it next to the JS engine.
# Requires the Rust toolchain (https://rustup.rs) with the wasm32 target.
set -euo pipefail

cd "$(dirname "$0")"

# Ensure the wasm32 target is installed (no-op if already present).
rustup target add wasm32-unknown-unknown >/dev/null 2>&1 || true

cargo build --release --target wasm32-unknown-unknown

mkdir -p ../src/wasm
cp target/wasm32-unknown-unknown/release/tron_vanity_wasm.wasm ../src/wasm/kernel.wasm
echo "Built src/wasm/kernel.wasm"
