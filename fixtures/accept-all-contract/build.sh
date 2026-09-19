#!/usr/bin/env bash
# Build the measurement fixture to build/accept-all.wasm.
set -euo pipefail
cd "$(dirname "$0")"
cargo build --release --target wasm32-unknown-unknown "$@"
mkdir -p ../../build
cp target/wasm32-unknown-unknown/release/accept_all_contract.wasm ../../build/accept-all.wasm
echo "build/accept-all.wasm $(wc -c < ../../build/accept-all.wasm | tr -d ' ') bytes sha256=$(shasum -a 256 ../../build/accept-all.wasm | cut -c1-16)"
