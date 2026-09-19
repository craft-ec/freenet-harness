#!/usr/bin/env bash
# Build the validation-cost fixture to build/validate-cost.wasm.
set -euo pipefail
cd "$(dirname "$0")"
cargo build --release --target wasm32-unknown-unknown "$@"
mkdir -p ../../build
cp target/wasm32-unknown-unknown/release/validate_cost_contract.wasm ../../build/validate-cost.wasm
echo "build/validate-cost.wasm $(wc -c < ../../build/validate-cost.wasm | tr -d ' ') bytes sha256=$(shasum -a 256 ../../build/validate-cost.wasm | cut -c1-16)"
