#!/usr/bin/env bash
# Two builds: base (contract GET only) and wakeup (also imports the wakeup host fn).
set -euo pipefail
cd "$(dirname "$0")"
out=target/wasm32-unknown-unknown/release/freenet_probe_delegate.wasm
mkdir -p ../build
cargo build --release --target wasm32-unknown-unknown
cp $out ../build/probe.wasm
cargo build --release --target wasm32-unknown-unknown --features wakeup
cp $out ../build/probe-wakeup.wasm
ls -l ../build/*.wasm | awk '{print $NF, $5" B"}'
