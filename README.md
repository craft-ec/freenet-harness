# freenet-harness

Drives a real Freenet node: deploys contracts, round-trips state, records
timings. Every measured number in `craftworks-docs` comes from here.

    cargo run -- roundtrip --n 3 --size 4096      # put N blocks, read them back
    ./probe-delegate/build.sh && cargo run -- delegate-probe   # what can a delegate do on this node?

## Runbook: running a measurement without voiding it

These are the ways runs from this harness have actually been lost. Each line is
one that happened.

**Run one condition at a time.** A datacentre arm taken while a hotspot arm was
running reported a 1 MiB p50 of 2200 ms; run alone it was 1590 ms, and the
p90 fell from 9352 to 2106. The concurrent load inflated the large sizes most,
which is the direction that makes a big body look worst — and the conclusion
drawn from it was wrong. A contamination you have NOTICED is a run to redo, not
a caveat to write underneath.

**A deferred step must check its inputs when it RUNS.** A chained job copied a
cross-compiled binary to the server and ran it there. Between the chain being
written and the chain running, that binary's directory was deleted in an
unrelated cleanup; the copy failed quietly, and the remote step ran whatever was
already on the host — an older build without the flag the run depended on. Two
truths exist, one at authoring time and one at execution time, and nothing
carries the first into the second. So: assert the file exists, make a failed
transfer ABORT the chain rather than fall through, and where it is cheap verify
the deployed thing has the property being relied on (a flag present in its help
output, a version string, a checksum).

**Say what the instrument can resolve.** Every "time until X was true" here is
polled: ask, wait one bounded attempt, ask again. That is a PERIOD, and anything
happening inside one period is reported at the end of it. Two tables have been
voided this way. `stats::Grid` exists for it — print the resolution above the
table and flag any series whose whole spread fits inside one step.

**Never wait on a stall.** Every attempt has a deadline, every run has a total
budget (`--budget-secs`), and what is not back by then is recorded as `not
within T`. A missing value is a data point. See also the workspace rule of the
same name.

**Keep one built tree per repo, and delete a target dir as soon as its gate is
green.** Four Rust trees plus wasm targets took this machine to 168 MiB free and
killed a tool call mid-run.

## Epoch artefacts for `upgrade-cycle`

`upgrade-cycle` needs two builds of each contract, from two real commits, so a
code upgrade can be demonstrated rather than described. **Neither side is a
fixture** — both are contracts this project has shipped. `build/` is not
tracked, so they are rebuilt rather than committed:

| file | bytes | sha256 | built from |
|---|---|---|---|
| `block-A.wasm` | 118,807 | `21ae7e734d40224d` | freenet-contracts `9bf6845`, before the parity rule |
| `block-B.wasm` | 123,393 | `1521dddb9ecbaa16` | freenet-contracts `201e9bc` |
| `register-A.wasm` | 157,234 | `a3be5ec412ddb6b4` | freenet-contracts `1c3a710`, before the cost counters |
| `register-B.wasm` | 152,430 | `e273be8c6f35a739` | freenet-contracts `201e9bc` |

Build each side in a DETACHED worktree, never by moving the shared checkout —
several sessions work in these folders:

    git -C ../freenet-contracts worktree add --detach /tmp/epoch 9bf6845
    (cd /tmp/epoch && ./block/build.sh && ./register/build.sh)
    mkdir -p build/epochs && cp /tmp/epoch/build/*.wasm build/epochs/
    rm -rf /tmp/epoch/target
    git -C ../freenet-contracts worktree remove --force /tmp/epoch

Then:

    cargo run -- --local upgrade-cycle \
      --sha-block-a 21ae7e73 --sha-block-b 1521dddb \
      --sha-register-a a3be5ec4 --sha-register-b e273be8c --n 100

The run refuses to start if the two hashes on either side are equal: two epochs
with the same code hash are the same epoch, and every "it moved" it prints would
be vacuously true.
