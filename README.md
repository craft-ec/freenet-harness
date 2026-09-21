# freenet-harness

Drives a real Freenet node: deploys contracts, round-trips state, records
timings. Every measured number in `craftworks-docs` comes from here.

    WS='ws://127.0.0.1:<your node's port>/v1/contract/command?encodingProtocol=native'
    cargo run -- --ws "$WS" roundtrip --n 3 --size 4096      # put N blocks, read them back
    ./probe-delegate/build.sh && cargo run -- --ws "$WS" delegate-probe   # what can a delegate do on this node?

**Every run names its node with `--ws`. There is no default**, and ports 7509
and 7609 — the owner's nodes — are refused on any host, before a socket opens
(freenet-harness#45). `--local` only LABELS the node at `--ws` as local-mode;
it never changes where the socket goes. `kill9` starts its own node and
refuses both flags.

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

**A blocked SEND is this harness, not the node.** A reader probing 200 cold
keys sent a GET for every one of them before reading anything. A GET for a key
no node holds is never answered, so nothing drained, the socket backpressured,
and the run's only output was "the node stopped accepting requests" — about a
node that was serving perfectly well. Probes go out in bounded rounds now, and
the message names what the caller had not drained. Before writing that a node
refused anything, show the harness was still collecting.

**A polled instrument's resolution is its ROUND, not its probe period.** When
the reader rotates 32 keys per round, a run of 200 keys resolves a first-read
to `ceil(200/32) x probe_ms`, which at 250 ms is 1750 ms and not 250. It is
printed above the table, and `pair` flags any series whose whole spread fits
inside one step. Choosing how many keys a run carries is therefore choosing its
resolution as well as its population — say which one you traded.

**A run that prints nothing until it ends cannot be told from a wedged one.**
Seventy seconds into a 25-minute put run, `grep -c '^PUT'` returned 0, because
that role reported nothing until its final phase. Per-trial progress and a 30 s
heartbeat, always.

**Kill by the PID you recorded at launch, never by a name pattern.** Stopping a
run with `ps aux | grep "[f]reenet-harness" | awk '{print $2}' | xargs kill`
also killed another session's `freenet-harness-ro` — a superstring of the name
— and that session lost two live measurements. The process list being killed
from had their PIDs in it, printed two lines above. If a pattern is
unavoidable, carry your own run's unique argument and PRINT what it matched
before killing anything.

**Keep one built tree per repo, and delete a target dir as soon as its gate is
green.** Four Rust trees plus wasm targets took this machine to 168 MiB free and
killed a tool call mid-run.

## `latency`: the put/get ladder, per contract kind

    cargo run --release -- --local --ws "$WS" latency \
      --kinds Register,Set,Bag \
      --expect-sha Register=e273be8c6f35a739,Set=688cb0c656a7ec3d,Bag=32e10cd6131eb3c5 \
      --only series --samples 30 --budget-secs 900

`--wasm` names the Block artefact; the other three are taken from the same
directory, because one `freenet-contracts/build.sh` writes all four and a second
path could only ever disagree with it.

**`--expect-sha` is `<kind>=<sha256 prefix>`, and every measured kind needs
one.** Four contracts is four chances to time a build nobody ships, and a run
with no check and a run whose check passed print the same table.

**`--only series` is parts 1 and 2 and nothing else.** `--only put` and
`--only get` both RUN the ladder — a get needs a put — and differ only in which
table they print, so asking for both would mean two runs over two different
populations. Parts 3 to 6 all measure Block specifically and say SKIPPED when
`--kinds` does not name it.

**Every kind has a ceiling, and it is the contract's.** A Register holds one
value (`MAX_VALUE`, 4 KiB); a Set keeps `MAX_M` slots of `MAX_PAYLOAD`; a Bag
keeps `M` pointers. A size above the ceiling is reported under the table as not
measured, with the limit that refused it — a row silently missing from a ladder
reads as a measurement that failed.

**The table has a `body` column and a `state` column, and they are different
numbers.** A 4 KiB body is 4242 B of Register state and 6040 B of Set state:
comparing "PUT 4 KiB" across kinds without the second column compares four
different weights.

**The Bag fixture mines at `work_bits = 0`.** The price of a name is the Bag's
own cost and the CLIENT pays it, so mining inside the timed section would put
this machine's CPU inside a latency the table attributes to the network.

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

    cargo run -- --local --ws "$WS" upgrade-cycle \
      --sha-block-a 21ae7e73 --sha-block-b 1521dddb \
      --sha-register-a a3be5ec4 --sha-register-b e273be8c --n 100

The run refuses to start if the two hashes on either side are equal: two epochs
with the same code hash are the same epoch, and every "it moved" it prints would
be vacuously true.
