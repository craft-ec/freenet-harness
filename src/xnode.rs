//! `xnode`: how long until a block written on one node is readable on another?
//!
//! WORKAROUND(freenet-core#5446): this module never gates on a PUT
//! acknowledgement. The relay's flat 60 s downstream wait lands on roughly one
//! put in 10-50, so waiting for every ack costs minutes per run for
//! information a bounded read-back gives in ~200 ms. See
//! craftworks-docs/docs/WORKAROUNDS.md (W1).
//!
//! WHEN THE UPSTREAM FIX SHIPS: the read-back gate STAYS — it is a stronger
//! statement than the ack (the node can SERVE the block, not merely that the
//! operation finished) and it is what makes `--local` runs finish in seconds.
//! Parallel puts STAY: a batch should pay any tail once, not N times.
//! `--local` STAYS: functional round-trips have no business on the network.
//! What GOES is the 90 s ack-collection deadline and the "acks collected M/N"
//! column, which exist only to measure a tail we expect to disappear.
//!
//! Local readability (#6) is a property of the writer. This is the number the
//! write design actually needs: when can a DIFFERENT node serve the block.
//!
//! Two roles on two machines, so two clocks. Timestamps are absolute
//! (`UNIX_EPOCH` nanos) and the offset between the clocks is measured
//! separately and reported beside the table rather than assumed to be zero —
//! a cross-machine duration computed from two unsynchronised clocks is not a
//! measurement, it is a subtraction.
//!
//! The reader's positive control is mandatory and runs first: a bounded GET
//! that must FAIL before the write proves the key really is cold. Without it,
//! "readable at +0 ms" cannot be distinguished from "this node already had it".

use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, bail, Result};
use craftec_block_contract as block;
use freenet_stdlib::{
    client_api::{ClientRequest, ContractRequest, ContractResponse, HostResponse, WebApi},
    prelude::*,
};
use tokio::time::timeout;

use crate::{
    latency::{ms_since, progress_pub, send_req},
    stats::{kib, Grid, Summary, Table},
};

fn now_ns() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// The body for a given seed and size — deterministic, so a mint file needs
/// to carry only the 16-byte seed rather than the whole state.
///
/// Storing the state as hex made a 21-block file 3.9 MB, most of it three
/// 256 KiB bodies written twice over. The seed reproduces the same bytes on
/// both phases at 32 characters.
fn body_from_seed(seed: &[u8; 16], size: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(size);
    let mut counter: u64 = 0;
    while out.len() < size {
        let mut h = blake3::Hasher::new();
        h.update(seed);
        h.update(&counter.to_le_bytes());
        out.extend_from_slice(h.finalize().as_bytes());
        counter += 1;
    }
    out.truncate(size);
    out
}

/// Mint a Block whose key nothing has seen: the body is derived from a fresh
/// random seed, so the key is a fresh hash. This is the writer's whole
/// contribution to "cold".
fn mint(code: &Arc<ContractCode<'static>>, size: usize) -> Result<(ContractContainer, Vec<u8>)> {
    let mut seed = [0u8; 16];
    getrandom::getrandom(&mut seed)?;
    let body = body_from_seed(&seed, size);
    let state = block::encode(block::kind::RAW, &body);
    let params = Parameters::from(blake3::hash(&state).as_bytes().to_vec());
    Ok((
        ContractContainer::Wasm(ContractWasmAPIVersion::V1(WrappedContract::new(
            code.clone(),
            params,
        ))),
        state,
    ))
}

/// MINT: compute the keys WITHOUT putting anything.
///
/// A Block's key is `hash(code, blake3(state))`, so it is knowable before the
/// put. That removes the race that makes a naive cross-node measurement
/// meaningless: if the reader only learns the key AFTER the write, the key
/// must travel over the same link the block is propagating on, and the block
/// wins. Minting first lets the reader prove the key is cold and be already
/// polling when the write happens.
pub async fn mint_only(
    wasm: &str,
    samples: usize,
    sizes: &[usize],
    out: &str,
    arms: bool,
) -> Result<()> {
    let code = Arc::new(ContractCode::from(std::fs::read(wasm).map_err(|e| {
        anyhow!("{wasm}: {e} — run ../freenet-contracts/build.sh first")
    })?));
    let mut f = String::new();
    let mut n = 0usize;
    for &size in sizes {
        for _ in 0..samples {
            // Interleaved, not blocked: two arms run one after the other are
            // two runs under two sets of conditions, and on a hotspot the
            // conditions are the thing that moves.
            let arm = if arms && n % 2 == 1 {
                Arm::Hedge
            } else {
                Arm::Control
            };
            n += 1;
            let mut seed = [0u8; 16];
            getrandom::getrandom(&mut seed)?;
            let body = body_from_seed(&seed, size);
            let state = block::encode(block::kind::RAW, &body);
            let params = Parameters::from(blake3::hash(&state).as_bytes().to_vec());
            let key = ContractContainer::Wasm(ContractWasmAPIVersion::V1(WrappedContract::new(
                code.clone(),
                params,
            )))
            .key();
            // key, body size, seed, arm — the put phase regenerates identical
            // bytes and inherits the assignment rather than making one.
            f.push_str(&format!(
                "MINT {} {} {} {}\n",
                key.id(),
                size,
                seed.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                arm.as_str()
            ));
        }
    }
    std::fs::write(out, f)?;
    println!(
        "# minted {} blocks to {out} (nothing put yet){}",
        samples * sizes.len(),
        if arms {
            ", interleaved control/hedge"
        } else {
            ", all control"
        }
    );
    Ok(())
}

/// PUT the blocks a previous `mint` produced, confirming each by READ-BACK
/// rather than by waiting for its acknowledgement.
///
/// The ack is not a usable gate: the relay's flat 60 s wait (F20) lands on
/// roughly one put in 10-50, so a run that waits for every ack pays that tail
/// repeatedly for information it already has. A block is readable on the
/// accepting node about 60 ms after the put is sent (F22), so read-back is
/// both faster and a stronger statement — it says the node can SERVE the
/// block, where the ack only says the operation finished.
///
/// The ack is still collected, on its own connection-draining pass with its
/// own deadline, and reported as its own column. Not measuring it would trade
/// one blind spot for another.
pub async fn put_minted(
    ws: &str,
    wasm: &str,
    minted: &str,
    hedge: Option<Duration>,
    until_conditioned: usize,
    wait: Duration,
) -> Result<()> {
    let code = Arc::new(ContractCode::from(std::fs::read(wasm)?));
    let text = std::fs::read_to_string(minted)
        .map_err(|e| anyhow!("{minted}: {e} — run the mint role first"))?;
    let mut writer = crate::connect(ws).await?;
    // A second connection, so a read-back cannot be answered by the put's own
    // reply arriving on the same socket.
    let mut confirm = crate::connect(ws).await?;

    /// One trial's whole life, so the loop below has one place to look.
    struct T {
        key: ContractKey,
        size: usize,
        seed: [u8; 16],
        arm: Arm,
        sent_ns: u128,
        t0: std::time::Instant,
        ack_ms: Option<f64>,
        confirm_ms: Option<f64>,
        unacked_at_t: Option<bool>,
        hedged: bool,
        marked: bool,
    }

    // The plan: what to send, in order. Nothing is sent here.
    //
    // Sending every put BEFORE the loop starts — which is what this role used
    // to do — makes the hedge unusable at scale. A hedge fires T after its own
    // trial's send, and the loop that fires it cannot run until the last send
    // returns: on a hotspot uplink, 200 puts of ~127 KiB each take minutes, so
    // trial 1's hedge would fire minutes after its T rather than at it, and
    // the "T" in the table would be a number nothing obeyed. The sends are now
    // issued BY the loop, one per pass, so each trial's clock starts when its
    // own bytes go out and the hedges keep their timing.
    let mut plan: Vec<([u8; 16], usize, Arm)> = Vec::new();
    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        if f.first() != Some(&"MINT") || f.len() < 4 {
            continue;
        }
        let size: usize = f[2].parse().unwrap_or(0);
        let mut seed = [0u8; 16];
        for (i, b) in seed.iter_mut().enumerate() {
            *b = u8::from_str_radix(&f[3][i * 2..i * 2 + 2], 16).unwrap_or(0);
        }
        plan.push((
            seed,
            size,
            f.get(4).map(|a| Arm::parse(a)).unwrap_or(Arm::Control),
        ));
    }
    let expected = plan.len();
    let mut trials: Vec<T> = Vec::with_capacity(expected);
    let mut to_send = 0usize;
    let mut last_beat = std::time::Instant::now();

    // Phase 2: ONE loop for the three things that are all happening at once —
    // acknowledgements arriving, the hedge's instant coming round, and the
    // local read-back. Two loops would mean a hedge that cannot fire while a
    // read-back is waiting, which is a hedge timed by whatever else the loop
    // was doing rather than by T.
    // The caller's `--timeout-secs` IS the budget for this role, not a floor
    // under a hidden cap: with the sends inside the loop, a 180 s ceiling
    // would stop a 200-trial run a third of the way through and report the
    // rest as unsent. Every run states its budget on the command line.
    let budget = std::time::Instant::now() + wait;
    let mut hedged_bytes = 0usize;
    let mut next = 0usize;
    while std::time::Instant::now() < budget {
        // One send per pass, so a trial's clock starts when its own bytes go
        // out and every hedge below is timed from that instant.
        if to_send < plan.len() {
            let (seed, size, arm) = plan[to_send];
            to_send += 1;
            let state = block::encode(block::kind::RAW, &body_from_seed(&seed, size));
            let params = Parameters::from(blake3::hash(&state).as_bytes().to_vec());
            let contract = ContractContainer::Wasm(ContractWasmAPIVersion::V1(
                WrappedContract::new(code.clone(), params),
            ));
            let key = contract.key();
            let sent_ns = now_ns();
            let t0 = std::time::Instant::now();
            send_req(
                &mut writer,
                ClientRequest::ContractOp(ContractRequest::Put {
                    contract,
                    state: WrappedState::from(state.clone()),
                    related_contracts: RelatedContracts::default(),
                    subscribe: false,
                    blocking_subscribe: false,
                }),
                Duration::from_secs(60),
            )
            .await?;
            progress_pub(format_args!(
                "  sent {}/{} {} {}",
                trials.len() + 1,
                plan.len(),
                arm.as_str(),
                key.id()
            ));
            trials.push(T {
                key,
                size,
                seed,
                arm,
                sent_ns,
                t0,
                ack_ms: None,
                confirm_ms: None,
                unacked_at_t: None,
                hedged: false,
                marked: hedge.is_none(),
            });
        }

        // Acknowledgements first: they are what the hedge decision reads, and
        // an ack sitting unread in the socket is a hedge fired for nothing.
        while let Ok(Ok(msg)) = timeout(Duration::from_millis(0), writer.recv()).await {
            if let HostResponse::ContractResponse(ContractResponse::PutResponse { key: k }) = msg {
                if let Some(t) = trials.iter_mut().find(|t| t.key.id() == k.id()) {
                    if t.ack_ms.is_none() {
                        t.ack_ms = Some(ms_since(t.t0));
                    }
                }
            }
        }

        // The mark is taken in BOTH arms at each trial's own T, so "still
        // unacknowledged at T" means the same thing on each side of the
        // comparison. Only the hedge arm acts on it.
        if let Some(d) = hedge {
            let now = std::time::Instant::now();
            // By index, and `trials` is borrowed mutably inside: the body
            // both reads a trial's state and awaits a send, which an iterator
            // over `&mut` cannot do while the loop also reads `code`.
            #[allow(clippy::needless_range_loop)]
            for i in 0..trials.len() {
                if trials[i].marked || now < trials[i].t0 + d {
                    continue;
                }
                trials[i].marked = true;
                let still = trials[i].ack_ms.is_none();
                trials[i].unacked_at_t = Some(still);
                if still && trials[i].arm == Arm::Hedge {
                    // The SAME bytes under the SAME key: re-putting an
                    // immutable block is idempotent, so this is a second offer
                    // of one block and not a new block.
                    let state = block::encode(
                        block::kind::RAW,
                        &body_from_seed(&trials[i].seed, trials[i].size),
                    );
                    let params = Parameters::from(blake3::hash(&state).as_bytes().to_vec());
                    let same = ContractContainer::Wasm(ContractWasmAPIVersion::V1(
                        WrappedContract::new(code.clone(), params),
                    ));
                    send_req(
                        &mut writer,
                        ClientRequest::ContractOp(ContractRequest::Put {
                            contract: same,
                            state: WrappedState::from(state.clone()),
                            related_contracts: RelatedContracts::default(),
                            subscribe: false,
                            blocking_subscribe: false,
                        }),
                        Duration::from_secs(60),
                    )
                    .await?;
                    trials[i].hedged = true;
                    // The whole PUT, not the body: a relay forwards the
                    // contract container at every hop, so ~120 KiB of wasm
                    // (F28) rides with every re-put and it is the dominant
                    // term. Counting only the state reported 180 KiB for a
                    // trade that actually cost about 5.7 MB.
                    hedged_bytes += state.len() + code.data().len();
                    progress_pub(format_args!(
                        "  hedged {} at T ({} of {} sent so far)",
                        trials[i].key.id(),
                        i + 1,
                        plan.len()
                    ));
                }
            }
        }

        // One read-back attempt per pass, round-robin over the trials that do
        // not have one yet, so no single slow key stalls the others' hedges.
        let mut looked = 0usize;
        while looked < trials.len() && !trials.is_empty() {
            let i = next % trials.len();
            next += 1;
            looked += 1;
            if trials[i].confirm_ms.is_none() {
                if probe_once(
                    &mut confirm,
                    trials[i].key.id(),
                    false,
                    Duration::from_millis(200),
                )
                .await?
                .is_some()
                {
                    trials[i].confirm_ms = Some(ms_since(trials[i].t0));
                }
                break;
            }
        }

        // A heartbeat, because a run that prints nothing until phase 3 is
        // indistinguishable from a wedged one — `grep -c '^PUT'` returned 0
        // seventy seconds into a 25-minute run, and that told nobody anything.
        if last_beat.elapsed() >= Duration::from_secs(30) {
            last_beat = std::time::Instant::now();
            progress_pub(format_args!(
                "  {} sent, {} acked, {} readable here, {} hedged, conditioned {}c/{}h \
                 of {until_conditioned}",
                trials.len(),
                trials.iter().filter(|t| t.ack_ms.is_some()).count(),
                trials.iter().filter(|t| t.confirm_ms.is_some()).count(),
                trials.iter().filter(|t| t.hedged).count(),
                trials
                    .iter()
                    .filter(|t| t.arm == Arm::Control && t.unacked_at_t == Some(true))
                    .count(),
                trials
                    .iter()
                    .filter(|t| t.arm == Arm::Hedge && t.unacked_at_t == Some(true))
                    .count()
            ));
        }

        // The MILESTONE, not the clock.
        //
        // What this run needs is a conditioned population — trials still
        // unacknowledged at T, in BOTH arms — because that is the only
        // comparison worth printing. So it stops when it HAS that, and `wait`
        // is a backstop set far beyond rather than the thing being waited on.
        // A duration ends a healthy run early and lets a barren one burn the
        // whole budget.
        let conditioned = |arm: Arm| {
            trials
                .iter()
                .filter(|t| t.arm == arm && t.unacked_at_t == Some(true))
                .count()
        };
        if until_conditioned > 0
            && conditioned(Arm::Control) >= until_conditioned
            && conditioned(Arm::Hedge) >= until_conditioned
        {
            progress_pub(format_args!(
                "  milestone: {until_conditioned} conditioned in each arm ({} control, {} \
                 hedge) after {} of {} trials — stopping, the comparison has what it needs",
                conditioned(Arm::Control),
                conditioned(Arm::Hedge),
                trials.len(),
                plan.len()
            ));
            break;
        }

        let done = to_send == plan.len()
            && trials
                .iter()
                .all(|t| t.confirm_ms.is_some() && t.ack_ms.is_some() && t.marked);
        if done {
            break;
        }
    }

    // Phase 3: one line per trial, with everything the pairing needs.
    let mut confirmed_n = 0usize;
    for t in &trials {
        match t.confirm_ms {
            Some(ms) => {
                confirmed_n += 1;
                println!(
                    "PUT {} {} {:.1} {} {} {} {} {}",
                    t.key.id(),
                    t.sent_ns,
                    ms,
                    t.size,
                    t.arm.as_str(),
                    match t.unacked_at_t {
                        Some(true) => "unacked",
                        Some(false) => "acked",
                        None => "-",
                    },
                    if t.hedged { "hedged" } else { "-" },
                    t.ack_ms.map(|a| format!("{a:.1}")).unwrap_or("-".into()),
                );
            }
            None => println!(
                "# not readable on the writer within the budget: {}",
                t.key.id()
            ),
        }
    }

    if let Err(e) = stimulus_ok(expected, trials.len(), confirmed_n) {
        bail!("{e}");
    }

    let acked = trials.iter().filter(|t| t.ack_ms.is_some()).count();
    let fired = trials.iter().filter(|t| t.hedged).count();
    let eligible = trials.iter().filter(|t| t.arm == Arm::Hedge).count();
    println!(
        "# stimulus: {} sent, {} read-back confirmed, {} acks collected (the rest are the \
         relay tail, not failures)",
        trials.len(),
        confirmed_n,
        acked
    );
    if let Some(d) = hedge {
        println!(
            "# hedge: T={:.1}s, fired on {fired} of {eligible} hedge-arm trials, {} KiB re-sent \
             (state AND the contract code that rides every PUT — the code is the dominant term)",
            d.as_secs_f64(),
            hedged_bytes / 1024
        );
    }
    let _ = writer.send(ClientRequest::Disconnect { cause: None }).await;
    let _ = confirm
        .send(ClientRequest::Disconnect { cause: None })
        .await;
    Ok(())
}

/// WRITER: put `samples` fresh blocks per size/// WRITER: put `samples` fresh blocks per size, emitting one machine-readable
/// line per block so the reader side can be driven from it.
pub async fn write(
    ws: &str,
    wasm: &str,
    samples: usize,
    sizes: &[usize],
    wait: Duration,
) -> Result<()> {
    let code = Arc::new(ContractCode::from(std::fs::read(wasm).map_err(|e| {
        anyhow!("{wasm}: {e} — run ../freenet-contracts/build.sh first")
    })?));
    let mut client = crate::connect(ws).await?;
    println!("# role=write node={ws}");
    for &size in sizes {
        for _ in 0..samples {
            let (contract, state) = mint(&code, size)?;
            let key = contract.key();
            let t_send = now_ns();
            let t = std::time::Instant::now();
            send_req(
                &mut client,
                ClientRequest::ContractOp(ContractRequest::Put {
                    contract,
                    state: WrappedState::from(state.clone()),
                    related_contracts: RelatedContracts::default(),
                    subscribe: false,
                    blocking_subscribe: false,
                }),
                wait,
            )
            .await?;
            let ack = match timeout(wait, client.recv()).await {
                Ok(Ok(HostResponse::ContractResponse(ContractResponse::PutResponse {
                    key: k,
                }))) if k == key => format!("{:.1}", ms_since(t)),
                other => {
                    println!("# put failed for {}: {other:?}", key.id());
                    continue;
                }
            };
            // One line per block: key, absolute send time, ack ms, state size.
            println!("PUT {} {} {} {}", key.id(), t_send, ack, state.len());
        }
    }
    let _ = client.send(ClientRequest::Disconnect { cause: None }).await;
    Ok(())
}

/// READER: for each key, prove it is absent, then poll until it is readable.
pub async fn read(
    ws: &str,
    keys_file: &str,
    return_code: bool,
    probe_ms: u64,
    limit_secs: u64,
) -> Result<()> {
    let text = std::fs::read_to_string(keys_file)
        .map_err(|e| anyhow!("{keys_file}: {e} — run the write role first"))?;
    let mut client = crate::connect(ws).await?;
    println!("# role=read node={ws} return_contract_code={return_code}");
    // Two phases, and the split is the whole correctness of this role.
    //
    // Polling key-by-key makes each key's "first readable" time depend on how
    // long the PREVIOUS keys were polled for — with a 60 s bound per key the
    // last key in a list of 60 is first probed an hour late, and the number
    // reported is reader queueing, not propagation. So: control every key
    // first (one bounded probe each, fast), then ROUND-ROBIN the cold ones so
    // every key is re-probed on the same cadence.
    let mut pending: Vec<(String, ContractInstanceId, u128, String)> = Vec::new();
    let mut warm_at_start = 0usize;
    // The control pass had no deadline at all: 240 bounded probes is a minute
    // on a good day and unbounded on a bad one, before the run's own limit had
    // been consulted once.
    let started = std::time::Instant::now();
    let deadline = started + Duration::from_secs(limit_secs);
    for line in text.lines() {
        if std::time::Instant::now() >= deadline {
            bail!(
                "the {limit_secs} s limit ran out during the COLD CONTROL, with {} of the keys \
                 checked. No key was proved cold, so nothing this run could measure would mean \
                 anything.",
                pending.len() + warm_at_start
            );
        }
        let f: Vec<&str> = line.split_whitespace().collect();
        // Accept both shapes: PUT lines carry the send time, MINT lines do
        // not exist yet on the network at all (t_send filled in later by the
        // caller pairing the two files).
        let (id_s, t_send, size) = match f.first() {
            Some(&"PUT") if f.len() >= 5 => (f[1], f[2].parse::<u128>().unwrap_or(0), f[4]),
            Some(&"MINT") if f.len() >= 3 => (f[1], 0u128, f[2]),
            _ => continue,
        };
        let id =
            ContractInstanceId::try_from(id_s.to_string()).map_err(|e| anyhow!("{id_s}: {e}"))?;
        if probe_once(
            &mut client,
            &id,
            return_code,
            Duration::from_millis(probe_ms),
        )
        .await?
        .is_some()
        {
            warm_at_start += 1;
            println!("VOID {id_s} {size} already readable before polling — not a cold key");
        } else {
            pending.push((id_s.to_string(), id, t_send, size.to_string()));
        }
    }
    let cold_confirmed = pending.len();
    println!("# control done: {cold_confirmed} cold, {warm_at_start} already readable");

    // Probe in BOUNDED rounds, then drain and match by key.
    //
    // Two failures have to be avoided at once, and the obvious fix for each is
    // the other one's bug:
    //
    //  - Send-then-wait per key does not work: an abandoned response is never
    //    consumed, the unread replies backpressure the socket, and the next
    //    send blocks forever.
    //  - Probing EVERY pending key in one burst does not work either, and this
    //    is the one that killed a 200-key run: a GET for a key no node has yet
    //    may never be answered at all, so the outstanding requests only grow,
    //    the socket backpressures, and `send_req` trips its bound. It surfaces
    //    as "the node stopped accepting requests" while the node is healthy —
    //    the harness had stopped collecting.
    //
    // So a round probes at most [`BURST`] keys and rotates through the rest.
    // That bounds what can be outstanding at any instant by something that
    // does not depend on how many keys the run has — at the price of
    // resolution, which the run PRINTS rather than leaves to be discovered: a
    // key's first-readable time is resolved to a full cycle, not to one probe
    // period.
    let mut first_reads = Vec::new();
    let rounds_per_cycle = pending.len().div_ceil(BURST).max(1);
    println!(
        "# probe grid: one probe at a time, up to {} ms each, {BURST} keys per round, \
         {rounds_per_cycle} round(s) per cycle — a first-readable time is resolved to about \
         {} ms, which is what a key waits between two looks at it",
        PROBE_ONE.as_millis(),
        rounds_per_cycle as u128 * BURST as u128 * PROBE_ONE.as_millis()
    );
    let mut cursor = 0usize;
    let mut rounds = 0usize;
    let mut sends = 0usize;
    // A heartbeat, because in the case this loop is hardest on — every key
    // cold, so no READ line will ever be printed — it otherwise produces NO
    // output at all. A wedged reader and a working one then look identical
    // from outside, which is exactly what happened: 65 minutes of nothing,
    // indistinguishable from 65 minutes of work. Progress has to be visible
    // before anything can watch for it.
    let mut last_beat = std::time::Instant::now();
    while !pending.is_empty() && std::time::Instant::now() < deadline {
        // ONE probe at a time, send then read — the only pattern with any
        // evidence behind it.
        //
        // The batched form (send N, then drain) blocked its send at probe 3 of
        // a round, then 13, then 8, then 27, then 14. Batching was tried three
        // ways — a cap on outstanding requests, a cancel-and-reconnect, a fresh
        // socket per round — and every one of them still died, at 1,900 then
        // 2,432 then 7,904 probes. Those looked like a progression and are not:
        // the same binary later died in its FIRST round, so the failure is
        // non-deterministic and single runs of it measure nothing. The
        // difference between those numbers was noise I read as a slope.
        //
        // What has never failed is this: the cold control pass above sends one
        // probe, waits for its answer, and walks all 240 keys — in every run
        // today, including the ones that died seconds later in the batched
        // loop. So the rounds use the control pass's own call.
        //
        // It costs a bounded wait per key rather than per round, so the cycle
        // is `keys x PROBE_ONE` and the run PRINTS that. A first-readable time
        // is resolved to a cycle. This is slower than the batched form was
        // supposed to be, and it is the form that finishes.
        let mut seen: Vec<ContractInstanceId> = Vec::new();
        let n = BURST.min(pending.len());
        for step in 0..n {
            if std::time::Instant::now() >= deadline {
                break;
            }
            let (_, id, _, _) = &pending[(cursor + step) % pending.len()];
            if probe_once(&mut client, id, return_code, PROBE_ONE)
                .await?
                .is_some()
            {
                seen.push(*id);
            }
        }
        cursor = (cursor + n) % pending.len();
        rounds += 1;
        sends += n;
        if last_beat.elapsed() >= Duration::from_secs(5) {
            last_beat = std::time::Instant::now();
            println!(
                "# alive: round {rounds}, {sends} probes sent, {} read, {} still cold, \
                 {:.0} s of {limit_secs}",
                first_reads.len(),
                pending.len(),
                started.elapsed().as_secs_f64()
            );
            use std::io::Write as _;
            let _ = std::io::stdout().flush();
        }
        let hit_at = now_ns();
        let mut still = Vec::with_capacity(pending.len());
        for (id_s, id, t_send, size) in pending.into_iter() {
            if seen.contains(&id) {
                let delta_ms = (hit_at.saturating_sub(t_send)) as f64 / 1e6;
                first_reads.push(delta_ms);
                println!("READ {id_s} {size} {delta_ms:.1}");
            } else {
                still.push((id_s, id, t_send, size));
            }
        }
        pending = still;
    }
    let ran_out = std::time::Instant::now() >= deadline;
    for (id_s, _, _, size) in &pending {
        println!("MISS {id_s} {size} not readable within {limit_secs} s");
    }
    println!(
        "# stopped after {:.0} s because {}",
        started.elapsed().as_secs_f64(),
        if ran_out {
            "the run reached its limit — the MISSes above are 'not within the limit', NOT 'never'"
        } else {
            "every key had been read"
        }
    );
    let _ = client.send(ClientRequest::Disconnect { cause: None }).await;
    println!(
        "# cold-confirmed={cold_confirmed} void(warm at start)={warm_at_start} \
         read={} missed={}",
        first_reads.len(),
        cold_confirmed.saturating_sub(first_reads.len())
    );
    if let Some(s) = Summary::of(&first_reads) {
        println!(
            "# t_read - t_put_sent (ms, ACROSS MACHINES — apply the clock offset): \
             n={} min {:.1} p50 {:.1} p90 {:.1} max {:.1}",
            s.n, s.min, s.p50, s.p90, s.max
        );
    }
    Ok(())
}

/// How many probes one ROUND sends.
///
/// This bounds a burst. It does NOT bound the leak — see [`OUTSTANDING_CAP`].
const BURST: usize = 32;

/// How long one probe waits for its answer.
///
/// Short: a node that holds the block answers from its own store in a
/// millisecond or two, and a node that does not hold it will not answer at
/// all. Waiting longer buys nothing and costs every other key its place in the
/// cycle.
const PROBE_ONE: Duration = Duration::from_millis(20);

/// One bounded GET. `Some(len)` when this node served the state.
/// `bound` is how long to wait for the ANSWER, not for the send.
///
/// Passing it to the send too is wrong twice: a sub-second send bound trips
/// the moment the websocket backpressures, and it aborts the whole run with
/// "send blocked for 0 s" — a duration that reads as nonsense precisely
/// because it was never meant to be a send budget.
async fn probe_once(
    client: &mut WebApi,
    id: &ContractInstanceId,
    return_code: bool,
    bound: Duration,
) -> Result<Option<usize>> {
    // Drain anything still queued before sending another request.
    //
    // A probe that times out leaves its answer unread. Poll in a loop without
    // draining and those answers accumulate until the socket backpressures and
    // the next SEND blocks — which surfaces as "the node stopped accepting
    // requests" when in fact this client stopped reading. Cheap to drain, and
    // it also lets a late answer count: if the queued reply names the key we
    // are asking about, that IS the hit.
    let mut queued_hit = None;
    while let Ok(Ok(msg)) = timeout(Duration::from_millis(0), client.recv()).await {
        if let HostResponse::ContractResponse(ContractResponse::GetResponse {
            key: k, state, ..
        }) = msg
        {
            if k.id() == id {
                queued_hit = Some(state.as_ref().len());
            }
        }
    }
    if queued_hit.is_some() {
        return Ok(queued_hit);
    }
    send_req(
        client,
        ClientRequest::ContractOp(ContractRequest::Get {
            key: *id,
            return_contract_code: return_code,
            subscribe: false,
            blocking_subscribe: false,
        }),
        Duration::from_secs(30),
    )
    .await?;
    match timeout(bound, client.recv()).await {
        Ok(Ok(HostResponse::ContractResponse(ContractResponse::GetResponse { state, .. }))) => {
            Ok(Some(state.as_ref().len()))
        }
        Ok(Ok(_)) | Ok(Err(_)) | Err(_) => Ok(None),
    }
}

/// Which arm a trial belongs to.
///
/// Assigned at MINT time and INTERLEAVED, so the two arms share the link's
/// weather rather than one running before the other. A block's key is known
/// before it is put, so the assignment cannot depend on anything the put
/// observes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arm {
    /// Never re-puts. Its population is computed from its own ack times.
    Control,
    /// Re-puts at T when no acknowledgement has arrived.
    Hedge,
}

impl Arm {
    pub fn as_str(self) -> &'static str {
        match self {
            Arm::Control => "control",
            Arm::Hedge => "hedge",
        }
    }
    fn parse(s: &str) -> Arm {
        match s {
            "hedge" => Arm::Hedge,
            // A file minted before arms existed is all control, which is what
            // a run with no hedge is.
            _ => Arm::Control,
        }
    }
}

/// One writer line: the key, when it was SENT, and the local confirm time.
#[derive(Debug, Clone, PartialEq)]
pub struct Send {
    pub key: String,
    pub sent_ns: u128,
    pub confirm_ms: f64,
    pub size: usize,
    pub arm: Arm,
    /// Was this trial still unacknowledged when T came round? Taken in BOTH
    /// arms, so "the population a hedge fires on" means the same thing on each
    /// side of the comparison. `None` when the run had no T.
    pub unacked_at_t: Option<bool>,
    /// Did a hedge actually fire here?
    pub hedged: bool,
    /// ms from the send to this key's acknowledgement, where one arrived.
    pub ack_ms: Option<f64>,
}

/// One reader line: the key and the absolute time this node first served it.
#[derive(Debug, Clone, PartialEq)]
pub struct Hit {
    pub key: String,
    pub size: usize,
    pub at_ms: f64,
}

/// One sound pair: how long until the FAR node served it, beside everything
/// the writer knew about the same trial.
///
/// One row rather than two parallel lists. The conditional comparison and the
/// ack-versus-far-readability question are asked of the same trials, and two
/// vectors that have to stay in step are a way to ask them of different ones.
#[derive(Debug, Clone, PartialEq)]
pub struct Joined {
    pub size: usize,
    /// ms from the writer's send until the far node first served the block.
    pub far_ms: f64,
    pub arm: Arm,
    pub unacked_at_t: Option<bool>,
    pub hedged: bool,
    pub ack_ms: Option<f64>,
}

/// What pairing produced, including everything it REFUSED.
#[derive(Debug, Default, PartialEq)]
pub struct Paired {
    /// Every sound pair.
    pub deltas: Vec<Joined>,
    /// Hits whose delta came out negative — impossible, so refused.
    pub refused_negative: usize,
    /// Hits naming a key the writer never reported sending.
    pub unmatched: usize,
}

/// Pair reader hits against writer sends.
///
/// A negative delta means the reader served a block before the writer sent it,
/// which cannot happen — it means the two sides are describing different runs.
/// This has occurred: a phase-2 failure left blocks published while the PUT
/// line count reported almost none, and pairing those hits against a LATER
/// re-run's send times produced deltas of -71 s. Refusing them (and counting
/// the refusals) is what turns that from a published number into a caught bug.
pub fn pair(sends: &[Send], hits: &[Hit]) -> Paired {
    let mut out = Paired::default();
    for h in hits {
        match sends.iter().find(|s| s.key == h.key) {
            None => out.unmatched += 1,
            Some(s) => {
                let d = h.at_ms - (s.sent_ns as f64) / 1e6;
                if d < 0.0 {
                    out.refused_negative += 1;
                } else {
                    out.deltas.push(Joined {
                        size: h.size,
                        far_ms: d,
                        arm: s.arm,
                        unacked_at_t: s.unacked_at_t,
                        hedged: s.hedged,
                        ack_ms: s.ack_ms,
                    });
                }
            }
        }
    }
    out
}

/// The smallest conditioned population this instrument draws a comparison
/// from.
///
/// A hedge fires on a minority of writes, so the population that matters is a
/// fraction of the trials — and two arms of eight tell you about the eight.
/// Below this the run says NO FINDING and prints the count, rather than a p50
/// over a handful that reads like a result.
pub const FLOOR: usize = 20;

/// May this run be read as a comparison at all?
///
/// A decision rather than a printed sentence, so a test can put a population
/// on each side of the floor and watch it change. A floor asserted against
/// itself is not a floor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// The smaller conditioned arm is below [`FLOOR`].
    NoFinding { smaller_arm: usize },
    /// Both arms reached the floor.
    Comparable { smaller_arm: usize },
}

pub fn verdict(rows: &[Joined]) -> Verdict {
    let smaller_arm = [Arm::Control, Arm::Hedge]
        .into_iter()
        .map(|a| conditional(rows, a).n)
        .min()
        .unwrap_or(0);
    if smaller_arm < FLOOR {
        Verdict::NoFinding { smaller_arm }
    } else {
        Verdict::Comparable { smaller_arm }
    }
}

/// One arm's conditioned population: the trials that were still unacknowledged
/// when T came round.
#[derive(Debug, Default, PartialEq)]
pub struct Conditioned {
    pub n: usize,
    /// Time until the FAR node served it, for the trials it served.
    pub far: Vec<f64>,
    /// The acknowledgement, for the trials that got one. Reported BESIDE the
    /// far-node number rather than instead of it: #11 measured the ack, and
    /// the whole point of this run is that an ack is not the thing the engine
    /// waits on.
    pub ack: Vec<f64>,
    /// Trials that never acknowledged at all. They are in `n`, and they are
    /// the most unacknowledged trials there are.
    pub never_acked: usize,
    /// Trials the far node never served within the run.
    pub never_far: usize,
}

/// Split the sound pairs into the two arms' conditioned populations.
///
/// The condition is `unacked_at_t == Some(true)` in BOTH arms — the mark the
/// writer took at each trial's own T, whether or not it acted on it. A
/// whole-arm comparison is diluted by the trials a hedge never touches, which
/// is what freenet-harness#11 found and what makes this the only comparison
/// worth printing.
pub fn conditional(rows: &[Joined], arm: Arm) -> Conditioned {
    let mut out = Conditioned::default();
    for r in rows
        .iter()
        .filter(|r| r.arm == arm && r.unacked_at_t == Some(true))
    {
        out.n += 1;
        out.far.push(r.far_ms);
        match r.ack_ms {
            Some(a) => out.ack.push(a),
            None => out.never_acked += 1,
        }
    }
    out
}

/// Does the acknowledgement predict readability on another node at all?
///
/// The question freenet-harness#11 could not ask. An ack that arrives AFTER
/// the far node is already serving the block is not a signal a writer could
/// have waited on; a block readable elsewhere with no ack at all says the same
/// thing more strongly.
#[derive(Debug, Default, PartialEq)]
pub struct Proxy {
    /// Pairs where both an ack and a far-node read exist.
    pub both: usize,
    /// ...of which the FAR node served the block CLEARLY before the ack.
    pub far_first: usize,
    /// ...and the other way round.
    pub ack_first: usize,
    /// ...and those whose order the clock bound cannot settle.
    pub within_margin: usize,
    /// `ack_ms - far_ms` for those pairs: positive means the far node was
    /// first, so the ack told the writer nothing it did not already have.
    pub gaps: Vec<f64>,
    /// Readable on the far node, never acknowledged. The ack cannot be a
    /// precondition for these, and no clock correction can change that.
    pub far_without_ack: usize,
}

/// Which came first, the acknowledgement or the far node serving the block?
///
/// `margin_ms` is the clock bound, and it is not optional. The ack is timed on
/// the WRITER's clock and the far read on the READER's, so their difference
/// carries whatever the two clocks disagree by — and a run that reported "the
/// far node was first" for a 40 ms gap between two machines synchronised to a
/// few hundred milliseconds would be reporting the clocks. Pairs inside the
/// margin are counted as undecided rather than assigned to a side.
///
/// `far_without_ack` needs no margin at all: no clock correction turns an
/// acknowledgement that never arrived into one that did.
pub fn proxy(rows: &[Joined], margin_ms: f64) -> Proxy {
    let mut out = Proxy::default();
    for r in rows {
        match r.ack_ms {
            None => out.far_without_ack += 1,
            Some(a) => {
                out.both += 1;
                if r.far_ms + margin_ms < a {
                    out.far_first += 1;
                } else if a + margin_ms < r.far_ms {
                    out.ack_first += 1;
                } else {
                    out.within_margin += 1;
                }
                out.gaps.push(a - r.far_ms);
            }
        }
    }
    out
}

/// Does a run's stimulus match what was asked for?
///
/// SENDS are the stimulus, not confirmations: puts are issued in one phase and
/// confirmed in another, so a confirmation failure leaves every block genuinely
/// published while the confirmed count reports almost none. Asserting on the
/// wrong one is how a real stimulus got reported as absent.
pub fn stimulus_ok(expected: usize, sent: usize, confirmed: usize) -> Result<(), String> {
    if sent < expected {
        return Err(format!(
            "stimulus incomplete: {sent} sent, expected {expected} \
             (confirmed {confirmed} — confirmations are NOT the stimulus)"
        ));
    }
    Ok(())
}

/// Pair a writer's PUT lines against a reader's READ lines and print the
/// table — including everything refused, so a reader cannot quietly drop the
/// impossible values that reveal a mispaired run.
pub fn pair_files(put_file: &str, read_file: &str, margin_ms: f64, grid_ms: f64) -> Result<()> {
    let put = std::fs::read_to_string(put_file)
        .map_err(|e| anyhow!("{put_file}: {e} — run the put role first"))?;
    let read = std::fs::read_to_string(read_file)
        .map_err(|e| anyhow!("{read_file}: {e} — run the read role first"))?;
    let sends: Vec<Send> = put
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.first() == Some(&"PUT") && f.len() >= 5).then(|| Send {
                key: f[1].to_string(),
                sent_ns: f[2].parse().unwrap_or(0),
                confirm_ms: f[3].parse().unwrap_or(0.0),
                size: f[4].parse().unwrap_or(0),
                // Absent in a file written before arms existed, which is a
                // run with no hedge: all control, no mark, nothing fired.
                arm: f.get(5).map(|a| Arm::parse(a)).unwrap_or(Arm::Control),
                unacked_at_t: match f.get(6) {
                    Some(&"unacked") => Some(true),
                    Some(&"acked") => Some(false),
                    _ => None,
                },
                hedged: f.get(7) == Some(&"hedged"),
                ack_ms: f.get(8).and_then(|a| a.parse().ok()),
            })
        })
        .collect();
    let hits: Vec<Hit> = read
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.first() == Some(&"READ") && f.len() >= 4).then(|| Hit {
                key: f[1].to_string(),
                size: f[2].parse().unwrap_or(0),
                at_ms: f[3].parse().unwrap_or(0.0),
            })
        })
        .collect();
    let p = pair(&sends, &hits);
    println!(
        "pairs={} refused_negative={} unmatched={}  (sends={} hits={})",
        p.deltas.len(),
        p.refused_negative,
        p.unmatched,
        sends.len(),
        hits.len()
    );
    if p.refused_negative > 0 {
        println!(
            "  WARNING: {} hit(s) preceded their send. That is impossible, so these two files \
             describe different runs — the table below is NOT a measurement of this run.",
            p.refused_negative
        );
    }
    let mut by: std::collections::BTreeMap<usize, Vec<f64>> = Default::default();
    for j in &p.deltas {
        by.entry(j.size).or_default().push(j.far_ms);
    }
    let mut t = Table::new(["size", "n", "readable elsewhere p50", "min", "max"]);
    for (size, v) in &by {
        let s = Summary::of(v);
        t.row([
            kib(*size),
            v.len().to_string(),
            s.map(|x| format!("{:.1}", x.p50)).unwrap_or("-".into()),
            s.map(|x| format!("{:.1}", x.min)).unwrap_or("-".into()),
            s.map(|x| format!("{:.1}", x.max)).unwrap_or("-".into()),
        ]);
    }
    print!("{t}");
    if grid_ms > 0.0 {
        let g = Grid { ms: grid_ms };
        println!("{}", g.line());
        for (size, v) in &by {
            if let Some(s) = Summary::of(v) {
                if let Some(note) = g.unresolved(&kib(*size), &s) {
                    println!("  {note}");
                }
            }
        }
    }
    report_hedge(&p.deltas, margin_ms, grid_ms);
    Ok(())
}

/// The two tables this run exists for: the conditional comparison, and whether
/// the acknowledgement predicts far-node readability at all.
///
/// Silent when the run had no arms, because a file from a no-hedge run has
/// nothing to say about a hedge and a table of dashes reads like one that does.
pub fn report_hedge(rows: &[Joined], margin_ms: f64, grid_ms: f64) {
    if !rows.iter().any(|r| r.unacked_at_t.is_some()) {
        return;
    }
    let p50 = |v: &[f64]| {
        Summary::of(v)
            .map(|s| format!("{:.1}", s.p50))
            .unwrap_or("-".into())
    };
    let p90 = |v: &[f64]| {
        Summary::of(v)
            .map(|s| format!("{:.1}", s.p90))
            .unwrap_or("-".into())
    };

    println!();
    println!(
        "CONDITIONAL — only the trials still UNACKNOWLEDGED at T, which is the \
         population a hedge fires on"
    );
    let mut t = Table::new([
        "arm",
        "n",
        "readable elsewhere p50",
        "p90",
        "ack p50",
        "p90",
        "never acked",
    ]);
    for arm in [Arm::Control, Arm::Hedge] {
        let c = conditional(rows, arm);
        t.row([
            arm.as_str().to_string(),
            c.n.to_string(),
            p50(&c.far),
            p90(&c.far),
            p50(&c.ack),
            p90(&c.ack),
            c.never_acked.to_string(),
        ]);
    }
    print!("{t}");
    if grid_ms > 0.0 {
        let g = Grid { ms: grid_ms };
        for arm in [Arm::Control, Arm::Hedge] {
            let c = conditional(rows, arm);
            if let Some(s) = Summary::of(&c.far) {
                if let Some(note) = g.unresolved(&format!("{} far-read", arm.as_str()), &s) {
                    println!("  {note}");
                }
            }
        }
        println!(
            "  the ack column is on the WRITER's own clock and is not on this grid; the \
             far-read column is."
        );
    }
    if let Verdict::NoFinding { smaller_arm } = verdict(rows) {
        println!(
            "NO FINDING: the smaller conditioned arm has {smaller_arm} trials, below the floor \
             of {FLOOR}. The numbers above describe those trials and nothing else — they are \
             not evidence that a hedge does or does not help."
        );
    }

    let fired = rows.iter().filter(|r| r.hedged).count();
    let eligible = rows.iter().filter(|r| r.arm == Arm::Hedge).count();
    if eligible > 0 {
        println!(
            "fire rate: {fired} of {eligible} hedge-arm trials ({:.0} %)",
            100.0 * fired as f64 / eligible as f64
        );
    }

    let x = proxy(rows, margin_ms);
    println!();
    println!("DOES THE ACK PREDICT FAR-NODE READABILITY?");
    println!(
        "  clock margin: ±{margin_ms:.0} ms. The ack is on the writer's clock and the far read \
         on the reader's, so an order inside this is not decided."
    );
    println!(
        "  readable elsewhere with NO acknowledgement at all: {} of {} pairs  \
         (no clock correction changes these)",
        x.far_without_ack,
        rows.len()
    );
    println!(
        "  of the {} pairs with both: far node first {}, ack first {}, undecided {}",
        x.both, x.far_first, x.ack_first, x.within_margin
    );
    println!(
        "  ack - readable-elsewhere (ms, positive = the far node was first): p50 {} p90 {}",
        p50(&x.gaps),
        p90(&x.gaps)
    );
    if x.far_without_ack > 0 || x.far_first > 0 {
        println!(
            "  An ack that arrives after the block is already being served elsewhere is not a \
             signal a writer could have waited on."
        );
    }
}

/// Print this machine's clock against a reference, so a cross-machine
/// duration can be corrected rather than quietly trusted.
pub fn stamp() -> Result<()> {
    println!("CLOCK {} {}", now_ns(), kib(0));
    Ok(())
}

/// Everything the read role needs; grouped so `run` stays inside the
/// argument-count lint rather than growing a tenth positional parameter.
pub struct ReadOpts {
    pub keys: String,
    /// T for the hedge, in seconds; 0 turns it off and the run is exactly the
    /// one that existed before arms did.
    pub hedge_secs: f64,
    /// How far apart the two machines' clocks may be, in ms. Measured, never
    /// assumed: the `clock` role prints each machine's stamp, and the run that
    /// produced these files reports what it could bound them to.
    pub clock_margin_ms: f64,
    /// Stop the put role once BOTH arms hold this many trials that were still
    /// unacknowledged at T — the population the comparison is made over. The
    /// milestone, not a clock; 0 means run the whole plan.
    pub until_conditioned: usize,
    /// The READER's probe grid, in ms, which it printed at the top of its own
    /// output: `rounds_per_cycle * probe_ms`. A far-node time is resolved to
    /// this, not to the probe period, and a series whose whole spread fits
    /// inside one step measured the instrument.
    pub grid_ms: f64,
    /// The reader's log, for the `pair` role.
    pub reads: String,
    pub return_code: bool,
    pub probe_ms: u64,
    pub limit_secs: u64,
}

pub async fn run(
    ws: &str,
    role: &str,
    wasm: &str,
    samples: usize,
    sizes: &[usize],
    opts: ReadOpts,
    wait: Duration,
) -> Result<()> {
    match role {
        "write" => write(ws, wasm, samples, sizes, wait).await,
        "mint" => mint_only(wasm, samples, sizes, &opts.keys, opts.hedge_secs > 0.0).await,
        "put" => {
            put_minted(
                ws,
                wasm,
                &opts.keys,
                (opts.hedge_secs > 0.0).then(|| Duration::from_secs_f64(opts.hedge_secs)),
                opts.until_conditioned,
                wait,
            )
            .await
        }
        "read" => {
            read(
                ws,
                &opts.keys,
                opts.return_code,
                opts.probe_ms,
                opts.limit_secs,
            )
            .await
        }
        "pair" => pair_files(&opts.keys, &opts.reads, opts.clock_margin_ms, opts.grid_ms),
        "clock" => stamp(),
        other => bail!("unknown role {other}; expected write, read or clock"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(key: &str, sent_ns: u128) -> Send {
        Send {
            key: key.into(),
            sent_ns,
            confirm_ms: 100.0,
            size: 1024,
            arm: Arm::Control,
            unacked_at_t: None,
            hedged: false,
            ack_ms: None,
        }
    }
    fn h(key: &str, at_ms: f64) -> Hit {
        Hit {
            key: key.into(),
            size: 1024,
            at_ms,
        }
    }

    #[test]
    fn a_sound_pair_yields_the_elapsed_time() {
        let p = pair(&[s("a", 1_000_000_000)], &[h("a", 1500.0)]);
        assert_eq!(p.deltas.len(), 1);
        assert_eq!(p.deltas[0].far_ms, 500.0);
        assert_eq!(p.deltas[0].size, 1024);
        assert_eq!(p.refused_negative, 0);
    }

    /// The defect this function exists for: a hit that precedes its send is
    /// impossible, so it must be refused and COUNTED — never reported as a
    /// measurement. The old pairing published -71735 ms.
    #[test]
    fn a_negative_delta_is_refused_not_reported() {
        let p = pair(&[s("a", 2_000_000_000)], &[h("a", 1000.0)]);
        assert!(p.deltas.is_empty(), "a negative delta must not be reported");
        assert_eq!(p.refused_negative, 1, "and it must be counted");
    }

    /// Half a pair is not a measurement.
    #[test]
    fn a_hit_with_no_send_is_unmatched_not_zero() {
        let p = pair(&[s("a", 1_000_000_000)], &[h("b", 1500.0)]);
        assert!(p.deltas.is_empty());
        assert_eq!(p.unmatched, 1);
        let none = pair(&[s("a", 1_000_000_000)], &[]);
        assert_eq!(none, Paired::default());
    }

    /// Mixed input: the sound pair survives, the impossible one does not, and
    /// neither hides the other.
    #[test]
    fn refusals_do_not_suppress_sound_pairs() {
        let p = pair(
            &[s("a", 1_000_000_000), s("b", 5_000_000_000)],
            &[h("a", 1200.0), h("b", 1000.0), h("zz", 9.0)],
        );
        assert_eq!(p.deltas.len(), 1);
        assert_eq!(p.deltas[0].far_ms, 200.0);
        assert_eq!(p.refused_negative, 1);
        assert_eq!(p.unmatched, 1);
    }

    /// The stimulus assertion keys on SENDS. A run that sent everything but
    /// confirmed almost nothing has a complete stimulus; the old assertion
    /// looked at confirmations and called it absent.
    #[test]
    fn stimulus_keys_on_sends_not_confirmations() {
        assert!(stimulus_ok(21, 21, 3).is_ok(), "21 sent IS the stimulus");
        let e = stimulus_ok(21, 3, 3).unwrap_err();
        assert!(
            e.contains("3 sent"),
            "must name what was actually sent: {e}"
        );
        assert!(
            e.contains("confirmations are NOT the stimulus"),
            "must say why: {e}"
        );
    }

    fn j(arm: Arm, unacked: Option<bool>, hedged: bool, far: f64, ack: Option<f64>) -> Joined {
        Joined {
            size: 1024,
            far_ms: far,
            arm,
            unacked_at_t: unacked,
            hedged,
            ack_ms: ack,
        }
    }

    /// The comparison is CONDITIONAL, and the condition is the mark taken in
    /// BOTH arms. A whole-arm comparison is diluted by the trials a hedge
    /// never touches — measured on #11, where it buried the effect entirely.
    #[test]
    fn only_the_trials_unacked_at_t_are_compared() {
        let rows = vec![
            j(Arm::Control, Some(true), false, 900.0, Some(3000.0)),
            j(Arm::Control, Some(false), false, 100.0, Some(80.0)),
            j(Arm::Hedge, Some(true), true, 400.0, Some(1200.0)),
            j(Arm::Hedge, Some(false), false, 120.0, Some(90.0)),
        ];
        let c = conditional(&rows, Arm::Control);
        assert_eq!(c.n, 1, "a trial acked before T is not in the population");
        assert_eq!(c.far, vec![900.0]);
        let h = conditional(&rows, Arm::Hedge);
        assert_eq!(h.n, 1);
        assert_eq!(h.far, vec![400.0]);
    }

    /// A trial that NEVER acknowledged is the most unacknowledged trial there
    /// is. Dropping it would select for the trials that recovered, which is
    /// the population a hedge exists to rescue.
    #[test]
    fn a_trial_that_never_acked_counts_and_is_named() {
        let rows = vec![
            j(Arm::Control, Some(true), false, 5000.0, None),
            j(Arm::Control, Some(true), false, 800.0, Some(2000.0)),
        ];
        let c = conditional(&rows, Arm::Control);
        assert_eq!(c.n, 2, "the never-acked trial is in the population");
        assert_eq!(c.far.len(), 2, "and its far-node time is a measurement");
        assert_eq!(c.ack.len(), 1, "but it contributes no ack");
        assert_eq!(c.never_acked, 1, "and it is counted separately");
    }

    /// A run with no arms must produce no conditioned population at all,
    /// rather than one made of every trial.
    #[test]
    fn a_run_without_a_hedge_has_no_conditioned_population() {
        let rows = vec![j(Arm::Control, None, false, 100.0, Some(50.0))];
        assert_eq!(conditional(&rows, Arm::Control), Conditioned::default());
    }

    /// The question #11 could not ask: an ack arriving after the far node is
    /// already serving the block is not a signal a writer could have waited on.
    #[test]
    fn the_proxy_question_counts_both_ways_round() {
        let rows = vec![
            // far node first: the ack told the writer nothing new
            j(Arm::Control, Some(true), false, 300.0, Some(2000.0)),
            // ack first
            j(Arm::Control, Some(true), false, 4000.0, Some(900.0)),
            // readable elsewhere, never acked at all
            j(Arm::Hedge, Some(true), true, 700.0, None),
        ];
        let x = proxy(&rows, 0.0);
        assert_eq!(x.both, 2);
        assert_eq!(x.far_first, 1);
        assert_eq!(x.far_without_ack, 1);
        assert_eq!(x.gaps, vec![1700.0, -3100.0]);
    }

    /// The clock margin must decide the ORDER, not decorate it. A gap smaller
    /// than the two machines' disagreement is the clocks, and assigning it to
    /// a side is reporting them as if they were the network.
    #[test]
    fn an_ordering_inside_the_clock_margin_is_undecided() {
        // 40 ms apart, on two clocks bounded to 300 ms.
        let rows = vec![j(Arm::Control, Some(true), false, 100.0, Some(140.0))];
        let tight = proxy(&rows, 0.0);
        assert_eq!(tight.far_first, 1, "with no margin it would be called");
        let honest = proxy(&rows, 300.0);
        assert_eq!(honest.far_first, 0);
        assert_eq!(honest.ack_first, 0);
        assert_eq!(honest.within_margin, 1);
        // The control: a gap well outside the margin is still decided, so the
        // margin is not simply refusing to answer.
        let wide = vec![j(Arm::Control, Some(true), false, 100.0, Some(5000.0))];
        assert_eq!(proxy(&wide, 300.0).far_first, 1);
    }

    /// A block readable elsewhere that was never acknowledged needs no clock
    /// correction at all, so no margin may hide it.
    #[test]
    fn a_far_read_with_no_ack_survives_any_margin() {
        let rows = vec![j(Arm::Hedge, Some(true), true, 700.0, None)];
        for margin in [0.0, 300.0, 60_000.0] {
            assert_eq!(proxy(&rows, margin).far_without_ack, 1, "margin {margin}");
            assert_eq!(proxy(&rows, margin).both, 0);
        }
    }

    /// The floor decides, and it decides at the boundary. One trial short of
    /// it in EITHER arm is no finding — a run is only as strong as its smaller
    /// conditioned population.
    #[test]
    fn one_trial_short_in_either_arm_is_no_finding() {
        let arm_of = |arm, n| (0..n).map(move |_| j(arm, Some(true), false, 100.0, None));
        let full: Vec<Joined> = arm_of(Arm::Control, FLOOR)
            .chain(arm_of(Arm::Hedge, FLOOR))
            .collect();
        assert_eq!(verdict(&full), Verdict::Comparable { smaller_arm: FLOOR });
        let short: Vec<Joined> = arm_of(Arm::Control, FLOOR)
            .chain(arm_of(Arm::Hedge, FLOOR - 1))
            .collect();
        assert_eq!(
            verdict(&short),
            Verdict::NoFinding {
                smaller_arm: FLOOR - 1
            }
        );
        // And a run with no conditioned trials at all is not a comparison
        // either — the emptiest case must not fall through to Comparable.
        assert_eq!(verdict(&[]), Verdict::NoFinding { smaller_arm: 0 });
    }
}
