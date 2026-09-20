//! `put-shape`: the same payload put as ONE contract or as k in parallel.
//!
//! The engine has to choose a pack size, and single-put latencies cannot settle
//! it: a batch of four is not four times one put, and inferring one from the
//! other is exactly the reasoning this harness exists to replace. So the two
//! shapes are measured directly, against the same wall clock, putting the same
//! number of payload bytes.
//!
//! Three rules the measurement is built around, each from a way an earlier run
//! of this kind went wrong:
//!
//! - **Interleaved, never blocked.** Arm A ten times then arm B ten times
//!   measures the node's drift as much as the arms. One round does every arm
//!   before any arm repeats, so drift lands on both.
//! - **Two clocks, reported separately.** A writer commits when the bytes can
//!   be READ BACK and publishes when the ack arrives, and on this platform
//!   those differ by seconds. One number for both would hide whichever the
//!   engine actually waits for.
//! - **Bytes, not just milliseconds.** Every PUT carries the whole contract, so
//!   k puts carry the code k times. A shape that wins on latency and loses on
//!   bytes is a real trade, and it cannot be seen in a latency table.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{bail, Result};
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

/// Between passes over the keys, so a tight loop does not become the load.
const PROBE_GAP: Duration = Duration::from_millis(10);

/// One trial of one arm.
struct Trial {
    /// ms from the first send to the LAST acknowledgement, or None if some
    /// never arrived within the deadline.
    ack_last: Option<f64>,
    /// ms from the first send until every piece could be READ BACK.
    readable_last: Option<f64>,
    /// How many pieces were acknowledged and read back, for the trials that
    /// did NOT complete — an incomplete trial has no wall clock, but how far
    /// it got is the difference between "slow" and "lost".
    acks: usize,
    readable: usize,
    /// Answers to requests an earlier trial had given up on.
    stale: usize,
}

struct Arm {
    split: usize,
    piece: usize,
    trials: Vec<Trial>,
}

fn make(code: &Arc<ContractCode<'static>>, size: usize) -> Result<(ContractContainer, Vec<u8>)> {
    let mut body = vec![0u8; size];
    getrandom::getrandom(&mut body)?;
    let state = block::encode(block::kind::RAW, &body);
    let params = Parameters::from(blake3::hash(&state).as_bytes().to_vec());
    let contract = ContractContainer::Wasm(ContractWasmAPIVersion::V1(WrappedContract::new(
        code.clone(),
        params,
    )));
    Ok((contract, state))
}

/// Put `split` pieces at once and watch both clocks.
#[allow(clippy::too_many_arguments)]
async fn trial(
    writer: &mut WebApi,
    reader: &mut WebApi,
    code: &Arc<ContractCode<'static>>,
    piece: usize,
    split: usize,
    wait: Duration,
    probe: Duration,
    minted: &mut HashSet<ContractInstanceId>,
    requests: &mut usize,
) -> Result<Trial> {
    let mut pieces = Vec::with_capacity(split);
    for _ in 0..split {
        pieces.push(make(code, piece)?);
    }
    let keys: Vec<ContractKey> = pieces.iter().map(|(c, _)| c.key()).collect();
    let want: HashMap<ContractInstanceId, Vec<u8>> = pieces
        .iter()
        .map(|(c, s)| (*c.key().id(), s.clone()))
        .collect();
    for k in &keys {
        minted.insert(*k.id());
        *requests += 1;
    }

    let t0 = Instant::now();
    for (contract, state) in pieces {
        send_req(
            writer,
            ClientRequest::ContractOp(ContractRequest::Put {
                contract,
                state: WrappedState::from(state),
                related_contracts: RelatedContracts::default(),
                subscribe: false,
                blocking_subscribe: false,
            }),
            wait,
        )
        .await?;
    }

    let deadline = t0 + wait;
    let ids: HashSet<ContractInstanceId> = keys.iter().map(|k| *k.id()).collect();
    let (acks, readable) = tokio::join!(
        collect_acks(writer, &ids, deadline, t0),
        poll_readable(reader, &keys, &want, deadline, t0, probe),
    );
    let (ack_ms, stale) = acks?;
    let read_ms = readable?;

    Ok(Trial {
        acks: ack_ms.len(),
        readable: read_ms.len(),
        ack_last: (ack_ms.len() == split).then(|| max_of(&ack_ms)),
        readable_last: (read_ms.len() == split).then(|| max_of(&read_ms)),
        stale,
    })
}

fn max_of(v: &[f64]) -> f64 {
    v.iter().copied().fold(f64::MIN, f64::max)
}

/// Acknowledgements for THIS trial's keys, offset from the batch start.
async fn collect_acks(
    client: &mut WebApi,
    ids: &HashSet<ContractInstanceId>,
    deadline: Instant,
    t0: Instant,
) -> Result<(Vec<f64>, usize)> {
    let mut seen: HashSet<ContractInstanceId> = HashSet::new();
    let mut out = Vec::new();
    let mut stale = 0usize;
    while seen.len() < ids.len() {
        let Some(left) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        match timeout(left, client.recv()).await {
            Ok(Ok(HostResponse::ContractResponse(ContractResponse::PutResponse { key }))) => {
                let id = *key.id();
                if ids.contains(&id) {
                    if seen.insert(id) {
                        out.push(ms_since(t0));
                    }
                } else {
                    // An earlier trial's answer, arriving after that trial gave
                    // up. Not this one's latency and not this one's error.
                    stale += 1;
                }
            }
            Ok(Ok(_)) => stale += 1,
            Ok(Err(e)) => bail!("node error while collecting acks: {e}"),
            Err(_) => break,
        }
    }
    Ok((out, stale))
}

/// When each piece first reads back, on a SECOND connection.
///
/// Round-robin over the keys, not one key to completion: polling them in order
/// makes the later keys wait behind the earlier ones and turns the reader's own
/// queueing into what looks like propagation time.
#[allow(clippy::too_many_arguments)]
async fn poll_readable(
    reader: &mut WebApi,
    keys: &[ContractKey],
    want: &HashMap<ContractInstanceId, Vec<u8>>,
    deadline: Instant,
    t0: Instant,
    probe: Duration,
) -> Result<Vec<f64>> {
    let mut left: Vec<ContractKey> = keys.to_vec();
    let mut out = Vec::new();
    while !left.is_empty() && Instant::now() < deadline {
        let mut still = Vec::with_capacity(left.len());
        for key in left {
            if Instant::now() >= deadline {
                still.push(key);
                continue;
            }
            send_req(
                reader,
                ClientRequest::ContractOp(ContractRequest::Get {
                    key: *key.id(),
                    return_contract_code: false,
                    subscribe: false,
                    blocking_subscribe: false,
                }),
                probe,
            )
            .await?;
            let mut hit = false;
            let probe_end = Instant::now() + probe;
            while let Some(rest) = probe_end.checked_duration_since(Instant::now()) {
                match timeout(rest, reader.recv()).await {
                    Ok(Ok(HostResponse::ContractResponse(ContractResponse::GetResponse {
                        key: k,
                        state,
                        ..
                    }))) => {
                        // A late answer for a key already satisfied is a hit for
                        // THAT key if it is still outstanding, and otherwise
                        // discarded — never counted against this key.
                        let id = *k.id();
                        if want.get(&id).is_some_and(|w| state.as_ref() == w) && id == *key.id() {
                            hit = true;
                            break;
                        }
                    }
                    Ok(Ok(_)) => continue,
                    _ => break,
                }
            }
            if hit {
                out.push(ms_since(t0));
            } else {
                still.push(key);
            }
        }
        left = still;
        if !left.is_empty() {
            tokio::time::sleep(PROBE_GAP).await;
        }
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    ws: &str,
    wasm: &str,
    total: usize,
    splits: &[usize],
    rounds: usize,
    budget_secs: u64,
    probe_ms: u64,
    wait: Duration,
) -> Result<()> {
    if splits.is_empty() || rounds == 0 {
        bail!("nothing to measure: --splits and --rounds must both be non-empty");
    }
    for &s in splits {
        if s == 0 || !total.is_multiple_of(s) {
            bail!("--total {total} does not divide evenly by split {s} — the arms would not be putting the same payload");
        }
    }
    let bytes = std::fs::read(wasm)?;
    let code_len = bytes.len();
    let code = Arc::new(ContractCode::from(bytes));
    crate::latency::describe_environment(&crate::latency::node_version());
    println!("contract: {wasm} ({code_len} B of code on EVERY put)");
    println!();

    let probe = Duration::from_millis(probe_ms.max(20));
    let budget = (budget_secs > 0).then(|| Instant::now() + Duration::from_secs(budget_secs));
    let g = Grid::new(
        probe.as_secs_f64() * 1000.0,
        PROBE_GAP.as_secs_f64() * 1000.0,
    );
    println!("read-back {}", g.line());
    let mut writer = crate::connect(ws).await?;
    let mut reader = crate::connect(ws).await?;
    let mut minted: HashSet<ContractInstanceId> = HashSet::new();
    let mut requests = 0usize;

    let mut arms: Vec<Arm> = splits
        .iter()
        .map(|&split| Arm {
            split,
            piece: total / split,
            trials: Vec::new(),
        })
        .collect();

    let mut cut = false;
    'rounds: for r in 0..rounds {
        // Interleaved: every arm gets round r before any arm gets round r+1.
        for arm in arms.iter_mut() {
            if budget.is_some_and(|d| Instant::now() >= d) {
                cut = true;
                break 'rounds;
            }
            let t = trial(
                &mut writer,
                &mut reader,
                &code,
                arm.piece,
                arm.split,
                wait,
                probe,
                &mut minted,
                &mut requests,
            )
            .await?;
            progress_pub(format_args!(
                "  round {}/{rounds}  {}x{}  ack {}  readable {}",
                r + 1,
                arm.split,
                kib(arm.piece),
                t.ack_last.map_or("—".into(), |v| format!("{v:.0} ms")),
                t.readable_last.map_or("—".into(), |v| format!("{v:.0} ms")),
            ));
            arm.trials.push(t);
        }
    }

    println!();
    println!(
        "putting {} as k pieces at once — {} rounds asked, arms interleaved",
        kib(total),
        rounds
    );
    println!();

    let mut t = Table::new(
        ["shape", "piece", "trials", "complete", "bytes sent"]
            .into_iter()
            .map(String::from)
            .chain(Summary::HEADINGS.iter().map(|h| format!("ack {h}"))),
    );
    let mut unresolved: Vec<String> = Vec::new();
    let mut t2 = Table::new(
        ["shape", "piece", "complete"]
            .into_iter()
            .map(String::from)
            .chain(Summary::HEADINGS.iter().map(|h| format!("readable {h}"))),
    );
    for arm in &arms {
        // Every PUT carries the whole contract, so k pieces carry the code k
        // times. This is the number a latency table cannot show.
        let sent = total + arm.split * (code_len + block::PARAMS_LEN);
        let ack: Vec<f64> = arm.trials.iter().filter_map(|x| x.ack_last).collect();
        let read: Vec<f64> = arm.trials.iter().filter_map(|x| x.readable_last).collect();
        let head = vec![
            format!("{}x", arm.split),
            kib(arm.piece),
            arm.trials.len().to_string(),
            format!("{}/{}", ack.len(), arm.trials.len()),
            kib(sent),
        ];
        match Summary::of(&ack) {
            Some(s) => t.row(head.into_iter().chain(s.cells())),
            None => t.row(
                head.into_iter()
                    .chain(["—"; 5].iter().map(|s| s.to_string())),
            ),
        }
        let head2 = vec![
            format!("{}x", arm.split),
            kib(arm.piece),
            format!("{}/{}", read.len(), arm.trials.len()),
        ];
        match Summary::of(&read) {
            Some(s) => {
                // An arm whose whole spread fits inside one grid step was
                // measured by the instrument, not by the node.
                if let Some(u) = g.unresolved(&format!("{}x{}", arm.split, kib(arm.piece)), &s) {
                    unresolved.push(u);
                }
                t2.row(head2.into_iter().chain(s.cells()))
            }
            None => t2.row(
                head2
                    .into_iter()
                    .chain(["—"; 5].iter().map(|s| s.to_string())),
            ),
        }
    }
    println!("1. wall-clock to the LAST acknowledgement (ms) — what publishing waits for");
    print!("{t}");
    println!();
    println!("2. wall-clock until EVERY piece reads back (ms) — what a commit waits for");
    print!("{t2}");
    for u in &unresolved {
        println!("   {u}");
    }
    println!();

    let stale: usize = arms.iter().flat_map(|a| &a.trials).map(|t| t.stale).sum();
    let short: usize = arms
        .iter()
        .flat_map(|a| &a.trials)
        .filter(|t| t.ack_last.is_none() || t.readable_last.is_none())
        .count();
    println!(
        "control: {requests} put requests, {} distinct contract keys — {}",
        minted.len(),
        if minted.len() == requests {
            "every put was a first put"
        } else {
            "REPEATED KEYS: some puts were merges and the arms are not comparable"
        }
    );
    if stale > 0 {
        println!(
            "{stale} late answer(s) to earlier trials were discarded, not charged to a later one"
        );
    }
    if short > 0 {
        println!(
            "{short} trial(s) did not complete within {} s and are EXCLUDED from the percentiles above — an incomplete trial is not a fast one",
            wait.as_secs()
        );
        for arm in &arms {
            for (i, t) in arm.trials.iter().enumerate() {
                if t.ack_last.is_none() || t.readable_last.is_none() {
                    println!(
                        "   {}x{} trial {}: {} of {} acked, {} of {} readable",
                        arm.split,
                        kib(arm.piece),
                        i + 1,
                        t.acks,
                        arm.split,
                        t.readable,
                        arm.split
                    );
                }
            }
        }
    }
    if cut {
        println!(
            "the run reached its {budget_secs} s budget; the rounds not taken are NOT within it"
        );
    }
    Ok(())
}
