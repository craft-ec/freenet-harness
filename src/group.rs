//! `group`: how long until k of n pieces are readable on ANOTHER node, with
//! our strategies on and with them off.
//!
//! **This is a stand-in, and the table says so.** Erasure coding does not exist
//! yet, so the twelve pieces here are twelve unrelated blocks and "the first
//! nine" is a stopwatch rule rather than a decode. What it measures is the
//! TIMING shape a k-of-n reader would see — how much of the tail belongs to the
//! slowest pieces, which a real group would never wait for. What it cannot
//! measure is repair, or anything that depends on the pieces being related.
//! (freenet-harness#13: part (a) now, part (b) on real groups in phase 4.)
//!
//! Two arms, interleaved, because a run of one then the other measures the
//! network's drift as much as the arms:
//!
//! - **RAW** — the platform as it comes. Put each piece and wait for its
//!   acknowledgement; then read the pieces one at a time, each read given the
//!   full deadline.
//! - **BASELINE** — what the design is actually sized from. Put every piece
//!   without waiting for an acknowledgement, confirm by READ-BACK, re-put what
//!   is not confirmed; on the read side ask for all n at once, bound every
//!   attempt, re-issue, and stop at the first k.
//!
//! Nothing here waits on a stall. Every attempt has a deadline, the run has a
//! total budget, and a group that has not reached k by then is recorded as
//! `not within T` — a missing value is a data point, not a reason to keep
//! waiting.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{bail, Result};
use craftec_block_contract as block;
use freenet_stdlib::{
    client_api::{ClientRequest, ContractRequest, ContractResponse, HostResponse},
    prelude::*,
};
use tokio::time::timeout;

use crate::{
    latency::{ms_since, progress_pub, send_req},
    stats::{kib, Grid, Summary, Table},
};

/// Between passes over the pieces still outstanding.
const GAP: Duration = Duration::from_millis(10);

/// How long a SEND may block before the node is declared unresponsive.
///
/// Generous, and deliberately unrelated to the read attempt bound. A send is
/// the harness handing bytes to the socket; on a constrained uplink a PUT that
/// carries 122 KB of contract can sit in backpressure for many seconds while
/// the node is perfectly healthy. Binding a send to the same short deadline as
/// a RECEIVE aborted a whole run here with "the node stopped accepting
/// requests: send blocked for 5 s" — the node had not stopped accepting
/// anything. Short bounds belong on waits for an ANSWER, never on the offer.
const SEND: Duration = Duration::from_secs(60);

/// How long the RAW arm waits for ONE acknowledgement before recording it as
/// not arrived and moving on.
///
/// Blocking on the ack IS the RAW arm, but "blocking" cannot mean "until the
/// group deadline" when there are twelve of them: one put meeting the ~60 s
/// relay tail consumes the whole group, and the remaining eleven sends then
/// pile into a connection nobody is reading. That is how this run died with
/// "send blocked for 60 s" — the node had not stopped accepting anything, the
/// harness had stopped collecting.
const ACK_BOUND: Duration = Duration::from_secs(10);

/// freenet's own `OPERATION_TTL` (config.rs, v0.2.135). The RAW arm does not
/// bound its reads; this is the bound the PLATFORM imposes, and naming it here
/// keeps "unbounded" meaning "we added no deadline" rather than "this run may
/// take any amount of time".
const TTL: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Arm {
    /// The platform as it comes: block on each acknowledgement, then read the
    /// pieces ONE AT A TIME, each bounded only by the platform's own TTL.
    Raw,
    /// RAW's write side, and all n pieces asked for at once on the read side —
    /// one attempt each, no re-issue, no hedging. The difference between this
    /// and [`Arm::Raw`] is the cost of asking one at a time, and nothing else.
    RawConcurrent,
    /// What the design is sized from: parallel puts, read-back confirmation,
    /// hedged re-puts, every read attempt bounded and re-issued, stop at k.
    /// The difference between this and [`Arm::RawConcurrent`] is what our
    /// strategies add on top of concurrency.
    Baseline,
}

impl Arm {
    fn name(self) -> &'static str {
        match self {
            Arm::Raw => "RAW",
            Arm::RawConcurrent => "RAW-CONC",
            Arm::Baseline => "BASELINE",
        }
    }
}

/// One group's result.
struct Group {
    arm: Arm,
    /// ms from the first send until the kth piece was readable on the far node.
    to_k: Option<f64>,
    /// ms until ALL n were readable — the number a non-erasure reader pays.
    to_n: Option<f64>,
    readable: usize,
    /// GET attempts issued across the whole group.
    attempts: usize,
    /// Pieces re-put because a read-back did not confirm them (BASELINE only).
    hedged: usize,
    /// RAW only: acknowledgements that did not arrive within ACK_BOUND. The
    /// bytes may well be there — this counts the WAIT, which is what the arm is
    /// about.
    late_acks: usize,
}

fn mint(code: &Arc<ContractCode<'static>>, size: usize) -> Result<(ContractContainer, Vec<u8>)> {
    let mut body = vec![0u8; size];
    getrandom::getrandom(&mut body)?;
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

/// Read whatever is already waiting, so the next send is not queueing behind
/// answers nobody collected. A connection nobody drains backpressures, and a
/// blocked SEND then looks exactly like a dead node.
async fn drain(client: &mut crate::probe::Client) {
    while (timeout(Duration::from_millis(1), client.recv()).await).is_ok() {}
}

/// One bounded GET. `true` when the far node returned exactly these bytes.
async fn probe(
    reader: &mut crate::probe::Client,
    key: &ContractKey,
    want: &[u8],
    bound: Duration,
) -> Result<bool> {
    send_req(
        reader,
        ClientRequest::ContractOp(ContractRequest::Get {
            key: *key.id(),
            return_contract_code: false,
            subscribe: false,
            blocking_subscribe: false,
        }),
        bound,
    )
    .await?;
    let end = Instant::now() + bound;
    while let Some(left) = end.checked_duration_since(Instant::now()) {
        match timeout(left, reader.recv()).await {
            Ok(Ok(HostResponse::ContractResponse(ContractResponse::GetResponse {
                key: k,
                state,
                ..
            }))) => {
                // Keyed: an answer for another piece is that piece's business,
                // not this one's, and must not be read as this one arriving.
                if k.id() == key.id() {
                    return Ok(state.as_ref() == want);
                }
            }
            Ok(Ok(_)) => continue,
            _ => break,
        }
    }
    Ok(false)
}

#[allow(clippy::too_many_arguments)]
async fn one_group(
    writer: &mut crate::probe::Client,
    reader: &mut crate::probe::Client,
    code: &Arc<ContractCode<'static>>,
    arm: Arm,
    size: usize,
    n: usize,
    k: usize,
    attempt: Duration,
    deadline_in: Duration,
    minted: &mut HashSet<ContractInstanceId>,
    requests: &mut usize,
) -> Result<Group> {
    let mut pieces = Vec::with_capacity(n);
    for _ in 0..n {
        pieces.push(mint(code, size)?);
    }
    let keys: Vec<ContractKey> = pieces.iter().map(|(c, _)| c.key()).collect();
    let want: HashMap<ContractInstanceId, Vec<u8>> = pieces
        .iter()
        .map(|(c, s)| (*c.key().id(), s.clone()))
        .collect();
    for key in &keys {
        minted.insert(*key.id());
        *requests += 1;
    }

    let t0 = Instant::now();
    let deadline = t0 + deadline_in;
    let mut hedged = 0usize;
    let mut late_acks = 0usize;

    match arm {
        // The platform as it comes: each put is waited on before the next.
        // RAW-CONCURRENT shares this write side on purpose — the only thing
        // that differs between them is how the READS are asked for.
        Arm::Raw | Arm::RawConcurrent => {
            for (contract, state) in pieces {
                let key = contract.key();
                drain(writer).await;
                send_req(
                    writer,
                    ClientRequest::ContractOp(ContractRequest::Put {
                        contract,
                        state: WrappedState::from(state),
                        related_contracts: RelatedContracts::default(),
                        subscribe: false,
                        blocking_subscribe: false,
                    }),
                    SEND,
                )
                .await?;
                // Blocking on the acknowledgement IS the arm, bounded so one
                // slow put cannot eat the group and leave the rest of the sends
                // queueing against a connection nobody reads.
                let until = (Instant::now() + ACK_BOUND).min(deadline);
                let mut acked = false;
                while let Some(left) = until.checked_duration_since(Instant::now()) {
                    match timeout(left, writer.recv()).await {
                        Ok(Ok(HostResponse::ContractResponse(ContractResponse::PutResponse {
                            key: got,
                        }))) if got.id() == key.id() => {
                            acked = true;
                            break;
                        }
                        Ok(Ok(_)) => continue,
                        _ => break,
                    }
                }
                if !acked {
                    late_acks += 1;
                }
            }
        }
        // Every put issued at once; confirmation is a read-back, not an ack.
        Arm::Baseline => {
            for (contract, state) in pieces {
                drain(writer).await;
                send_req(
                    writer,
                    ClientRequest::ContractOp(ContractRequest::Put {
                        contract,
                        state: WrappedState::from(state),
                        related_contracts: RelatedContracts::default(),
                        subscribe: false,
                        blocking_subscribe: false,
                    }),
                    SEND,
                )
                .await?;
            }
        }
    }

    // ---- the read side ------------------------------------------------------
    let mut hits: Vec<f64> = Vec::with_capacity(n);
    let mut attempts = 0usize;

    if arm == Arm::RawConcurrent {
        // Every piece asked for at once, then the answers collected as they
        // arrive. One attempt each: no re-issue, no hedging. This is the arm
        // that isolates concurrency from everything else we do.
        // Drained ONCE, before any of them is asked for. Draining between the
        // sends threw away the answers to the pieces asked for first — the arm
        // reported 0 of 6 readable while the node had answered every one of
        // them. A drain is for a connection nobody is about to read; here we
        // are about to read it.
        drain(reader).await;
        for key in &keys {
            attempts += 1;
            send_req(
                reader,
                ClientRequest::ContractOp(ContractRequest::Get {
                    key: *key.id(),
                    return_contract_code: false,
                    subscribe: false,
                    blocking_subscribe: false,
                }),
                SEND,
            )
            .await?;
        }
        let until = (t0 + TTL).min(deadline);
        let mut seen: HashSet<ContractInstanceId> = HashSet::new();
        while seen.len() < n {
            let Some(left) = until.checked_duration_since(Instant::now()) else {
                break;
            };
            match timeout(left, reader.recv()).await {
                Ok(Ok(HostResponse::ContractResponse(ContractResponse::GetResponse {
                    key: k,
                    state,
                    ..
                }))) => {
                    let id = *k.id();
                    // Keyed, and the bytes checked: an answer for another piece
                    // is that piece's, and a wrong body is not an arrival.
                    if want.get(&id).is_some_and(|w| state.as_ref() == w) && seen.insert(id) {
                        hits.push(ms_since(t0));
                    }
                }
                Ok(Ok(_)) => continue,
                _ => break,
            }
        }
    } else {
        let mut outstanding: Vec<ContractKey> = keys.clone();
        let mut hedge_after = t0 + deadline_in / 4;
        while !outstanding.is_empty() && Instant::now() < deadline {
            let mut still = Vec::with_capacity(outstanding.len());
            for key in outstanding {
                if Instant::now() >= deadline {
                    still.push(key);
                    continue;
                }
                // RAW reads one piece at a time, each bounded by the PLATFORM's
                // own TTL — "unbounded" means we add no deadline of our own.
                // BASELINE bounds every attempt itself and moves on.
                let bound = match arm {
                    Arm::Raw => TTL.min(deadline.saturating_duration_since(Instant::now())),
                    _ => attempt,
                };
                attempts += 1;
                let w = want.get(key.id()).expect("every key was minted here");
                if probe(reader, &key, w, bound).await? {
                    hits.push(ms_since(t0));
                } else {
                    still.push(key);
                }
            }
            outstanding = still;

            // W1's hedged re-put, BASELINE only: a piece nobody can read is a
            // piece that may never have landed, and re-offering it costs one put.
            if arm == Arm::Baseline && Instant::now() >= hedge_after && !outstanding.is_empty() {
                for key in &outstanding {
                    let w = want.get(key.id()).expect("minted here");
                    let params = Parameters::from(blake3::hash(w).as_bytes().to_vec());
                    let contract = ContractContainer::Wasm(ContractWasmAPIVersion::V1(
                        WrappedContract::new(code.clone(), params),
                    ));
                    drain(writer).await;
                    send_req(
                        writer,
                        ClientRequest::ContractOp(ContractRequest::Put {
                            contract,
                            state: WrappedState::from(w.clone()),
                            related_contracts: RelatedContracts::default(),
                            subscribe: false,
                            blocking_subscribe: false,
                        }),
                        SEND,
                    )
                    .await?;
                    hedged += 1;
                }
                hedge_after = Instant::now() + deadline_in / 4;
            }
            if !outstanding.is_empty() {
                tokio::time::sleep(GAP).await;
            }
        }
    }

    hits.sort_by(|a, b| a.partial_cmp(b).expect("no NaN"));
    Ok(Group {
        arm,
        to_k: (hits.len() >= k).then(|| hits[k - 1]),
        to_n: (hits.len() == n).then(|| hits[n - 1]),
        readable: hits.len(),
        attempts,
        hedged,
        late_acks,
    })
}

pub struct Opts {
    pub size: usize,
    pub n: usize,
    pub k: usize,
    pub groups: usize,
    pub attempt_ms: u64,
    pub group_secs: u64,
    pub budget_secs: u64,
}

pub async fn run(write_ws: &str, read_ws: &str, wasm: &str, o: Opts) -> Result<()> {
    if o.k == 0 || o.k > o.n {
        bail!("k must be between 1 and n (got k={} n={})", o.k, o.n);
    }
    let bytes = std::fs::read(wasm)?;
    let code_len = bytes.len();
    let code = Arc::new(ContractCode::from(bytes));
    crate::latency::describe_environment(&crate::latency::node_version());
    println!("contract: {wasm} ({code_len} B of code on every put)");
    println!("write on: {write_ws}");
    println!("read on:  {read_ws}");
    println!(
        "STAND-IN: {} unrelated blocks per group, finish at the first {} — a timing shape, not a decode. Erasure is phase 4.",
        o.n, o.k
    );
    println!(
        "bounds:   {} ms per BASELINE read attempt, {} s per group, {} s for the run",
        o.attempt_ms, o.group_secs, o.budget_secs
    );
    let grid = Grid::new(o.attempt_ms as f64, GAP.as_secs_f64() * 1000.0);
    println!("BASELINE {}", grid.line());
    println!();

    let mut writer = crate::connect(write_ws).await?;
    let mut reader = crate::connect(read_ws).await?;
    let attempt = Duration::from_millis(o.attempt_ms.max(50));
    let per_group = Duration::from_secs(o.group_secs.max(1));
    let budget = (o.budget_secs > 0).then(|| Instant::now() + Duration::from_secs(o.budget_secs));

    let mut out: Vec<Group> = Vec::new();
    let mut minted: HashSet<ContractInstanceId> = HashSet::new();
    let mut requests = 0usize;
    let mut cut = false;

    'groups: for g in 0..o.groups {
        for arm in [Arm::Raw, Arm::RawConcurrent, Arm::Baseline] {
            if budget.is_some_and(|d| Instant::now() >= d) {
                cut = true;
                break 'groups;
            }
            let r = one_group(
                &mut writer,
                &mut reader,
                &code,
                arm,
                o.size,
                o.n,
                o.k,
                attempt,
                per_group,
                &mut minted,
                &mut requests,
            )
            .await?;
            progress_pub(format_args!(
                "  group {}/{} {:<8} to-{}: {}  readable {}/{}  attempts {}",
                g + 1,
                o.groups,
                arm.name(),
                o.k,
                r.to_k
                    .map_or("not within T".into(), |v| format!("{v:.0} ms")),
                r.readable,
                o.n,
                r.attempts
            ));
            out.push(r);
        }
    }

    println!();
    let mut unresolved: Vec<String> = Vec::new();
    let mut t = Table::new(
        [
            "arm",
            "groups",
            &format!("reached {} of {}", o.k, o.n),
            "attempts/piece",
            "late acks / hedged",
            "bytes/group",
        ]
        .into_iter()
        .map(String::from)
        .chain(
            ["min", "p50", "p75", "p90", "max"]
                .iter()
                .map(|s| s.to_string()),
        ),
    );
    for arm in [Arm::Raw, Arm::RawConcurrent, Arm::Baseline] {
        let mine: Vec<&Group> = out.iter().filter(|g| g.arm == arm).collect();
        let vals: Vec<f64> = mine.iter().filter_map(|g| g.to_k).collect();
        let att: usize = mine.iter().map(|g| g.attempts).sum();
        let hedged: usize = mine.iter().map(|g| g.hedged).sum();
        let late: usize = mine.iter().map(|g| g.late_acks).sum();
        let head = vec![
            arm.name().to_string(),
            mine.len().to_string(),
            format!("{}/{}", vals.len(), mine.len()),
            if mine.is_empty() {
                "—".into()
            } else {
                format!("{:.1}", att as f64 / (mine.len() * o.n) as f64)
            },
            match arm {
                Arm::Baseline => format!("{hedged} hedged"),
                _ => format!("{late} late"),
            },
            // Every PUT carries the whole contract, so the write side dominates
            // and a hedge costs a full one again. The read side is counted as
            // the piece bytes that actually came back — a miss returns almost
            // nothing, so this is the honest floor rather than attempts x size.
            kib(if mine.is_empty() {
                0
            } else {
                let puts = mine.len() * o.n + hedged;
                let got: usize = mine.iter().map(|g| g.readable).sum();
                (puts * (o.size + code_len) + got * o.size) / mine.len()
            }),
        ];
        if arm == Arm::Baseline {
            if let Some(s) = Summary::of(&vals) {
                if let Some(u) = grid.unresolved(arm.name(), &s) {
                    unresolved.push(u);
                }
            }
        }
        match Summary::of(&vals) {
            Some(s) => t.row(head.into_iter().chain([
                format!("{:.0}", s.min),
                format!("{:.0}", s.p50),
                format!("{:.0}", pct(&vals, 75.0)),
                format!("{:.0}", s.p90),
                format!("{:.0}", s.max),
            ])),
            None => t.row(
                head.into_iter()
                    .chain(["—"; 5].iter().map(|s| s.to_string())),
            ),
        }
    }
    println!(
        "time until {} of {} pieces are readable on the far node (ms), {} per piece",
        o.k,
        o.n,
        kib(o.size)
    );
    print!("{t}");
    for u in &unresolved {
        println!("   {u}");
    }
    println!();

    // What a reader WITHOUT erasure pays: the slowest piece, not the kth.
    let mut t2 = Table::new(["arm", "all n readable", "min", "p50", "p90", "max"]);
    for arm in [Arm::Raw, Arm::RawConcurrent, Arm::Baseline] {
        let mine: Vec<&Group> = out.iter().filter(|g| g.arm == arm).collect();
        let vals: Vec<f64> = mine.iter().filter_map(|g| g.to_n).collect();
        let head = vec![
            arm.name().to_string(),
            format!("{}/{}", vals.len(), mine.len()),
        ];
        match Summary::of(&vals) {
            Some(s) => t2.row(head.into_iter().chain([
                format!("{:.0}", s.min),
                format!("{:.0}", s.p50),
                format!("{:.0}", s.p90),
                format!("{:.0}", s.max),
            ])),
            None => t2.row(
                head.into_iter()
                    .chain(["—"; 4].iter().map(|s| s.to_string())),
            ),
        }
    }
    println!(
        "and the same groups waiting for ALL {} — the statistic erasure exists to avoid",
        o.n
    );
    print!("{t2}");
    println!();

    println!(
        "control: {requests} put requests, {} distinct contract keys — {}",
        minted.len(),
        if minted.len() == requests {
            "every put was a first put"
        } else {
            "REPEATED KEYS: the arms are not comparable"
        }
    );
    let short = out.iter().filter(|g| g.to_k.is_none()).count();
    if short > 0 {
        println!(
            "{short} group(s) never reached {} of {} within {} s and are recorded as `not within T`, not as a latency",
            o.k, o.n, o.group_secs
        );
    }
    if cut {
        println!(
            "the run reached its {} s budget; the groups not taken are NOT within it",
            o.budget_secs
        );
    }
    Ok(())
}

/// Nearest-rank percentile, for the one percentile `Summary` does not carry.
fn pct(v: &[f64], p: f64) -> f64 {
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).expect("no NaN"));
    let rank = ((p / 100.0 * s.len() as f64).ceil() as usize).clamp(1, s.len());
    s[rank - 1]
}
