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
    client_api::{ClientRequest, ContractRequest, ContractResponse, HostResponse, WebApi},
    prelude::*,
};
use tokio::time::timeout;

use crate::{
    latency::{ms_since, progress_pub, send_req},
    stats::{kib, Grid, Summary, Table},
};

/// Between passes over the pieces still outstanding.
const GAP: Duration = Duration::from_millis(10);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Arm {
    Raw,
    Baseline,
}

impl Arm {
    fn name(self) -> &'static str {
        match self {
            Arm::Raw => "RAW",
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

/// One bounded GET. `true` when the far node returned exactly these bytes.
async fn probe(
    reader: &mut WebApi,
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
    writer: &mut WebApi,
    reader: &mut WebApi,
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

    match arm {
        // The platform as it comes: each put is waited on before the next.
        Arm::Raw => {
            for (contract, state) in pieces {
                let key = contract.key();
                send_req(
                    writer,
                    ClientRequest::ContractOp(ContractRequest::Put {
                        contract,
                        state: WrappedState::from(state),
                        related_contracts: RelatedContracts::default(),
                        subscribe: false,
                        blocking_subscribe: false,
                    }),
                    attempt.max(Duration::from_secs(5)),
                )
                .await?;
                // Blocking on the acknowledgement IS the arm. It is bounded
                // only by the group's own deadline, because an unbounded wait
                // is the thing being measured, not a thing to be endured.
                while Instant::now() < deadline {
                    let Some(left) = deadline.checked_duration_since(Instant::now()) else {
                        break;
                    };
                    match timeout(left, writer.recv()).await {
                        Ok(Ok(HostResponse::ContractResponse(ContractResponse::PutResponse {
                            key: got,
                        }))) if got.id() == key.id() => break,
                        Ok(Ok(_)) => continue,
                        _ => break,
                    }
                }
            }
        }
        // Every put issued at once; confirmation is a read-back, not an ack.
        Arm::Baseline => {
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
                    attempt.max(Duration::from_secs(5)),
                )
                .await?;
            }
        }
    }

    // ---- the read side ------------------------------------------------------
    let mut outstanding: Vec<ContractKey> = keys.clone();
    let mut hits: Vec<f64> = Vec::with_capacity(n);
    let mut attempts = 0usize;
    let mut hedge_after = t0 + deadline_in / 4;

    while !outstanding.is_empty() && Instant::now() < deadline {
        let mut still = Vec::with_capacity(outstanding.len());
        for key in outstanding {
            if Instant::now() >= deadline {
                still.push(key);
                continue;
            }
            // RAW reads one piece at a time, each given the whole remaining
            // deadline; BASELINE bounds every attempt and moves on.
            let bound = match arm {
                Arm::Raw => deadline.saturating_duration_since(Instant::now()),
                Arm::Baseline => attempt,
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

        // W1's hedged re-put, BASELINE only: a piece nobody can read is a piece
        // that may never have landed, and re-offering it costs one put.
        if arm == Arm::Baseline && Instant::now() >= hedge_after && !outstanding.is_empty() {
            for key in &outstanding {
                let w = want.get(key.id()).expect("minted here");
                let params = Parameters::from(blake3::hash(w).as_bytes().to_vec());
                let contract = ContractContainer::Wasm(ContractWasmAPIVersion::V1(
                    WrappedContract::new(code.clone(), params),
                ));
                send_req(
                    writer,
                    ClientRequest::ContractOp(ContractRequest::Put {
                        contract,
                        state: WrappedState::from(w.clone()),
                        related_contracts: RelatedContracts::default(),
                        subscribe: false,
                        blocking_subscribe: false,
                    }),
                    Duration::from_secs(5),
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

    hits.sort_by(|a, b| a.partial_cmp(b).expect("no NaN"));
    Ok(Group {
        arm,
        to_k: (hits.len() >= k).then(|| hits[k - 1]),
        to_n: (hits.len() == n).then(|| hits[n - 1]),
        readable: hits.len(),
        attempts,
        hedged,
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
        for arm in [Arm::Raw, Arm::Baseline] {
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
            "hedged re-puts",
        ]
        .into_iter()
        .map(String::from)
        .chain(
            ["min", "p50", "p75", "p90", "max"]
                .iter()
                .map(|s| s.to_string()),
        ),
    );
    for arm in [Arm::Raw, Arm::Baseline] {
        let mine: Vec<&Group> = out.iter().filter(|g| g.arm == arm).collect();
        let vals: Vec<f64> = mine.iter().filter_map(|g| g.to_k).collect();
        let att: usize = mine.iter().map(|g| g.attempts).sum();
        let hedged: usize = mine.iter().map(|g| g.hedged).sum();
        let head = vec![
            arm.name().to_string(),
            mine.len().to_string(),
            format!("{}/{}", vals.len(), mine.len()),
            if mine.is_empty() {
                "—".into()
            } else {
                format!("{:.1}", att as f64 / (mine.len() * o.n) as f64)
            },
            hedged.to_string(),
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
    for arm in [Arm::Raw, Arm::Baseline] {
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
