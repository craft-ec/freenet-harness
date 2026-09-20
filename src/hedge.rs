//! `hedge`: does re-putting a block make its acknowledgement arrive sooner?
//!
//! The flat 60 s relay wait (F20, freenet-core#5446) lands on roughly one PUT
//! in ten. Re-putting an immutable block is idempotent, so a writer that has
//! not been acknowledged by T can simply offer the same bytes again and race
//! the two. freenet-harness#11 asks whether that helps, because if it does it
//! is the engine's `published` strategy too (ARCHITECTURE §7).
//!
//! **It is a trade, so both sides are in one table.** A hedge costs an extra
//! PUT, and every PUT carries the whole contract — about 120 KiB of code
//! (F28) — so the question is never "is it faster" alone.
//!
//! The comparison that matters is CONDITIONAL. Most puts are acknowledged in a
//! second or two and no hedge ever fires; averaging those in would bury the
//! effect under trials the strategy never touched. So the table reports, for
//! each T, the population of trials STILL UNACKNOWLEDGED AT T — the ones a
//! hedge actually fires on — and compares them against the control arm's
//! trials that were also still unacknowledged at the same instant.

use std::{
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

/// A send may block on a slow uplink while the node is perfectly healthy.
const SEND: Duration = Duration::from_secs(60);
/// One read-back attempt. Also this clock's resolution, which the run prints.
const PROBE: Duration = Duration::from_millis(250);
/// How long the loop waits on the websocket before looking at the clock again.
const TICK: Duration = Duration::from_millis(50);

/// One trial.
struct Trial {
    /// ms from the first send to the first acknowledgement for this key.
    ack: Option<f64>,
    /// ms from the first send until the block read back.
    readable: Option<f64>,
    hedged: bool,
}

struct Arm {
    /// `None` = the control, which never hedges.
    t: Option<Duration>,
    trials: Vec<Trial>,
}

impl Arm {
    fn name(&self) -> String {
        match self.t {
            None => "no hedge (control)".into(),
            Some(t) => format!("hedge at {}", secs(t)),
        }
    }
}

/// `2 s`, `500 ms` — `as_secs()` alone printed a 500 ms arm as "0 s".
fn secs(d: Duration) -> String {
    if d.as_millis().is_multiple_of(1000) {
        format!("{} s", d.as_secs())
    } else {
        format!("{} ms", d.as_millis())
    }
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

async fn put(writer: &mut WebApi, contract: ContractContainer, state: &[u8]) -> Result<()> {
    send_req(
        writer,
        ClientRequest::ContractOp(ContractRequest::Put {
            contract,
            state: WrappedState::from(state.to_vec()),
            related_contracts: RelatedContracts::default(),
            subscribe: false,
            blocking_subscribe: false,
        }),
        SEND,
    )
    .await
}

/// One trial: put, optionally hedge at `t`, and watch both clocks.
#[allow(clippy::too_many_arguments)]
async fn trial(
    writer: &mut WebApi,
    reader: &mut WebApi,
    code: &Arc<ContractCode<'static>>,
    size: usize,
    t: Option<Duration>,
    deadline_in: Duration,
) -> Result<Trial> {
    let (contract, state) = mint(code, size)?;
    let key = contract.key();
    let id = *key.id();

    let t0 = Instant::now();
    let deadline = t0 + deadline_in;
    put(writer, contract, &state).await?;

    let mut out = Trial {
        ack: None,
        readable: None,
        hedged: false,
    };
    let fire_at = t.map(|d| t0 + d);
    let mut marked = false;
    let mut next_probe = t0;

    while Instant::now() < deadline && (out.ack.is_none() || out.readable.is_none()) {
        let now = Instant::now();

        // The mark is taken in BOTH arms, so "still unacked at T" means the
        // same thing on each side of the comparison.
        if let Some(at) = fire_at {
            if !marked && now >= at {
                marked = true;
                if out.ack.is_none() {
                    // The SAME bytes under the SAME key: re-putting an
                    // immutable block is idempotent, so this is a second offer
                    // of one block and not a new block.
                    let params = Parameters::from(blake3::hash(&state).as_bytes().to_vec());
                    let same = ContractContainer::Wasm(ContractWasmAPIVersion::V1(
                        WrappedContract::new(code.clone(), params),
                    ));
                    put(writer, same, &state).await?;
                    out.hedged = true;
                }
            }
        }

        // A read-back attempt, on the SECOND connection so it never queues
        // behind the writer's acknowledgements.
        if out.readable.is_none() && now >= next_probe {
            send_req(
                reader,
                ClientRequest::ContractOp(ContractRequest::Get {
                    key: id,
                    return_contract_code: false,
                    subscribe: false,
                    blocking_subscribe: false,
                }),
                SEND,
            )
            .await?;
            let end = Instant::now() + PROBE;
            while let Some(left) = end.checked_duration_since(Instant::now()) {
                match timeout(left, reader.recv()).await {
                    Ok(Ok(HostResponse::ContractResponse(ContractResponse::GetResponse {
                        key: k,
                        state: got,
                        ..
                    }))) if k.id() == &id => {
                        if got.as_ref() == state.as_slice() {
                            out.readable = Some(ms_since(t0));
                        }
                        break;
                    }
                    Ok(Ok(_)) => continue,
                    _ => break,
                }
            }
            next_probe = Instant::now() + PROBE;
        }

        // And a short look at the writer for the acknowledgement.
        if out.ack.is_none() {
            match timeout(TICK, writer.recv()).await {
                Ok(Ok(HostResponse::ContractResponse(ContractResponse::PutResponse {
                    key: k,
                }))) if k.id() == &id => out.ack = Some(ms_since(t0)),
                // Another key's answer, or another kind: not this trial's.
                Ok(Ok(_)) => continue,
                Ok(Err(e)) => bail!("node error while waiting for an ack: {e}"),
                Err(_) => continue,
            }
        }
    }
    Ok(out)
}

pub struct Opts {
    pub wasm: String,
    pub expect_sha: String,
    pub size: usize,
    pub ts_ms: Vec<u64>,
    /// Stop once every T has this many CONDITIONED trials — hedges actually
    /// fired, and control trials that were in the same state at the same
    /// instant.
    ///
    /// Sizing by rounds is what a first version did, and it cannot work: with a
    /// tail on roughly one put in ten, thirty rounds leaves about THREE
    /// conditioned trials per T, and three against three can show neither that
    /// a hedge helps nor that it does not. The second of those is the result
    /// that would redirect the engine, so it has to be reachable.
    pub target_conditioned: usize,
    /// A cell below this many conditioned trials reports "no finding" in words
    /// rather than a ratio nobody should read.
    pub min_report: usize,
    /// A cap, so a condition with no tail at all cannot run forever.
    pub max_rounds: usize,
    pub trial_secs: u64,
    pub budget_secs: u64,
}

pub async fn run(ws: &str, o: Opts) -> Result<()> {
    if o.ts_ms.is_empty() || o.max_rounds == 0 {
        bail!("nothing to measure: --ts-ms and --max-rounds must both be non-empty");
    }
    let bytes = crate::wasm_check::load(&o.wasm, &o.expect_sha)?;
    let code_len = bytes.len();
    let code = Arc::new(ContractCode::from(bytes));
    crate::latency::describe_environment(&crate::latency::node_version());
    println!(
        "contract: {} ({code_len} B of code on EVERY put, hedges included)",
        o.wasm
    );
    let grid = Grid::new(PROBE.as_secs_f64() * 1000.0, 0.0);
    println!("read-back {}", grid.line());
    println!(
        "bounds:   {} s per trial, {} s for the whole run, {} per block",
        o.trial_secs,
        o.budget_secs,
        kib(o.size)
    );
    println!(
        "stop:     when every T has {} conditioned trials on BOTH sides, or at {} rounds, or at the budget",
        o.target_conditioned, o.max_rounds
    );
    println!();

    let mut writer = crate::connect(ws).await?;
    let mut reader = crate::connect(ws).await?;
    let mut arms: Vec<Arm> = std::iter::once(Arm {
        t: None,
        trials: Vec::new(),
    })
    .chain(o.ts_ms.iter().map(|&ms| Arm {
        t: Some(Duration::from_millis(ms)),
        trials: Vec::new(),
    }))
    .collect();

    let budget = (o.budget_secs > 0).then(|| Instant::now() + Duration::from_secs(o.budget_secs));
    let per_trial = Duration::from_secs(o.trial_secs.max(1));
    let mut cut = false;

    // How many CONDITIONED trials each T has so far, on both sides. The loop
    // stops on this rather than on a round count, because rounds buy trials the
    // strategy never touches.
    let conditioned = |arms: &[Arm], t: Duration| -> (usize, usize) {
        let ctl = arms
            .iter()
            .find(|a| a.t.is_none())
            .map(|c| {
                c.trials
                    .iter()
                    .filter(|x| x.ack.is_none_or(|a| a > t.as_secs_f64() * 1000.0))
                    .count()
            })
            .unwrap_or(0);
        let fired = arms
            .iter()
            .find(|a| a.t == Some(t))
            .map(|a| a.trials.iter().filter(|x| x.hedged).count())
            .unwrap_or(0);
        (ctl, fired)
    };
    let enough = |arms: &[Arm]| -> bool {
        o.ts_ms.iter().all(|&ms| {
            let (c, f) = conditioned(arms, Duration::from_millis(ms));
            c >= o.target_conditioned && f >= o.target_conditioned
        })
    };

    let mut rounds = 0usize;
    let mut cut_reason = "";
    'rounds: for r in 0..o.max_rounds {
        if enough(&arms) {
            cut_reason = "every T reached its conditioned target";
            break;
        }
        for arm in arms.iter_mut() {
            if budget.is_some_and(|d| Instant::now() >= d) {
                cut = true;
                cut_reason = "the budget";
                break 'rounds;
            }
            let x = trial(&mut writer, &mut reader, &code, o.size, arm.t, per_trial).await?;
            progress_pub(format_args!(
                "  r{} {:<18} ack {}  readable {}{}",
                r + 1,
                arm.name(),
                x.ack.map_or("—".into(), |v| format!("{v:.0} ms")),
                x.readable.map_or("—".into(), |v| format!("{v:.0} ms")),
                if x.hedged { "  HEDGED" } else { "" }
            ));
            arm.trials.push(x);
        }
        rounds = r + 1;
        // Say where the conditioned counts stand, so a long run is legible
        // while it is happening rather than only at the end.
        if rounds.is_multiple_of(10) {
            let state: Vec<String> = o
                .ts_ms
                .iter()
                .map(|&ms| {
                    let (c, f) = conditioned(&arms, Duration::from_millis(ms));
                    format!("{}s {c}/{f}", ms / 1000)
                })
                .collect();
            progress_pub(format_args!(
                "  after {rounds} rounds, conditioned control/hedged per T: {}  (target {})",
                state.join("  "),
                o.target_conditioned
            ));
        }
    }
    if cut_reason.is_empty() {
        cut_reason = "the round cap";
    }

    // ---- the headline table -------------------------------------------------
    let mut t = Table::new(
        ["arm", "trials", "acked", "hedges", "extra bytes"]
            .into_iter()
            .map(String::from)
            .chain(
                ["ack p50", "ack p90", "ack max"]
                    .iter()
                    .map(|s| s.to_string()),
            ),
    );
    for arm in &arms {
        let acks: Vec<f64> = arm.trials.iter().filter_map(|x| x.ack).collect();
        let hedges = arm.trials.iter().filter(|x| x.hedged).count();
        let head = vec![
            arm.name(),
            arm.trials.len().to_string(),
            format!("{}/{}", acks.len(), arm.trials.len()),
            hedges.to_string(),
            kib(hedges * (o.size + code_len)),
        ];
        match Summary::of(&acks) {
            Some(s) => t.row(head.into_iter().chain([
                format!("{:.0}", s.p50),
                format!("{:.0}", s.p90),
                format!("{:.0}", s.max),
            ])),
            None => t.row(
                head.into_iter()
                    .chain(["—"; 3].iter().map(|s| s.to_string())),
            ),
        }
    }
    println!("1. every trial — most puts are acknowledged quickly and no hedge fires, so this");
    println!("   table is DILUTED by trials the strategy never touched");
    print!("{t}");
    println!();

    // ---- the comparison that answers the question ---------------------------
    //
    // Per T, and both arms on the SAME population: trials that were still
    // unacknowledged when T came round. For the hedged arm that is exactly the
    // trials where a hedge fired. For the control it is computed from its own
    // acknowledgement times — it never hedges, so "still unacked at T" means
    // "its ack came later than T, or never". Comparing whole arms instead
    // would bury the effect under trials the strategy never touched.
    let control = arms
        .iter()
        .find(|a| a.t.is_none())
        .expect("the control arm is always built");
    let mut t2 = Table::new([
        "T",
        "arm",
        "still unacked at T",
        "of those, acked later",
        "ack p50",
        "ack p90",
        "ack max",
    ]);
    let late = |x: &&Trial, t: Duration| -> bool {
        match x.ack {
            Some(a) => a > t.as_secs_f64() * 1000.0,
            None => true,
        }
    };
    for arm in arms.iter().filter(|a| a.t.is_some()) {
        let t = arm.t.expect("filtered");
        for (label, pool) in [
            (
                "no hedge",
                control
                    .trials
                    .iter()
                    .filter(|x| late(x, t))
                    .collect::<Vec<_>>(),
            ),
            (
                "hedged",
                arm.trials.iter().filter(|x| x.hedged).collect::<Vec<_>>(),
            ),
        ] {
            let acks: Vec<f64> = pool.iter().filter_map(|x| x.ack).collect();
            let head = vec![
                secs(t),
                label.to_string(),
                pool.len().to_string(),
                format!("{}/{}", acks.len(), pool.len()),
            ];
            // A ratio over four samples is a number a reader will quote and
            // should not. Below the floor the row says so in words instead.
            if pool.len() < o.min_report {
                t2.row(head.into_iter().chain([
                    "no finding".to_string(),
                    format!("n={} < {}", pool.len(), o.min_report),
                    String::new(),
                ]));
                continue;
            }
            match Summary::of(&acks) {
                Some(s) => t2.row(head.into_iter().chain([
                    format!("{:.0}", s.p50),
                    format!("{:.0}", s.p90),
                    format!("{:.0}", s.max),
                ])),
                None => t2.row(
                    head.into_iter()
                        .chain(["—"; 3].iter().map(|s| s.to_string())),
                ),
            }
        }
    }
    println!("2. ONLY the trials still unacknowledged at T — the population a hedge fires on,");
    println!("   with the control's trials that were in the same state at the same instant");
    print!("{t2}");
    println!();

    // ---- what the hedges cost ----------------------------------------------
    //
    // "Wasted" cannot be observed directly: both offers carry the same key, so
    // an acknowledgement does not say which one produced it. The obvious proxy
    // — how many control trials still unacked at T acked ANYWAY — turned out to
    // be actively misleading, and the hotspot run is what showed it. There, 96%
    // of them did ack anyway, which reads as "96% of hedges were pointless"
    // until you look at WHEN: the control's p90 was 61 seconds. They acked, at
    // the far end of the tail, which is precisely the wait the hedge exists to
    // cut. So the line reports both halves and refuses to call the first one
    // waste on its own.
    println!("3. what the hedges cost, and what the control did without them");
    for arm in arms.iter().filter(|a| a.t.is_some()) {
        let hedges = arm.trials.iter().filter(|x| x.hedged).count();
        let t = arm.t.expect("filtered to hedged arms");
        let pool: Vec<&Trial> = control.trials.iter().filter(|x| late(x, t)).collect();
        let acked_anyway = pool.iter().filter(|x| x.ack.is_some()).count();
        let when = Summary::of(&pool.iter().filter_map(|x| x.ack).collect::<Vec<f64>>());
        println!(
            "   {}: {hedges} extra puts, {} extra on the wire",
            arm.name(),
            kib(hedges * (o.size + code_len))
        );
        match (pool.is_empty(), when) {
            (true, _) | (_, None) => {
                println!("      no control population at this T to compare against")
            }
            (false, Some(w)) => println!(
                "      of the {} control trials in the same state, {acked_anyway} acked without help — \
                 but at p50 {:.0} ms and p90 {:.0} ms, so \"unnecessary\" is the wrong word \
                 wherever that is slower than the hedged arm above",
                pool.len(),
                w.p50,
                w.p90
            ),
        }
    }

    println!();
    println!("stopped after {rounds} rounds on {cut_reason}.");
    println!("conditioned trials per T (control / hedged), which is what these rows rest on:");
    for &ms in &o.ts_ms {
        let t = Duration::from_millis(ms);
        let (c, f) = conditioned(&arms, t);
        println!(
            "   {}: {c} / {f}  (target {}){}",
            secs(t),
            o.target_conditioned,
            if c < o.min_report || f < o.min_report {
                " — TOO FEW, that row reports no finding"
            } else if c < o.target_conditioned || f < o.target_conditioned {
                " — under target, treat the row as weak"
            } else {
                ""
            }
        );
    }
    if cut {
        println!(
            "the run reached its {} s budget; what it did not reach is NOT within it",
            o.budget_secs
        );
    }
    Ok(())
}
