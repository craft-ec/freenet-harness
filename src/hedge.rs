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

/// Was this trial still unacknowledged when `t` came round?
///
/// The control never hedges, so its population has to be computed from its own
/// acknowledgement times, and it must mean the SAME thing as the hedged arm's
/// "a hedge fired here". Two cases are easy to get wrong and both move every
/// number in the conditional table:
///
/// - a trial whose ack arrived EXACTLY at `t` was not waiting at `t`, so the
///   comparison is strictly greater-than;
/// - a trial that NEVER acked is the most unacknowledged trial there is. It
///   counts. Dropping it would quietly select for the trials that recovered,
///   which is the population the hedge exists to rescue.
fn unacked_at(x: &Trial, t: Duration) -> bool {
    match x.ack {
        Some(a) => a > t.as_secs_f64() * 1000.0,
        None => true,
    }
}

/// What the control did, unaided, on the population a hedge fires on.
///
/// Both halves, always. The single-number form — "96 % acked anyway, so 96 % of
/// hedges were unnecessary" — answered *would it have acked?* when the question
/// is *would it have acked IN TIME?*, and so counted the hedge's best case as
/// its waste. It read as sensible on a datacentre pilot, where there is barely
/// a tail, and was badly wrong on the hotspot, where the unaided acks it called
/// fine had a p90 of 61 seconds.
struct Unaided {
    pool: usize,
    acked: usize,
    p50: Option<f64>,
    p90: Option<f64>,
}

impl Unaided {
    fn of(control: &[Trial], t: Duration) -> Self {
        let pool: Vec<&Trial> = control.iter().filter(|x| unacked_at(x, t)).collect();
        let acks: Vec<f64> = pool.iter().filter_map(|x| x.ack).collect();
        let s = Summary::of(&acks);
        Unaided {
            pool: pool.len(),
            acked: acks.len(),
            p50: s.map(|s| s.p50),
            p90: s.map(|s| s.p90),
        }
    }

    /// The line that replaced the misleading one.
    fn line(&self) -> String {
        match (self.pool, self.p50, self.p90) {
            (0, _, _) | (_, None, _) | (_, _, None) => {
                "no control population at this T to compare against".to_string()
            }
            (pool, Some(p50), Some(p90)) => format!(
                "of the {pool} control trials in the same state, {} acked without help — but at p50 {p50:.0} ms and p90 {p90:.0} ms, so \"unnecessary\" is the wrong word wherever that is slower than the hedged arm above",
                self.acked
            ),
        }
    }

    /// The form this replaced, kept so the suite can show what it said.
    ///
    /// Not dead weight: a defect that is only described is a defect the next
    /// person re-introduces, and the test that pins it is the only place the
    /// old wording can be compared against the new one.
    #[cfg(test)]
    fn misleading_line(&self, hedges: usize) -> String {
        if self.pool == 0 {
            return "no control population to compare against".to_string();
        }
        let rate = self.acked as f64 / self.pool as f64;
        format!(
            "in the control, {:.0} % of trials still unacked at that point acked anyway, so about {:.0} of these hedges were probably unnecessary",
            100.0 * rate,
            rate * hedges as f64
        )
    }
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
    for arm in arms.iter().filter(|a| a.t.is_some()) {
        let t = arm.t.expect("filtered");
        for (label, pool) in [
            (
                "no hedge",
                control
                    .trials
                    .iter()
                    .filter(|x| unacked_at(x, t))
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
        println!(
            "   {}: {hedges} extra puts, {} extra on the wire",
            arm.name(),
            kib(hedges * (o.size + code_len))
        );
        println!("      {}", Unaided::of(&control.trials, t).line());
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A trial with a given acknowledgement time, or none at all.
    fn t(ack: Option<f64>) -> Trial {
        Trial {
            ack,
            readable: Some(500.0),
            hedged: false,
        }
    }

    const T2: Duration = Duration::from_millis(2000);

    /// The population is what every number in the conditional table rests on,
    /// and both of these cases move it.
    #[test]
    fn a_trial_that_never_acked_is_the_most_unacknowledged_trial_there_is() {
        assert!(
            unacked_at(&t(None), T2),
            "never-acked counts, it is not dropped"
        );
        // Dropping it would silently select for the trials that recovered —
        // exactly the population a hedge exists to rescue.
        let control = vec![t(Some(500.0)), t(None), t(Some(9000.0))];
        let u = Unaided::of(&control, T2);
        assert_eq!(
            u.pool, 2,
            "the 500 ms trial was not waiting at 2 s; the other two were"
        );
        assert_eq!(u.acked, 1, "only one of those two ever acked");
    }

    #[test]
    fn the_boundary_is_strictly_after_t() {
        // Acked AT t was not waiting at t.
        assert!(!unacked_at(&t(Some(2000.0)), T2));
        assert!(unacked_at(&t(Some(2000.1)), T2));
        assert!(!unacked_at(&t(Some(1999.9)), T2));
    }

    /// THE WORKED EXAMPLE. The old single-number line on a fixture shaped like
    /// the hotspot result: every unaided trial acked, and its p90 is 61 s.
    #[test]
    fn the_old_waste_line_calls_a_61_second_wait_unnecessary() {
        // Twenty fast and five in the tail. Nearest-rank p90 over 25 samples is
        // the 23rd, so the tail must be at least three deep for the p90 to sit
        // in it; a single slow sample left the p90 at 3000 ms and this test
        // said so — the fixture did not have the shape it claimed.
        let mut control: Vec<Trial> = (0..20).map(|_| t(Some(3000.0))).collect();
        control.extend((0..5).map(|_| t(Some(61_000.0))));
        let u = Unaided::of(&control, T2);
        assert_eq!(u.pool, 25);
        assert_eq!(u.acked, 25);
        assert!(u.p90.is_some_and(|p| p >= 61_000.0), "p90 is in the tail");

        let old = u.misleading_line(25);
        assert!(old.contains("100 %"), "{old}");
        assert!(old.contains("probably unnecessary"), "{old}");
        // That is the defect: a population whose p90 is 61 seconds, described
        // as one that did not need help.
        assert!(
            !old.contains("61000"),
            "the old line never showed WHEN they acked"
        );

        let new = u.line();
        assert!(new.contains("25 acked without help"), "{new}");
        assert!(new.contains("p90 61000 ms"), "{new}");
        assert!(new.contains("\"unnecessary\" is the wrong word"), "{new}");
    }

    /// And on a fixture with no tail — the datacentre shape — the new line is
    /// still correct rather than alarmist: it reports the same two halves and
    /// lets the reader see that the unaided acks were fast.
    #[test]
    fn with_no_tail_the_new_line_reports_fast_unaided_acks() {
        let control: Vec<Trial> = (0..12).map(|_| t(Some(2500.0))).collect();
        let u = Unaided::of(&control, T2);
        let s = u.line();
        assert!(s.contains("p50 2500 ms and p90 2500 ms"), "{s}");
        assert!(s.contains("12 acked without help"), "{s}");
    }

    #[test]
    fn an_empty_population_claims_nothing() {
        let control = vec![t(Some(100.0)), t(Some(200.0))];
        let u = Unaided::of(&control, T2);
        assert_eq!(u.pool, 0);
        assert!(u.line().contains("no control population"));
        assert!(u.misleading_line(5).contains("no control population"));
    }

    /// A population that never acked at all has a pool but no percentiles, and
    /// must not print a ratio over nothing.
    #[test]
    fn a_population_that_never_acked_has_no_percentiles() {
        let control = vec![t(None), t(None)];
        let u = Unaided::of(&control, T2);
        assert_eq!((u.pool, u.acked), (2, 0));
        assert!(u.line().contains("no control population at this T"));
    }

    /// The floor below which a cell must refuse to show a ratio. Mirrors the
    /// rule in the table: a percentile over four samples is a number a reader
    /// will quote and should not.
    #[test]
    fn below_min_report_a_cell_shows_no_finding_and_no_ratio() {
        let min_report = 5usize;
        for pool in 0..min_report {
            let cell = cell_text(pool, min_report);
            assert!(cell.starts_with("no finding"), "n={pool}: {cell}");
            assert!(!cell.contains('%'), "n={pool}: {cell}");
        }
        assert!(!cell_text(min_report, min_report).starts_with("no finding"));
    }

    /// The decision the table makes for one cell, as a string.
    fn cell_text(pool: usize, min_report: usize) -> String {
        if pool < min_report {
            format!("no finding (n={pool} < {min_report})")
        } else {
            format!("p50 over {pool} samples")
        }
    }
}
