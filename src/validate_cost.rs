//! `validate-cost`: what does the host's re-validation actually cost?
//!
//! The source says the host calls `validate_state` over the FULL new state
//! after every `update_state`, before comparing the result with the current
//! state (freenet v0.2.135, `contract_ops.rs:375-391`). That is a claim about
//! code; this measures the consequence.
//!
//! Four arms, because "a no-op update" is not one thing:
//!
//! - `growth` — each update appends a chunk. If the host re-validates the full
//!   state, per-update latency grows LINEARLY with accumulated state; if it
//!   validated only the delta it would be flat.
//! - `distinct-noop` — updates whose bytes differ but whose merged result does
//!   not. The node's `broadcast_dedup_cache` hashes the payload, not the
//!   outcome, so this is the shape it cannot collapse.
//! - `repeat-delta` — the identical delta every time, the shape dedup CAN see.
//! - `repeat-state` — the identical FULL state every time, which
//!   `executor_impl.rs:885-899` short-circuits before any wasm call.
//!
//! Run the whole thing twice, with the fixture's work in `validate_state`
//! (`--mode 0`) and in `update_state` (`--mode 1`). One arm cannot separate
//! "the host re-validates" from "the merge is expensive"; the pair can.

use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, bail, Result};
use freenet_stdlib::{
    client_api::{ClientRequest, ContractRequest, ContractResponse, HostResponse},
    prelude::*,
};
use tokio::time::timeout;

use crate::{
    latency::{ms_since, progress_pub, put_container, send_req, Sample},
    stats::{kib, Summary, Table},
};

const TAG_APPEND: u8 = 0x01;
const TAG_NOOP: u8 = 0xFF;

#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Arm {
    /// Append a chunk per update; state grows.
    Growth,
    /// Distinct bytes, identical outcome — dedup cannot collapse these.
    DistinctNoop,
    /// The same delta bytes every time.
    RepeatDelta,
    /// The same full state every time.
    RepeatState,
}

impl Arm {
    fn label(self) -> &'static str {
        match self {
            Arm::Growth => "growth",
            Arm::DistinctNoop => "distinct-noop",
            Arm::RepeatDelta => "repeat-delta",
            Arm::RepeatState => "repeat-state",
        }
    }
}

/// `[mode, repeat_le32, salt]` — the fixture rejects anything shorter.
///
/// The salt makes each run a distinct contract. A key is `hash(code, params)`,
/// so without it two runs with the same mode and repeat share an instance and
/// the second run's seed put is a merge into the first run's state — which
/// fails the fixture's own update rules and, had it succeeded, would have
/// measured the wrong state entirely.
fn params(mode: u8, repeat: u32, salt: &[u8; 16]) -> Parameters<'static> {
    let mut p = vec![mode];
    p.extend_from_slice(&repeat.to_le_bytes());
    p.extend_from_slice(salt);
    Parameters::from(p)
}

async fn timed_update(
    client: &mut crate::probe::Client,
    key: &ContractKey,
    data: UpdateData<'static>,
    wait: Duration,
) -> Result<Sample> {
    let t = std::time::Instant::now();
    send_req(
        client,
        ClientRequest::ContractOp(ContractRequest::Update { key: *key, data }),
        wait,
    )
    .await?;
    Ok(match timeout(wait, client.recv()).await {
        Ok(Ok(HostResponse::ContractResponse(ContractResponse::UpdateResponse {
            key: k, ..
        }))) if k.id() == key.id() => Sample::Ms(ms_since(t)),
        Ok(Ok(other)) => Sample::Failed(format!("unexpected response: {other:?}")),
        Ok(Err(e)) => Sample::Failed(format!("node error: {e}")),
        Err(_) => Sample::Failed(format!("no response within {} s", wait.as_secs())),
    })
}

/// One update's observation, paired with the state size it ran against.
struct Row {
    i: usize,
    state_len: usize,
    sample: Sample,
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    ws: &str,
    wasm: &str,
    mode: u8,
    repeat: u32,
    arm: Arm,
    updates: usize,
    chunk: usize,
    preload: usize,
    salt_hex: Option<&str>,
    wait: Duration,
) -> Result<()> {
    let code = Arc::new(ContractCode::from(std::fs::read(wasm).map_err(|e| {
        anyhow!("{wasm}: {e} — run fixtures/validate-cost-contract/build.sh first")
    })?));
    // A caller-supplied salt makes the key reproducible, so a SECOND node can
    // address the same contract — which is the whole point of the two-node
    // arm. Random otherwise, so ordinary runs never collide.
    let mut salt = [0u8; 16];
    match salt_hex {
        Some(h) => {
            let h = h.trim();
            if h.len() != 32 {
                bail!("--salt must be 32 hex chars (16 bytes), got {}", h.len());
            }
            for (i, b) in salt.iter_mut().enumerate() {
                *b = u8::from_str_radix(&h[i * 2..i * 2 + 2], 16)
                    .map_err(|e| anyhow!("--salt is not hex: {e}"))?;
            }
        }
        None => getrandom::getrandom(&mut salt)?,
    }
    let contract = ContractContainer::Wasm(ContractWasmAPIVersion::V1(WrappedContract::new(
        code,
        params(mode, repeat, &salt),
    )));
    let key = contract.key();
    println!(
        "contract: {}  salt={}",
        key.id(),
        salt.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    let mut client = crate::connect(ws).await?;

    let mut state: Vec<u8> = salt.to_vec();
    state.resize(preload.max(salt.len()), b'.');

    let t = std::time::Instant::now();
    put_container(&mut client, contract, &state, wait).await?;
    println!(
        "seed: mode={mode} repeat={repeat} arm={} initial state {} in {:.1} ms",
        arm.label(),
        kib(state.len()),
        ms_since(t)
    );

    let mut rows = Vec::with_capacity(updates);
    // For the repeat arms, one payload minted once and reused verbatim.
    let fixed_noop = {
        let mut d = vec![TAG_NOOP];
        d.extend_from_slice(&salt);
        d
    };
    for i in 0..updates {
        let before = state.len();
        let data = match arm {
            Arm::Growth => {
                let mut d = vec![TAG_APPEND];
                d.resize(1 + chunk, b'x');
                state.extend_from_slice(&d[1..]);
                UpdateData::Delta(StateDelta::from(d))
            }
            Arm::DistinctNoop => {
                // Same outcome, different bytes every time.
                let mut d = vec![TAG_NOOP];
                d.extend_from_slice(&(i as u64).to_le_bytes());
                d.extend_from_slice(&salt);
                UpdateData::Delta(StateDelta::from(d))
            }
            Arm::RepeatDelta => UpdateData::Delta(StateDelta::from(fixed_noop.clone())),
            Arm::RepeatState => UpdateData::State(State::from(state.clone())),
        };
        let sample = timed_update(&mut client, &key, data, wait).await?;
        progress_pub(format_args!(
            "  {} {i}/{updates} state {} -> {}",
            arm.label(),
            kib(before),
            match &sample {
                Sample::Ms(v) => format!("{v:.1} ms"),
                Sample::Failed(e) => format!("ERROR {e}"),
            }
        ));
        rows.push(Row {
            i,
            state_len: before,
            sample,
        });
    }
    let _ = client.send(ClientRequest::Disconnect { cause: None }).await;

    report(arm, mode, repeat, &rows);
    Ok(())
}

fn report(arm: Arm, mode: u8, repeat: u32, rows: &[Row]) {
    println!();
    println!(
        "validate-cost  arm={}  mode={} ({})  repeat={repeat}",
        arm.label(),
        mode,
        if mode == 0 {
            "work in validate_state"
        } else {
            "work in update_state"
        }
    );
    let mut t = Table::new(["update", "state", "latency ms"]);
    for r in rows {
        t.row([
            r.i.to_string(),
            kib(r.state_len),
            match &r.sample {
                Sample::Ms(v) => format!("{v:.1}"),
                Sample::Failed(_) => "ERROR".to_string(),
            },
        ]);
    }
    print!("{t}");

    let ok: Vec<(f64, f64)> = rows
        .iter()
        .filter_map(|r| match &r.sample {
            Sample::Ms(v) => Some((r.state_len as f64, *v)),
            Sample::Failed(_) => None,
        })
        .collect();
    let lat: Vec<f64> = ok.iter().map(|(_, v)| *v).collect();
    match Summary::of(&lat) {
        Some(s) => println!(
            "  n={} errors={}  min {:.1}  p50 {:.1}  p90 {:.1}  max {:.1}",
            s.n,
            rows.len() - ok.len(),
            s.min,
            s.p50,
            s.p90,
            s.max
        ),
        None => println!("  no successful updates"),
    }
    // Least squares on latency vs state size. The slope is the number the
    // design question turns on: > 0 means the cost tracks the whole state.
    if ok.len() >= 3 {
        let n = ok.len() as f64;
        let (sx, sy): (f64, f64) = ok.iter().fold((0.0, 0.0), |a, (x, y)| (a.0 + x, a.1 + y));
        let (mx, my) = (sx / n, sy / n);
        let num: f64 = ok.iter().map(|(x, y)| (x - mx) * (y - my)).sum();
        let den: f64 = ok.iter().map(|(x, _)| (x - mx).powi(2)).sum();
        if den > 0.0 {
            let slope = num / den;
            println!(
                "  fit: {:.4} ms per KiB of state ({:+.1} ms at 1 MiB), intercept {:.1} ms",
                slope * 1024.0,
                slope * 1024.0 * 1024.0,
                my - slope * mx
            );
        } else {
            println!("  fit: state size constant across this arm — slope undefined, as expected");
        }
    }
    println!();
}
