//! Drives a real Freenet node: round-trips Blocks, measures put/get latency,
//! probes delegate capabilities.

mod bag;
mod latency;
mod pack;
mod putshape;
mod register;
mod set;
mod stats;
mod validate_cost;
mod wasm_check;
mod watch;
mod xnode;

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Result};
use clap::{Parser, Subcommand};
use craftec_block_contract as block;
use freenet_stdlib::{
    client_api::{
        ClientRequest, ContractRequest, ContractResponse, DelegateRequest, HostResponse, WebApi,
    },
    prelude::*,
};
use tokio::time::timeout;

#[derive(Parser)]
struct Cli {
    /// The node's client API.
    #[arg(
        long,
        default_value = "ws://127.0.0.1:7509/v1/contract/command?encodingProtocol=native"
    )]
    ws: String,
    /// Target the LOCAL-mode node (port 7609) instead of the network node.
    ///
    /// Anything asking "does the contract behave" belongs here: local mode
    /// pays ~30 ms per put and has no relay tail, so a functional round-trip
    /// finishes in seconds. Network mode is for propagation, latency and byte
    /// measurements only — and every table says which one produced it.
    #[arg(long, default_value_t = false)]
    local: bool,
    #[arg(long, default_value_t = 120)]
    timeout_secs: u64,
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Put N fresh blocks of SIZE bytes, then get each back and compare.
    Roundtrip {
        #[arg(long, default_value = "../freenet-contracts/build/block.wasm")]
        wasm: String,
        #[arg(long, default_value_t = 3)]
        n: usize,
        #[arg(long, default_value_t = 4096)]
        size: usize,
    },
    /// Does this node run delegate wakeups and delegate-originated contract GETs?
    DelegateProbe {
        #[arg(long, default_value = "../freenet-contracts/build/block.wasm")]
        block_wasm: String,
        /// Probe built without the wakeup import.
        #[arg(long, default_value = "build/probe.wasm")]
        delegate_wasm: String,
        /// Probe built with the wakeup import (a node lacking it cannot load this).
        #[arg(long, default_value = "build/probe-wakeup.wasm")]
        wakeup_wasm: String,
        /// Wakeup delay to request, seconds.
        #[arg(long, default_value_t = 3)]
        wake_secs: u32,
    },
    /// Put/get latency per contract kind and size, parallel-put behaviour, and
    /// whether a delegate may put (FREENET-CONSTRAINTS F15).
    Latency {
        #[arg(long, default_value = "../freenet-contracts/build/block.wasm")]
        wasm: String,
        /// Probe delegate used for the delegate-put question.
        #[arg(long, default_value = "build/probe.wasm")]
        delegate_wasm: String,
        /// Samples per kind and size. The issue asks for at least 30.
        #[arg(long, default_value_t = 30)]
        samples: usize,
        /// Body sizes in bytes.
        #[arg(long, value_delimiter = ',', default_values_t = [1024, 4096, 16384, 262144])]
        sizes: Vec<usize>,
        /// How many puts to issue at once, per parallel run.
        #[arg(long, value_delimiter = ',', default_values_t = [4, 8, 16, 32])]
        parallel: Vec<usize>,
        /// Body size for the parallel runs.
        #[arg(long, default_value_t = 4096)]
        parallel_size: usize,
        /// Largest k of puts asked for from a single delegate process() return.
        #[arg(long, default_value_t = 8)]
        max_k: usize,
        /// Run only one of the four measurements.
        #[arg(long, value_enum, default_value_t = latency::Part::All)]
        only: latency::Part,
        /// Ask the node to return the contract CODE with each GET, not just
        /// the state — does code ride reads as well as writes?
        #[arg(long, default_value_t = false)]
        return_code: bool,
        /// Total seconds for the WHOLE run. At the budget it reports what it
        /// has and says what it did not measure; 0 turns it off. Nobody is
        /// sitting here watching, so a run with no budget is a run that can
        /// take a night.
        #[arg(long, default_value_t = 600)]
        budget_secs: u64,
    },
    /// What does the host's re-validation of the full state after every
    /// update actually cost? Uses the validate-cost fixture.
    ValidateCost {
        #[arg(long, default_value = "build/validate-cost.wasm")]
        wasm: String,
        /// 0 = work in validate_state, 1 = work in update_state.
        #[arg(long, default_value_t = 0)]
        mode: u8,
        /// BLAKE3 passes over the whole state per call (the calibration).
        #[arg(long, default_value_t = 1)]
        repeat: u32,
        #[arg(long, value_enum, default_value_t = validate_cost::Arm::Growth)]
        arm: validate_cost::Arm,
        #[arg(long, default_value_t = 20)]
        updates: usize,
        /// Bytes appended per update on the growth arm.
        #[arg(long, default_value_t = 16384)]
        chunk: usize,
        /// Seed the state to this size before the first update.
        #[arg(long, default_value_t = 0)]
        preload: usize,
        /// 32 hex chars. Fixes the contract key so another node can address
        /// the same contract; random when omitted.
        #[arg(long)]
        salt: Option<String>,
    },
    /// Bag contract live-node round trip (#7). Runs in --local.
    Bag {
        #[arg(long, default_value = "../freenet-contracts/build/bag.wasm")]
        wasm: String,
        #[arg(long, default_value_t = 8)]
        work_bits: u8,
        #[arg(long, default_value_t = 8)]
        m: u16,
        /// REQUIRED. Refuse to run unless the wasm has this sha256 (prefix
        /// accepted). A parameter, not a constant: these move on every
        /// contract change. Required because the safe path must be the
        /// default — an omitted check and a passing check look identical in
        /// the output, and a round trip against a stale artefact reports a
        /// PASS for a contract nobody ships.
        #[arg(long)]
        expect_sha: String,
    },
    /// Register contract live-node round trip. Runs in --local.
    Register {
        #[arg(long, default_value = "../freenet-contracts/build/register.wasm")]
        wasm: String,
        /// REQUIRED — see `bag --expect-sha`.
        #[arg(long)]
        expect_sha: String,
    },
    /// PACK acceptance on the block path: what a pack may carry and what it
    /// must refuse, each refusal paired with its control. Runs in --local.
    Pack {
        #[arg(long, default_value = "../freenet-contracts/build/block.wasm")]
        wasm: String,
        /// REQUIRED — see `bag --expect-sha`.
        #[arg(long)]
        expect_sha: String,
    },
    /// The same payload put as ONE contract or as k in parallel: which shape
    /// commits sooner, and what each costs in bytes.
    PutShape {
        #[arg(long, default_value = "build/accept-all.wasm")]
        wasm: String,
        /// Payload bytes per trial, the same for every arm.
        #[arg(long, default_value_t = 1048576)]
        total: usize,
        /// How many pieces to split the payload into. Each must divide `total`.
        #[arg(long, value_delimiter = ',', default_values_t = [1usize, 2, 4])]
        splits: Vec<usize>,
        /// Trials per arm. The arms are interleaved, so round r is taken for
        /// every arm before round r+1 is taken for any.
        #[arg(long, default_value_t = 10)]
        rounds: usize,
        /// Total seconds for the whole run; 0 turns it off.
        #[arg(long, default_value_t = 600)]
        budget_secs: u64,
        /// How long one read-back GET attempt waits. This sets the resolution
        /// of the read-back clock: nothing finer than this plus the gap
        /// between passes can be measured, and the run says so.
        #[arg(long, default_value_t = 120)]
        probe_ms: u64,
    },
    /// Set contract live-node round trip. Runs in --local.
    Set {
        #[arg(long, default_value = "../freenet-contracts/build/set.wasm")]
        wasm: String,
        /// REQUIRED — see `bag --expect-sha`.
        #[arg(long)]
        expect_sha: String,
    },
    /// Cross-node: write blocks on one node, then measure on ANOTHER how
    /// long until each is readable there.
    Xnode {
        /// write | read | clock
        #[arg(long)]
        role: String,
        #[arg(long, default_value = "../freenet-contracts/build/block.wasm")]
        wasm: String,
        /// File of PUT lines produced by the write role.
        #[arg(long, default_value = "keys.txt")]
        keys: String,
        /// The reader's log, for `--role pair`.
        #[arg(long, default_value = "reads.txt")]
        reads: String,
        #[arg(long, default_value_t = 20)]
        samples: usize,
        #[arg(long, value_delimiter = ',', default_values_t = [1024, 16384, 262144])]
        sizes: Vec<usize>,
        /// Ask for the contract code on every read probe.
        #[arg(long, default_value_t = false)]
        return_code: bool,
        /// Bound on each probe, and the gap between probes.
        #[arg(long, default_value_t = 500)]
        probe_ms: u64,
        /// Give up on a key after this long.
        #[arg(long, default_value_t = 120)]
        limit_secs: u64,
    },
    /// Cold-GET a contract, subscribe, and report what arrives — run on the
    /// FAR node to see whether the near node's updates reach it.
    Watch {
        /// Contract instance id, as `validate-cost` prints it.
        #[arg(long)]
        key: String,
        #[arg(long, default_value_t = 60)]
        secs: u64,
    },
}

pub(crate) async fn connect(ws: &str) -> Result<WebApi> {
    let (stream, _) = tokio_tungstenite::connect_async(ws)
        .await
        .map_err(|e| anyhow!("cannot reach the node at {ws}: {e}"))?;
    Ok(WebApi::start(stream))
}

/// Put one fresh Block; returns its contract instance id and state.
async fn put_block(
    client: &mut WebApi,
    code: &Arc<ContractCode<'static>>,
    body: &[u8],
    wait: Duration,
) -> Result<(ContractKey, Vec<u8>)> {
    let state = block::encode(block::kind::RAW, body);
    let params = Parameters::from(blake3::hash(&state).as_bytes().to_vec());
    let contract = ContractContainer::Wasm(ContractWasmAPIVersion::V1(WrappedContract::new(
        code.clone(),
        params,
    )));
    let key = contract.key();
    client
        .send(ClientRequest::ContractOp(ContractRequest::Put {
            contract,
            state: WrappedState::from(state.clone()),
            related_contracts: RelatedContracts::default(),
            subscribe: false,
            blocking_subscribe: false,
        }))
        .await?;
    match timeout(wait, client.recv()).await {
        Ok(Ok(HostResponse::ContractResponse(ContractResponse::PutResponse { key: k })))
            if k == key =>
        {
            Ok((key, state))
        }
        other => bail!("put failed: {other:?}"),
    }
}

/// Register a delegate wasm with `params`; returns its key.
pub(crate) async fn register(
    client: &mut WebApi,
    wasm: &str,
    params: &[u8],
    wait: Duration,
) -> Result<DelegateKey> {
    let code = std::fs::read(wasm)
        .map_err(|e| anyhow!("{wasm}: {e} — run probe-delegate/build.sh first"))?;
    let delegate = Delegate::from((
        &DelegateCode::from(code),
        &Parameters::from(params.to_vec()),
    ));
    let key = delegate.key().clone();
    let (mut cipher, mut nonce) = ([0u8; 32], [0u8; 24]);
    getrandom::getrandom(&mut cipher)?;
    getrandom::getrandom(&mut nonce)?;
    client
        .send(ClientRequest::DelegateOp(
            DelegateRequest::RegisterDelegate {
                delegate: DelegateContainer::Wasm(DelegateWasmAPIVersion::V1(delegate)),
                cipher,
                nonce,
            },
        ))
        .await?;
    match timeout(wait, client.recv()).await {
        Ok(Ok(HostResponse::DelegateResponse { .. })) => Ok(key),
        other => bail!("register {wasm} failed: {other:?}"),
    }
}

/// Send one app message to a delegate on a fresh connection; collect every
/// application reply that arrives within `listen`, and every error the node
/// reported instead.
///
/// Errors come back as text rather than aborting, because a probe measuring a
/// refusal needs the node's own words: "the node refused this" is the finding,
/// not a failure of the harness.
pub(crate) async fn ask_raw(
    ws: &str,
    key: &DelegateKey,
    payload: Vec<u8>,
    listen: Duration,
) -> Result<(Vec<String>, Vec<String>)> {
    let mut c = connect(ws).await?;
    c.send(ClientRequest::DelegateOp(
        DelegateRequest::ApplicationMessages {
            key: key.clone(),
            params: Parameters::from(Vec::new()),
            inbound: vec![InboundDelegateMsg::ApplicationMessage(
                ApplicationMessage::new(payload),
            )],
        },
    ))
    .await?;
    let (mut out, mut errs) = (Vec::new(), Vec::new());
    let end = Instant::now() + listen;
    while let Some(left) = end.checked_duration_since(Instant::now()) {
        match timeout(left, c.recv()).await {
            Ok(Ok(HostResponse::DelegateResponse { values, .. })) => {
                for v in values {
                    if let OutboundDelegateMsg::ApplicationMessage(m) = v {
                        out.push(String::from_utf8_lossy(&m.payload).into_owned());
                    }
                }
                if !out.is_empty() {
                    break;
                }
            }
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                errs.push(format!("{e:?}"));
                break;
            }
            Err(_) => break,
        }
    }
    let _ = c.send(ClientRequest::Disconnect { cause: None }).await;
    Ok((out, errs))
}

/// [`ask_raw`] for callers that treat a node error as a failure.
pub(crate) async fn ask(
    ws: &str,
    key: &DelegateKey,
    payload: Vec<u8>,
    listen: Duration,
) -> Result<Vec<String>> {
    let (out, errs) = ask_raw(ws, key, payload, listen).await?;
    if let Some(e) = errs.first() {
        bail!("delegate connection error: {e}");
    }
    Ok(out)
}

/// Poll `stat` until `done(reply)` or `limit` elapses; returns the elapsed time.
pub(crate) async fn poll_stat(
    ws: &str,
    key: &DelegateKey,
    limit: Duration,
    done: impl Fn(&str) -> bool,
) -> Result<Option<(Duration, String)>> {
    let t = Instant::now();
    while t.elapsed() < limit {
        if let Some(r) = ask(ws, key, b"stat".to_vec(), Duration::from_secs(10))
            .await?
            .into_iter()
            .next()
        {
            if done(&r) {
                return Ok(Some((t.elapsed(), r)));
            }
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    Ok(None)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let wait = Duration::from_secs(cli.timeout_secs);
    let ws = if cli.local {
        "ws://127.0.0.1:7609/v1/contract/command?encodingProtocol=native".to_string()
    } else {
        cli.ws.clone()
    };
    println!(
        "mode:     {} ({ws})",
        if cli.local { "LOCAL" } else { "network" }
    );
    match cli.cmd {
        Cmd::Roundtrip { wasm, n, size } => {
            let code = Arc::new(ContractCode::from(std::fs::read(&wasm)?));
            let mut client = connect(&ws).await?;
            // A fresh salt per run so every block is new to the network.
            let salt = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos();
            let (mut put_ms, mut get_ms) = (Vec::new(), Vec::new());
            for i in 0..n {
                let mut body = format!("craftec harness {salt} {i} ").into_bytes();
                body.resize(size.max(body.len()), b'.');
                let state = block::encode(block::kind::RAW, &body);
                let params = Parameters::from(blake3::hash(&state).as_bytes().to_vec());
                let contract = ContractContainer::Wasm(ContractWasmAPIVersion::V1(
                    WrappedContract::new(code.clone(), params),
                ));
                let key = contract.key();

                let t = Instant::now();
                client
                    .send(ClientRequest::ContractOp(ContractRequest::Put {
                        contract,
                        state: WrappedState::from(state.clone()),
                        related_contracts: RelatedContracts::default(),
                        subscribe: false,
                        blocking_subscribe: false,
                    }))
                    .await?;
                match timeout(wait, client.recv()).await {
                    Ok(Ok(HostResponse::ContractResponse(ContractResponse::PutResponse {
                        key: k,
                    }))) if k == key => {}
                    other => bail!("put {i} failed: {other:?}"),
                }
                put_ms.push(t.elapsed().as_millis());

                let t = Instant::now();
                client
                    .send(ClientRequest::ContractOp(ContractRequest::Get {
                        key: *key.id(),
                        return_contract_code: false,
                        subscribe: false,
                        blocking_subscribe: false,
                    }))
                    .await?;
                match timeout(wait, client.recv()).await {
                    Ok(Ok(HostResponse::ContractResponse(ContractResponse::GetResponse {
                        state: got,
                        ..
                    }))) if got.as_ref() == state.as_slice() => {}
                    other => bail!("get {i} failed or mismatched: {other:?}"),
                }
                get_ms.push(t.elapsed().as_millis());
                println!(
                    "block {i}: {} put {} ms  get {} ms",
                    key.id(),
                    put_ms[i],
                    get_ms[i]
                );
            }
            let _ = client.send(ClientRequest::Disconnect { cause: None }).await;
            // Count, not just exit status: zero blocks round-tripped is a failure.
            if put_ms.len() != n || n == 0 {
                bail!("round-tripped {} of {n} blocks", put_ms.len());
            }
            println!("OK {n}/{n} blocks of {size} B round-tripped");
        }
        Cmd::DelegateProbe {
            block_wasm,
            delegate_wasm,
            wakeup_wasm,
            wake_secs,
        } => {
            // 1. A block this node holds, for the delegate to fetch.
            let code = Arc::new(ContractCode::from(std::fs::read(&block_wasm)?));
            let mut client = connect(&ws).await?;
            let mut salt = [0u8; 16];
            getrandom::getrandom(&mut salt)?;
            let body = [b"delegate-probe ".as_slice(), &salt].concat();
            let (bkey, state) = put_block(&mut client, &code, &body, wait).await?;
            println!("block put: {} ({} B)", bkey.id(), state.len());

            // 2. Register the base probe (fresh params → fresh secrets).
            let dkey = register(&mut client, &delegate_wasm, &salt, wait).await?;
            println!("delegate registered (base)");

            // 3. Contract GET from inside the delegate.
            let mut msg = b"get".to_vec();
            msg.extend_from_slice(bkey.id().as_bytes());
            let t = Instant::now();
            let direct = ask(&ws, &dkey, msg, Duration::from_secs(20)).await?;
            let want = format!("get=ok:{}", state.len());
            let got = poll_stat(&ws, &dkey, Duration::from_secs(60), |r| {
                !r.contains("get=pending")
            })
            .await?;
            let get_ok = matches!(&got, Some((_, r)) if r.contains(&want));
            println!(
                "delegate GET: {} | reply on asking connection: {:?} | recorded: {:?} | {} ms",
                if get_ok { "WORKS" } else { "MISSING" },
                direct,
                got.as_ref().map(|g| g.1.as_str()),
                t.elapsed().as_millis()
            );

            // 4. Wakeup — a separate build, because a node without the host
            //    function refuses to instantiate any wasm that imports it.
            let wkey = register(&mut client, &wakeup_wasm, &salt, wait).await?;
            let _ = client.send(ClientRequest::Disconnect { cause: None }).await;
            let mut msg = b"wake".to_vec();
            msg.extend_from_slice(&wake_secs.to_le_bytes());
            let (wake_ok, detail) = match ask(&ws, &wkey, msg, Duration::from_secs(10)).await {
                Err(e) => (false, format!("node refused the delegate: {e}")),
                Ok(armed) => {
                    let fired = poll_stat(
                        &ws,
                        &wkey,
                        Duration::from_secs(wake_secs as u64 + 30),
                        |r| r.contains("fired=1"),
                    )
                    .await?;
                    (
                        fired.is_some(),
                        format!(
                            "arm reply {:?}, requested {} s, observed {}",
                            armed,
                            wake_secs,
                            fired
                                .map(|f| format!("{} ms", f.0.as_millis()))
                                .unwrap_or_else(|| "never".into())
                        ),
                    )
                }
            };
            println!(
                "delegate WAKEUP: {} | {detail}",
                if wake_ok { "WORKS" } else { "MISSING" }
            );

            // A probe reports; it fails only if it could not run.
            println!(
                "SUMMARY node-side contract GET: {} · wakeup: {}",
                if get_ok { "yes" } else { "no" },
                if wake_ok { "yes" } else { "no" }
            );
        }
        Cmd::Latency {
            wasm,
            delegate_wasm,
            samples,
            sizes,
            parallel,
            parallel_size,
            max_k,
            only,
            return_code,
            budget_secs,
        } => {
            latency::run(
                &ws,
                &wasm,
                &delegate_wasm,
                samples,
                &sizes,
                &parallel,
                parallel_size,
                max_k,
                only,
                return_code,
                budget_secs,
                wait,
            )
            .await?;
        }
        Cmd::ValidateCost {
            wasm,
            mode,
            repeat,
            arm,
            updates,
            chunk,
            preload,
            salt,
        } => {
            validate_cost::run(
                &ws,
                &wasm,
                mode,
                repeat,
                arm,
                updates,
                chunk,
                preload,
                salt.as_deref(),
                wait,
            )
            .await?;
        }
        Cmd::Xnode {
            role,
            wasm,
            keys,
            reads,
            samples,
            sizes,
            return_code,
            probe_ms,
            limit_secs,
        } => {
            xnode::run(
                &ws,
                &role,
                &wasm,
                samples,
                &sizes,
                xnode::ReadOpts {
                    keys,
                    reads,
                    return_code,
                    probe_ms,
                    limit_secs,
                },
                wait,
            )
            .await?;
        }
        Cmd::Bag {
            wasm,
            work_bits,
            m,
            expect_sha,
        } => {
            bag::run(&ws, &wasm, work_bits, m, &expect_sha, wait).await?;
        }
        Cmd::Register { wasm, expect_sha } => {
            register::run(&ws, &wasm, &expect_sha, wait).await?;
        }
        Cmd::Pack { wasm, expect_sha } => {
            pack::run(&ws, &wasm, &expect_sha, wait).await?;
        }
        Cmd::PutShape {
            wasm,
            total,
            splits,
            rounds,
            budget_secs,
            probe_ms,
        } => {
            putshape::run(
                &ws,
                &wasm,
                total,
                &splits,
                rounds,
                budget_secs,
                probe_ms,
                wait,
            )
            .await?;
        }
        Cmd::Set { wasm, expect_sha } => {
            set::run(&ws, &wasm, &expect_sha, wait).await?;
        }
        Cmd::Watch { key, secs } => {
            watch::run(&ws, &key, secs, wait).await?;
        }
    }
    Ok(())
}
