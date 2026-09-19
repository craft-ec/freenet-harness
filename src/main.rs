//! Drives a real Freenet node: round-trips Blocks, measures put/get latency,
//! probes delegate capabilities.

mod latency;
mod stats;
mod validate_cost;
mod watch;

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
    match cli.cmd {
        Cmd::Roundtrip { wasm, n, size } => {
            let code = Arc::new(ContractCode::from(std::fs::read(&wasm)?));
            let mut client = connect(&cli.ws).await?;
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
            let mut client = connect(&cli.ws).await?;
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
            let direct = ask(&cli.ws, &dkey, msg, Duration::from_secs(20)).await?;
            let want = format!("get=ok:{}", state.len());
            let got = poll_stat(&cli.ws, &dkey, Duration::from_secs(60), |r| {
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
            let (wake_ok, detail) = match ask(&cli.ws, &wkey, msg, Duration::from_secs(10)).await {
                Err(e) => (false, format!("node refused the delegate: {e}")),
                Ok(armed) => {
                    let fired = poll_stat(
                        &cli.ws,
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
        } => {
            latency::run(
                &cli.ws,
                &wasm,
                &delegate_wasm,
                samples,
                &sizes,
                &parallel,
                parallel_size,
                max_k,
                only,
                return_code,
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
                &cli.ws,
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
        Cmd::Watch { key, secs } => {
            watch::run(&cli.ws, &key, secs, wait).await?;
        }
    }
    Ok(())
}
