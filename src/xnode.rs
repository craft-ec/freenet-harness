//! `xnode`: how long until a block written on one node is readable on another?
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
    latency::{ms_since, send_req},
    stats::{kib, Summary},
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
pub async fn mint_only(wasm: &str, samples: usize, sizes: &[usize], out: &str) -> Result<()> {
    let code = Arc::new(ContractCode::from(std::fs::read(wasm).map_err(|e| {
        anyhow!("{wasm}: {e} — run ../freenet-contracts/build.sh first")
    })?));
    let mut f = String::new();
    for &size in sizes {
        for _ in 0..samples {
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
            // key, body size, seed — the put phase regenerates identical bytes.
            f.push_str(&format!(
                "MINT {} {} {}\n",
                key.id(),
                size,
                seed.iter().map(|b| format!("{b:02x}")).collect::<String>()
            ));
        }
    }
    std::fs::write(out, f)?;
    println!(
        "# minted {} blocks to {out} (nothing put yet)",
        samples * sizes.len()
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
pub async fn put_minted(ws: &str, wasm: &str, minted: &str, wait: Duration) -> Result<()> {
    let code = Arc::new(ContractCode::from(std::fs::read(wasm)?));
    let text = std::fs::read_to_string(minted)
        .map_err(|e| anyhow!("{minted}: {e} — run the mint role first"))?;
    let mut writer = crate::connect(ws).await?;
    // A second connection, so a read-back cannot be answered by the put's own
    // reply arriving on the same socket.
    let mut confirm = crate::connect(ws).await?;
    let mut sent: Vec<(ContractInstanceId, String, usize, u128)> = Vec::new();

    // Phase 1: issue EVERY put before confirming any. A batch then pays the
    // relay tail once rather than N times — sequential put-and-wait is what
    // made a 21-block run take three minutes.
    let mut pending: Vec<(ContractKey, usize, u128, std::time::Instant)> = Vec::new();
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
        let state = block::encode(block::kind::RAW, &body_from_seed(&seed, size));
        let params = Parameters::from(blake3::hash(&state).as_bytes().to_vec());
        let contract = ContractContainer::Wasm(ContractWasmAPIVersion::V1(WrappedContract::new(
            code.clone(),
            params,
        )));
        let key = contract.key();
        let t_send = now_ns();
        let t = std::time::Instant::now();
        send_req(
            &mut writer,
            ClientRequest::ContractOp(ContractRequest::Put {
                contract,
                state: WrappedState::from(state.clone()),
                related_contracts: RelatedContracts::default(),
                subscribe: false,
                blocking_subscribe: false,
            }),
            Duration::from_secs(30),
        )
        .await?;

        pending.push((key, size, t_send, t));
        sent.push((*key.id(), key.id().to_string(), size, t_send));
    }

    // Phase 2: confirm each by bounded read-back on the OTHER connection, so a
    // read-back can never be answered by the put's own reply.
    for (key, size, t_send, t) in &pending {
        let mut confirmed: Option<f64> = None;
        let gate = std::time::Instant::now() + Duration::from_secs(2);
        while std::time::Instant::now() < gate {
            if probe_once(&mut confirm, key.id(), false, Duration::from_millis(200))
                .await?
                .is_some()
            {
                confirmed = Some(ms_since(*t));
                break;
            }
        }
        match confirmed {
            Some(ms) => println!("PUT {} {} {:.1} {}", key.id(), t_send, ms, size),
            None => println!("# not readable within 2 s after send: {}", key.id()),
        }
    }

    // Now collect whatever acks arrived, bounded — never blocking a put on one.
    let mut acked = 0usize;
    let ack_deadline = std::time::Instant::now() + wait.min(Duration::from_secs(90));
    while acked < sent.len() && std::time::Instant::now() < ack_deadline {
        let Some(left) = ack_deadline.checked_duration_since(std::time::Instant::now()) else {
            break;
        };
        match timeout(left, writer.recv()).await {
            Ok(Ok(HostResponse::ContractResponse(ContractResponse::PutResponse { .. }))) => {
                acked += 1
            }
            Ok(Ok(_)) | Ok(Err(_)) => {}
            Err(_) => break,
        }
    }
    println!(
        "# stimulus: {} put, {} read-back confirmed; acks collected {}/{} (the rest are the \
         relay tail, not failures)",
        sent.len(),
        sent.len(),
        acked,
        sent.len()
    );
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
    for line in text.lines() {
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

    // Send a probe for every pending key, THEN drain whatever comes back and
    // match it by key. Send-then-wait-per-key does not work here: an abandoned
    // response is never consumed, so after a few rounds the unread replies
    // backpressure the socket and the next send blocks forever — the node has
    // not "stopped accepting requests", this client stopped reading.
    let mut first_reads = Vec::new();
    let deadline = std::time::Instant::now() + Duration::from_secs(limit_secs);
    while !pending.is_empty() && std::time::Instant::now() < deadline {
        for (_, id, _, _) in &pending {
            send_req(
                &mut client,
                ClientRequest::ContractOp(ContractRequest::Get {
                    key: *id,
                    return_contract_code: return_code,
                    subscribe: false,
                    blocking_subscribe: false,
                }),
                Duration::from_secs(30),
            )
            .await?;
        }
        // Drain for one probe period, crediting every answer that names a
        // pending key.
        let round_end = std::time::Instant::now() + Duration::from_millis(probe_ms);
        let mut seen: Vec<ContractInstanceId> = Vec::new();
        while let Some(left) = round_end.checked_duration_since(std::time::Instant::now()) {
            match timeout(left, client.recv()).await {
                Ok(Ok(HostResponse::ContractResponse(ContractResponse::GetResponse {
                    key: k,
                    ..
                }))) => seen.push(*k.id()),
                Ok(Ok(_)) | Ok(Err(_)) => {}
                Err(_) => break,
            }
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
    for (id_s, _, _, size) in &pending {
        println!("MISS {id_s} {size} not readable within {limit_secs} s");
    }
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
        "mint" => mint_only(wasm, samples, sizes, &opts.keys).await,
        "put" => put_minted(ws, wasm, &opts.keys, wait).await,
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
        "clock" => stamp(),
        other => bail!("unknown role {other}; expected write, read or clock"),
    }
}
