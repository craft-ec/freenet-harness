//! Drives a real Freenet node. Phase 0: put a Block, get it back, time both.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Result};
use clap::{Parser, Subcommand};
use craftec_block_contract as block;
use freenet_stdlib::{
    client_api::{ClientRequest, ContractRequest, ContractResponse, HostResponse, WebApi},
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
}

async fn connect(ws: &str) -> Result<WebApi> {
    let (stream, _) = tokio_tungstenite::connect_async(ws)
        .await
        .map_err(|e| anyhow!("cannot reach the node at {ws}: {e}"))?;
    Ok(WebApi::start(stream))
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
    }
    Ok(())
}
