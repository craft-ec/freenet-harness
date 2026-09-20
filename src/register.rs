//! `register`: the Register contract's live-node round trip.
//!
//! Four claims, each checked on a node rather than in a unit test: a record is
//! stored, a higher seq displaces a lower one, an equivocation forks the
//! register, and a terminal record is never displaced.
//!
//! Runs in `--local` — this asks whether the contract behaves.

use std::{sync::Arc, time::Duration};

use anyhow::{bail, Result};
use craftec_register_contract::{testing, wire::RegState};
use freenet_stdlib::{
    client_api::{ClientRequest, ContractRequest, ContractResponse, HostResponse, WebApi},
    prelude::*,
};
use tokio::time::timeout;

use crate::latency::send_req;

const STEP: Duration = Duration::from_secs(2);

async fn get_state(client: &mut WebApi, key: &ContractKey) -> Result<Option<Vec<u8>>> {
    send_req(
        client,
        ClientRequest::ContractOp(ContractRequest::Get {
            key: *key.id(),
            return_contract_code: false,
            subscribe: false,
            blocking_subscribe: false,
        }),
        STEP,
    )
    .await?;
    let deadline = std::time::Instant::now() + STEP;
    while std::time::Instant::now() < deadline {
        let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) else {
            break;
        };
        match timeout(left, client.recv()).await {
            Ok(Ok(HostResponse::ContractResponse(ContractResponse::GetResponse {
                key: k,
                state,
                ..
            }))) if k.id() == key.id() => return Ok(Some(state.as_ref().to_vec())),
            Ok(Ok(_)) => continue,
            _ => break,
        }
    }
    Ok(None)
}

async fn update(client: &mut WebApi, key: &ContractKey, delta: Vec<u8>) -> Result<Option<Vec<u8>>> {
    send_req(
        client,
        ClientRequest::ContractOp(ContractRequest::Update {
            key: *key,
            data: UpdateData::Delta(StateDelta::from(delta)),
        }),
        STEP,
    )
    .await?;
    let deadline = std::time::Instant::now() + STEP;
    while std::time::Instant::now() < deadline {
        let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) else {
            break;
        };
        match timeout(left, client.recv()).await {
            Ok(Ok(HostResponse::ContractResponse(ContractResponse::UpdateResponse {
                key: k,
                ..
            }))) if k.id() == key.id() => break,
            Ok(Ok(_)) => continue,
            _ => break,
        }
    }
    get_state(client, key).await
}

fn verdict(b: bool) -> &'static str {
    if b {
        "PASS"
    } else {
        "FAIL"
    }
}

pub async fn run(ws: &str, wasm: &str, expect_sha: Option<&str>, wait: Duration) -> Result<()> {
    let bytes = crate::wasm_check::load(wasm, expect_sha)?;
    let code = Arc::new(ContractCode::from(bytes));

    // A fresh world per run, so the contract key is new and no step inherits a
    // previous run's state. (A key is hash(code, params).)
    let mut salt = [0u8; 8];
    getrandom::getrandom(&mut salt)?;
    let w = testing::keyset_seeded(salt[0], 2, 4, false);
    let p = &w.params;
    let contract = ContractContainer::Wasm(ContractWasmAPIVersion::V1(WrappedContract::new(
        code,
        Parameters::from(w.params_bytes.clone()),
    )));
    let key = contract.key();
    println!("contract: {}  k=2 n=4", key.id());
    let mut client = crate::connect(ws).await?;

    // ---- 1. a record is stored -------------------------------------------
    let r1 = w.record(false, 1, b"first");
    let s1 = w.encode(&w.state(r1.clone()));
    send_req(
        &mut client,
        ClientRequest::ContractOp(ContractRequest::Put {
            contract,
            state: WrappedState::from(s1.clone()),
            related_contracts: RelatedContracts::default(),
            subscribe: false,
            blocking_subscribe: false,
        }),
        wait,
    )
    .await?;
    let _ = timeout(STEP, client.recv()).await;
    let got = get_state(&mut client, &key).await?;
    let seq_of = |b: &Option<Vec<u8>>| -> Option<u64> {
        b.as_deref()
            .and_then(|x| RegState::parse_unverified(x, p))
            .and_then(|s| s.record.map(|r| r.signed.seq))
    };
    let ok1 = seq_of(&got) == Some(1);
    println!(
        "1. a record is stored: {}  (seq {:?})",
        verdict(ok1),
        seq_of(&got)
    );

    // ---- 2. a higher seq displaces a lower one ---------------------------
    let s2 = w.encode(&w.state(w.record(false, 2, b"second")));
    let g2 = update(&mut client, &key, s2).await?;
    let ok2 = seq_of(&g2) == Some(2);
    println!(
        "2. a higher seq wins: {}  (seq {:?})",
        verdict(ok2),
        seq_of(&g2)
    );

    // ---- 3. CONTROL: a LOWER seq does not displace ------------------------
    // Without this, step 2 shows only that the update path moves state at all,
    // not that SEQ is what decides.
    let s_low = w.encode(&w.state(w.record(false, 1, b"stale")));
    let g3 = update(&mut client, &key, s_low).await?;
    let ok3 = seq_of(&g3) == Some(2);
    println!(
        "3. CONTROL — a LOWER seq does not displace: {}  (seq {:?})",
        verdict(ok3),
        seq_of(&g3)
    );

    // ---- 4. an equivocation forks ----------------------------------------
    // Two different values decided at the same seq by valid quorums.
    let forked = match w.alternate(false, 2, b"conflicting") {
        Some(alt) => {
            let g = update(&mut client, &key, w.encode(&w.state(alt))).await?;
            g.as_deref()
                .and_then(|x| RegState::parse_unverified(x, p))
                .map(|s| s.forked())
                .unwrap_or(false)
        }
        None => bail!("this world has no spare key, so an equivocation cannot be built"),
    };
    println!("4. an equivocation forks the register: {}", verdict(forked));

    // ---- 5. a terminal record is never displaced -------------------------
    let term = w.record(true, 9, &[7u8; 32]);
    let g5 = update(&mut client, &key, w.encode(&w.state(term))).await?;
    let after_term = seq_of(&g5);
    let s_after = w.encode(&w.state(w.record(false, 99, b"after terminal")));
    let g6 = update(&mut client, &key, s_after).await?;
    let ok5 = seq_of(&g6) == after_term;
    println!(
        "5. a terminal record is never displaced: {}  (seq {:?} -> {:?} after a seq-99 attempt)",
        verdict(ok5),
        after_term,
        seq_of(&g6)
    );

    let _ = client.send(ClientRequest::Disconnect { cause: None }).await;
    let all = ok1 && ok2 && ok3 && forked && ok5;
    println!(
        "\nregister round-trip: {}",
        if all { "PASS" } else { "FAIL" }
    );
    if !all {
        bail!("register round-trip failed");
    }
    Ok(())
}
