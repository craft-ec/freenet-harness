//! `set`: the Set contract's live-node round trip.
//!
//! What a denial does is the interesting part and the easiest to get wrong: it
//! HIDES a slot from readers while the state RETAINS it. The retention is not
//! an implementation detail — dropping the slot would make its existence
//! depend on whether the denial had arrived yet, and the merge would stop
//! converging. So the run checks both halves, because checking only
//! "disappeared from view" would pass against an implementation that dropped
//! it and broke convergence.

use std::{sync::Arc, time::Duration};

use anyhow::{bail, Result};
use craftec_set_contract::{testing, wire::SetState};
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

    // Fresh keys per run so the contract key is new.
    let mut salt = [0u8; 1];
    getrandom::getrandom(&mut salt)?;
    let w = testing::world_with(
        salt[0].max(1),
        4,
        craftec_set_contract::wire::Admission::Cap,
        8,
        4,
        0,
    );
    let p = &w.params;
    let contract = ContractContainer::Wasm(ContractWasmAPIVersion::V1(WrappedContract::new(
        code,
        Parameters::from(w.params_bytes.clone()),
    )));
    let key = contract.key();
    println!("contract: {}  M=8 quota=4 admission=Cap", key.id());
    let mut client = crate::connect(ws).await?;

    let counts = |b: &Option<Vec<u8>>| -> (usize, usize) {
        b.as_deref()
            .and_then(|x| SetState::parse_unverified(x, p))
            .map(|s| (s.held.len(), s.visible().count()))
            .unwrap_or((0, 0))
    };

    // ---- 1. an owner-tier item is admitted -------------------------------
    let owner_item = w.item(0, b"k-owner", 10, b"by the owner");
    let s1 = w.state(vec![owner_item]).encode();
    send_req(
        &mut client,
        ClientRequest::ContractOp(ContractRequest::Put {
            contract,
            state: WrappedState::from(s1),
            related_contracts: RelatedContracts::default(),
            subscribe: false,
            blocking_subscribe: false,
        }),
        wait,
    )
    .await?;
    let _ = timeout(STEP, client.recv()).await;
    let g1 = get_state(&mut client, &key).await?;
    let (h1, v1) = counts(&g1);
    println!(
        "1. an owner-tier item is admitted: {}  (held {h1}, visible {v1})",
        verdict(h1 == 1 && v1 == 1)
    );

    // ---- 2. a cap-holder's item is admitted ------------------------------
    let cap_item = w.item(1, b"k-cap", 11, b"by a cap holder");
    let g2 = update(&mut client, &key, w.state(vec![cap_item]).encode()).await?;
    let (h2, v2) = counts(&g2);
    println!(
        "2. a cap-holder's item is admitted: {}  (held {h2}, visible {v2})",
        verdict(h2 == 2 && v2 == 2)
    );

    // ---- 3. a denial HIDES and RETAINS -----------------------------------
    let deny = w.deny_of(1);
    let g3 = update(&mut client, &key, w.state_with(vec![], vec![deny]).encode()).await?;
    let (h3, v3) = counts(&g3);
    let hides = v3 == 1;
    let retains = h3 == 2;
    println!(
        "3. a denial HIDES ({}) and RETAINS ({}): held {h3} (was {h2}), visible {v3} (was {v2})",
        verdict(hides),
        verdict(retains)
    );

    // ---- 4. a denial of the owner's own key is refused --------------------
    let self_deny = w.deny_of(0);
    let g4 = update(
        &mut client,
        &key,
        w.state_with(vec![], vec![self_deny]).encode(),
    )
    .await?;
    let (h4, v4) = counts(&g4);
    let refused = (h4, v4) == (h3, v3);
    println!(
        "4. a denial of the owner's OWN key is refused: {}  (held {h4}, visible {v4} — unchanged)",
        verdict(refused)
    );

    // ---- 5. CONTROL: the denial path still works for a non-owner ----------
    // Step 4 passing shows only that SOMETHING was refused. This denies a
    // different signer on the same path and requires it to take effect.
    let other = w.item(2, b"k-other", 12, b"by another cap holder");
    let g5a = update(&mut client, &key, w.state(vec![other]).encode()).await?;
    let (_, v5a) = counts(&g5a);
    let g5 = update(
        &mut client,
        &key,
        w.state_with(vec![], vec![w.deny_of(2)]).encode(),
    )
    .await?;
    let (_, v5) = counts(&g5);
    let control = v5 == v5a - 1;
    println!(
        "5. CONTROL — denying a DIFFERENT signer on the same path does take effect: {}  \
         (visible {v5a} -> {v5})",
        verdict(control)
    );

    let _ = client.send(ClientRequest::Disconnect { cause: None }).await;
    let all = h1 == 1 && v1 == 1 && h2 == 2 && v2 == 2 && hides && retains && refused && control;
    println!("\nset round-trip: {}", if all { "PASS" } else { "FAIL" });
    if !all {
        bail!("set round-trip failed");
    }
    Ok(())
}
