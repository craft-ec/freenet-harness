//! `bag`: the Bag contract's live-node round trip (freenet-harness#7).
//!
//! Runs in `--local` mode: this asks whether the CONTRACT behaves, not what the
//! network costs, so it has no business paying network latency.
//!
//! The harness links the bag crate's own `wire` and `testing` modules rather
//! than re-encoding the format. A harness with its own opinion of the wire
//! format tests that opinion, not the contract.

use std::{sync::Arc, time::Duration};

use anyhow::{bail, Result};
use craftec_bag_contract::{
    testing,
    wire::{BagState, Params, Pointer},
};
use freenet_stdlib::{
    client_api::{ClientRequest, ContractRequest, ContractResponse, HostResponse, WebApi},
    prelude::*,
};
use tokio::time::timeout;

use crate::latency::send_req;

/// Short, because nothing here should ever be slow: local mode answers in
/// milliseconds, and a wait that runs long is a failure to report, not a
/// reason to keep waiting.
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
    // Drain until OUR GetResponse arrives. Taking the next message as the
    // answer is wrong whenever anything else is in flight — an UpdateResponse
    // from the previous step satisfies the read, and the state returned is the
    // one from BEFORE the update. That reads as an update that did nothing.
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

/// Apply a delta and return the state the node then holds.
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
    // Wait for the UPDATE's own response before reading back, so the read
    // cannot be answered before the merge has happened.
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

fn count(params: &Params, state: &[u8]) -> usize {
    BagState::parse(state, params)
        .map(|s| s.held.len())
        .unwrap_or(0)
}

pub async fn run(
    ws: &str,
    wasm: &str,
    work_bits: u8,
    m: u16,
    expect_sha: &str,
    wait: Duration,
) -> Result<()> {
    // Says what it tested, and refuses the wrong artefact outright.
    let bytes = crate::wasm_check::load(wasm, expect_sha)?;
    let code = Arc::new(ContractCode::from(bytes));
    let mut p = testing::params(work_bits, m);
    // A fresh bucket per run, so every run addresses a NEW contract.
    //
    // A contract's key is hash(code, params). Without this, two runs with the
    // same shape share an instance and the second one's "PUT the empty bag"
    // merges into whatever the first left behind — which reads as the contract
    // refusing to create an empty bag, and makes every later step start from
    // someone else's state. Already learned once, on the validate-cost fixture.
    let mut b = [0u8; 4];
    getrandom::getrandom(&mut b)?;
    p.bucket = u32::from_le_bytes(b);
    let contract = ContractContainer::Wasm(ContractWasmAPIVersion::V1(WrappedContract::new(
        code,
        Parameters::from(p.encode()),
    )));
    let key = contract.key();
    println!("contract: {}  work_bits={work_bits} M={m}", key.id());
    let mut client = crate::connect(ws).await?;

    // ---- 1. the empty bag is six bytes, and creating it is a PUT ----------
    let empty = BagState { held: Vec::new() }.encode();
    if empty.len() != 6 {
        bail!("expected a 6-byte empty bag, got {} bytes", empty.len());
    }
    send_req(
        &mut client,
        ClientRequest::ContractOp(ContractRequest::Put {
            contract,
            state: WrappedState::from(empty.clone()),
            related_contracts: RelatedContracts::default(),
            subscribe: false,
            blocking_subscribe: false,
        }),
        wait,
    )
    .await?;
    let _ = timeout(STEP, client.recv()).await;
    let after_put = get_state(&mut client, &key).await?;
    let ok_create = after_put.as_deref() == Some(empty.as_slice());
    println!(
        "1. PUT of the 6-byte empty bag creates it: {}  (state {} bytes)",
        verdict(ok_create),
        after_put.as_ref().map(|s| s.len()).unwrap_or(0)
    );

    // ---- 2. two writers, disjoint pointers, union cut to M ---------------
    // Distinct PAYLOADS per writer, not just distinct seeds.
    //
    // `testing::many` derives its payload from the index, so two calls produce
    // the same payloads; `mine` then converges on the same nonce whatever seed
    // it starts from, and the two "writers" submit identical pointers. Their
    // union is one writer's set — which looks exactly like an update that was
    // ignored, and is in fact the contract behaving correctly.
    let a: Vec<Pointer> = (0..3)
        .map(|i| testing::mine(&p, format!("writer-A/{i}").as_bytes(), 11))
        .collect();
    let b: Vec<Pointer> = (0..3)
        .map(|i| testing::mine(&p, format!("writer-B/{i}").as_bytes(), 22))
        .collect();
    // Assert the premise the step's name makes: these sets really are disjoint.
    let names_a: Vec<_> = a.iter().map(|x| held(&p, x).name).collect();
    if b.iter().any(|x| names_a.contains(&held(&p, x).name)) {
        bail!("writers A and B share a pointer — 'disjoint' is not what is being tested");
    }
    let da = ranked(&p, &a);
    let db = ranked(&p, &b);
    update(&mut client, &key, da).await?;
    let s2 = update(&mut client, &key, db).await?;
    let n2 = s2.as_deref().map(|s| count(&p, s)).unwrap_or(0);
    let want = (a.len() + b.len()).min(m as usize);
    println!(
        "2. two writers' disjoint pointers union to {n2} (expected {want}, M={m}): {}",
        verdict(n2 == want)
    );

    // ---- 3. an under-priced pointer changes nothing ----------------------
    // Mined one bit BELOW the price: the discriminating case. A pointer mined
    // at zero bits would be refused by anything, and would not show that the
    // check fires AT the boundary rather than everywhere.
    let before = s2.clone();
    let want_bits = work_bits.saturating_sub(1) as u32;
    let Some(cheap) = mine_exactly(&p, b"under-priced", want_bits) else {
        bail!("could not mine a pointer with exactly {want_bits} bits — control cannot run");
    };
    let cheap_work = held(&p, &cheap).work;
    // The control asserts its own premise: if this pointer had met the price,
    // "nothing changed" would prove nothing.
    if cheap_work >= work_bits as u32 {
        bail!("control pointer has {cheap_work} bits, price is {work_bits} — not under-priced");
    }
    println!("   (control pointer work = {cheap_work} bits, price = {work_bits} bits)");
    let dc = ranked(&p, &[cheap]);
    let s3 = update(&mut client, &key, dc).await?;
    let unchanged = s3 == before;
    println!(
        "3. an under-priced pointer changes nothing: {}  ({} -> {} pointers)",
        verdict(unchanged),
        before.as_deref().map(|s| count(&p, s)).unwrap_or(0),
        s3.as_deref().map(|s| count(&p, s)).unwrap_or(0)
    );

    // ---- 4. POSITIVE CONTROL: the same path with a paid pointer ----------
    // Without this, step 3 passing proves only that SOMETHING was refused —
    // possibly the update path itself, in which case the price check was never
    // exercised. This shows the identical path admits a pointer that paid.
    let paid = testing::mine(&p, b"paid", 99);
    let dp = ranked(&p, &[paid]);
    let s4 = update(&mut client, &key, dp).await?;
    let grew = s4.as_deref().map(|s| count(&p, s)).unwrap_or(0)
        > s3.as_deref().map(|s| count(&p, s)).unwrap_or(0);
    println!(
        "4. CONTROL — a correctly-priced pointer IS admitted on the same path: {}",
        verdict(grew)
    );

    // ---- 5. the cut to M actually happens -------------------------------
    // Steps 2-4 never exceed M, so none of them shows the cut. Without this the
    // "union cut to M" claim rests on a case where no cutting was required.
    // A candidate may not itself exceed M: `BagState::parse` rejects
    // `count > M`, so an oversized delta is ignored wholesale rather than cut.
    // The cut is what happens when two VALID states join — so send a full but
    // legal candidate, whose union with what is held exceeds M.
    let extra: Vec<Pointer> = (0..(m as usize))
        .map(|i| testing::mine(&p, format!("overflow/{i}").as_bytes(), 1234))
        .collect();
    let before5 = s4.as_deref().map(|s| count(&p, s)).unwrap_or(0);
    let s5 = update(&mut client, &key, ranked(&p, &extra)).await?;
    let n5 = s5.as_deref().map(|s| count(&p, s)).unwrap_or(0);
    println!(
        "5. a full legal candidate ({} ptrs) joins {} held -> cut to M: bag holds {n5}, M={m}: {}",
        extra.len(),
        before5,
        verdict(n5 == m as usize)
    );

    let _ = client.send(ClientRequest::Disconnect { cause: None }).await;
    let all = ok_create && n2 == want && unchanged && grew && n5 == m as usize;
    println!("\nbag round-trip: {}", if all { "PASS" } else { "FAIL" });
    if !all {
        bail!("bag round-trip failed");
    }
    Ok(())
}

fn held(p: &Params, ptr: &Pointer) -> craftec_bag_contract::wire::Held {
    craftec_bag_contract::wire::Held::of(ptr.clone(), &p.hash())
}

/// A bag state the contract will actually parse.
///
/// `BagState::parse` requires STRICT rank order — work descending, then name
/// ascending — and rejects the whole candidate otherwise. Encoding pointers in
/// mining order therefore does not add "some" of them, it adds NONE, silently,
/// because an unreadable candidate is ignored rather than fatal. That reads
/// exactly like a contract that refuses everything.
fn ranked(p: &Params, ptrs: &[Pointer]) -> Vec<u8> {
    let mut h: Vec<_> = ptrs.iter().map(|x| held(p, x)).collect();
    h.sort_by_key(|x| x.rank());
    BagState { held: h }.encode()
}

/// A pointer whose work is EXACTLY `bits`, so an under-price control is
/// actually under-priced.
///
/// `mine_at` returns the first nonce with AT LEAST `bits` zeros, so asking for
/// `work_bits - 1` frequently yields a pointer that meets the price — and the
/// control then passes for the wrong reason, or fails while looking like a
/// contract bug.
fn mine_exactly(p: &Params, payload: &[u8], bits: u32) -> Option<Pointer> {
    for seed in 0..200_000u64 {
        let ptr = testing::mine_at(p, payload, seed, bits);
        if held(p, &ptr).work == bits {
            return Some(ptr);
        }
    }
    None
}

fn verdict(b: bool) -> &'static str {
    if b {
        "PASS"
    } else {
        "FAIL"
    }
}
