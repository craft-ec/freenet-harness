//! `upgrade-cycle`: one full contract-code epoch change, end to end.
//!
//! A Freenet contract's key is `BLAKE3(code_hash ‖ params)`, so changing a
//! contract's code moves every instance of it. Block IDS do not move —
//! `BLAKE3(kind ‖ body)` has nothing to do with the code — which is what makes
//! the migration possible at all: the same bytes are simply offered again under
//! the new code, by anyone, because they are self-certifying.
//!
//! This runs the procedure decided on freenet-contracts#8 against a live node
//! and shows each step happening rather than describing it:
//!
//! 1. blocks are put under code A;
//! 2. a reader holding the table `[B, A]` tries B, falls back to A, and re-puts
//!    what it found under B — lazy migration, one put per block;
//! 3. a reader holding `[B]` alone then finds everything;
//! 4. a Register record signed under A is re-published under B **by a third
//!    party that holds no keys**, and verifies — the signature binds the params,
//!    not the code;
//! 5. the rollback hazard, executed: the newest record exists only under A, the
//!    window closes, and a reader holding `[B]` gets an OLDER record. Nothing is
//!    forged and the answer is still wrong. A keeper-style re-publish heals it.
//!
//! Run in `--local`: this asks whether the PROCEDURE works, and every timing it
//! reports is a lower bound on what a network would cost.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Result};
use craftec_block_contract as block;
use craftec_register_contract::{
    testing,
    wire::{Params as RegParams, RegState},
};
use freenet_stdlib::{
    client_api::{ClientRequest, ContractRequest, ContractResponse, HostResponse, WebApi},
    prelude::*,
};
use tokio::time::timeout;

use crate::{latency::send_req, stats::kib};

/// Local mode answers in tens of milliseconds; two seconds is the deadline at
/// which a missing answer is recorded as missing.
const STEP: Duration = Duration::from_secs(2);

/// One epoch's code, and the hash that names it.
struct Epoch {
    code: Arc<ContractCode<'static>>,
    sha: String,
}

impl Epoch {
    fn load(path: &str, expect: &str) -> Result<Self> {
        let bytes = crate::wasm_check::load(path, expect)?;
        let sha = crate::wasm_check::sha256_hex(&bytes);
        Ok(Epoch {
            code: Arc::new(ContractCode::from(bytes)),
            sha,
        })
    }

    /// The contract this epoch would address these params under.
    fn at(&self, params: &[u8]) -> ContractContainer {
        ContractContainer::Wasm(ContractWasmAPIVersion::V1(WrappedContract::new(
            self.code.clone(),
            Parameters::from(params.to_vec()),
        )))
    }
}

/// GET one key and return the state, if the node has it.
async fn get(client: &mut WebApi, key: &ContractKey) -> Result<Option<Vec<u8>>> {
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
    let deadline = Instant::now() + STEP;
    while let Some(left) = deadline.checked_duration_since(Instant::now()) {
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

/// PUT one state under one epoch's code. `true` when the node kept it.
async fn put(client: &mut WebApi, epoch: &Epoch, params: &[u8], state: &[u8]) -> Result<bool> {
    let contract = epoch.at(params);
    let key = contract.key();
    send_req(
        client,
        ClientRequest::ContractOp(ContractRequest::Put {
            contract,
            state: WrappedState::from(state.to_vec()),
            related_contracts: RelatedContracts::default(),
            subscribe: false,
            blocking_subscribe: false,
        }),
        STEP,
    )
    .await?;
    let _ = timeout(STEP, client.recv()).await;
    // Read-back is the confirmation, not the acknowledgement: the ack tells you
    // the request was taken, and on this platform the bytes are readable long
    // before it arrives (and sometimes when it never does).
    Ok(get(client, &key).await?.as_deref() == Some(state))
}

/// First eight bytes of an identity, for a line a human reads.
fn hex16(b: &[u8]) -> String {
    b.iter().take(8).map(|x| format!("{x:02x}")).collect()
}

fn verdict(ok: bool) -> &'static str {
    if ok {
        "PASS"
    } else {
        "FAIL"
    }
}

/// A RAW block and its identity. The identity is the block ID, which does NOT
/// move when the code does — that is the whole reason a migration is possible.
struct Blk {
    /// `params` for the Block contract: the hash of the state bytes.
    id: Vec<u8>,
    state: Vec<u8>,
}

fn mint_block(size: usize) -> Result<Blk> {
    let mut body = vec![0u8; size];
    getrandom::getrandom(&mut body)?;
    let state = block::encode(block::kind::RAW, &body);
    Ok(Blk {
        id: blake3::hash(&state).as_bytes().to_vec(),
        state,
    })
}

pub struct Opts {
    pub block_a: String,
    pub block_b: String,
    pub sha_block_a: String,
    pub sha_block_b: String,
    pub register_a: String,
    pub register_b: String,
    pub sha_register_a: String,
    pub sha_register_b: String,
    pub n: usize,
    pub size: usize,
}

pub async fn run(ws: &str, o: Opts) -> Result<()> {
    let block_a = Epoch::load(&o.block_a, &o.sha_block_a)?;
    let block_b = Epoch::load(&o.block_b, &o.sha_block_b)?;
    let reg_a = Epoch::load(&o.register_a, &o.sha_register_a)?;
    let reg_b = Epoch::load(&o.register_b, &o.sha_register_b)?;

    // The premise of the whole exercise. Two epochs with the same code hash are
    // the same epoch, and every "it moved" below would be vacuously true.
    if block_a.sha == block_b.sha {
        bail!(
            "block A and B are the same code ({}) — there is no upgrade to demonstrate",
            &block_a.sha[..16]
        );
    }
    if reg_a.sha == reg_b.sha {
        bail!(
            "register A and B are the same code ({}) — there is no upgrade to demonstrate",
            &reg_a.sha[..16]
        );
    }
    println!(
        "block    A {} -> B {}",
        &block_a.sha[..16],
        &block_b.sha[..16]
    );
    println!("register A {} -> B {}", &reg_a.sha[..16], &reg_b.sha[..16]);
    println!(
        "{} blocks of {}, local mode — every duration here is a LOWER BOUND",
        o.n,
        kib(o.size)
    );
    println!();

    let mut w = crate::connect(ws).await?;
    let mut reader = crate::connect(ws).await?;
    let mut ok = true;

    // ---- 0. the identity does not move, the contract key does ---------------
    let probe = mint_block(o.size)?;
    let key_a = block_a.at(&probe.id).key();
    let key_b = block_b.at(&probe.id).key();
    let moved = key_a.id() != key_b.id();
    println!(
        "0. the same block has a DIFFERENT contract key under each code: {}",
        verdict(moved)
    );
    println!(
        "   id {}…  A {}  B {}",
        hex16(&probe.id),
        key_a.id(),
        key_b.id()
    );
    ok &= moved;

    // ---- 1. put N blocks under code A ---------------------------------------
    let blocks: Vec<Blk> = (0..o.n)
        .map(|_| mint_block(o.size))
        .collect::<Result<_>>()?;
    let t_put = Instant::now();
    let mut puts_a = 0usize;
    let mut stored_a = 0usize;
    for b in &blocks {
        puts_a += 1;
        if put(&mut w, &block_a, &b.id, &b.state).await? {
            stored_a += 1;
        }
    }
    let ms_a = t_put.elapsed().as_secs_f64() * 1000.0;
    println!(
        "1. {stored_a} of {} blocks stored under code A: {}  ({puts_a} puts, {ms_a:.0} ms)",
        o.n,
        verdict(stored_a == o.n)
    );
    ok &= stored_a == o.n;

    // ---- 2. a reader holding [B, A] migrates what it reads -------------------
    // The order is B first: the table is newest-first, and a block already
    // migrated must cost ONE get, not two.
    let t_mig = Instant::now();
    let (mut miss_b, mut hit_a, mut migrated, mut gets, mut puts_b) = (0, 0, 0, 0, 0);
    for b in &blocks {
        gets += 1;
        if get(&mut reader, &block_b.at(&b.id).key()).await?.is_some() {
            continue; // already current
        }
        miss_b += 1;
        gets += 1;
        let Some(found) = get(&mut reader, &block_a.at(&b.id).key()).await? else {
            continue;
        };
        hit_a += 1;
        // Self-certifying: the reader checks the bytes against the identity it
        // asked for before re-publishing them. It is not trusting the node.
        if blake3::hash(&found).as_bytes().to_vec() != b.id {
            bail!("a block read under A does not hash to the id it was asked for");
        }
        puts_b += 1;
        if put(&mut w, &block_b, &b.id, &found).await? {
            migrated += 1;
        }
    }
    let ms_mig = t_mig.elapsed().as_secs_f64() * 1000.0;
    println!(
        "2. reader with table [B, A]: {miss_b} missed under B, {hit_a} found under A, {migrated} re-put under B: {}",
        verdict(migrated == o.n)
    );
    println!(
        "   {gets} gets and {puts_b} puts for {} blocks — {:.1} puts and {:.1} gets per migrated block, {ms_mig:.0} ms total",
        o.n,
        puts_b as f64 / o.n as f64,
        gets as f64 / o.n as f64
    );
    ok &= migrated == o.n;

    // ---- 2b. the second pass, which is the steady state ---------------------
    // The table is newest-first for a reason: once a block has been migrated it
    // must cost ONE get, not two. Measuring the second pass is what shows the
    // migration is a transient cost rather than a permanent tax, and it is the
    // number that matters after the first reader has been through.
    let t_second = Instant::now();
    let (mut gets2, mut puts2, mut found2) = (0, 0, 0);
    for b in &blocks {
        gets2 += 1;
        if get(&mut reader, &block_b.at(&b.id).key()).await?.is_some() {
            found2 += 1;
            continue;
        }
        gets2 += 1;
        if get(&mut reader, &block_a.at(&b.id).key()).await?.is_some() {
            puts2 += 1;
        }
    }
    let ms_second = t_second.elapsed().as_secs_f64() * 1000.0;
    let steady = found2 == o.n && puts2 == 0 && gets2 == o.n;
    println!(
        "2b. a SECOND pass over the same blocks: {:.1} gets and {puts2} puts per block, {ms_second:.0} ms: {}",
        gets2 as f64 / o.n as f64,
        verdict(steady)
    );
    println!("    the migration is a transient cost; the table order is what makes it one");
    ok &= steady;

    // ---- 3. a reader holding [B] alone finds everything ----------------------
    let mut found_b = 0usize;
    for b in &blocks {
        if get(&mut reader, &block_b.at(&b.id).key()).await?.as_deref() == Some(b.state.as_slice())
        {
            found_b += 1;
        }
    }
    println!(
        "3. reader with table [B] alone finds {found_b} of {}: {}",
        o.n,
        verdict(found_b == o.n)
    );
    ok &= found_b == o.n;

    // ---- 4. CONTROL: bytes that do not hash to their id are refused ---------
    let liar = mint_block(o.size)?;
    let mut wrong = liar.state.clone();
    wrong[1] ^= 0xff; // same claimed id, different bytes
    let refused = !put(&mut w, &block_b, &liar.id, &wrong).await?;
    println!(
        "4. CONTROL — bytes that do not hash to the id they claim are refused under B: {}",
        verdict(refused)
    );
    ok &= refused;

    ok &= register_half(&mut w, &mut reader, &reg_a, &reg_b).await?;

    println!();
    if ok {
        println!("upgrade cycle: PASS");
        Ok(())
    } else {
        bail!("upgrade cycle: FAIL")
    }
}

/// The Register half: a signature binds the params, so a record crosses epochs.
async fn register_half(w: &mut WebApi, reader: &mut WebApi, a: &Epoch, b: &Epoch) -> Result<bool> {
    println!();
    let mut salt = [0u8; 8];
    getrandom::getrandom(&mut salt)?;
    let mut world = testing::keyset_seeded(salt[0], 2, 4, false);
    // The run's own label, so two runs never share a register. (The same
    // 8-bit-seed collision that cost five runs in thirty on the round trip.)
    world.params_bytes.extend_from_slice(&salt);
    world.params = RegParams::parse(&world.params_bytes)
        .ok_or_else(|| anyhow!("the salted params must still parse"))?;
    let p = &world.params;
    let params = world.params_bytes.clone();

    let seq_of = |bytes: &Option<Vec<u8>>| -> Option<u64> {
        bytes
            .as_deref()
            .and_then(|x| RegState::parse_unverified(x, p))
            .and_then(|s| s.record.map(|r| r.signed.seq))
    };
    let mut ok = true;

    // ---- 5. a record signed under A is re-published under B by a stranger ---
    let r3 = world.encode(&world.state(world.record(false, 3, b"three")));
    let stored_a = put(w, a, &params, &r3).await?;
    // The re-publisher reads the bytes and offers them again. It holds no keys
    // and signs nothing — which is the point: the signature inside the record
    // binds blake3(params), and params are the same under both epochs.
    let read_back = get(reader, &a.at(&params).key()).await?;
    let carried = match &read_back {
        Some(bytes) => put(w, b, &params, bytes).await?,
        None => false,
    };
    println!(
        "5. a record signed under A, re-published under B by a third party holding no keys: {}",
        verdict(stored_a && carried)
    );
    println!("   the signature binds the params, not the code — same bytes, new key");
    // Stated rather than left implicit: this is the claim that decides which
    // upgrades can carry records at all. Code A accepted a record built by the
    // CURRENT crate, so the record format did not move across this epoch. An
    // epoch that changed SIG_DOMAIN or the wire would fail here, loudly, and
    // that failure is the answer rather than a broken demo.
    println!(
        "   record format across this epoch: {} (code A accepted a record built by the current crate)",
        if stored_a { "COMPATIBLE" } else { "INCOMPATIBLE" }
    );
    ok &= stored_a && carried;

    // ---- 6. the reader takes the lattice max across [B, A] -------------------
    // Newest only under A; B holds an older one. The max across both is the
    // newest, which is what a reader does DURING the window.
    let r5 = world.encode(&world.state(world.record(false, 5, b"five")));
    let put_a5 = put(w, a, &params, &r5).await?;
    let from_b = get(reader, &b.at(&params).key()).await?;
    let from_a = get(reader, &a.at(&params).key()).await?;
    let across = seq_of(&from_a).max(seq_of(&from_b));
    let during_ok = put_a5 && across == Some(5);
    println!(
        "6. during the window, a reader across [B, A] gets seq {:?} (B has {:?}, A has {:?}): {}",
        across,
        seq_of(&from_b),
        seq_of(&from_a),
        verdict(during_ok)
    );
    ok &= during_ok;

    // ---- 7. THE ROLLBACK HAZARD, executed ------------------------------------
    // The window closes: the reader's table is [B] alone. The newest record
    // lived only under A. Nothing is forged and the answer is still wrong.
    let after_close = seq_of(&get(reader, &b.at(&params).key()).await?);
    let hazard = after_close == Some(3);
    println!(
        "7. the window closes. A reader with [B] alone sees seq {:?}, not 5: {}",
        after_close,
        verdict(hazard)
    );
    println!("   nothing was forged — this is the rollback hazard, and it is why re-publishing");
    println!("   the latest record of every register it keeps is a KEEPER DUTY at the switch");
    ok &= hazard;

    // ---- 8. a keeper heals it ------------------------------------------------
    let healed_put = match get(reader, &a.at(&params).key()).await? {
        Some(bytes) => put(w, b, &params, &bytes).await?,
        None => false,
    };
    let healed = seq_of(&get(reader, &b.at(&params).key()).await?);
    let heal_ok = healed_put && healed == Some(5);
    println!(
        "8. a keeper re-publishes the newest record under B; the same reader now sees seq {:?}: {}",
        healed,
        verdict(heal_ok)
    );
    ok &= heal_ok;

    // ---- 9. CONTROL: a tampered signature does not cross --------------------
    //
    // The tampered record carries a HIGHER seq than anything stored, so
    // acceptance would be VISIBLE. An earlier version of this control tampered
    // with the seq-5 record and asserted the seq did not change — which it
    // would not have done even if the node had taken it, because 5 is already
    // the maximum. A control that cannot distinguish "refused" from "accepted
    // and made no difference" is not a control.
    let clean9 = world.encode(&world.state(world.record(false, 9, b"nine")));
    let mut forged = clean9.clone();
    let at = forged.len() - 8;
    forged[at] ^= 0xff;
    if forged == clean9 {
        bail!("the tamper changed nothing — this control would pass against anything");
    }
    let before = seq_of(&get(reader, &b.at(&params).key()).await?);
    let took_forged = put(w, b, &params, &forged).await?;
    let after_forged = seq_of(&get(reader, &b.at(&params).key()).await?);
    let refused = !took_forged && after_forged == before;
    println!(
        "9. CONTROL — a seq-9 record with a tampered signature is refused under B: {}  (seq {:?} -> {:?}, not 9)",
        verdict(refused),
        before,
        after_forged
    );
    ok &= refused;

    // ---- 10. the positive half of that control ------------------------------
    // The same record, untampered, IS accepted. Without this, step 9 passes
    // against a node that refuses everything — including a run where the
    // harness had simply stopped being able to put anything at all.
    let took_clean = put(w, b, &params, &clean9).await?;
    let after_clean = seq_of(&get(reader, &b.at(&params).key()).await?);
    let clean_ok = took_clean && after_clean == Some(9);
    println!(
        "10. CONTROL — the SAME record with its signature intact is accepted: {}  (seq {:?} -> {:?})",
        verdict(clean_ok),
        before,
        after_clean
    );
    ok &= clean_ok;
    Ok(ok)
}
