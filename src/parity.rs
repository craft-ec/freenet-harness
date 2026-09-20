//! Group-readable-with-parity: can a reader get ANY m of an (m+3) group?
//!
//! The number a design needs is not "is this block fetchable". §7's reader asks
//! for m+3 blocks and stops at m, so what it experiences is a GROUP rate, and a
//! group rate cannot be computed from a per-block rate: the members of a group
//! are written by one writer, in one moment, over one uplink, along
//! neighbouring routes, so their misses are correlated and multiplying a
//! per-block rate assumes exactly the independence that is in question.
//!
//! So every group is scored from its OWN members' measured outcomes, and the
//! table that matters is the distribution of misses PER GROUP set beside what
//! independence would have predicted. The gap between those two columns is the
//! correlation, and it is what decides whether three parity blocks are enough.
//!
//! Four roles, three of which touch the network and one of which is arithmetic:
//! `write` (one concurrent batch per group, ack outcome recorded per key),
//! `read` (all m+3 asked at once, first-fetchable time per key), `reput` (every
//! key still missing, put again), and `score` (pure, rerunnable, no network).
//!
//! The parity blocks are stand-ins — random bytes of the same size class. The
//! code is not under test; the fetchability of m+3 objects written together is.
//!
//! **This is part (b) of freenet-harness#13**, which `group.rs` opened: that
//! module measured the TIMING shape of a k-of-n reader over twelve UNRELATED
//! blocks, and said in its own header that real groups belonged to phase 4.
//! The difference is not the stopwatch rule, which is the same; it is that the
//! members of a group here are written together, so their misses can be
//! correlated, and correlation is the whole question. `group.rs` also runs both
//! roles from one process, which requires one machine to reach both nodes —
//! this splits them so each role runs beside its own node and no tunnel sits in
//! a measured path.
//!
//! Matching an answer to the key that asked for it goes through
//! `latency::Awaiting`, the one implementation of that check in this crate. The
//! thin ask-and-wait wrapper around it now appears in three modules (`group`,
//! `xnode`, here) and wants unifying; that is its own issue, not a thing to do
//! inside a measurement.

use std::{collections::HashMap, sync::Arc, time::Duration};

use anyhow::{anyhow, bail, Result};
use freenet_stdlib::{
    client_api::{ClientRequest, ContractRequest, ContractResponse, HostResponse},
    prelude::*,
};
use tokio::time::timeout;

use crate::{
    latency::{ms_since, send_req, Awaiting},
    xnode::now_ns,
};

/// Which arm a group belongs to, assigned at MINT time and INTERLEAVED.
///
/// `Control` groups are read with their m DATA blocks only. They exist for one
/// question — does asking for m+3 slow the m data fetches — and that question
/// cannot be answered from the `Full` groups, because a second read of a group
/// already read comes warm from the far node's own cache (F33). Interleaved
/// rather than run in sequence so both arms share the link and the moment.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub enum Arm {
    Full,
    Control,
}

impl Arm {
    fn tag(self) -> &'static str {
        match self {
            Arm::Full => "full",
            Arm::Control => "control",
        }
    }
    fn parse(s: &str) -> Option<Arm> {
        match s {
            "full" => Some(Arm::Full),
            "control" => Some(Arm::Control),
            _ => None,
        }
    }
}

/// How a put's acknowledgement turned out.
///
/// Three outcomes, not two, and the middle one is the point: the relay's flat
/// 60 s downstream wait (F20, freenet-core#5446) makes "acknowledged late" a
/// normal event rather than a failure, and the question this run exists to
/// answer is whether the keys a far node never fetches are the same keys whose
/// acks were late or absent. That cannot be reconstructed afterwards, so it is
/// recorded per key as it happens.
// No `Eq`: it carries an f64. The ordering of acks is never needed; only
// which of the three kinds it is.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Ack {
    Within(f64),
    Late(f64),
    Never,
}

impl Ack {
    fn tag(self) -> String {
        match self {
            Ack::Within(ms) => format!("{ms:.1}"),
            Ack::Late(ms) => format!("LATE:{ms:.1}"),
            Ack::Never => "NEVER".into(),
        }
    }
    fn parse(s: &str) -> Option<Ack> {
        if s == "NEVER" {
            return Some(Ack::Never);
        }
        if let Some(rest) = s.strip_prefix("LATE:") {
            return rest.parse().ok().map(Ack::Late);
        }
        s.parse().ok().map(Ack::Within)
    }
    fn is_clean(self) -> bool {
        matches!(self, Ack::Within(_))
    }
}

fn hexify(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        let _ = write!(s, "{x:02x}");
    }
    s
}

fn unhexify(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).ok()?;
    }
    Some(out)
}

/// Mint from a KNOWN seed, so the same state — and therefore the same key —
/// can be rebuilt later by `reput`.
fn mint_seeded(
    code: &Arc<ContractCode<'static>>,
    seed: &[u8; 16],
    size: usize,
) -> (ContractContainer, Vec<u8>) {
    let body = crate::xnode::body_from_seed(seed, size);
    let state = craftec_block_contract::encode(craftec_block_contract::kind::RAW, &body);
    let params = Parameters::from(blake3::hash(&state).as_bytes().to_vec());
    (
        ContractContainer::Wasm(ContractWasmAPIVersion::V1(WrappedContract::new(
            code.clone(),
            params,
        ))),
        state,
    )
}

pub struct Block {
    /// The seed the state was generated from.
    ///
    /// Carried because a re-put must produce the SAME key: a Block's key is
    /// `hash(code, blake3(state))`, so re-putting freshly minted bytes would be
    /// a different key answering a different question. Sixteen bytes per block
    /// costs nothing; carrying the states themselves would be megabytes.
    pub seed: [u8; 16],
    pub gid: usize,
    pub m: usize,
    pub arm: Arm,
    pub idx: usize,
    pub parity: bool,
    pub key: String,
    pub t_send: u128,
    pub ack: Ack,
    pub size: usize,
}

impl Block {
    fn line(&self) -> String {
        format!(
            "GROUP {} {} {} BLOCK {} {} {} {} {} {} {}",
            self.gid,
            self.m,
            self.arm.tag(),
            self.idx,
            if self.parity { "parity" } else { "data" },
            self.key,
            self.t_send,
            self.ack.tag(),
            self.size,
            hexify(&self.seed)
        )
    }
}

pub fn parse_groups(path: &str) -> Result<Vec<Block>> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow!("{path}: {e} — run the write role first"))?;
    let mut out = Vec::new();
    for l in text.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        // GROUP gid m arm BLOCK idx data|parity key t_send ack size seed
        if f.len() < 12 || f[0] != "GROUP" || f[4] != "BLOCK" {
            continue;
        }
        out.push(Block {
            seed: unhexify(f[11]).ok_or_else(|| anyhow!("bad seed in: {l}"))?,
            gid: f[1].parse()?,
            m: f[2].parse()?,
            arm: Arm::parse(f[3]).ok_or_else(|| anyhow!("bad arm in: {l}"))?,
            idx: f[5].parse()?,
            parity: f[6] == "parity",
            key: f[7].to_string(),
            t_send: f[8].parse().unwrap_or(0),
            ack: Ack::parse(f[9]).ok_or_else(|| anyhow!("bad ack in: {l}"))?,
            size: f[10].parse().unwrap_or(0),
        });
    }
    if out.is_empty() {
        bail!("{path}: no GROUP lines — the write role wrote nothing");
    }
    Ok(out)
}

/// Save the connection's recording beside the data file it explains.
///
/// A measurement that produces a surprising table should be explainable
/// without re-running it. The probe is on for every one of these runs, so the
/// tail of its stream costs nothing to keep and is the difference between
/// "the far node missed 8% of blocks" and knowing what the client was doing
/// while it did.
///
/// It is a best effort: failing to write a diagnostic must never fail a
/// measurement that otherwise succeeded.
fn save_probe(client: &crate::probe::Client, out: &str, what: &'static str) {
    let path = format!("{out}.probe.txt");
    match std::fs::write(&path, client.dump(what)) {
        Ok(()) => println!("# probe recording: {path}"),
        Err(e) => println!("# probe recording could NOT be written to {path}: {e}"),
    }
}

/// WRITE: mint and put whole groups, one concurrent batch each.
///
/// Every member of a group is SENT before any acknowledgement is collected.
/// That is how the engine writes a commit, and it is also the only shape that
/// makes the misses correlated in the way the question is about — a run that
/// wrote the members one at a time, waiting for each, would be measuring a
/// different system and would flatter the independence assumption.
///
/// The connection is not drained between the sends of one batch. Draining
/// there throws away the answers to the members asked first, which is how a
/// previous run reported "0 of 6 readable" while the node had answered all six.
#[allow(clippy::too_many_arguments)]
pub async fn write(
    ws: &str,
    wasm: &str,
    ms: &[usize],
    groups: usize,
    control_groups: usize,
    parity: usize,
    size: usize,
    ack_secs: u64,
    out: &str,
    budget_mins: u64,
) -> Result<()> {
    let code = Arc::new(ContractCode::from(std::fs::read(wasm).map_err(|e| {
        anyhow!("{wasm}: {e} — run ../freenet-contracts/build.sh first")
    })?));
    let mut client = crate::connect(ws).await?;
    use std::io::Write as _;

    // The plan is built whole and INTERLEAVED before anything is sent: the two
    // arms and the three values of m alternate, so a link that degrades partway
    // through moves every arm rather than whichever one was running then.
    let mut plan: Vec<(usize, Arm)> = Vec::new();
    for i in 0..groups.max(control_groups) {
        for &m in ms {
            if i < groups {
                plan.push((m, Arm::Full));
            }
            if i < control_groups {
                plan.push((m, Arm::Control));
            }
        }
    }

    println!("# role=groups-write node={ws}");
    println!(
        "# plan: {} group(s) — m {:?}, {groups} full + {control_groups} control each, \
         {parity} parity, {size} B states, ack bound {ack_secs} s, budget {budget_mins} min",
        plan.len(),
        ms
    );
    println!("# a group is one CONCURRENT batch: every member is sent before any ack is read");

    // WHOLE-RUN bookkeeping, and that is the correction this carries.
    //
    // The first version kept a per-group ack map and stopped once it held as
    // many entries as the group had members. When one of a group's own acks
    // was slow the loop kept reading and filled the quota with LATE ACKS
    // BELONGING TO EARLIER GROUPS — the count reached n, the loop exited
    // satisfied, and this group's keys were written down NEVER while the
    // printed line said 15/15. One 240-group run printed 99.5% acked against a
    // per-key truth of 92.1%, and the per-key column was biased too, because a
    // group's own ack arriving after its window had closed was filed nowhere.
    //
    // A count is not a pairing — the same defect as harness#38, one layer up.
    // So: an ack is filed under its OWN key whenever it turns up, each group
    // waits for ITS OWN keys, and every key's outcome is decided at the end
    // from its own send instant.
    let mut acked: HashMap<String, std::time::Instant> = HashMap::new();
    let mut sent: Vec<(Block, std::time::Instant)> = Vec::new();

    let started = std::time::Instant::now();
    let budget = Duration::from_secs(budget_mins * 60);
    let mut done: HashMap<(usize, Arm), usize> = HashMap::new();
    let mut last_progress = std::time::Instant::now();
    let mut relay_notes_total = 0usize;

    for (gid, &(m, arm)) in plan.iter().enumerate() {
        if started.elapsed() >= budget {
            println!(
                "# BUDGET {budget_mins} min reached after {gid} group(s) — reporting what exists"
            );
            break;
        }
        // A stall is a SHORT timeout on PROGRESS, never a long one on the run.
        // The relay tail is ~60 s, so three of them with nothing finishing is a
        // wedge rather than a slow link.
        if last_progress.elapsed() >= Duration::from_secs(180) {
            println!("# STALL: no group completed for 180 s — stopping at {gid} group(s)");
            break;
        }

        let n = m + parity;
        let mut minted = Vec::with_capacity(n);
        for idx in 0..n {
            let mut seed = [0u8; 16];
            getrandom::getrandom(&mut seed)?;
            let (contract, state) = mint_seeded(&code, &seed, size);
            let key = contract.key();
            minted.push((idx, idx >= m, contract, state, key, seed));
        }

        // Every send first. No recv in this loop: draining between the sends of
        // one concurrent batch throws away the answers to the members asked
        // first.
        let t0 = std::time::Instant::now();
        let mut want: Vec<String> = Vec::with_capacity(n);
        for (idx, is_parity, contract, state, key, seed) in minted {
            let t_send = now_ns();
            let label = send_req(
                &mut client,
                ClientRequest::ContractOp(ContractRequest::Put {
                    contract,
                    state: WrappedState::from(state.clone()),
                    related_contracts: RelatedContracts::default(),
                    subscribe: false,
                    blocking_subscribe: false,
                }),
                Duration::from_secs(ack_secs),
            )
            .await?;
            let key = key.id().to_string();
            want.push(key.clone());
            sent.push((
                Block {
                    seed,
                    gid,
                    m,
                    arm,
                    idx,
                    parity: is_parity,
                    key,
                    t_send,
                    // Filled in at the end, from this key's own send instant.
                    ack: Ack::Never,
                    size: state.len(),
                },
                std::time::Instant::now(),
            ));
            let _ = label;
        }

        // Wait for THIS GROUP'S keys, not for a count.
        let deadline = std::time::Instant::now() + Duration::from_secs(2 * ack_secs);
        let mut relay_notes = 0usize;
        while !want.iter().all(|k| acked.contains_key(k)) {
            let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) else {
                break;
            };
            match timeout(left, client.recv()).await {
                Ok(Ok(HostResponse::ContractResponse(ContractResponse::PutResponse { key }))) => {
                    // Filed under its OWN key, whichever group it belongs to.
                    acked
                        .entry(key.id().to_string())
                        .or_insert_with(std::time::Instant::now);
                }
                Ok(Ok(_)) => {}
                // The relay's own text arrives on a response carrying no key,
                // so it cannot be attributed to a member. Counted per group.
                Ok(Err(_)) => relay_notes += 1,
                Err(_) => break,
            }
        }
        relay_notes_total += relay_notes;

        let got = want.iter().filter(|k| acked.contains_key(*k)).count();
        let c = done.entry((m, arm)).or_insert(0);
        *c += 1;
        last_progress = std::time::Instant::now();
        println!(
            "# group {gid} m={m} {} — {got}/{n} of ITS OWN keys acked, {:.1} s{}, {}",
            arm.tag(),
            t0.elapsed().as_secs_f64(),
            if relay_notes > 0 {
                format!(", {relay_notes} keyless error response(s)")
            } else {
                String::new()
            },
            client.line()
        );
    }

    // One last drain: an ack that arrives after its group's window has closed
    // still belongs to its key, and throwing it away would report a write as
    // unacknowledged when the node had answered.
    let drain_until = std::time::Instant::now() + Duration::from_secs(ack_secs);
    while std::time::Instant::now() < drain_until {
        let Some(left) = drain_until.checked_duration_since(std::time::Instant::now()) else {
            break;
        };
        match timeout(left, client.recv()).await {
            Ok(Ok(HostResponse::ContractResponse(ContractResponse::PutResponse { key }))) => {
                acked
                    .entry(key.id().to_string())
                    .or_insert_with(std::time::Instant::now);
            }
            Ok(Ok(_)) | Ok(Err(_)) => {}
            Err(_) => break,
        }
    }

    // Now every key's outcome, from ITS OWN send instant.
    let mut sink = std::io::BufWriter::new(std::fs::File::create(out)?);
    let bound = Duration::from_secs(ack_secs);
    let (mut within_n, mut late_n, mut never_n) = (0usize, 0usize, 0usize);
    for (mut b, sent_at) in sent {
        b.ack = match acked.get(&b.key) {
            Some(at) => {
                let d = at.saturating_duration_since(sent_at);
                if d <= bound {
                    within_n += 1;
                    Ack::Within(d.as_secs_f64() * 1000.0)
                } else {
                    late_n += 1;
                    Ack::Late(d.as_secs_f64() * 1000.0)
                }
            }
            None => {
                never_n += 1;
                Ack::Never
            }
        };
        writeln!(sink, "{}", b.line())?;
    }
    if relay_notes_total > 0 {
        writeln!(
            sink,
            "# NOTE: {relay_notes_total} keyless error response(s) over the run"
        )?;
    }
    sink.flush()?;

    // THE INVARIANT, asserted rather than trusted.
    //
    // The printed summary and the per-key file disagreed once already — the
    // line said 99.5% acked over a run whose records said 92.1% — because the
    // summary counted acks RECEIVED while the file matched acks to KEYS. The
    // two are computed differently on purpose, so agreeing is evidence; a tool
    // that prints a number nobody can check against its own output is how that
    // went unnoticed for a whole run.
    {
        let back = parse_groups(out)?;
        let (mut w, mut l, mut n2) = (0usize, 0usize, 0usize);
        for b in &back {
            match b.ack {
                Ack::Within(_) => w += 1,
                Ack::Late(_) => l += 1,
                Ack::Never => n2 += 1,
            }
        }
        if (w, l, n2) != (within_n, late_n, never_n) {
            bail!(
                "the printed summary and the file it just wrote DISAGREE.\n  \
                 printed: {within_n} within / {late_n} late / {never_n} never\n  \
                 file:    {w} within / {l} late / {n2} never\n  \
                 Every table downstream is built from the file, so a summary that \
                 does not match it is a number nobody can check — which is exactly \
                 how a 99.5% ack rate got reported over a run whose records said 92.1%."
            );
        }
        println!(
            "# invariant: the printed summary matches the file, {} block(s) checked",
            back.len()
        );
    }

    println!("# groups completed:");
    let mut keys: Vec<_> = done.keys().copied().collect();
    keys.sort_by_key(|(m, a)| (*m, a.tag()));
    for k in keys {
        println!("#   m={} {:8} {}", k.0, k.1.tag(), done[&k]);
    }
    let total = within_n + late_n + never_n;
    println!(
        "# per-key ack outcome over {total} block(s): {within_n} within {ack_secs} s, \
         {late_n} late, {never_n} never"
    );
    println!("# wrote {out}");
    save_probe(&client, out, "the group write");
    let _ = client.send(ClientRequest::Disconnect { cause: None }).await;
    Ok(())
}

/// READ: ask for every member of a group AT ONCE and record each one's first
/// fetchable time.
///
/// All keys are in flight together and probed round-robin, so no key's clock
/// starts when another key's ends. Polling key-by-key would make the last key
/// of a group of fifteen first probed fourteen bounds late, and the number
/// reported would be reader queueing rather than propagation.
///
/// `Control` groups are asked for their DATA members only. That is the whole
/// arm: the m data blocks of a control group and the m data blocks of a full
/// group are the same ask under different surrounding load.
pub async fn read(
    ws: &str,
    groups_file: &str,
    per_key_secs: u64,
    probe_ms: u64,
    out: &str,
) -> Result<()> {
    let blocks = parse_groups(groups_file)?;
    let mut client = crate::connect(ws).await?;
    let mut sink = std::io::BufWriter::new(std::fs::File::create(out)?);
    use std::io::Write as _;

    let wanted: Vec<&Block> = blocks
        .iter()
        .filter(|b| b.arm == Arm::Full || !b.parity)
        .collect();
    println!("# role=groups-read node={ws}");
    println!(
        "# {} block(s) of {} group(s); control groups are asked for their m data members only",
        wanted.len(),
        blocks
            .iter()
            .map(|b| b.gid)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
    );

    let mut ids = Vec::with_capacity(wanted.len());
    for b in &wanted {
        let id =
            ContractInstanceId::try_from(b.key.clone()).map_err(|e| anyhow!("{}: {e}", b.key))?;
        ids.push((b.gid, b.key.clone(), id));
    }

    // One ask per key up front, then round-robin re-asks on one cadence. The
    // grid is printed because a first-fetchable time is resolved to it, and a
    // series whose whole spread fits inside one step measured the instrument.
    let t0 = std::time::Instant::now();
    let deadline = t0 + Duration::from_secs(per_key_secs);
    let mut open: Vec<(usize, String, ContractInstanceId)> = ids;
    let mut found = 0usize;
    let mut round = 0usize;
    println!(
        "# probe grid: one probe at a time, up to {probe_ms} ms each, {} key(s) per round",
        open.len()
    );
    while !open.is_empty() && std::time::Instant::now() < deadline {
        round += 1;
        let mut still = Vec::with_capacity(open.len());
        for (gid, key, id) in open.drain(..) {
            if std::time::Instant::now() >= deadline {
                still.push((gid, key, id));
                continue;
            }
            match probe(&mut client, &id, Duration::from_millis(probe_ms)).await {
                Ok(Some(len)) => {
                    found += 1;
                    writeln!(sink, "READ {gid} {key} {:.1} {len}", ms_since(t0))?;
                }
                _ => still.push((gid, key, id)),
            }
        }
        open = still;
        sink.flush()?;
        if round.is_multiple_of(20) {
            println!(
                "# alive: round {round}, {found} fetched, {} still cold, {:.0} s of {per_key_secs}",
                open.len(),
                t0.elapsed().as_secs_f64()
            );
        }
    }
    for (gid, key, _) in &open {
        writeln!(sink, "MISS {gid} {key} {per_key_secs}")?;
    }
    sink.flush()?;
    println!(
        "# fetched {found}, missed {} within {per_key_secs} s — the MISSes are \
         'not within the limit', NOT 'never'",
        open.len()
    );
    println!("# wrote {out}");
    save_probe(&client, out, "the group read");
    let _ = client.send(ClientRequest::Disconnect { cause: None }).await;
    Ok(())
}

/// One bounded ask for one key, matched BY KEY.
///
/// Answers for other keys are consumed and discarded rather than being allowed
/// to satisfy this one: with many keys in flight, accepting any `GetResponse`
/// credits one key's answer to another, which is not a rare mix-up but the
/// normal case.
async fn probe(
    client: &mut crate::probe::Client,
    id: &ContractInstanceId,
    bound: Duration,
) -> Result<Option<usize>> {
    let sent = send_req(
        client,
        ClientRequest::ContractOp(ContractRequest::Get {
            key: *id,
            return_contract_code: false,
            subscribe: false,
            blocking_subscribe: false,
        }),
        Duration::from_secs(30),
    )
    .await?;
    let end = std::time::Instant::now() + bound;
    let mut waiting = Awaiting::new(*id);
    loop {
        let Some(left) = end.checked_duration_since(std::time::Instant::now()) else {
            client.finish(sent, instrument::vocab::Outcome::Timeout);
            return Ok(None);
        };
        let (arrived, len) = match timeout(left, client.recv()).await {
            Ok(Ok(HostResponse::ContractResponse(ContractResponse::GetResponse {
                key: k,
                state,
                ..
            }))) => (Some(*k.id()), Some(state.as_ref().len())),
            Ok(Ok(_)) => (None, None),
            Ok(Err(_)) | Err(_) => {
                client.finish(sent, instrument::vocab::Outcome::Blocked);
                return Ok(None);
            }
        };
        if waiting.offer(arrived.as_ref()) {
            client.finish(
                sent,
                match len {
                    Some(_) => instrument::vocab::Outcome::Ok,
                    None => instrument::vocab::Outcome::Missing,
                },
            );
            return Ok(len);
        }
    }
}

fn parse_reads(path: &str) -> Result<HashMap<String, Option<f64>>> {
    let text = std::fs::read_to_string(path).map_err(|e| anyhow!("{path}: {e}"))?;
    let mut out = HashMap::new();
    for l in text.lines() {
        let f: Vec<&str> = l.split_whitespace().collect();
        match f.first() {
            Some(&"READ") if f.len() >= 4 => {
                out.insert(f[2].to_string(), f[3].parse::<f64>().ok());
            }
            Some(&"MISS") if f.len() >= 3 => {
                out.insert(f[2].to_string(), None);
            }
            _ => {}
        }
    }
    Ok(out)
}

fn pct(a: usize, b: usize) -> String {
    if b == 0 {
        "   —".into()
    } else {
        format!("{:5.1}%", 100.0 * a as f64 / b as f64)
    }
}

fn quantile(v: &mut [f64], q: f64) -> Option<f64> {
    if v.is_empty() {
        return None;
    }
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    Some(v[((v.len() - 1) as f64 * q).round() as usize])
}

/// C(n,k) p^k (1-p)^(n-k) — what independence WOULD have predicted.
///
/// Printed beside the measured distribution and never used in place of it. The
/// gap between the two columns is the correlation, and the correlation is the
/// finding; a run that reported only the binomial would be reporting its own
/// assumption back.
fn binomial(n: usize, k: usize, p: f64) -> f64 {
    let mut c = 1.0f64;
    for i in 0..k {
        c = c * (n - i) as f64 / (i + 1) as f64;
    }
    c * p.powi(k as i32) * (1.0 - p).powi((n - k) as i32)
}

pub fn score(
    groups_file: &str,
    reads_file: &str,
    reput_file: Option<&str>,
    thresholds: &[f64],
    min_groups: usize,
) -> Result<()> {
    let blocks = parse_groups(groups_file)?;
    let reads = parse_reads(reads_file)?;
    let reput = match reput_file {
        Some(p) => Some(parse_reads(p)?),
        None => None,
    };

    // Per-block, over every block that was ASKED for. A control group's parity
    // members were never asked, so they are not misses and must not be counted
    // as fetchable either.
    let asked: Vec<&Block> = blocks
        .iter()
        .filter(|b| reads.contains_key(&b.key))
        .collect();
    println!("== 1. per-block fetchable ==");
    println!("   blocks asked: {}", asked.len());
    print!("   within        ");
    for t in thresholds {
        print!("{:>10}", format!("{t:.0} s"));
    }
    println!("{:>12}", "never");
    print!("   {:14}", "");
    let mut ever = 0usize;
    for t in thresholds {
        let n = asked
            .iter()
            .filter(|b| matches!(reads.get(&b.key), Some(Some(ms)) if *ms <= t * 1000.0))
            .count();
        print!("{:>10}", format!("{n} {}", pct(n, asked.len())));
    }
    for b in &asked {
        if matches!(reads.get(&b.key), Some(Some(_))) {
            ever += 1;
        }
    }
    let never = asked.len() - ever;
    println!("{:>12}", format!("{never} {}", pct(never, asked.len())));

    println!();
    println!("== 2. ack x fetchable (is 'never fetchable' the relay bug, F20/#5446?) ==");
    println!(
        "   {:<18}{:>12}{:>12}{:>10}",
        "ack outcome", "fetchable", "never", "n"
    );
    type AckRow = (&'static str, fn(Ack) -> bool);
    let rows_of: [AckRow; 3] = [
        ("within bound", |a| matches!(a, Ack::Within(_))),
        ("LATE", |a| matches!(a, Ack::Late(_))),
        ("NEVER acked", |a| matches!(a, Ack::Never)),
    ];
    for (name, f) in rows_of {
        let rows: Vec<&&Block> = asked.iter().filter(|b| f(b.ack)).collect();
        let ok = rows
            .iter()
            .filter(|b| matches!(reads.get(&b.key), Some(Some(_))))
            .count();
        println!(
            "   {:<18}{:>12}{:>12}{:>10}",
            name,
            format!("{ok} {}", pct(ok, rows.len())),
            format!("{} {}", rows.len() - ok, pct(rows.len() - ok, rows.len())),
            rows.len()
        );
    }
    println!(
        "   'same bug' is supported only if the never-fetchable keys CONCENTRATE in the\n   \
         LATE / NEVER rows. Equal rates across rows say the two are unrelated."
    );

    // Groups, scored from their OWN members.
    let mut by_group: HashMap<usize, Vec<&Block>> = HashMap::new();
    for b in &blocks {
        by_group.entry(b.gid).or_default().push(b);
    }
    let ms_values: std::collections::BTreeSet<usize> = blocks.iter().map(|b| b.m).collect();

    println!();
    println!("== 3. group readable (>= m of m+p) by parity count ==");
    println!("   scored from each group's OWN members — a per-block rate is never multiplied");
    for &t in thresholds {
        println!("   within {t:.0} s:");
        println!(
            "      {:>4}{:>8}{:>12}{:>12}{:>12}{:>12}",
            "m", "groups", "0 parity", "1", "2", "3"
        );
        for &m in &ms_values {
            let gs: Vec<&Vec<&Block>> = by_group
                .values()
                .filter(|g| g[0].m == m && g[0].arm == Arm::Full)
                .collect();
            print!("      {m:>4}{:>8}", gs.len());
            // How many parity blocks these groups actually HAVE. A column for
            // more parity than was written would report the same number under
            // a different heading — the choice of 3 has to be tested, and a
            // column that silently falls back to "all of them" tests nothing.
            let have = gs
                .iter()
                .map(|g| g.iter().filter(|b| b.parity).count())
                .max()
                .unwrap_or(0);
            for p in 0..=3usize {
                if p > have {
                    print!("{:>12}", "—");
                    continue;
                }
                let readable = gs
                    .iter()
                    .filter(|g| {
                        g.iter()
                            .filter(|b| !b.parity || b.idx < m + p)
                            .filter(
                                |b| matches!(reads.get(&b.key), Some(Some(v)) if *v <= t * 1000.0),
                            )
                            .count()
                            >= m
                    })
                    .count();
                print!("{:>12}", format!("{readable} {}", pct(readable, gs.len())));
            }
            println!();
        }
    }

    println!();
    println!("== 4. misses PER GROUP, measured against what independence predicts ==");
    println!("   the gap between the two columns IS the correlation");
    let mut groups_with_a_miss = 0usize;
    for &m in &ms_values {
        let gs: Vec<&Vec<&Block>> = by_group
            .values()
            .filter(|g| g[0].m == m && g[0].arm == Arm::Full)
            .collect();
        if gs.is_empty() {
            continue;
        }
        // The group's real width, not an assumed m+3.
        let n = gs.iter().map(|g| g.len()).max().unwrap_or(m);
        let total_blocks: usize = gs.iter().map(|g| g.len()).sum();
        let total_miss: usize = gs
            .iter()
            .map(|g| {
                g.iter()
                    .filter(|b| !matches!(reads.get(&b.key), Some(Some(_))))
                    .count()
            })
            .sum();
        let p = if total_blocks == 0 {
            0.0
        } else {
            total_miss as f64 / total_blocks as f64
        };
        println!(
            "   m={m} (n={n}), {} groups, per-block miss rate {:.3}",
            gs.len(),
            p
        );
        println!(
            "      {:>8}{:>14}{:>18}",
            "misses", "measured", "if independent"
        );
        for k in 0..=4usize {
            let measured = gs
                .iter()
                .filter(|g| {
                    let miss = g
                        .iter()
                        .filter(|b| !matches!(reads.get(&b.key), Some(Some(_))))
                        .count();
                    if k == 4 {
                        miss >= 4
                    } else {
                        miss == k
                    }
                })
                .count();
            if k > 0 {
                groups_with_a_miss += measured;
            }
            let pred = if k == 4 {
                1.0 - (0..4).map(|j| binomial(n, j, p)).sum::<f64>()
            } else {
                binomial(n, k, p)
            };
            println!(
                "      {:>8}{:>14}{:>18}",
                if k == 4 {
                    "4+".to_string()
                } else {
                    k.to_string()
                },
                format!("{measured} {}", pct(measured, gs.len())),
                format!("{:5.1}%", pred * 100.0)
            );
        }
    }

    println!();
    println!("== 5. time to readable: the m-th fastest of the whole group, against all m data ==");
    println!(
        "   {:>4}{:>10}{:>14}{:>14}{:>14}{:>14}",
        "m", "groups", "m+3 p50", "m+3 p90", "data p50", "data p90"
    );
    for &m in &ms_values {
        let gs: Vec<&Vec<&Block>> = by_group
            .values()
            .filter(|g| g[0].m == m && g[0].arm == Arm::Full)
            .collect();
        let (mut with, mut without) = (Vec::new(), Vec::new());
        for g in &gs {
            let mut all: Vec<f64> = g
                .iter()
                .filter_map(|b| reads.get(&b.key).copied().flatten())
                .collect();
            all.sort_by(|a, b| a.partial_cmp(b).unwrap());
            if all.len() >= m {
                with.push(all[m - 1]);
            }
            let mut data: Vec<f64> = g
                .iter()
                .filter(|b| !b.parity)
                .filter_map(|b| reads.get(&b.key).copied().flatten())
                .collect();
            data.sort_by(|a, b| a.partial_cmp(b).unwrap());
            if data.len() == m {
                without.push(data[m - 1]);
            }
        }
        let f = |v: &mut Vec<f64>, q| {
            quantile(v, q)
                .map(|x| format!("{:.0} ms", x))
                .unwrap_or("—".into())
        };
        println!(
            "   {m:>4}{:>10}{:>14}{:>14}{:>14}{:>14}",
            gs.len(),
            f(&mut with.clone(), 0.5),
            f(&mut with.clone(), 0.9),
            f(&mut without.clone(), 0.5),
            f(&mut without.clone(), 0.9)
        );
    }

    println!();
    println!("== 6. cost: does asking for m+3 slow the m DATA fetches? ==");
    println!("   full-arm vs control-arm, batch against batch — never single operations");
    println!(
        "   {:>4}{:>12}{:>14}{:>14}{:>12}{:>14}",
        "m", "arm", "data p50", "data p90", "groups", "bytes asked"
    );
    for &m in &ms_values {
        for arm in [Arm::Full, Arm::Control] {
            let gs: Vec<&Vec<&Block>> = by_group
                .values()
                .filter(|g| g[0].m == m && g[0].arm == arm)
                .collect();
            let mut last = Vec::new();
            let mut bytes = 0usize;
            for g in &gs {
                let mut data: Vec<f64> = g
                    .iter()
                    .filter(|b| !b.parity)
                    .filter_map(|b| reads.get(&b.key).copied().flatten())
                    .collect();
                data.sort_by(|a, b| a.partial_cmp(b).unwrap());
                if data.len() == m {
                    last.push(data[m - 1]);
                }
                bytes += g
                    .iter()
                    .filter(|b| reads.contains_key(&b.key))
                    .map(|b| b.size)
                    .sum::<usize>();
            }
            let f = |v: &mut Vec<f64>, q| {
                quantile(v, q)
                    .map(|x| format!("{:.0} ms", x))
                    .unwrap_or("—".into())
            };
            println!(
                "   {m:>4}{:>12}{:>14}{:>14}{:>12}{:>14}",
                arm.tag(),
                f(&mut last.clone(), 0.5),
                f(&mut last.clone(), 0.9),
                gs.len(),
                bytes
            );
        }
    }

    if let Some(rp) = &reput {
        println!();
        println!("== 7. re-put of every key not fetchable within the bound ==");
        let stuck: Vec<&&Block> = asked
            .iter()
            .filter(|b| !matches!(reads.get(&b.key), Some(Some(_))))
            .collect();
        let back = stuck
            .iter()
            .filter(|b| matches!(rp.get(&b.key), Some(Some(_))))
            .count();
        println!(
            "   {} stuck key(s); {back} fetchable after a re-put {}",
            stuck.len(),
            pct(back, stuck.len())
        );
        let mut t: Vec<f64> = stuck
            .iter()
            .filter_map(|b| rp.get(&b.key).copied().flatten())
            .collect();
        if !t.is_empty() {
            println!(
                "   time after re-put: p50 {:.0} ms, p90 {:.0} ms",
                quantile(&mut t, 0.5).unwrap_or(0.0),
                quantile(&mut t, 0.9).unwrap_or(0.0)
            );
        }
    }

    // Floors. A run that does not meet them has not measured what it was asked
    // to measure, and saying so is the whole point of printing them.
    println!();
    println!("== floors ==");
    let mut ok = true;
    for &m in &ms_values {
        let n = by_group
            .values()
            .filter(|g| g[0].m == m && g[0].arm == Arm::Full)
            .count();
        let met = n >= min_groups;
        ok &= met;
        println!(
            "   m={m}: {n} scored group(s), need {min_groups} — {}",
            if met { "met" } else { "NOT MET" }
        );
    }
    println!(
        "   groups with at least one miss: {groups_with_a_miss} — {}",
        if groups_with_a_miss > 0 {
            "the run can say something about correlation".to_string()
        } else {
            "COULD NOT CHECK (zero misses is not 'parity unnecessary')".to_string()
        }
    );
    if !ok || groups_with_a_miss == 0 {
        println!("   VERDICT WITHHELD: a floor is unmet, so the tables above are indicative only.");
    }
    Ok(())
}

/// REPUT: put every key the far node could not fetch, again.
///
/// The question is whether a stuck block is stuck because of the write — the
/// relay's flat 60 s wait (F20) — or because of where it landed. If a re-put
/// makes it fetchable, the block was never placed; if it does not, something
/// else is wrong. Parity REBUILD on read does not exist today, so a re-put is
/// the only recovery a reader has, and its rate is worth knowing exactly.
///
/// It re-puts the SAME bytes, rebuilt from the seed recorded at write time. A
/// fresh mint would be a different key and would report a recovery rate for
/// keys nobody was stuck on.
pub async fn reput(
    ws: &str,
    wasm: &str,
    groups_file: &str,
    reads_file: &str,
    ack_secs: u64,
    out: &str,
) -> Result<()> {
    let blocks = parse_groups(groups_file)?;
    let reads = parse_reads(reads_file)?;
    let stuck: Vec<&Block> = blocks
        .iter()
        .filter(|b| matches!(reads.get(&b.key), Some(None)))
        .collect();
    let code = Arc::new(ContractCode::from(std::fs::read(wasm).map_err(|e| {
        anyhow!("{wasm}: {e} — run ../freenet-contracts/build.sh first")
    })?));
    let mut sink = std::io::BufWriter::new(std::fs::File::create(out)?);
    use std::io::Write as _;

    println!("# role=parity-reput node={ws}");
    println!("# {} key(s) the far node could not fetch", stuck.len());
    if stuck.is_empty() {
        println!("# nothing to re-put — an empty file is written so `score` still runs");
        sink.flush()?;
        return Ok(());
    }

    let mut client = crate::connect(ws).await?;
    // One concurrent batch again, and for the same reason: these blocks were
    // written together and are being given the same treatment a second time.
    let t0 = std::time::Instant::now();
    let mut pending = Vec::with_capacity(stuck.len());
    for b in &stuck {
        let (contract, state) = mint_seeded(&code, &b.seed, b.size.saturating_sub(1));
        let rebuilt = contract.key().id().to_string();
        // If the rebuild does not reproduce the key, the seed round trip is
        // broken and every number after this would be about other blocks.
        if rebuilt != b.key {
            bail!(
                "re-mint from the recorded seed produced {rebuilt}, not {}.\n  \
                 The seed round trip is broken, so a re-put would be putting DIFFERENT \
                 blocks and calling their fetch rate a recovery rate.",
                b.key
            );
        }
        let label = send_req(
            &mut client,
            ClientRequest::ContractOp(ContractRequest::Put {
                contract,
                state: WrappedState::from(state),
                related_contracts: RelatedContracts::default(),
                subscribe: false,
                blocking_subscribe: false,
            }),
            Duration::from_secs(ack_secs),
        )
        .await?;
        pending.push((b, label));
    }
    println!(
        "# {} re-put(s) sent as one batch, collecting acks",
        pending.len()
    );

    let mut acks: HashMap<String, Ack> = HashMap::new();
    let within = std::time::Instant::now() + Duration::from_secs(ack_secs);
    let grace = within + Duration::from_secs(ack_secs);
    while acks.len() < pending.len() {
        let Some(left) = grace.checked_duration_since(std::time::Instant::now()) else {
            break;
        };
        match timeout(left, client.recv()).await {
            Ok(Ok(HostResponse::ContractResponse(ContractResponse::PutResponse { key }))) => {
                let late = std::time::Instant::now() > within;
                let ms = ms_since(t0);
                acks.insert(
                    key.id().to_string(),
                    if late { Ack::Late(ms) } else { Ack::Within(ms) },
                );
            }
            Ok(Ok(_)) => {}
            Ok(Err(_)) => {}
            Err(_) => break,
        }
    }
    for (b, label) in pending {
        let ack = acks.get(&b.key).copied().unwrap_or(Ack::Never);
        if !ack.is_clean() {
            client.finish(label, instrument::vocab::Outcome::Timeout);
        }
        let mut again = Block {
            seed: b.seed,
            gid: b.gid,
            m: b.m,
            arm: b.arm,
            idx: b.idx,
            parity: b.parity,
            key: b.key.clone(),
            t_send: now_ns(),
            ack,
            size: b.size,
        };
        // The re-put file is READ by the read role, so it is written in the
        // same shape as the groups file — one reader, one format.
        again.t_send = now_ns();
        writeln!(sink, "{}", again.line())?;
    }
    sink.flush()?;
    println!(
        "# {} acked within {ack_secs} s; wrote {out} — now run `--role read --groups-file {out}`",
        acks.values().filter(|a| a.is_clean()).count()
    );
    save_probe(&client, out, "the re-put");
    let _ = client.send(ClientRequest::Disconnect { cause: None }).await;
    Ok(())
}
