//! `race-get`: how long until k of a parity group's k+3 are readable on a
//! SECOND node, read through the SDK ENGINE's own read path.
//!
//! **What is measured is what ships** (the owner's rule 4: one read path). The
//! reader here is `page_io::PageIo::reader` over `page::server::Server` — the
//! engine a browser page runs, framing the same client-API bytes — linked from
//! the SDK checkout beside this repo. So the ARM is the SDK build, not a flag:
//! today's engine is the one-at-a-time ("serial") reader, and craftworks-sdk#303
//! (race get: ask all k+3, finish on the first k) is the other arm once its
//! branch exists. Each record names the SDK revision it linked
//! (`HARNESS_SDK_REV`, from `build.rs`), and the runbook builds this tool once
//! per SDK checkout and INTERLEAVES the two binaries trial by trial over the
//! SAME published groups (freenet-harness#13, part (b)).
//!
//! Four roles:
//!
//! - `up` — start a private GATEWAY node A under `--dir`, publish `--rows` rows
//!   of `--value-bytes` through a writer page (the engine's write path and the
//!   signer), wait until every write is `ParityComplete` so each group's parity
//!   is on A too, and write `race-get.run.json`. A keeps running.
//! - `read` — per trial, start a FRESH peer B joined to A (new dirs: cold by
//!   construction), open a READER page on A's published tree, read every row,
//!   and time each group from the arrival of the node that lists it to the
//!   arrival of its k-th block (data or parity). B is stopped and its dirs
//!   removed after each trial. Records append to `race-get.records.jsonl`.
//! - `score` — pure: the records file, per arm, as p50/p75/p90/max and the
//!   count `not within T`. Rerunnable.
//! - `down` — stop A.
//!
//! **Why the clock starts at the parent node.** A group's k+3 ids are listed
//! in its parent; a reader cannot ask for any of them before that node has
//! arrived. From there to the k-th arrival is exactly the part a race reader
//! and a serial reader do differently, so that is the interval reported — the
//! head read, the join and every other group's wait are outside it. Arrivals
//! are stamped as the harness receives each whole message (event-timed, not
//! polled), so the resolution is the socket read, not a probe period.
//!
//! **What this cannot show.** Two private nodes on one machine have no relay
//! and no ~60 s downstream wait (F20). The tail a race reader exists to cut is
//! the real network's, so a REAL-NETWORK arm (the reader beside a node in
//! another datacentre) is planned in the README and runs only with core dev's
//! OK under the Hetzner rules; this is the local pair.
//!
//! Nothing waits on a stall: every wait has a deadline, every trial has
//! `--trial-secs`, the role has `--budget-mins`, and a group short of k by its
//! trial's end is recorded as `not within T`.

use std::{
    collections::{BTreeMap, HashMap},
    io::Write as _,
    net::{TcpListener, TcpStream, UdpSocket},
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Context, Result};
use futures::{SinkExt, StreamExt};
use page::server::{Server, SignerFacts};
use page::{Ms, Page, PutPath};
use page_io::{Artefacts, PageIo};
use protocol::{Reply, Request, WriteState};
use sdk_prolly as prolly;
use sha2::Digest as _;
use tokio_tungstenite::tungstenite::Message;

use crate::stats::{nearest_rank, Table};

/// The SDK revision this binary LINKED, stamped by `build.rs`. The arm's
/// identity: two builds of this tool differ in nothing else.
pub const SDK_REV: &str = env!("HARNESS_SDK_REV");

/// The protocol version and session the pages here speak.
const VERSION: u16 = 4;
const SESSION: u64 = 11;

/// How long a node may take to open its client API.
const NODE_UP: Duration = Duration::from_secs(45);

/// Rows per write, bounded by bytes so a write stays well under the engine's
/// own write bound whatever `--value-bytes` is.
const WRITE_BYTES: usize = 64 * 1024;

/// The run file `up` writes and every other role reads.
const RUN_FILE: &str = "race-get.run.json";
const RECORDS: &str = "race-get.records.jsonl";

// ---------------------------------------------------------------- nodes ----

/// A private node this process started. Stopped on drop unless DETACHED
/// (`up` leaves A running for the `read` trials).
pub struct Node {
    child: Option<Child>,
    pub ws: u16,
    pub net: u16,
}

impl Node {
    pub fn url(&self) -> String {
        format!(
            "ws://127.0.0.1:{}/v1/contract/command?encodingProtocol=native",
            self.ws
        )
    }
    fn pid(&self) -> u32 {
        self.child.as_ref().map_or(0, |c| c.id())
    }
    fn detach(mut self) -> u32 {
        let pid = self.pid();
        self.child = None;
        pid
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

/// A port the OS hands out, free for TCP and UDP (the node's transport), never
/// the owner's and never one already `taken`.
fn free_port(taken: &[u16]) -> Result<u16> {
    for _ in 0..50 {
        let p = TcpListener::bind("127.0.0.1:0")?.local_addr()?.port();
        if crate::PROTECTED_PORTS.contains(&p) || taken.contains(&p) {
            continue;
        }
        if UdpSocket::bind(("127.0.0.1", p)).is_ok() {
            return Ok(p);
        }
    }
    bail!("no port free for TCP and UDP in 50 asks")
}

enum Role<'a> {
    /// An isolated gateway on loopback, with a transport key we chose so a
    /// peer can name it.
    Gateway { keypair: &'a Path },
    /// A peer that joins exactly that gateway and nothing else.
    Peer { gateway: &'a str },
}

/// Start `freenet network` with EXPLICIT data, config, log AND web-app cache
/// dirs under `dir`, `--disable-auto-update`, loopback addresses and free ports.
fn spawn(dir: &Path, role: Role<'_>) -> Result<Node> {
    for d in ["data", "config", "log", "webapp-cache"] {
        std::fs::create_dir_all(dir.join(d))?;
    }
    let ws = free_port(&[])?;
    let net = free_port(&[ws])?;
    let (ws_s, net_s) = (ws.to_string(), net.to_string());
    let path = |d: &str| dir.join(d).to_string_lossy().into_owned();
    let mut args: Vec<String> = [
        "network",
        "--skip-load-from-network",
        "--network-address",
        "127.0.0.1",
        "--network-port",
        &net_s,
        "--ws-api-address",
        "127.0.0.1",
        "--ws-api-port",
        &ws_s,
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    for (flag, d) in [
        ("--data-dir", "data"),
        ("--config-dir", "config"),
        ("--log-dir", "log"),
    ] {
        args.push(flag.into());
        args.push(path(d));
    }
    args.push("--disable-auto-update".into());
    match role {
        Role::Gateway { keypair } => {
            for a in [
                "--is-gateway",
                "--public-network-address",
                "127.0.0.1",
                "--public-network-port",
                &net_s,
            ] {
                args.push(a.into());
            }
            args.push("--transport-keypair".into());
            args.push(keypair.to_string_lossy().into_owned());
        }
        Role::Peer { gateway } => {
            args.push("--gateway".into());
            args.push(gateway.into());
        }
    }
    let out = std::fs::File::create(dir.join("node.out"))?;
    let child = Command::new("freenet")
        .args(&args)
        // ITS OWN web-app cache. The default is one per-USER directory, so a
        // test node would share, and sweep, the owner's node's cache
        // (craftworks CLAUDE.md; freenet-core config.rs:3330).
        .env("FREENET_WEBAPP_CACHE_DIR", dir.join("webapp-cache"))
        .stdin(Stdio::null())
        .stdout(out.try_clone()?)
        .stderr(out)
        .spawn()
        .context("spawning `freenet` (is it on PATH?)")?;
    let node = Node {
        child: Some(child),
        ws,
        net,
    };
    let t = Instant::now();
    while TcpStream::connect(("127.0.0.1", ws)).is_err() {
        if t.elapsed() > NODE_UP {
            bail!(
                "the node in {} did not open its client API within {NODE_UP:?}",
                dir.display()
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    Ok(node)
}

/// A fresh X25519 transport key for the gateway, in the node's own file form
/// (the secret, hex), and its public half as a peer names it.
fn transport_key(path: &Path) -> Result<String> {
    let mut secret = [0u8; 32];
    getrandom::getrandom(&mut secret).map_err(|e| anyhow!("no randomness: {e}"))?;
    std::fs::write(path, hex(&secret))?;
    let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret));
    Ok(hex(public.as_bytes()))
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex32(s: &str) -> Result<[u8; 32]> {
    if s.len() != 64 {
        bail!("not 64 hex chars: {s}");
    }
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)?;
    }
    Ok(out)
}

// ---------------------------------------------------------------- pages ----

/// The SDK artefacts a page needs, from the SDK's own build output, with the
/// sha256 of each so a record names exactly what ran.
struct Pkg {
    signer: Vec<u8>,
    block: Vec<u8>,
    register: Vec<u8>,
    sums: BTreeMap<&'static str, String>,
}

fn pkg(dir: &Path) -> Result<Pkg> {
    let read = |f: &str| {
        std::fs::read(dir.join(f))
            .with_context(|| format!("{}/{f} (run the SDK's build.sh)", dir.display()))
    };
    let (signer, block, register) = (
        read("signer.wasm")?,
        read("block.wasm")?,
        read("register.wasm")?,
    );
    let sum = |b: &[u8]| hex(&sha2::Sha256::digest(b))[..12].to_string();
    let sums = BTreeMap::from([
        ("signer", sum(&signer)),
        ("block", sum(&block)),
        ("register", sum(&register)),
    ]);
    Ok(Pkg {
        signer,
        block,
        register,
        sums,
    })
}

fn now_ms(t0: Instant) -> u64 {
    1_000 + t0.elapsed().as_millis() as u64
}

type Sock =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>>;

async fn open(url: &str) -> Result<Sock> {
    crate::check_endpoint(url, &crate::PROTECTED_PORTS)?;
    let (s, _) = tokio::time::timeout(
        Duration::from_secs(10),
        tokio_tungstenite::connect_async(url),
    )
    .await
    .map_err(|_| anyhow!("{url} did not accept a connection within 10 s"))??;
    Ok(s)
}

/// One block as it ARRIVED at the harness: when, which, and its bytes.
struct Arrival {
    ms: f64,
    id: [u8; 32],
    kind: u8,
    body: Vec<u8>,
}

/// What the harness saw, beside the page: whole block answers decoded on its
/// own reassembler (so their arrival can be stamped), and frames sent.
#[derive(Default)]
struct Watch {
    reassembler: wire::Reassembler,
    arrivals: Vec<Arrival>,
    frames_out: u64,
    /// When the engine was last given the time. A page's host ticks it every
    /// `TICK_MS` (sdk js/session.js), and the engine decides on a tick what
    /// is owed (parity, re-asks); a harness that never ticked would measure
    /// an engine no browser runs.
    last_tick: Option<Instant>,
}

/// Drive a page until `done`, or `deadline`. Every frame out as the page made
/// it, every message in as it came, the page's timers on its own clock — the
/// browser's shape. Whole block answers are ALSO decoded here, on a separate
/// reassembler, so their arrival can be stamped; the page's own path is not
/// touched.
async fn drive(
    sock: &mut Sock,
    io: &mut PageIo,
    t0: Instant,
    deadline: Instant,
    w: &mut Watch,
    mut done: impl FnMut(&[Reply], &PageIo) -> bool,
) -> Result<Vec<Reply>> {
    let mut replies = Vec::new();
    loop {
        if w.last_tick
            .is_none_or(|t| t.elapsed() >= Duration::from_millis(protocol::TICK_MS))
        {
            w.last_tick = Some(Instant::now());
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs();
            io.client(&session(&Request::Tick { now }));
        }
        for f in io.take_frames() {
            w.frames_out += 1;
            sock.send(Message::Binary(f.into())).await.context("send")?;
        }
        for r in io.take_replies() {
            let r = protocol::decode_reply(&r)
                .map_err(|d| anyhow!("a reply that does not decode: {d:?}"))?;
            if std::env::var_os("RACEGET_TRACE").is_some() {
                let line = format!("{r:?}");
                eprintln!(
                    "  [{:>7.0} ms] {}",
                    t0.elapsed().as_secs_f64() * 1000.0,
                    &line[..line.len().min(160)]
                );
            }
            replies.push(r);
        }
        if done(&replies, io) {
            return Ok(replies);
        }
        if Instant::now() > deadline {
            bail!(
                "not within its deadline; the page says unusable: {:?}",
                io.unusable()
            );
        }
        let wait = io
            .next_due()
            .map_or(50, |d| d.0.saturating_sub(now_ms(t0)).clamp(1, 50));
        match tokio::time::timeout(Duration::from_millis(wait), sock.next()).await {
            Ok(Some(Ok(Message::Binary(b)))) => {
                let at = t0.elapsed().as_secs_f64() * 1000.0;
                if let wire::Incoming::Got { state, .. } = wire::unframe(&mut w.reassembler, &b) {
                    if let Some((id, body)) = wire::block::block_of_state(&state) {
                        w.arrivals.push(Arrival {
                            ms: at,
                            id,
                            kind: state[0],
                            body: body.to_vec(),
                        });
                    }
                }
                io.inbound(&b, Ms(now_ms(t0)));
            }
            Ok(Some(Ok(_))) => {}
            Ok(Some(Err(e))) => bail!("the socket: {e}"),
            Ok(None) => bail!("the node closed the socket"),
            Err(_) => io.tick(Ms(now_ms(t0))),
        }
    }
}

fn session(req: &Request) -> Vec<u8> {
    protocol::encode_session_request(VERSION, SESSION, req)
        .expect("a request this harness builds encodes")
}

fn write_state_any(r: &Reply) -> Option<WriteState> {
    match r {
        Reply::SessionWriteState { state, .. } | Reply::WriteState { state, .. } => Some(*state),
        _ => None,
    }
}

fn write_id_of(r: &Reply) -> u64 {
    match r {
        Reply::SessionWriteState { write_id, .. } | Reply::WriteState { write_id, .. } => *write_id,
        _ => 0,
    }
}

fn write_state(r: &Reply, id: u64) -> Option<WriteState> {
    match r {
        Reply::SessionWriteState {
            write_id, state, ..
        }
        | Reply::WriteState { write_id, state }
            if *write_id == id =>
        {
            Some(*state)
        }
        _ => None,
    }
}

// ------------------------------------------------------------------- up ----

#[derive(serde::Serialize, serde::Deserialize)]
struct Run {
    gateway_pid: u32,
    gateway_ws: u16,
    /// `127.0.0.1:<port>,<hex public key>`, as `--gateway` takes it.
    gateway: String,
    register_id: String,
    rows: usize,
    value_bytes: usize,
    writer_sdk_rev: String,
    pkg: BTreeMap<String, String>,
}

pub async fn up(
    dir: &Path,
    pkg_dir: &Path,
    rows: usize,
    value_bytes: usize,
    budget: Duration,
) -> Result<()> {
    if dir.join(RUN_FILE).exists() {
        bail!(
            "{} exists: a run is up there already (`race-get down` first, or a new --dir)",
            dir.join(RUN_FILE).display()
        );
    }
    let p = pkg(pkg_dir)?;
    let adir = dir.join("gateway");
    std::fs::create_dir_all(&adir)?;
    let kp = adir.join("transport_keypair");
    let public = transport_key(&kp)?;
    let a = spawn(&adir, Role::Gateway { keypair: &kp })?;
    println!(
        "gateway A: ws {}, network {}, dirs under {}",
        a.ws,
        a.net,
        adir.display()
    );
    let deadline = Instant::now() + budget;

    let mut sock = open(&a.url()).await?;
    let t0 = Instant::now();
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| anyhow!("no randomness: {e}"))?;
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let (container, signer) = wire::delegate_from_code(&p.signer);
    let mut io = PageIo::new(
        Server::new(
            Page::unstarted(engine::Params::default(), PutPath::Page),
            SignerFacts::default(),
        ),
        Artefacts {
            block_code: p.block.clone(),
            register_code: p.register.clone(),
            register_params: wire::register_params(&sk.verifying_key().to_bytes(), wire::HEAD_NAME),
            signer,
        },
    );
    io.provision(container, sk.to_bytes().to_vec());
    let mut w = Watch::default();
    let mut parity_done = std::collections::BTreeSet::new();

    // Provisioned, then the page knows who it is.
    let step = (Instant::now() + Duration::from_secs(60)).min(deadline);
    drive(&mut sock, &mut io, t0, step, &mut w, |_, io| {
        io.provisioned()
    })
    .await
    .context("provisioning the signer")?;
    io.client(&session(&Request::Identity));
    drive(&mut sock, &mut io, t0, deadline, &mut w, |r, _| {
        r.iter().any(|x| matches!(x, Reply::Identity { .. }))
    })
    .await
    .context("identity")?;

    // The rows, in writes, each waited on until Published; then a flush, and
    // every write waited on until its parity is out too: a group whose parity
    // never reached A is a group no race reader can use.
    let per_write = (WRITE_BYTES / value_bytes.max(1)).clamp(1, 200);
    let mut published = 0usize;
    let mut ids = Vec::new();
    for (n, chunk) in (0..rows).collect::<Vec<_>>().chunks(per_write).enumerate() {
        let id = n as u64 + 1;
        ids.push(id);
        // A CREATE of each row, said as such: every key read as Absent, the
        // way the SDK's `Db` commits one (a reads-less write is refused
        // `Unread`, sdk#235).
        let keys: Vec<Vec<u8>> = chunk
            .iter()
            .map(|i| format!("r/{i:06}").into_bytes())
            .collect();
        let reads = keys
            .iter()
            .map(|k| (k.clone(), protocol::Expect::Absent))
            .collect();
        let ops = keys
            .into_iter()
            .zip(chunk)
            .map(|(k, i)| protocol::Op::Put(k, value(*i, value_bytes)))
            .collect();
        io.client(&session(&Request::Commit {
            write_id: id,
            reads,
            ops,
        }));
        let got = drive(&mut sock, &mut io, t0, deadline, &mut w, |r, _| {
            r.iter().any(|x| {
                matches!(
                    write_state(x, id),
                    Some(
                        WriteState::Published
                            | WriteState::Lost
                            | WriteState::Failed
                            | WriteState::Busy
                            | WriteState::TooLarge { .. }
                    )
                )
            })
        })
        .await
        .with_context(|| format!("write {id}: not Published within the budget"))?;
        let states: Vec<WriteState> = got.iter().filter_map(|x| write_state(x, id)).collect();
        if !states.contains(&WriteState::Published) {
            bail!("write {id} ended {states:?}, not Published");
        }
        for x in &got {
            if let Some(WriteState::ParityComplete) = write_state_any(x) {
                parity_done.insert(write_id_of(x));
            }
        }
        published += chunk.len();
        if n % 10 == 0 {
            println!(
                "  published {published}/{rows} rows ({} s)",
                t0.elapsed().as_secs()
            );
        }
    }
    io.client(&session(&Request::Flush));
    let want = ids.len();
    drive(&mut sock, &mut io, t0, deadline, &mut w, |r, _| {
        for x in r {
            if let Some(WriteState::ParityComplete) = write_state_any(x) {
                parity_done.insert(write_id_of(x));
            }
        }
        parity_done.len() >= want
    })
    .await
    .with_context(|| {
        format!(
            "parity: {} of {want} writes ParityComplete within the budget",
            parity_done.len()
        )
    })?;
    println!(
        "  every write ParityComplete ({} s)",
        t0.elapsed().as_secs()
    );
    let run = Run {
        gateway_pid: a.pid(),
        gateway_ws: a.ws,
        gateway: format!("127.0.0.1:{},{public}", a.net),
        register_id: hex(&io.register_id()),
        rows,
        value_bytes,
        writer_sdk_rev: SDK_REV.into(),
        pkg: p
            .sums
            .iter()
            .map(|(k, v)| (k.to_string(), v.clone()))
            .collect(),
    };
    std::fs::write(dir.join(RUN_FILE), serde_json::to_string_pretty(&run)?)?;
    let pid = a.detach();
    println!(
        "UP: {rows} rows of {value_bytes} B published with parity in {} s; register {}; gateway A pid {pid} stays up (`race-get down`). sdk {SDK_REV}",
        t0.elapsed().as_secs(),
        &run.register_id[..12]
    );
    Ok(())
}

/// A row's value: `value_bytes` bytes, distinct per row so no two leaves dedup.
fn value(i: usize, len: usize) -> Vec<u8> {
    let mut v = format!("row {i} ").into_bytes();
    let mut x = (i as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    while v.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        v.push(b'a' + (x % 26) as u8);
    }
    v.truncate(len.max(1));
    v
}

pub fn down(dir: &Path) -> Result<()> {
    let run: Run = serde_json::from_slice(
        &std::fs::read(dir.join(RUN_FILE)).context("no run file: nothing is up")?,
    )?;
    let st = Command::new("kill")
        .arg(run.gateway_pid.to_string())
        .status()?;
    std::fs::rename(dir.join(RUN_FILE), dir.join(format!("{RUN_FILE}.down")))?;
    println!(
        "DOWN: gateway pid {} {}",
        run.gateway_pid,
        if st.success() {
            "stopped"
        } else {
            "was not running"
        }
    );
    Ok(())
}

// ----------------------------------------------------------------- read ----

/// One group's outcome in one trial.
#[derive(serde::Serialize, serde::Deserialize, Clone)]
pub struct GroupRecord {
    pub arm: String,
    pub sdk_rev: String,
    pub trial: usize,
    pub value_bytes: usize,
    /// Data members (k); the group has k + 3 blocks.
    pub k: usize,
    /// From the parent node's arrival to the k-th arrival among the k+3, ms.
    /// `None`: fewer than k had arrived when the trial ended — `not within T`.
    pub ms: Option<f64>,
    /// T: how long this group had, from its parent's arrival to the trial's end.
    pub t_ms: f64,
    pub data_got: usize,
    pub parity_got: usize,
}

/// One trial's totals.
#[derive(serde::Serialize, serde::Deserialize)]
struct TrialRecord {
    arm: String,
    sdk_rev: String,
    trial: usize,
    rows_read: usize,
    rows: usize,
    groups: usize,
    blocks_arrived: usize,
    frames_out: u64,
    head_ms: Option<f64>,
    read_ms: f64,
    complete: bool,
    error: Option<String>,
}

#[allow(clippy::too_many_arguments)]
pub async fn read(
    dir: &Path,
    pkg_dir: &Path,
    arm: &str,
    trials: usize,
    first_trial: usize,
    trial_secs: u64,
    budget: Duration,
    min_groups: usize,
) -> Result<()> {
    let run: Run = serde_json::from_slice(
        &std::fs::read(dir.join(RUN_FILE)).context("no run file: `race-get up` first")?,
    )?;
    let p = pkg(pkg_dir)?;
    if p.sums.iter().any(|(k, v)| run.pkg.get(*k) != Some(v)) {
        println!("note: the pkg here differs from the writer's ({:?} vs {:?}); the reader uses only block.wasm's code to name block contracts", p.sums, run.pkg);
    }
    if run.pkg.get("block") != p.sums.get("block") {
        bail!("block.wasm differs from the one the tree was written with: every block id would name a different contract");
    }
    let register_id = unhex32(&run.register_id)?;
    let end = Instant::now() + budget;
    let mut out = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(RECORDS))?;
    println!("read: arm `{arm}`, sdk {SDK_REV}; {trials} trial(s) over register {}; each reader a FRESH node (cold by construction)", &run.register_id[..12]);
    for trial in first_trial..first_trial + trials {
        if Instant::now() > end {
            println!("budget spent: trials from {trial} not run");
            break;
        }
        let bdir = dir.join(format!("reader-{arm}-{trial}"));
        if bdir.exists() {
            bail!(
                "{} exists: a reader dir is never reused (a warm reader is not a cold read)",
                bdir.display()
            );
        }
        let b = spawn(
            &bdir,
            Role::Peer {
                gateway: &run.gateway,
            },
        )?;
        let deadline = (Instant::now() + Duration::from_secs(trial_secs)).min(end);
        let t = one_read(&b, &p.block, register_id, run.rows, deadline).await;
        drop(b);
        let _ = std::fs::remove_dir_all(&bdir);
        let (groups, total) = match t {
            Ok(r) => r,
            Err((e, r)) => {
                println!("  trial {trial}: {e:#}");
                (
                    r.0,
                    TrialTotals {
                        error: Some(format!("{e:#}")),
                        ..r.1
                    },
                )
            }
        };
        for g in &groups {
            let rec = GroupRecord {
                arm: arm.into(),
                sdk_rev: SDK_REV.into(),
                trial,
                value_bytes: run.value_bytes,
                ..g.clone()
            };
            writeln!(out, "{}", serde_json::to_string(&rec)?)?;
        }
        let tr = TrialRecord {
            arm: arm.into(),
            sdk_rev: SDK_REV.into(),
            trial,
            rows_read: total.rows_read,
            rows: run.rows,
            groups: groups.len(),
            blocks_arrived: total.blocks,
            frames_out: total.frames_out,
            head_ms: total.head_ms,
            read_ms: total.read_ms,
            complete: total.rows_read == run.rows && total.error.is_none(),
            error: total.error,
        };
        writeln!(out, "{}", serde_json::json!({ "trial": tr }))?;
        let late = groups.iter().filter(|g| g.ms.is_none()).count();
        println!(
            "  trial {trial}: {}/{} rows in {:.0} ms; {} groups ({} not within T); {} blocks arrived; {} frames out",
            tr.rows_read, run.rows, tr.read_ms, groups.len(), late, tr.blocks_arrived, tr.frames_out
        );
        if tr.complete && groups.len() < min_groups {
            bail!("the tree has {} groups, under --min-groups {min_groups}: write more rows (`up --rows`)", groups.len());
        }
    }
    Ok(())
}

#[derive(Default)]
struct TrialTotals {
    rows_read: usize,
    blocks: usize,
    frames_out: u64,
    head_ms: Option<f64>,
    read_ms: f64,
    error: Option<String>,
}

type Partial = (Vec<GroupRecord>, TrialTotals);

/// One cold read of the whole tree. On an error, what was observed up to it is
/// still scored: a group that did not reach k is `not within T`, not dropped.
async fn one_read(
    b: &Node,
    block_code: &[u8],
    register_id: [u8; 32],
    rows: usize,
    deadline: Instant,
) -> std::result::Result<Partial, (anyhow::Error, Partial)> {
    let t0 = Instant::now();
    let mut io = PageIo::reader(
        Server::new(
            Page::unstarted(engine::Params::default(), PutPath::Page),
            SignerFacts::default(),
        ),
        block_code.to_vec(),
        register_id,
        1,
    );
    let mut w = Watch::default();
    let mut totals = TrialTotals::default();
    let r: Result<()> = async {
        let mut sock = open(&b.url()).await?;
        io.client(&session(&Request::Identity));
        drive(&mut sock, &mut io, t0, deadline, &mut w, |r, _| {
            r.iter().any(|x| matches!(x, Reply::Identity { .. }))
        })
        .await
        .context("the head")?;
        totals.head_ms = Some(t0.elapsed().as_secs_f64() * 1000.0);
        let mut after = None;
        let mut req_id = 100;
        loop {
            req_id += 1;
            let rid = req_id;
            io.client(&session(&Request::Range {
                req_id: rid,
                lo: protocol::Bound::Unbounded,
                hi: protocol::Bound::Unbounded,
                reverse: false,
                after: after.take(),
                max_entries: 256,
            }));
            let got = drive(&mut sock, &mut io, t0, deadline, &mut w, |rs, _| {
                rs.iter()
                    .any(|x| matches!(x, Reply::Page { req_id, .. } if *req_id == rid))
            })
            .await
            .with_context(|| format!("rows from {}", totals.rows_read))?;
            let Some(Reply::Page {
                entries, cursor, ..
            }) = got
                .into_iter()
                .find(|x| matches!(x, Reply::Page { req_id, .. } if *req_id == rid))
            else {
                bail!("no page for request {rid}");
            };
            totals.rows_read += entries.len();
            match cursor {
                Some(c) if !entries.is_empty() => after = Some(c),
                _ => break,
            }
        }
        if totals.rows_read != rows {
            bail!("read {} rows of {rows}", totals.rows_read);
        }
        Ok(())
    }
    .await;
    totals.read_ms = t0.elapsed().as_secs_f64() * 1000.0;
    totals.blocks = w.arrivals.len();
    totals.frames_out = w.frames_out;
    let groups = score_groups(&w.arrivals, totals.read_ms);
    match r {
        Ok(()) => Ok((groups, totals)),
        Err(e) => Err((e, (groups, totals))),
    }
}

/// Every group the arrived NODES list, timed from its node's arrival to its
/// k-th block's. Pure, so it is tested on hand-built arrivals.
fn score_groups(arrivals: &[Arrival], end_ms: f64) -> Vec<GroupRecord> {
    let mut first: HashMap<[u8; 32], f64> = HashMap::new();
    for a in arrivals {
        first.entry(a.id).or_insert(a.ms);
    }
    let mut out: BTreeMap<[u8; 32], GroupRecord> = BTreeMap::new();
    for a in arrivals
        .iter()
        .filter(|a| a.kind == prolly::kind::TREE_NODE)
    {
        if first.get(&a.id) != Some(&a.ms) {
            continue; // a second copy of a node already scored
        }
        let Ok(node) = prolly::node::Node::parse(&a.body) else {
            continue;
        };
        let ids: Vec<[u8; 32]> = node.parity().collect();
        let groups = prolly::parity::group_members(&node);
        if ids.len() != groups.len() * 3 {
            continue; // a node whose parity disagrees with its grouping; the contract refuses it
        }
        for (i, (_, members)) in groups.into_iter().enumerate() {
            let trio = &ids[i * 3..i * 3 + 3];
            let k = members.len();
            let data: Vec<f64> = members
                .iter()
                .filter_map(|m| first.get(m).copied())
                .collect();
            let parity: Vec<f64> = trio.iter().filter_map(|m| first.get(m).copied()).collect();
            let mut all: Vec<f64> = data.iter().chain(parity.iter()).copied().collect();
            all.sort_by(|x, y| x.partial_cmp(y).expect("times are never NaN"));
            // NEGATIVE DELTAS ARE REFUSED: a block cannot arrive before the
            // node that names it was read. One that did is a block this
            // reader already held for another reason, and it is not evidence
            // about this group's read — so it is not counted as fast.
            let ms = (all.len() >= k)
                .then(|| all[k - 1] - a.ms)
                .filter(|d| *d >= 0.0);
            out.entry(trio[0]).or_insert(GroupRecord {
                arm: String::new(),
                sdk_rev: String::new(),
                trial: 0,
                value_bytes: 0,
                k,
                ms,
                t_ms: end_ms - a.ms,
                data_got: data.len(),
                parity_got: parity.len(),
            });
        }
    }
    out.into_values().collect()
}

// ---------------------------------------------------------------- score ----

pub fn score(dir: &Path) -> Result<()> {
    let text = std::fs::read_to_string(dir.join(RECORDS))
        .context("no records: run `race-get read` first")?;
    let mut by_arm: BTreeMap<(String, String), Vec<GroupRecord>> = BTreeMap::new();
    let mut trials: BTreeMap<(String, String), (usize, usize)> = BTreeMap::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line)?;
        if let Some(t) = v.get("trial").filter(|t| t.is_object()) {
            let t: TrialRecord = serde_json::from_value(t.clone())?;
            let e = trials.entry((t.arm, t.sdk_rev)).or_default();
            e.0 += 1;
            e.1 += t.complete as usize;
        } else {
            let g: GroupRecord = serde_json::from_value(v)?;
            by_arm
                .entry((g.arm.clone(), g.sdk_rev.clone()))
                .or_default()
                .push(g);
        }
    }
    println!("race-get: time from a group's parent node arriving to its k-th block (data or parity) arriving, ms");
    println!("event-timed at the harness socket (whole messages), not polled; two private nodes on one machine: NO relay tail (F20)");
    let mut t = Table::new([
        "arm",
        "sdk",
        "trials (complete)",
        "groups",
        "not within T",
        "p50",
        "p75",
        "p90",
        "max",
        "parity used",
    ]);
    for ((arm, rev), gs) in &by_arm {
        let mut ms: Vec<f64> = gs.iter().filter_map(|g| g.ms).collect();
        ms.sort_by(|a, b| a.partial_cmp(b).expect("never NaN"));
        let late = gs.len() - ms.len();
        let pct = |p: f64| {
            if ms.is_empty() {
                "—".to_string()
            } else {
                format!("{:.1}", nearest_rank(&ms, p))
            }
        };
        let (n, done) = trials
            .get(&(arm.clone(), rev.clone()))
            .copied()
            .unwrap_or_default();
        t.row([
            arm.clone(),
            rev.clone(),
            format!("{n} ({done})"),
            gs.len().to_string(),
            late.to_string(),
            pct(50.0),
            pct(75.0),
            pct(90.0),
            ms.last().map_or("—".into(), |m| format!("{m:.1}")),
            gs.iter().filter(|g| g.parity_got > 0).count().to_string(),
        ]);
    }
    print!("{t}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use prolly::store::MemBlocks;

    /// A real tree from the SDK's own tree library, with its parity, and the
    /// arrivals a reader would see: the root at t=0, then chosen blocks.
    fn tree() -> (Vec<Arrival>, Vec<[u8; 32]>, Vec<[u8; 32]>) {
        let mut b = MemBlocks::default();
        let mut root = prolly::build::init(&mut b);
        let edits: Vec<(Vec<u8>, prolly::apply::Edit)> = (0..3000u32)
            .map(|i| {
                (
                    format!("r/{i:06}").into_bytes(),
                    prolly::apply::Edit::Put(value(i as usize, 200)),
                )
            })
            .collect();
        let applied = prolly::apply::apply_into(&mut b, &root, &edits).expect("applies");
        root = applied.root;
        for (id, bytes) in &applied.parity {
            b.insert(*id, bytes);
        }
        let body = prolly::store::Blocks::get(&b, &root)
            .expect("root held")
            .to_vec();
        let node = prolly::node::Node::parse(&body).expect("a node");
        assert!(!node.is_leaf(), "the fixture needs a branch root");
        let (_, members) = prolly::parity::group_members(&node)
            .into_iter()
            .next()
            .expect("a group");
        let parity: Vec<[u8; 32]> = node.parity().take(3).collect();
        let arrivals = vec![Arrival {
            ms: 0.0,
            id: root,
            kind: prolly::kind::TREE_NODE,
            body,
        }];
        (arrivals, members, parity)
    }

    fn at(ms: f64, id: [u8; 32]) -> Arrival {
        Arrival {
            ms,
            id,
            kind: prolly::kind::RAW,
            body: Vec::new(),
        }
    }

    #[test]
    fn a_group_is_done_at_its_kth_block_whether_data_or_parity() {
        let (mut arr, members, parity) = tree();
        let k = members.len();
        assert!(k >= 3, "a group of {k} is too small to test this");
        // All but one data block, early; the last data block never comes; one
        // parity block completes the group at t=500.
        for (i, m) in members.iter().take(k - 1).enumerate() {
            arr.push(at(10.0 + i as f64, *m));
        }
        arr.push(at(500.0, parity[1]));
        let g = &score_groups(&arr, 1000.0)[0];
        assert_eq!(
            (g.k, g.ms, g.data_got, g.parity_got),
            (k, Some(500.0), k - 1, 1)
        );
    }

    #[test]
    fn a_group_short_of_k_is_not_within_t_and_says_how_long_it_had() {
        let (mut arr, members, _) = tree();
        arr.push(at(20.0, members[0]));
        let g = &score_groups(&arr, 900.0)[0];
        assert_eq!((g.ms, g.t_ms, g.data_got), (None, 900.0, 1));
    }

    /// The CONTROL for the two above: all k data blocks, no parity — the
    /// serial reader's shape — ends at the k-th DATA arrival.
    #[test]
    fn all_data_and_no_parity_ends_at_the_last_data_block() {
        let (mut arr, members, _) = tree();
        for (i, m) in members.iter().enumerate() {
            arr.push(at(100.0 * (i + 1) as f64, *m));
        }
        let g = &score_groups(&arr, 1e9)[0];
        assert_eq!(g.ms, Some(100.0 * members.len() as f64));
        assert_eq!(g.parity_got, 0);
    }

    #[test]
    fn a_block_held_before_its_node_arrived_is_not_counted_as_fast() {
        let (mut arr, members, _) = tree();
        // The node itself arrives at 50; every member "arrived" at 10.
        arr[0].ms = 50.0;
        let node = arr.remove(0);
        for m in &members {
            arr.push(at(10.0, *m));
        }
        arr.push(node);
        let g = &score_groups(&arr, 1e9)[0];
        assert_eq!(g.ms, None, "a negative delta was reported as a time");
    }

    #[test]
    fn a_value_is_its_length_and_distinct_per_row() {
        assert_eq!(value(7, 1024).len(), 1024);
        assert_ne!(value(1, 64), value(2, 64));
    }
}
