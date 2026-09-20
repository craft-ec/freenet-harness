//! `kill9`: does a read-back-confirmed PUT survive the node dying?
//!
//! Phase 3 calls a write `durable` once its pack reads back from our own node
//! (craftworks-sdk#23). F22 says the bytes are readable ~60 ms after the put is
//! sent; it says nothing about whether they are on DISK. If they are not, then
//! "durable" means "durable until the process dies", and the definition has to
//! move to a second node's read-back.
//!
//! **This spawns its own node and kills only that.** Its own port, its own
//! temp data directory, local mode, and the child is reaped whether the run
//! ends well or badly. It never touches a node it did not start.
//!
//! The control cell kills BEFORE the read-back. If nothing is ever lost there,
//! the kill is not landing where this code thinks it is and none of the other
//! cells mean anything.

use std::{
    net::TcpStream,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

use anyhow::{bail, Context, Result};
use craftec_block_contract as block;
use freenet_stdlib::{
    client_api::{ClientRequest, ContractRequest, ContractResponse, HostResponse},
    prelude::*,
};
use tokio::time::timeout;

use crate::{latency::send_req, stats::kib};

/// Every wait against the node. Local mode answers in milliseconds.
const STEP: Duration = Duration::from_secs(3);
/// How long a freshly spawned node may take to accept connections.
const BOOT: Duration = Duration::from_secs(45);
/// Free space demanded before a run that writes blocks in a loop.
const NEED_FREE_GIB: u64 = 15;

/// A node this process started, and will stop.
///
/// `Drop` kills and reaps. A run that panics or is cut short must not leave a
/// freenet node running against a temp directory nobody remembers — and a
/// zombie child is exactly what "always reaped" means.
struct Node {
    child: Option<Child>,
    port: u16,
    dir: PathBuf,
}

impl Node {
    fn spawn(port: u16, dir: &Path) -> Result<Self> {
        for sub in ["data", "config", "log"] {
            std::fs::create_dir_all(dir.join(sub))?;
        }
        let child = Command::new("freenet")
            .args([
                "local",
                "local",
                "--ws-api-port",
                &port.to_string(),
                "--data-dir",
                &dir.join("data").to_string_lossy(),
                "--config-dir",
                &dir.join("config").to_string_lossy(),
                "--log-dir",
                &dir.join("log").to_string_lossy(),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("spawning `freenet local local` — is the binary on PATH?")?;
        let mut n = Node {
            child: Some(child),
            port,
            dir: dir.to_path_buf(),
        };
        n.wait_ready()?;
        Ok(n)
    }

    /// Poll the port rather than sleeping a guessed interval: a fixed sleep is
    /// either wasted time or a flake, and on a loop of hundreds of restarts it
    /// is both.
    fn wait_ready(&mut self) -> Result<()> {
        let deadline = Instant::now() + BOOT;
        while Instant::now() < deadline {
            if let Some(c) = self.child.as_mut() {
                if let Ok(Some(status)) = c.try_wait() {
                    bail!("the node exited before it was ready ({status})");
                }
            }
            if TcpStream::connect(("127.0.0.1", self.port)).is_ok() {
                // Accepting TCP is not the same as serving the client API; one
                // short grace beats a retry loop around the first request.
                std::thread::sleep(Duration::from_millis(300));
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        bail!("the node did not accept connections within {BOOT:?}")
    }

    /// SIGKILL, then REAP. Killing without waiting leaves a zombie and the next
    /// spawn races the old process for the port.
    fn kill9(&mut self) {
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }

    fn restart(&mut self) -> Result<()> {
        let dir = self.dir.clone();
        let port = self.port;
        self.kill9();
        let fresh = Node::spawn(port, &dir)?;
        // The new child is ours now; stop the temporary from reaping it.
        self.child = {
            let mut f = fresh;
            f.child.take()
        };
        self.wait_ready()
    }

    fn ws(&self) -> String {
        format!(
            "ws://127.0.0.1:{}/v1/contract/command?encodingProtocol=native",
            self.port
        )
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.kill9();
    }
}

/// Removes its directory whatever happens.
///
/// The removal used to be the last statement of the run, so a fixture error —
/// a pack one byte over MAX_PACK, say — returned early and left a temp tree
/// behind. Two of them survived a session that way. Cleanup on the success
/// path only is cleanup that runs exactly when it is least needed.
struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn put(
    client: &mut crate::probe::Client,
    contract: ContractContainer,
    state: &[u8],
) -> Result<()> {
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
    .await
}

/// `Some(bytes)` when the node serves exactly these bytes for this key.
async fn get(client: &mut crate::probe::Client, key: &ContractKey, want: &[u8]) -> Result<bool> {
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
            }))) if k.id() == key.id() => return Ok(state.as_ref() == want),
            Ok(Ok(_)) => continue,
            _ => break,
        }
    }
    Ok(false)
}

/// A PACK whose state is close to `target` bytes, made of RAW members.
///
/// Members are ~64 KiB, the size the engine's pack plan inlines. The builder
/// orders and de-duplicates them, so what comes back is a pack the Block
/// contract accepts — which this asserts rather than hopes for, because a
/// fixture the contract refuses would make every cell below a measurement of a
/// refusal.
fn make_pack(target: usize) -> Result<Vec<u8>> {
    const MEMBER: usize = 64 * 1024;
    const HEADER: usize = 4 + 2; // "PK01" + count
    const PER_MEMBER: usize = 1 + 4; // kind + length
                                     // The body is bounded by MAX_PACK, and the framing is part of the body, so
                                     // the MEMBERS get what is left after it. Sizing the members to the target
                                     // and hoping overshot by 86 bytes — the arithmetic is small enough to do
                                     // exactly, and a fixture that is right by luck is one that breaks when a
                                     // constant moves.
    let body_cap = target.saturating_sub(1).min(block::pack::MAX_PACK);
    let count = body_cap
        .saturating_sub(HEADER)
        .div_ceil(MEMBER + PER_MEMBER)
        .max(1);
    let avail = body_cap
        .checked_sub(HEADER + count * PER_MEMBER)
        .ok_or_else(|| anyhow::anyhow!("a {target} B pack has no room for {count} members"))?;
    let mut members = Vec::with_capacity(count);
    for i in 0..count {
        // The last member takes the remainder, so the pack lands ON the size
        // asked for rather than near it.
        let len = if i + 1 == count {
            avail - (avail / count) * (count - 1)
        } else {
            avail / count
        };
        let mut b = vec![0u8; len];
        getrandom::getrandom(&mut b)?;
        members.push((block::kind::RAW, b));
    }
    let body = block::pack::build(&members)
        .map_err(|e| anyhow::anyhow!("building a {target} B pack: {e:?}"))?;
    let state = block::encode(block::kind::PACK, &body);
    // Asserted, not hoped for: a fixture the contract refuses would make every
    // cell below a measurement of a refusal.
    if !block::check(blake3::hash(&state).as_bytes(), &state) {
        bail!(
            "the pack this fixture built ({} B of state) is not one block.wasm accepts",
            state.len()
        );
    }
    Ok(state)
}

/// One cell of the table.
struct Cell {
    size: usize,
    /// `None` = the control: killed BEFORE any read-back.
    delay: Option<Duration>,
    /// Trials asked for. A cell that ran fewer says so rather than reporting a
    /// rate over a sample nobody chose.
    want: usize,
    confirmed: usize,
    survived: usize,
    trials: usize,
}

impl Cell {
    fn label(&self) -> String {
        match self.delay {
            None => "CONTROL (killed before read-back)".to_string(),
            Some(d) => format!("{} ms", d.as_millis()),
        }
    }
}

pub struct Opts {
    pub wasm: String,
    pub expect_sha: String,
    pub port: u16,
    pub sizes: Vec<usize>,
    /// Build the state as a PACK of RAW members rather than one RAW block.
    ///
    /// This is what Phase 3 actually calls durable: a commit's blocks travel as
    /// a PACK under `block.wasm`, and `MAX_PACK` is 1 MiB while a single RAW
    /// body is capped at `MAX_BODY` = 262,208. Measuring a 1 MiB RAW block
    /// under `block.wasm` measures nothing — the contract refuses it, correctly
    /// — and measuring it under an accept-all fixture answers a different
    /// question ("does the node's storage survive") from the one the engine's
    /// definition rests on.
    pub pack: bool,
    pub delays_ms: Vec<u64>,
    /// Trials per delay, positionally matched to `delays_ms`.
    ///
    /// Not one number for the whole table: the trials are worth most where a
    /// loss is most likely, which is the window immediately after the
    /// read-back. Spending them evenly buys precision where nothing is
    /// expected to happen.
    pub n_per_delay: Vec<usize>,
    pub n_control: usize,
    pub budget_secs: u64,
}

fn free_gib() -> Option<u64> {
    let out = Command::new("df").args(["-g", "/"]).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .nth(1)?
        .split_whitespace()
        .nth(3)?
        .parse::<u64>()
        .ok()
}

pub async fn run(o: Opts) -> Result<()> {
    match free_gib() {
        Some(g) if g < NEED_FREE_GIB => bail!(
            "{g} GiB free on / — this run spawns nodes and writes blocks in a loop; \
             it wants at least {NEED_FREE_GIB} GiB. Free some space first."
        ),
        Some(g) => println!("disk:     {g} GiB free on / (want >= {NEED_FREE_GIB})"),
        None => println!("disk:     could not read `df -g /` — proceeding, but nobody checked"),
    }
    if o.port == 7509 || o.port == 7609 {
        bail!(
            "port {} is the owner's node. This run must spawn its OWN.",
            o.port
        );
    }
    let bytes = crate::wasm_check::load(&o.wasm, &o.expect_sha)?;
    let code = std::sync::Arc::new(ContractCode::from(bytes));

    let dir = std::env::temp_dir().join(format!("craftworks-kill9-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let _cleanup = TempDir(dir.clone());
    println!(
        "shape:    {}",
        if o.pack {
            "PACK of ~64 KiB RAW members — what a commit actually puts"
        } else {
            "one RAW block"
        }
    );
    println!(
        "node:     freenet local, port {}, data dir {}",
        o.port,
        dir.display()
    );
    println!("budget:   {} s for the whole run", o.budget_secs);
    println!();

    if o.n_per_delay.len() != o.delays_ms.len() {
        bail!(
            "--n-per-delay has {} entries for {} delays; they are matched positionally, \
             so a mismatch would silently run the wrong plan",
            o.n_per_delay.len(),
            o.delays_ms.len()
        );
    }
    let mut cells: Vec<Cell> = Vec::new();
    for &size in &o.sizes {
        for (&d, &want) in o.delays_ms.iter().zip(o.n_per_delay.iter()) {
            cells.push(Cell {
                size,
                delay: Some(Duration::from_millis(d)),
                want,
                confirmed: 0,
                survived: 0,
                trials: 0,
            });
        }
        cells.push(Cell {
            size,
            delay: None,
            want: o.n_control,
            confirmed: 0,
            survived: 0,
            trials: 0,
        });
    }

    let budget = (o.budget_secs > 0).then(|| Instant::now() + Duration::from_secs(o.budget_secs));
    let mut node = Node::spawn(o.port, &dir)?;
    let mut cut = false;

    'cells: for cell in cells.iter_mut() {
        for _ in 0..cell.want {
            if budget.is_some_and(|d| Instant::now() >= d) {
                cut = true;
                break 'cells;
            }
            let state = if o.pack {
                make_pack(cell.size)?
            } else {
                let mut body = vec![0u8; cell.size];
                getrandom::getrandom(&mut body)?;
                block::encode(block::kind::RAW, &body)
            };
            let params = Parameters::from(blake3::hash(&state).as_bytes().to_vec());
            let contract = ContractContainer::Wasm(ContractWasmAPIVersion::V1(
                WrappedContract::new(code.clone(), params),
            ));
            let key = contract.key();

            let mut client = crate::connect(&node.ws()).await?;
            put(&mut client, contract, &state).await?;

            let confirmed = match cell.delay {
                // The control: no read-back at all, killed immediately.
                None => false,
                Some(d) => {
                    // "Confirmed" is the read-back, never the acknowledgement.
                    let ok = get(&mut client, &key, &state).await?;
                    if ok {
                        tokio::time::sleep(d).await;
                    }
                    ok
                }
            };
            drop(client);
            cell.trials += 1;
            if confirmed {
                cell.confirmed += 1;
            }

            node.restart()?;
            let mut after = crate::connect(&node.ws()).await?;
            let survived = get(&mut after, &key, &state).await?;
            drop(after);
            if survived {
                cell.survived += 1;
            }
            if cell.delay.is_some() && !confirmed {
                // A trial whose read-back never confirmed is not a trial of
                // "does a CONFIRMED put survive". Counted, and visible.
                eprintln!(
                    "  {} {}: a put was never confirmed by read-back — not a trial of the question",
                    kib(cell.size),
                    cell.label()
                );
            }
            println!(
                "  {} {:<34} confirmed={confirmed} survived={survived}  ({}/{})",
                kib(cell.size),
                cell.label(),
                cell.trials,
                cell.want
            );
        }
    }
    node.kill9();

    println!();
    let mut t = crate::stats::Table::new([
        "size",
        "killed after",
        "asked",
        "trials",
        "confirmed",
        "lost / n",
    ]);
    for c in &cells {
        if c.trials == 0 {
            continue;
        }
        t.row([
            kib(c.size),
            c.label(),
            c.want.to_string(),
            c.trials.to_string(),
            c.confirmed.to_string(),
            if c.delay.is_none() {
                format!(
                    "{} / {} (control: LOST is expected)",
                    c.trials - c.survived,
                    c.trials
                )
            } else if c.confirmed == 0 {
                "—".into()
            } else {
                format!(
                    "{} / {}",
                    c.confirmed - c.survived.min(c.confirmed),
                    c.confirmed
                )
            },
        ]);
    }
    println!("does a read-back-confirmed PUT survive kill -9 of the node?");
    print!("{t}");
    println!();

    // The control is the whole run's positive control. If killing before the
    // read-back never loses anything, the kill is not landing where this code
    // thinks it is, and every other cell is meaningless.
    let ctl: Vec<&Cell> = cells
        .iter()
        .filter(|c| c.delay.is_none() && c.trials > 0)
        .collect();
    let ctl_lost: usize = ctl.iter().map(|c| c.trials - c.survived).sum();
    let ctl_trials: usize = ctl.iter().map(|c| c.trials).sum();
    println!(
        "CONTROL — killed before any read-back: {ctl_lost} of {ctl_trials} lost. {}",
        if ctl_lost == 0 {
            "NOTHING WAS EVER LOST, so this run does not show the kill landing where it is meant to \
             — treat every cell above as unproven."
        } else {
            "The kill does destroy an unconfirmed put, so the cells above are testing what they claim."
        }
    );
    // The row that answers the issue: everything killed IMMEDIATELY after the
    // read-back, pooled across sizes, because that window is the whole question
    // and one size's cell is too small to bound anything on its own.
    let d0: Vec<&Cell> = cells
        .iter()
        .filter(|c| c.delay == Some(Duration::from_millis(0)) && c.trials > 0)
        .collect();
    let d0_conf: usize = d0.iter().map(|c| c.confirmed).sum();
    let d0_lost: usize = d0
        .iter()
        .map(|c| c.confirmed - c.survived.min(c.confirmed))
        .sum();
    println!(
        "POOLED, killed 0 ms after the read-back, all sizes: {}",
        crate::stats::loss_claim(d0_lost, d0_conf)
    );

    let lost: usize = cells
        .iter()
        .filter(|c| c.delay.is_some())
        .map(|c| c.confirmed - c.survived.min(c.confirmed))
        .sum();
    let conf: usize = cells
        .iter()
        .filter(|c| c.delay.is_some())
        .map(|c| c.confirmed)
        .sum();
    println!(
        "ALL confirmed puts, every delay: {}",
        crate::stats::loss_claim(lost, conf)
    );
    if cut {
        println!(
            "the run reached its {} s budget; the cells not taken are NOT within it",
            o.budget_secs
        );
    }
    Ok(())
}
