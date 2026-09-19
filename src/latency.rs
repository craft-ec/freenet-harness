//! `latency`: put/get latency per contract kind and size, parallel-put
//! behaviour, and whether a delegate may put at all (FREENET-CONSTRAINTS F15).
//!
//! Every number here is one observed request/response pair on a live node. A
//! request that errors is counted as an error, never as a latency — a fast
//! failure must not be able to improve a percentile.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{anyhow, bail, Result};
use craftec_block_contract as block;
use freenet_stdlib::{
    client_api::{ClientRequest, ContractRequest, ContractResponse, HostResponse, WebApi},
    prelude::*,
};
use tokio::time::timeout;

use crate::stats::{kib, Summary, Table};

/// Builds one fresh instance of a kind with a body of the given size: the
/// container to put, and the exact state bytes a get must return.
type Make = fn(&Arc<ContractCode<'static>>, usize) -> Result<(ContractContainer, Vec<u8>)>;

/// A contract kind the table measures.
///
/// Only Block exists today. Register, Set and Derived each become **one more
/// entry in [`KINDS`]** plus their own `make` — no change to the measurement
/// loops, the tables or the CLI.
struct Kind {
    name: &'static str,
    make: Make,
}

const KINDS: &[Kind] = &[Kind {
    name: "Block",
    make: make_block,
}];

/// A Block of `size` random bytes: fresh randomness means a key no node has
/// seen, so every put is a first put and never a no-op re-put.
fn make_block(
    code: &Arc<ContractCode<'static>>,
    size: usize,
) -> Result<(ContractContainer, Vec<u8>)> {
    let mut body = vec![0u8; size];
    getrandom::getrandom(&mut body)?;
    let state = block::encode(block::kind::RAW, &body);
    let params = Parameters::from(blake3::hash(&state).as_bytes().to_vec());
    let contract = ContractContainer::Wasm(ContractWasmAPIVersion::V1(WrappedContract::new(
        code.clone(),
        params,
    )));
    Ok((contract, state))
}

/// Every contract key this run asked the node to store.
///
/// The claim behind table 1 is "fresh random bodies, so every put is a new
/// contract". That is checkable, not something to assert: a repeated key would
/// make the put a merge into state the node already holds, which is a
/// different and much cheaper operation. Fewer distinct keys than requests
/// means the numbers measure the wrong thing.
#[derive(Default)]
struct Minted {
    requests: usize,
    distinct: HashSet<ContractInstanceId>,
}

impl Minted {
    fn add(&mut self, id: ContractInstanceId) {
        self.requests += 1;
        self.distinct.insert(id);
    }

    fn report(&self) {
        let ok = self.distinct.len() == self.requests;
        println!(
            "control: {} put requests, {} distinct contract keys — {}",
            self.requests,
            self.distinct.len(),
            if ok {
                "every put was a first put"
            } else {
                "REPEATED KEYS: some puts were merges, the latencies above are not comparable"
            }
        );
    }
}

/// One observation: a latency, or why there is no latency to report.
#[derive(Clone)]
pub(crate) enum Sample {
    Ms(f64),
    Failed(String),
}

pub(crate) fn ms_since(t: Instant) -> f64 {
    t.elapsed().as_secs_f64() * 1000.0
}

/// Send a request, refusing to block forever.
///
/// `WebApi::send` awaits the websocket sink. If the node stops reading, that
/// await never returns and the harness hangs with no error and no sample — the
/// one failure an instrument must not have, because it is indistinguishable
/// from slow.
pub(crate) async fn send_req(
    client: &mut WebApi,
    req: ClientRequest<'static>,
    wait: Duration,
) -> Result<()> {
    match timeout(wait, client.send(req)).await {
        Ok(r) => r.map_err(Into::into),
        Err(_) => bail!(
            "the node stopped accepting requests: send blocked for {} s",
            wait.as_secs()
        ),
    }
}

/// Progress lines carry the clock and the last sample's own latency.
///
/// Without them a long run is indistinguishable from a wedged one, and the
/// rate — the thing you actually want when deciding whether to wait — can only
/// be recovered by polling the file and diffing mtimes.
pub(crate) fn progress_pub(args: std::fmt::Arguments<'_>) {
    eprintln!("[{}] {args}", chrono_ish(std::time::SystemTime::now()));
}

/// freenet-core gives a put attempt 240 s before it declares `stream_stall`
/// and retries. A sample at or above that did not take "a long time" — it took
/// a timeout, and the distribution is bimodal. Counting them keeps a p90 from
/// hiding a mode.
const STALL_MS: f64 = 240_000.0;

fn stalls(samples: &[Sample]) -> usize {
    latencies(samples)
        .iter()
        .filter(|v| **v >= STALL_MS)
        .count()
}

/// Samples more than `TAIL_FACTOR` times the median.
///
/// The 240 s count alone hides a tail that sits below freenet's stall
/// constant: a series can run at a 1.7 s median with a handful of 61 s
/// outliers and still report zero stalls. A distribution with two modes has to
/// look like it in the table, wherever the second mode happens to sit.
const TAIL_FACTOR: f64 = 10.0;

fn tail(samples: &[Sample]) -> usize {
    let lat = latencies(samples);
    match Summary::of(&lat) {
        Some(s) => lat.iter().filter(|v| **v > s.p50 * TAIL_FACTOR).count(),
        None => 0,
    }
}

/// Latencies only; the failures are counted and printed separately.
fn latencies(samples: &[Sample]) -> Vec<f64> {
    samples
        .iter()
        .filter_map(|s| match s {
            Sample::Ms(v) => Some(*v),
            Sample::Failed(_) => None,
        })
        .collect()
}

fn failures(samples: &[Sample]) -> Vec<&str> {
    samples
        .iter()
        .filter_map(|s| match s {
            Sample::Failed(e) => Some(e.as_str()),
            Sample::Ms(_) => None,
        })
        .collect()
}

/// Put an already-built container and wait for its acknowledgement.
pub(crate) async fn put_container(
    client: &mut WebApi,
    contract: ContractContainer,
    state: &[u8],
    wait: Duration,
) -> Result<()> {
    match timed_put(client, contract, state, wait).await? {
        Sample::Ms(_) => Ok(()),
        Sample::Failed(e) => bail!("seed put failed: {e}"),
    }
}

/// Put one contract and time the acknowledgement.
async fn timed_put(
    client: &mut WebApi,
    contract: ContractContainer,
    state: &[u8],
    wait: Duration,
) -> Result<Sample> {
    let key = contract.key();
    let t = Instant::now();
    send_req(
        client,
        ClientRequest::ContractOp(ContractRequest::Put {
            contract,
            state: WrappedState::from(state.to_vec()),
            related_contracts: RelatedContracts::default(),
            subscribe: false,
            blocking_subscribe: false,
        }),
        wait,
    )
    .await?;
    Ok(match timeout(wait, client.recv()).await {
        Ok(Ok(HostResponse::ContractResponse(ContractResponse::PutResponse { key: k })))
            if k == key =>
        {
            Sample::Ms(ms_since(t))
        }
        Ok(Ok(other)) => Sample::Failed(format!("unexpected response: {other:?}")),
        Ok(Err(e)) => Sample::Failed(format!("node error: {e}")),
        Err(_) => Sample::Failed(format!("no response within {} s", wait.as_secs())),
    })
}

/// Get one contract and time the answer. The state is compared, so a get that
/// returns the wrong bytes is an error and not a fast sample.
async fn timed_get(
    client: &mut WebApi,
    key: &ContractKey,
    want: &[u8],
    wait: Duration,
) -> Result<Sample> {
    let t = Instant::now();
    send_req(
        client,
        ClientRequest::ContractOp(ContractRequest::Get {
            key: *key.id(),
            return_contract_code: false,
            subscribe: false,
            blocking_subscribe: false,
        }),
        wait,
    )
    .await?;
    Ok(match timeout(wait, client.recv()).await {
        Ok(Ok(HostResponse::ContractResponse(ContractResponse::GetResponse {
            state: got,
            ..
        }))) => {
            if got.as_ref() == want {
                Sample::Ms(ms_since(t))
            } else {
                Sample::Failed(format!(
                    "state mismatch: got {} B, expected {} B",
                    got.as_ref().len(),
                    want.len()
                ))
            }
        }
        Ok(Ok(other)) => Sample::Failed(format!("unexpected response: {other:?}")),
        Ok(Err(e)) => Sample::Failed(format!("node error: {e}")),
        Err(_) => Sample::Failed(format!("no response within {} s", wait.as_secs())),
    })
}

/// Put and warm-get one (kind, size) `n` times.
struct Series {
    kind: &'static str,
    size: usize,
    put: Vec<Sample>,
    get: Vec<Sample>,
}

async fn measure_series(
    client: &mut WebApi,
    kind: &Kind,
    code: &Arc<ContractCode<'static>>,
    size: usize,
    n: usize,
    wait: Duration,
    minted: &mut Minted,
) -> Result<Series> {
    let mut put = Vec::with_capacity(n);
    let mut held: Vec<(ContractKey, Vec<u8>)> = Vec::with_capacity(n);
    for i in 0..n {
        let (contract, state) = (kind.make)(code, size)?;
        let key = contract.key();
        minted.add(*key.id());
        let s = timed_put(client, contract, &state, wait).await?;
        // Only a block the node acknowledged is a block it can serve warm.
        if matches!(s, Sample::Ms(_)) {
            held.push((key, state));
        }
        put.push(s);
        // The contract id on every sample: without it, matching a slow sample
        // to its transaction in the node log is guesswork by timestamp, and
        // guesswork is how a wrong cause gets published.
        progress_pub(format_args!(
            "  {} {} put {}/{n} {} {}",
            kind.name,
            kib(size),
            i + 1,
            key.id(),
            match &put.last() {
                Some(Sample::Ms(v)) => format!("{v:.1} ms"),
                _ => "error".to_string(),
            }
        ));
    }
    let mut get = Vec::with_capacity(held.len());
    for (key, state) in held.iter() {
        get.push(timed_get(client, key, state, wait).await?);
    }
    progress_pub(format_args!(
        "  {} {} done ({n} put, {} get)",
        kind.name,
        kib(size),
        held.len()
    ));
    Ok(Series {
        kind: kind.name,
        size,
        put,
        get,
    })
}

/// How long until a block this node is putting can be READ BACK from this
/// node, measured from the same instant as the put.
///
/// The question behind it: does a `PutResponse` mean "stored here" or "settled
/// on the network"? If a block is locally readable in milliseconds while its
/// PutResponse takes minutes, a write pipeline can commit on local acceptance
/// and let propagation trail. The poll runs on its own connection so it cannot
/// be answered by the put's own response.
struct Readable {
    put: Sample,
    readable: Sample,
}

/// Ask for `key` until the node returns exactly `want`.
///
/// Each attempt is bounded by [`PROBE_ATTEMPT`], and that bound is the whole
/// correctness of this measurement. The first poll goes out before the block
/// exists anywhere, so the node cannot find it locally and starts a NETWORK
/// search, which freenet abandons only at its 60 s get attempt deadline
/// (`timeout_kind="attempt_deadline" timeout_secs=60`). An unbounded wait on
/// that first answer therefore reports ~60 s for a block that was readable in
/// milliseconds — measuring this harness's own patience, not the node.
///
/// Responses for any other key are discarded, so a late answer to an abandoned
/// attempt cannot be mistaken for a hit.
const PROBE_ATTEMPT: Duration = Duration::from_millis(250);
const PROBE_GAP: Duration = Duration::from_millis(250);
/// Past this, the answer to "readable before the PutResponse?" is already no,
/// and continuing only piles up network searches inside the node.
const PROBE_LIMIT: Duration = Duration::from_secs(30);

async fn poll_readable(
    client: &mut WebApi,
    key: &ContractKey,
    want: &[u8],
    from: Instant,
    limit: Duration,
    _interval: Duration,
) -> Result<Sample> {
    let limit = limit.min(PROBE_LIMIT);
    let deadline = from + limit;
    while Instant::now() < deadline {
        send_req(
            client,
            ClientRequest::ContractOp(ContractRequest::Get {
                key: *key.id(),
                return_contract_code: false,
                subscribe: false,
                blocking_subscribe: false,
            }),
            PROBE_ATTEMPT,
        )
        .await?;
        let attempt_end = Instant::now() + PROBE_ATTEMPT;
        loop {
            let now = Instant::now();
            if now >= deadline {
                break;
            }
            let Some(left) = attempt_end.checked_duration_since(now) else {
                break;
            };
            match timeout(left, client.recv()).await {
                Ok(Ok(HostResponse::ContractResponse(ContractResponse::GetResponse {
                    key: k,
                    state: got,
                    ..
                }))) if k.id() == key.id() && got.as_ref() == want => {
                    return Ok(Sample::Ms(from.elapsed().as_secs_f64() * 1000.0));
                }
                // Another key, a miss, or a node error: not yet.
                Ok(Ok(_)) | Ok(Err(_)) => {}
                Err(_) => break,
            }
        }
        tokio::time::sleep(PROBE_GAP).await;
    }
    Ok(Sample::Failed(format!(
        "not readable on this node within {} s",
        limit.as_secs()
    )))
}

/// Two connections used as one instrument: the put goes out on `writer` while
/// `reader` polls, so a hit can only come from the node serving the block and
/// never from the put's own response arriving on the same socket.
struct Pair<'a> {
    writer: &'a mut WebApi,
    reader: &'a mut WebApi,
}

async fn measure_readable(
    conns: Pair<'_>,
    kind: &Kind,
    code: &Arc<ContractCode<'static>>,
    size: usize,
    n: usize,
    wait: Duration,
    minted: &mut Minted,
) -> Result<Vec<Readable>> {
    let mut out = Vec::with_capacity(n);
    let Pair { writer, reader } = conns;
    for i in 0..n {
        let (contract, state) = (kind.make)(code, size)?;
        let key = contract.key();
        minted.add(*key.id());
        // One clock for both, so the two numbers are comparable.
        let t0 = Instant::now();
        let (put, readable) = tokio::join!(
            timed_put(writer, contract, &state, wait),
            poll_readable(reader, &key, &state, t0, wait, Duration::from_millis(50))
        );
        let (put, readable) = (put?, readable?);
        progress_pub(format_args!(
            "  readable {} {} {}/{n}  put {}  readable {}",
            kind.name,
            kib(size),
            i + 1,
            match &put {
                Sample::Ms(v) => format!("{v:.1} ms"),
                Sample::Failed(_) => "error".into(),
            },
            match &readable {
                Sample::Ms(v) => format!("{v:.1} ms"),
                Sample::Failed(_) => "never".into(),
            }
        ));
        out.push(Readable { put, readable });
    }
    Ok(out)
}

/// One line per finished series, printed the moment it is finished.
///
/// The consolidated tables at the end are the readable form, but they are
/// worthless if the run does not reach them: a measurement against this node
/// takes tens of minutes, and an interrupted run that printed nothing has
/// thrown away every sample it paid for. Results are emitted as they are
/// earned.
fn emit(label: &str, samples: &[Sample]) {
    let lat = latencies(samples);
    let errs = failures(samples);
    match Summary::of(&lat) {
        Some(s) => println!(
            "partial: {label}  n={} errors={} >=240s={} >10xp50={}  min {:.1}  p50 {:.1}  p90 {:.1}  p99 {:.1}  max {:.1}",
            s.n,
            errs.len(),
            stalls(samples),
            tail(samples),
            s.min,
            s.p50,
            s.p90,
            s.p99,
            s.max
        ),
        None => println!("partial: {label}  n=0 errors={}", errs.len()),
    }
    if let Some(first) = errs.first() {
        println!("partial: {label}  first error: {first}");
    }
    // Flushed now, not at exit: a killed process never reaches its exit.
    use std::io::Write as _;
    let _ = std::io::stdout().flush();
}

/// N puts issued back to back on one connection, then all answers collected.
struct ParallelRun {
    n: usize,
    /// First send to last acknowledgement.
    wall_ms: f64,
    per_put: Vec<Sample>,
    /// Offset from batch start to each acknowledgement, ascending.
    ///
    /// "Wall time to all-acknowledged" is the wrong number for an
    /// erasure-coded write: the batch only has to reach k of n before the
    /// writer moves on, and one stalled put must not hold the other n-1
    /// hostage. This curve is what sizes k — the cost of demanding the last
    /// ack is read off the gap between its 50% and 100% points.
    done_ms: Vec<f64>,
}

impl ParallelRun {
    /// Time by which `frac` of the batch was acknowledged.
    fn at(&self, frac: f64) -> Option<f64> {
        if self.done_ms.is_empty() {
            return None;
        }
        let i = ((self.done_ms.len() as f64) * frac).ceil().max(1.0) as usize;
        self.done_ms.get(i.min(self.done_ms.len()) - 1).copied()
    }
}

async fn measure_parallel(
    client: &mut WebApi,
    kind: &Kind,
    code: &Arc<ContractCode<'static>>,
    size: usize,
    n: usize,
    wait: Duration,
    minted: &mut Minted,
) -> Result<ParallelRun> {
    let mut sent: HashMap<ContractInstanceId, Instant> = HashMap::with_capacity(n);
    let mut order = Vec::with_capacity(n);
    let start = Instant::now();
    for _ in 0..n {
        let (contract, state) = (kind.make)(code, size)?;
        let key = contract.key();
        send_req(
            client,
            ClientRequest::ContractOp(ContractRequest::Put {
                contract,
                state: WrappedState::from(state),
                related_contracts: RelatedContracts::default(),
                subscribe: false,
                blocking_subscribe: false,
            }),
            wait,
        )
        .await?;
        minted.add(*key.id());
        // Stamped after the send returns: the send itself is part of issuing,
        // not of the node's latency.
        sent.insert(*key.id(), Instant::now());
        order.push(*key.id());
    }
    let issued = ms_since(start);
    // Offset from batch start to each acknowledgement, in arrival order.
    let mut done_ms: Vec<f64> = Vec::with_capacity(n);
    let mut per_put: HashMap<ContractInstanceId, Sample> = HashMap::with_capacity(n);
    let deadline = Instant::now() + wait;
    while per_put.len() < n {
        let Some(left) = deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        match timeout(left, client.recv()).await {
            Ok(Ok(HostResponse::ContractResponse(ContractResponse::PutResponse { key: k }))) => {
                let id = *k.id();
                match sent.get(&id) {
                    Some(t) => {
                        if per_put
                            .insert(id, Sample::Ms(t.elapsed().as_secs_f64() * 1000.0))
                            .is_none()
                        {
                            // Only a first acknowledgement advances the curve;
                            // a duplicate must not make the batch look faster.
                            done_ms.push(ms_since(start));
                        }
                    }
                    // A straggler from an earlier batch on this same
                    // connection is not an error: the previous run stopped
                    // waiting at its deadline, and its late answer must not
                    // abort this one. It is simply not ours to count.
                    None => {
                        progress_pub(format_args!(
                            "  (late put response from an earlier batch: {id})"
                        ));
                    }
                }
            }
            Ok(Ok(other)) => {
                eprintln!("  (ignored while collecting puts: {other:?})");
            }
            Ok(Err(e)) => bail!("node error while collecting parallel puts: {e}"),
            Err(_) => break,
        }
    }
    let wall_ms = ms_since(start);
    done_ms.sort_by(|a, b| a.partial_cmp(b).expect("elapsed times are never NaN"));
    // Anything still unanswered when the deadline passed is an error, in the
    // order it was issued, so the count in the table is N every time.
    let per_put = order
        .into_iter()
        .map(|id| {
            per_put.remove(&id).unwrap_or_else(|| {
                Sample::Failed(format!("no response within {} s", wait.as_secs()))
            })
        })
        .collect::<Vec<_>>();
    progress_pub(format_args!(
        "  parallel N={n}: issued in {issued:.1} ms, all answers in {wall_ms:.1} ms"
    ));
    Ok(ParallelRun {
        n,
        wall_ms,
        per_put,
        done_ms,
    })
}

/// What one `k` of the delegate-put probe reported.
struct DelegatePut {
    k: usize,
    /// What the delegate said it asked the host for.
    asked: String,
    ok: String,
    err: String,
    /// The node's own words, where it gave any.
    detail: String,
}

/// F15's open question: do puts issued **by a delegate** count against the
/// ≤4 network contract ops per `process()` return — and can a delegate put at
/// all on this node?
///
/// The delegate returns `k` `PutContractRequest`s from a single `process()`
/// call and records every `PutContractResponse` the host sends back. We read
/// the tally out of its secrets, so a late answer is still counted.
async fn probe_delegate_put(
    ws: &str,
    dkey: &DelegateKey,
    block_code: &[u8],
    k: usize,
    settle: Duration,
) -> Result<DelegatePut> {
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce)?;
    let mut msg = b"putk".to_vec();
    msg.push(k as u8);
    msg.extend_from_slice(&nonce);
    msg.extend_from_slice(block_code);

    let (replies, errors) = crate::ask_raw(ws, dkey, msg, Duration::from_secs(20)).await?;
    // Poll until the delegate has as many answers as it asked for, or time is up.
    let done = crate::poll_stat(ws, dkey, settle, |r| {
        r.split_whitespace()
            .find_map(|f| f.strip_prefix("put="))
            .map(|v| v == format!("{k}/{k}"))
            .unwrap_or(false)
    })
    .await?;
    let last = match done {
        Some((_, r)) => r,
        None => crate::ask(ws, dkey, b"putstat".to_vec(), Duration::from_secs(20))
            .await
            .unwrap_or_default()
            .into_iter()
            .next()
            .unwrap_or_else(|| "no reply to putstat".into()),
    };
    let field = |name: &str| -> String {
        last.split_whitespace()
            .find_map(|f| f.strip_prefix(name))
            .unwrap_or("?")
            .to_string()
    };
    let mut detail = Vec::new();
    if !replies.is_empty() {
        detail.push(format!("reply {replies:?}"));
    }
    if !errors.is_empty() {
        detail.push(format!("node error {errors:?}"));
    }
    detail.push(format!("stat {last:?}"));
    Ok(DelegatePut {
        k,
        asked: field("asked="),
        ok: field("ok="),
        err: field("err="),
        detail: detail.join(" | "),
    })
}

fn describe_environment(node_version: &str) {
    println!(
        "command:  {}",
        std::env::args().collect::<Vec<_>>().join(" ")
    );
    println!("node:     {node_version}");
    println!("machine:  {}", machine());
    // Network-mode latency is a property of THIS uplink as much as of the
    // protocol: the same node on a poor mobile link and on a good one differs
    // by two orders of magnitude. A table without the link is not reproducible,
    // and the number must never be recorded as a platform constant.
    println!("uplink:   {}", uplink());
    println!("measured: {}", chrono_ish(std::time::SystemTime::now()));
    println!();
}

/// Date only, from the clock, without taking a date crate for one line.
fn chrono_ish(t: std::time::SystemTime) -> String {
    let secs = t
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let (mut y, mut days) = (1970i64, (secs / 86_400) as i64);
    loop {
        let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
        let len = if leap { 366 } else { 365 };
        if days < len {
            break;
        }
        days -= len;
        y += 1;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let months = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    let mut m = 0;
    while m < 12 && days >= months[m] {
        days -= months[m];
        m += 1;
    }
    format!(
        "{y:04}-{:02}-{:02} {:02}:{:02}:{:02}Z",
        m + 1,
        days + 1,
        (secs / 3600) % 24,
        (secs / 60) % 60,
        secs % 60
    )
}

fn run_tool(cmd: &str, args: &[&str]) -> Option<String> {
    let out = std::process::Command::new(cmd).args(args).output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// The default interface, its gateway, and the round trip to the freenet
/// gateways this node dials — the three facts that decide what a network-mode
/// put can possibly cost.
///
/// Portable across the two systems this harness runs on, which do not agree:
/// `route -n get default` is BSD-only and `ip route` is Linux-only, and
/// `ping -t` means "deadline" on macOS but "TTL" on Linux. Getting the second
/// one wrong does not error — it silently reports an unreachable host, which
/// would enter a report as a fact about the network.
fn uplink() -> String {
    let field = |bsd: &str, linux: &str| {
        run_tool(
            "sh",
            &[
                "-c",
                &format!(
                    "{{ route -n get default 2>/dev/null | awk '{bsd}'; \
                        ip -o route get 1.1.1.1 2>/dev/null | sed -n '{linux}'; }} | head -1"
                ),
            ],
        )
        .unwrap_or_else(|| "unknown".into())
    };
    let iface = field("/interface:/{print $2}", "s/.* dev \\([^ ]*\\).*/\\1/p");
    let router = field("/gateway:/{print $2}", "s/.* via \\([^ ]*\\) .*/\\1/p");
    let rtt = ["gw1.freenet.org", "gw2.freenet.org"]
        .iter()
        .map(|gw| {
            let cmd = format!(
                "if [ \"$(uname -s)\" = Darwin ]; then ping -c 3 -t 5 {gw}; \
                 else ping -c 3 -w 5 {gw}; fi 2>/dev/null | tail -1 | cut -d= -f2"
            );
            match run_tool("sh", &["-c", &cmd]) {
                Some(v) if !v.is_empty() => format!("{gw} {v}"),
                // Unreachable is itself a measurement, and a relevant one —
                // but only once the probe is known to be well formed.
                _ => format!("{gw} no reply"),
            }
        })
        .collect::<Vec<_>>()
        .join(" · ");
    format!("iface {iface} via {router} · rtt min/avg/max/stddev {rtt}")
}

fn machine() -> String {
    let uname = run_tool("uname", &["-srm"]).unwrap_or_else(|| "unknown".into());
    match run_tool("sysctl", &["-n", "machdep.cpu.brand_string"]) {
        Some(cpu) => format!("{uname} · {cpu}"),
        None => uname,
    }
}

/// The node version, or an honest admission that we could not read it.
fn node_version() -> String {
    run_tool("freenet", &["--version"])
        .map(|v| v.lines().collect::<Vec<_>>().join(" · "))
        .unwrap_or_else(|| "unknown — `freenet --version` did not run on this machine".into())
}

/// Which of the four measurements to run.
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum Part {
    All,
    Put,
    Get,
    Parallel,
    DelegatePut,
    /// Put and, from a second connection, poll until the block reads back.
    Readable,
}

impl Part {
    fn wants(self, p: Part) -> bool {
        self == Part::All || self == p
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    ws: &str,
    wasm: &str,
    delegate_wasm: &str,
    samples: usize,
    sizes: &[usize],
    parallel: &[usize],
    parallel_size: usize,
    max_k: usize,
    only: Part,
    wait: Duration,
) -> Result<()> {
    if samples == 0 {
        bail!("--samples 0 measures nothing");
    }
    let code = Arc::new(ContractCode::from(std::fs::read(wasm).map_err(|e| {
        anyhow!("{wasm}: {e} — run ../freenet-contracts/build.sh first")
    })?));
    let version = node_version();
    describe_environment(&version);

    let mut client = crate::connect(ws).await?;
    let mut minted = Minted::default();

    // 1 & 2. Put, then warm get, every kind at every size.
    let mut series = Vec::new();
    if only.wants(Part::Put) || only.wants(Part::Get) {
        for kind in KINDS {
            for &size in sizes {
                let s = measure_series(&mut client, kind, &code, size, samples, wait, &mut minted)
                    .await?;
                emit(&format!("PUT  {} {}", s.kind, kib(s.size)), &s.put);
                emit(&format!("GET  {} {}", s.kind, kib(s.size)), &s.get);
                series.push(s);
            }
        }
    }

    // 3. What does a PutResponse wait for? Put and poll for local readability
    //    off one clock, on two connections.
    let mut readable = Vec::new();
    if only.wants(Part::Readable) {
        let mut reader = crate::connect(ws).await?;
        for kind in KINDS {
            for &size in sizes {
                let rows = measure_readable(
                    Pair {
                        writer: &mut client,
                        reader: &mut reader,
                    },
                    kind,
                    &code,
                    size,
                    samples,
                    wait,
                    &mut minted,
                )
                .await?;
                let label = format!("{} {}", kind.name, kib(size));
                emit(
                    &format!("RDBL-put  {label}"),
                    &rows.iter().map(|r| r.put.clone()).collect::<Vec<_>>(),
                );
                emit(
                    &format!("RDBL-read {label}"),
                    &rows.iter().map(|r| r.readable.clone()).collect::<Vec<_>>(),
                );
                readable.push((kind.name, size, rows));
            }
        }
        let _ = reader.send(ClientRequest::Disconnect { cause: None }).await;
    }

    // 4. Parallel puts on one connection.
    let mut runs = Vec::new();
    if only.wants(Part::Parallel) {
        for &n in parallel {
            let r = measure_parallel(
                &mut client,
                &KINDS[0],
                &code,
                parallel_size,
                n,
                wait,
                &mut minted,
            )
            .await?;
            emit(
                &format!("PAR  N={} wall {:.1} ms", r.n, r.wall_ms),
                &r.per_put,
            );
            runs.push(r);
        }
    }
    let _ = client.send(ClientRequest::Disconnect { cause: None }).await;

    // 5. Can a delegate put at all, and how many per process() return?
    let mut dputs = Vec::new();
    let mut delegate_note = String::new();
    if only.wants(Part::DelegatePut) {
        let block_code = std::fs::read(wasm)?;
        let mut salt = [0u8; 16];
        getrandom::getrandom(&mut salt)?;
        let mut c = crate::connect(ws).await?;
        let dkey = crate::register(&mut c, delegate_wasm, &salt, wait).await?;
        let _ = c.send(ClientRequest::Disconnect { cause: None }).await;
        for k in 1..=max_k {
            progress_pub(format_args!("  delegate put k={k}"));
            let d = probe_delegate_put(ws, &dkey, &block_code, k, Duration::from_secs(30)).await?;
            println!(
                "partial: DPUT k={} asked={} accepted={} refused/errored={}  {}",
                d.k, d.asked, d.ok, d.err, d.detail
            );
            dputs.push(d);
        }
        delegate_note = format!(
            "probe delegate {delegate_wasm}, block contract {wasm} ({} B of wasm sent in the app message)",
            block_code.len()
        );
    }

    // ---- tables -------------------------------------------------------
    if only.wants(Part::Put) {
        println!("1. PUT latency (ms) — fresh random body, every put a new contract");
        print_series(&series, |s| &s.put);
    }
    if only.wants(Part::Get) {
        println!("2. GET latency (ms) — warm: a block this node just put");
        print_series(&series, |s| &s.get);
    }
    if only.wants(Part::Parallel) {
        println!(
            "4. Parallel PUT — N blocks of {} issued back to back on one connection",
            kib(parallel_size)
        );
        print_parallel(&runs);
    }
    if only.wants(Part::Readable) {
        println!(
            "5. What does a PutResponse wait for? — put vs time until the same node serves it"
        );
        print_readable(&readable);
    }
    if only.wants(Part::DelegatePut) {
        println!("6. Delegate-originated PUT (F15) — k PutContractRequests from one process()");
        if !delegate_note.is_empty() {
            println!("   {delegate_note}");
        }
        print_delegate(&dputs);
    }
    if minted.requests > 0 {
        minted.report();
    }
    Ok(())
}

fn print_series(series: &[Series], pick: fn(&Series) -> &Vec<Sample>) {
    let mut t = Table::new(
        ["kind", "size", "n", "errors", ">=240s", ">10xp50"]
            .into_iter()
            .chain(Summary::HEADINGS),
    );
    let mut notes = Vec::new();
    for s in series {
        let samples = pick(s);
        let lat = latencies(samples);
        let errs = failures(samples);
        let head = vec![
            s.kind.to_string(),
            kib(s.size),
            lat.len().to_string(),
            errs.len().to_string(),
            stalls(samples).to_string(),
            tail(samples).to_string(),
        ];
        match Summary::of(&lat) {
            Some(sum) => t.row(head.into_iter().chain(sum.cells())),
            None => t.row(
                head.into_iter()
                    .chain(["-"; 5].into_iter().map(String::from)),
            ),
        }
        if let Some(first) = errs.first() {
            notes.push(format!(
                "   {} {}: {} error(s), first: {first}",
                s.kind,
                kib(s.size),
                errs.len()
            ));
        }
    }
    print!("{t}");
    for n in notes {
        println!("{n}");
    }
    println!();
}

fn print_parallel(runs: &[ParallelRun]) {
    // The curve first: for an erasure-coded write the writer moves on at k of
    // n, so "time to all" is a cost we may simply choose not to pay.
    let mut c = Table::new(["N", "25%", "50%", "75%", "100% (all)", "all / 50%"]);
    for r in runs {
        let cell = |f: f64| match r.at(f) {
            Some(v) => format!("{v:.1}"),
            None => "-".to_string(),
        };
        let ratio = match (r.at(0.5), r.at(1.0)) {
            (Some(h), Some(a)) if h > 0.0 => format!("{:.1}x", a / h),
            _ => "-".to_string(),
        };
        c.row([
            r.n.to_string(),
            cell(0.25),
            cell(0.5),
            cell(0.75),
            cell(1.0),
            ratio,
        ]);
    }
    println!("   batch completion curve (ms from first send) — what a k-of-n write would wait for");
    print!("{c}");
    println!();

    let mut t = Table::new(
        ["N", "wall ms", "ok", "errors"]
            .into_iter()
            .map(String::from)
            .chain(Summary::HEADINGS.iter().map(|h| format!("put {h}"))),
    );
    let mut notes = Vec::new();
    for r in runs {
        let lat = latencies(&r.per_put);
        let errs = failures(&r.per_put);
        let head = vec![
            r.n.to_string(),
            format!("{:.1}", r.wall_ms),
            lat.len().to_string(),
            errs.len().to_string(),
        ];
        match Summary::of(&lat) {
            Some(sum) => t.row(head.into_iter().chain(sum.cells())),
            None => t.row(
                head.into_iter()
                    .chain(["-"; 5].into_iter().map(String::from)),
            ),
        }
        if let Some(first) = errs.first() {
            notes.push(format!(
                "   N={}: {} error(s), first: {first}",
                r.n,
                errs.len()
            ));
        }
    }
    print!("{t}");
    for n in notes {
        println!("{n}");
    }
    println!();
}

/// Put latency and readable-here latency side by side, because the gap
/// between them is the whole question.
fn print_readable(rows: &[(&'static str, usize, Vec<Readable>)]) {
    let mut t = Table::new([
        "kind",
        "size",
        "n",
        "put p50",
        "put p99",
        "readable p50",
        "readable p99",
        "never readable",
    ]);
    for (kind, size, rs) in rows {
        let puts: Vec<Sample> = rs.iter().map(|r| r.put.clone()).collect();
        let reads: Vec<Sample> = rs.iter().map(|r| r.readable.clone()).collect();
        let (ps, rz) = (
            Summary::of(&latencies(&puts)),
            Summary::of(&latencies(&reads)),
        );
        let cell = |s: &Option<Summary>, f: fn(&Summary) -> f64| match s {
            Some(v) => format!("{:.1}", f(v)),
            None => "-".to_string(),
        };
        t.row([
            kind.to_string(),
            kib(*size),
            rs.len().to_string(),
            cell(&ps, |s| s.p50),
            cell(&ps, |s| s.p99),
            cell(&rz, |s| s.p50),
            cell(&rz, |s| s.p99),
            failures(&reads).len().to_string(),
        ]);
    }
    print!("{t}");
    println!();
}

fn print_delegate(dputs: &[DelegatePut]) {
    let mut t = Table::new(["k", "asked", "accepted", "refused/errored"]);
    for d in dputs {
        t.row([
            d.k.to_string(),
            d.asked.clone(),
            d.ok.clone(),
            d.err.clone(),
        ]);
    }
    print!("{t}");
    for d in dputs {
        println!("   k={}: {}", d.k, d.detail);
    }
    println!();
}
