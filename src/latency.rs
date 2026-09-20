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
use craftec_bag_contract as bag_contract;
use craftec_block_contract as block;
use craftec_register_contract as register_contract;
use craftec_set_contract as set_contract;
use freenet_stdlib::{
    client_api::{ClientRequest, ContractRequest, ContractResponse, HostResponse},
    prelude::*,
};
use tokio::time::timeout;

use crate::stats::{kib, Summary, Table};

/// Builds one fresh instance of a kind with a body of the given size: the
/// container to put, and the exact state bytes a get must return.
type Make = fn(&Arc<ContractCode<'static>>, usize) -> Result<(ContractContainer, Vec<u8>)>;

/// A contract kind the table measures.
///
/// A kind is three things: the artefact it is, how a fresh instance of it is
/// built, and the largest body it can carry. The ceiling belongs here rather
/// than in the CLI because it is the CONTRACT's, not the run's — a Register
/// refuses a value over `MAX_VALUE` however `--sizes` is spelled, and a series
/// that asked for one would report node errors for a fixture mistake.
#[derive(Debug)]
struct Kind {
    name: &'static str,
    /// The wasm's file name, taken from the directory `--wasm` names. All four
    /// artefacts come out of one `freenet-contracts/build.sh`, so naming three
    /// more paths on the command line could only ever disagree with it.
    wasm: &'static str,
    /// The largest BODY this kind can carry, from the contract's own limits.
    cap: usize,
    /// Why, in the contract's own terms. A size skipped without a reason reads
    /// as a failure.
    cap_why: &'static str,
    make: Make,
}

/// How many slots a measured Set has, and how many pointers a measured Bag
/// has. Both are set to the contract's own maximum so the size ladder is as
/// long as the format allows; both are reported with the numbers, because a
/// Set of 64 slots and a Set of 8 are not the same contract to put.
const SET_M: u16 = set_contract::wire::MAX_M;
const BAG_M: u16 = 1024;

/// Block stays FIRST. Parts 3 to 6 measure Block specifically and reach it as
/// `KINDS[0]`; reordering this list would silently re-point them.
const KINDS: &[Kind] = &[
    Kind {
        name: "Block",
        wasm: "block.wasm",
        cap: block::MAX_BODY,
        cap_why: "block::MAX_BODY, the largest RAW body a Block will hold",
        make: make_block,
    },
    Kind {
        name: "Register",
        wasm: "register.wasm",
        cap: register_contract::wire::MAX_VALUE,
        cap_why: "register::wire::MAX_VALUE — a register holds ONE value",
        make: make_register,
    },
    Kind {
        name: "Set",
        wasm: "set.wasm",
        cap: SET_M as usize * set_contract::wire::MAX_PAYLOAD as usize,
        cap_why: "MAX_M slots x MAX_PAYLOAD — a Set cannot hold more than it keeps",
        make: make_set,
    },
    Kind {
        name: "Bag",
        wasm: "bag.wasm",
        cap: BAG_M as usize * bag_contract::wire::MAX_PAYLOAD as usize,
        cap_why: "M pointers x MAX_PAYLOAD",
        make: make_bag,
    },
];

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

/// A Register holding one non-terminal record whose value is `size` random
/// bytes.
///
/// The label carries eight random bytes and the params are RE-PARSED from the
/// salted bytes before anything is signed. `keyset_seeded` takes one byte and
/// hardcodes the label, which makes the key space 256 wide — measured on the
/// round-trip, 5 runs in 30 opened on another run's final state. A key is
/// `hash(code, params)` and every signature binds to `blake3(params)`, so the
/// salt has to be in place BEFORE the record is made, not after.
fn make_register(
    code: &Arc<ContractCode<'static>>,
    size: usize,
) -> Result<(ContractContainer, Vec<u8>)> {
    use register_contract::{testing, wire::Params};
    let mut salt = [0u8; 9];
    getrandom::getrandom(&mut salt)?;
    let mut w = testing::keyset_seeded(salt[0], 2, 4, false);
    let seeded = w.params_bytes.clone();
    w.params_bytes.extend_from_slice(&salt[1..]);
    w.params = Params::parse(&w.params_bytes)
        .ok_or_else(|| anyhow!("the salted register params must still parse"))?;
    if w.params_bytes == seeded {
        bail!("the register salt changed nothing — two samples could share a key");
    }
    let mut value = vec![0u8; size];
    getrandom::getrandom(&mut value)?;
    let state = w.encode(&w.state(w.record(false, 1, &value)));
    let contract = ContractContainer::Wasm(ContractWasmAPIVersion::V1(WrappedContract::new(
        code.clone(),
        Parameters::from(w.params_bytes.clone()),
    )));
    Ok((contract, state))
}

/// A Set holding `size` bytes of payload, spread over as few owner-tier items
/// as `MAX_PAYLOAD` allows.
///
/// Every item is signed by the OWNER, so admission is never the thing being
/// timed: an item that needed a capability would make the series depend on
/// whether the cap was also in the state.
fn make_set(
    code: &Arc<ContractCode<'static>>,
    size: usize,
) -> Result<(ContractContainer, Vec<u8>)> {
    use set_contract::wire::{Admission, MAX_PAYLOAD};
    let mut salt = [0u8; 9];
    getrandom::getrandom(&mut salt)?;
    // quota = M: the owner is allowed to hold every slot, so the item count is
    // bounded by the size asked for and not by a quota the table never states.
    let mut w = set_contract::testing::world_with(salt[0], 2, Admission::Cap, SET_M, SET_M, 0);
    w.params.label = salt[1..].to_vec();
    w.params_bytes = w.params.encode();
    let per = MAX_PAYLOAD as usize;
    let mut items = Vec::new();
    let mut left = size;
    while left > 0 || items.is_empty() {
        let take = left.min(per);
        let mut payload = vec![0u8; take];
        getrandom::getrandom(&mut payload)?;
        let i = items.len();
        items.push(w.item(0, format!("k{i:04}").as_bytes(), 10 + i as u64, &payload));
        left -= take;
    }
    if items.len() > SET_M as usize {
        bail!(
            "{} items asked for, but this Set keeps {SET_M} — the cap in KINDS is wrong",
            items.len()
        );
    }
    let state = w.encode(&w.state(items));
    let contract = ContractContainer::Wasm(ContractWasmAPIVersion::V1(WrappedContract::new(
        code.clone(),
        Parameters::from(w.params_bytes.clone()),
    )));
    Ok((contract, state))
}

/// A Bag holding `size` bytes of payload, spread over as few pointers as
/// `MAX_PAYLOAD` allows.
///
/// `work_bits = 0`. The price of a name is the Bag's own cost and it is paid by
/// the CLIENT, not the node: mining it here would put the harness's CPU inside
/// a latency this table attributes to the network. The tables say so.
///
/// The pointers are encoded in RANK order — work descending, then name
/// ascending. `BagState::parse` requires it and rejects the whole candidate
/// otherwise, and an unreadable candidate is ignored rather than fatal, so
/// mining order would add NO pointers rather than some, silently.
fn make_bag(
    code: &Arc<ContractCode<'static>>,
    size: usize,
) -> Result<(ContractContainer, Vec<u8>)> {
    use bag_contract::{
        testing,
        wire::{BagState, Held, MAX_PAYLOAD},
    };
    let mut p = testing::params(0, BAG_M);
    let mut salt = [0u8; 12];
    getrandom::getrandom(&mut salt)?;
    p.bucket = u32::from_le_bytes(salt[..4].try_into().expect("4 bytes"));
    p.label = salt[4..].to_vec();
    let ph = p.hash();
    let per = MAX_PAYLOAD as usize;
    let mut held: Vec<Held> = Vec::new();
    let mut left = size;
    while left > 0 || held.is_empty() {
        let take = left.min(per);
        let mut payload = vec![0u8; take];
        getrandom::getrandom(&mut payload)?;
        held.push(Held::of(
            testing::mine(&p, &payload, held.len() as u64),
            &ph,
        ));
        left -= take;
    }
    if held.len() > BAG_M as usize {
        bail!(
            "{} pointers asked for, but this Bag keeps {BAG_M} — the cap in KINDS is wrong",
            held.len()
        );
    }
    held.sort_by_key(|x| x.rank());
    let state = BagState { held }.encode();
    let contract = ContractContainer::Wasm(ContractWasmAPIVersion::V1(WrappedContract::new(
        code.clone(),
        Parameters::from(p.encode()),
    )));
    Ok((contract, state))
}

/// Why this kind cannot be measured at this size, if it cannot.
///
/// Separate from the loop so it can be tested: inline, the only way to find out
/// that a ceiling was off by one would be a live run that quietly measured one
/// row fewer.
fn skip_note(kind: &Kind, size: usize) -> Option<String> {
    (size > kind.cap).then(|| {
        format!(
            "{} {}: not measured — {} holds at most {} ({})",
            kind.name,
            kib(size),
            kind.name,
            kib(kind.cap),
            kind.cap_why
        )
    })
}

/// Every sample of one series must encode to the same number of bytes, or the
/// percentiles are over a mixture and the table's `state` column names none of
/// it.
fn same_weight(kind: &Kind, size: usize, first: usize, now: usize, nth: usize) -> Result<()> {
    if first == now {
        return Ok(());
    }
    bail!(
        "{} {}: sample {nth} encodes to {now} B where the first encoded to {first} B — \
         this series is a mixture, not a measurement",
        kind.name,
        kib(size)
    )
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
    client: &mut crate::probe::Client,
    req: ClientRequest<'static>,
    wait: Duration,
) -> Result<()> {
    send_req_ctx(client, req, wait, "").await
}

/// The same send, with what the CALLER knows about its own state.
///
/// The old message said "the node stopped accepting requests", and that is
/// almost never what happened: a send blocks when this client has stopped
/// reading and the socket has backpressured. It cost a 200-key run, whose
/// reader had sent 200 GETs for keys nobody held — requests that are never
/// answered, so nothing drained — and the run's only output blamed a node that
/// was serving perfectly well. A message that names the wrong component sends
/// the next person to the wrong machine.
///
/// `what` is the caller's own count of what it has not read. Empty when the
/// caller genuinely has nothing to add.
pub(crate) async fn send_req_ctx(
    client: &mut crate::probe::Client,
    req: ClientRequest<'static>,
    wait: Duration,
    what: &str,
) -> Result<()> {
    match timeout(wait, client.send(req)).await {
        Ok(r) => r,
        Err(_) => {
            // The operation ENDED, and it ended in a timeout. Without this the
            // dump would show an edge nobody answered, which is the same shape
            // a slow node makes — and the two want different responses.
            client.finish_last(instrument::vocab::Outcome::Timeout);
            // The message is now a PROJECTION of the recording rather than a
            // sentence someone wrote about it. "What the caller had not
            // drained" used to be a string each call site passed in by hand,
            // which is a number that can be wrong; `OUTSTANDING` is counted by
            // the transport itself, with the ids of the requests that are
            // stuck, and the tail of the stream comes with it.
            bail!(
                "this client's send did not complete within {} s{}{}.\n  {}\n{}\n  \
                 A blocked send is backpressure on a socket this harness is not draining — \
                 it is NOT evidence that the node refused anything.",
                wait.as_secs(),
                if what.is_empty() { "" } else { ", " },
                what,
                client.line(),
                client.dump("the send that blocked")
            )
        }
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
    client: &mut crate::probe::Client,
    contract: ContractContainer,
    state: &[u8],
    wait: Duration,
) -> Result<()> {
    let mut stale = 0usize;
    match timed_put(client, contract, state, wait, &mut stale).await? {
        Sample::Ms(_) => Ok(()),
        Sample::Failed(e) => bail!("seed put failed: {e}"),
    }
}

/// Deciding what one arriving response IS, for a series waiting on one key.
///
/// Pulled out of the receive loops so it can be tested without a node. The
/// loops differ only in which response variant they unwrap; the decision they
/// share is this one, and it is the decision that was wrong.
///
/// `Awaiting` is deliberately generic over the key: the bug had nothing to do
/// with contract ids, and a test that needed a live node to reach it would not
/// have been written.
pub(crate) struct Awaiting<K> {
    want: K,
    /// Answers to requests this series had already given up on.
    pub(crate) stale: usize,
}

impl<K: PartialEq> Awaiting<K> {
    pub(crate) fn new(want: K) -> Self {
        Awaiting { want, stale: 0 }
    }

    /// Offer one arrived response. `None` is a response that carries no key at
    /// all — another operation's kind, or a message this series does not read.
    ///
    /// `true` means it is the awaited answer and the caller should stop. Every
    /// other case is counted and the caller keeps waiting: an answer to an
    /// earlier request is that request's business, not this one's, and it must
    /// neither end this wait nor be recorded as this sample's error.
    pub(crate) fn offer(&mut self, arrived: Option<&K>) -> bool {
        match arrived {
            Some(k) if *k == self.want => true,
            _ => {
                self.stale += 1;
                false
            }
        }
    }
}

/// Put one contract and time the acknowledgement.
///
/// The answer is matched BY KEY, and answers to earlier requests are discarded
/// rather than counted against this one. One connection carries every request
/// in a series, so a put that timed out at 90 s and was given up on can still
/// have its acknowledgement arrive while a LATER put is being timed — and the
/// earlier version of this function reported that as "unexpected response" and
/// threw away the later put's sample. On a hotspot, where the first put took
/// 61 s, that lost 5 of 30 samples and every one of them was a slow one, which
/// biases a percentile in the flattering direction.
async fn timed_put(
    client: &mut crate::probe::Client,
    contract: ContractContainer,
    state: &[u8],
    wait: Duration,
    stale: &mut usize,
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
    let deadline = t + wait;
    let mut waiting = Awaiting::new(key);
    loop {
        let Some(left) = deadline.checked_duration_since(Instant::now()) else {
            *stale += waiting.stale;
            return Ok(Sample::Failed(format!(
                "no response within {} s",
                wait.as_secs()
            )));
        };
        let arrived = match timeout(left, client.recv()).await {
            Ok(Ok(HostResponse::ContractResponse(ContractResponse::PutResponse { key: k }))) => {
                Some(k)
            }
            Ok(Ok(_other)) => None,
            Ok(Err(e)) => {
                *stale += waiting.stale;
                return Ok(Sample::Failed(format!("node error: {e}")));
            }
            Err(_) => {
                *stale += waiting.stale;
                return Ok(Sample::Failed(format!(
                    "no response within {} s",
                    wait.as_secs()
                )));
            }
        };
        if waiting.offer(arrived.as_ref()) {
            *stale += waiting.stale;
            return Ok(Sample::Ms(ms_since(t)));
        }
    }
}

/// Get one contract and time the answer. The state is compared, so a get that
/// returns the wrong bytes is an error and not a fast sample.
async fn timed_get(
    client: &mut crate::probe::Client,
    key: &ContractKey,
    want: &[u8],
    return_code: bool,
    wait: Duration,
    stale: &mut usize,
) -> Result<Sample> {
    let t = Instant::now();
    send_req(
        client,
        ClientRequest::ContractOp(ContractRequest::Get {
            key: *key.id(),
            // Does the contract CODE ride a read, or only the state?
            // The client asks; this flag is the whole question.
            return_contract_code: return_code,
            subscribe: false,
            blocking_subscribe: false,
        }),
        wait,
    )
    .await?;
    let deadline = t + wait;
    // Keyed, not "the next GetResponse". Comparing an answer for another key
    // against these bytes reports a state mismatch, which reads as a node fault
    // and is an instrument fault.
    let mut waiting = Awaiting::new(*key.id());
    loop {
        let Some(left) = deadline.checked_duration_since(Instant::now()) else {
            *stale += waiting.stale;
            return Ok(Sample::Failed(format!(
                "no response within {} s",
                wait.as_secs()
            )));
        };
        let (arrived, got) = match timeout(left, client.recv()).await {
            Ok(Ok(HostResponse::ContractResponse(ContractResponse::GetResponse {
                key: k,
                state: got,
                ..
            }))) => (Some(*k.id()), Some(got)),
            Ok(Ok(_other)) => (None, None),
            Ok(Err(e)) => {
                *stale += waiting.stale;
                return Ok(Sample::Failed(format!("node error: {e}")));
            }
            Err(_) => {
                *stale += waiting.stale;
                return Ok(Sample::Failed(format!(
                    "no response within {} s",
                    wait.as_secs()
                )));
            }
        };
        if waiting.offer(arrived.as_ref()) {
            *stale += waiting.stale;
            let got = got.expect("a matched GetResponse carries its state");
            return Ok(if got.as_ref() == want {
                Sample::Ms(ms_since(t))
            } else {
                Sample::Failed(format!(
                    "state mismatch: got {} B, expected {} B",
                    got.as_ref().len(),
                    want.len()
                ))
            });
        }
    }
}

/// Put and warm-get one (kind, size) `n` times.
struct Series {
    kind: &'static str,
    size: usize,
    /// What the node was actually asked to store, which is not the body size:
    /// a Register adds a keyset's signatures, a Set adds a key and a signature
    /// per item. Comparing "PUT 4 KiB" across kinds without this compares four
    /// different numbers of bytes.
    state_bytes: usize,
    /// How many samples were ASKED for. A series that stopped at its budget
    /// reports fewer than this, and the gap is the measurement: "we did not
    /// wait long enough to find out" is a different statement from "30 puts
    /// took this long", and a table that prints only what came back cannot
    /// tell them apart.
    wanted: usize,
    /// Answers to requests this series had already given up on, discarded.
    stale: usize,
    put: Vec<Sample>,
    get: Vec<Sample>,
}

/// What one (kind, size) series measures: the body size, how many samples,
/// and whether each GET asks for the contract code as well as the state.
struct SeriesSpec {
    size: usize,
    n: usize,
    return_code: bool,
    /// When this series must stop, whatever it has. `None` = no budget.
    deadline: Option<Instant>,
}

async fn measure_series(
    client: &mut crate::probe::Client,
    kind: &Kind,
    code: &Arc<ContractCode<'static>>,
    spec: SeriesSpec,
    wait: Duration,
    minted: &mut Minted,
) -> Result<Series> {
    let SeriesSpec {
        size,
        n,
        return_code,
        deadline,
    } = spec;
    let over = || deadline.is_some_and(|d| Instant::now() >= d);
    // Answers to requests this series had already given up on. Counted, not
    // silently dropped: they are the measure of how much the run is running
    // ahead of the node, and a series with many of them is one whose
    // percentiles were taken while the connection was still catching up.
    let mut stale_put = 0usize;
    let mut stale_get = 0usize;
    let mut put = Vec::with_capacity(n);
    let mut held: Vec<(ContractKey, Vec<u8>)> = Vec::with_capacity(n);
    // Every sample of one series must be the same weight, or the percentiles
    // are over a mixture and the table's size column names none of it.
    let mut state_bytes = 0usize;
    for i in 0..n {
        // The budget is checked BEFORE a sample is started, never during: a
        // sample cut off half way is not a fast sample and must not enter the
        // distribution. What the budget costs is samples not taken, and that
        // is what the table reports.
        if over() {
            progress_pub(format_args!(
                "  {} {} budget reached after {} of {n} puts",
                kind.name,
                kib(size),
                i
            ));
            break;
        }
        let (contract, state) = (kind.make)(code, size)?;
        if state_bytes == 0 {
            state_bytes = state.len();
        } else {
            same_weight(kind, size, state_bytes, state.len(), i + 1)?;
        }
        let key = contract.key();
        minted.add(*key.id());
        let s = timed_put(client, contract, &state, wait, &mut stale_put).await?;
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
        if over() {
            break;
        }
        get.push(timed_get(client, key, state, return_code, wait, &mut stale_get).await?);
    }
    progress_pub(format_args!(
        "  {} {} done ({} of {n} put, {} get)",
        kind.name,
        kib(size),
        put.len(),
        get.len()
    ));
    if stale_put + stale_get > 0 {
        progress_pub(format_args!(
            "  {} {} discarded {stale_put} late put answers and {stale_get} late get answers",
            kind.name,
            kib(size)
        ));
    }
    Ok(Series {
        kind: kind.name,
        size,
        state_bytes,
        wanted: n,
        stale: stale_put + stale_get,
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
    /// t_ack - t0, where t0 is immediately before the put request is sent.
    put: Sample,
    /// t_read - t0, same t0. One clock for both, so the per-sample
    /// DIFFERENCE is meaningful rather than a subtraction of two medians
    /// taken from different distributions.
    readable: Sample,
}

impl Readable {
    /// t_read - t_ack for this sample. Negative means the node served the
    /// block BEFORE it acknowledged the put — the case that would let a write
    /// pipeline commit on local acceptance.
    fn delta_ms(&self) -> Option<f64> {
        match (&self.put, &self.readable) {
            (Sample::Ms(ack), Sample::Ms(read)) => Some(read - ack),
            _ => None,
        }
    }
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
/// The poll period is the measurement's RESOLUTION, so it must be small
/// against the quantity being measured. At 250+250 ms every sample landed on
/// the second poll (120 of 120 between 300 and 600 ms, none outside) and the
/// reported figure was the schedule, not the node — fatal where the ack itself
/// is ~500 ms. A warm GET answers in 0.2-1.5 ms, so 40 ms is ample per attempt.
const PROBE_ATTEMPT: Duration = Duration::from_millis(40);
const PROBE_GAP: Duration = Duration::from_millis(10);
/// One poll period: no readable figure can be finer than this.
const PROBE_GRID_MS: f64 = 50.0;
/// Past this, the answer to "readable before the PutResponse?" is already no,
/// and continuing only piles up network searches inside the node.
const PROBE_LIMIT: Duration = Duration::from_secs(30);

async fn poll_readable(
    client: &mut crate::probe::Client,
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
    writer: &'a mut crate::probe::Client,
    reader: &'a mut crate::probe::Client,
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
        let mut stale = 0usize;
        let (put, readable) = tokio::join!(
            timed_put(writer, contract, &state, wait, &mut stale),
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
        let row = Readable { put, readable };
        if let Some(d) = row.delta_ms() {
            progress_pub(format_args!("    delta t_read-t_ack = {d:+.1} ms"));
        }
        out.push(row);
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
    client: &mut crate::probe::Client,
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

pub(crate) fn describe_environment(node_version: &str) {
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
pub(crate) fn node_version() -> String {
    run_tool("freenet", &["--version"])
        .map(|v| v.lines().collect::<Vec<_>>().join(" · "))
        .unwrap_or_else(|| "unknown — `freenet --version` did not run on this machine".into())
}

/// Which of the measurements to run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, clap::ValueEnum)]
pub enum Part {
    All,
    /// Parts 1 and 2 together: the put/get ladder and nothing else.
    ///
    /// `--only put` and `--only get` both RUN the ladder — a get needs a put —
    /// and differ only in which table they print, so asking for both means two
    /// runs over two different populations. The other parts all measure Block
    /// specifically, so a run of another kind that asked for `all` would spend
    /// its budget on parts that print SKIPPED.
    Series,
    Put,
    Get,
    Parallel,
    DelegatePut,
    /// Put and, from a second connection, poll until the block reads back.
    Readable,
}

impl Part {
    fn wants(self, p: Part) -> bool {
        self == Part::All
            || self == p
            || (self == Part::Series && matches!(p, Part::Put | Part::Get))
    }
}

/// The kinds named on the command line, de-duplicated and put back into
/// [`KINDS`] order so the table reads the same however the flag was spelled.
fn select_kinds(names: &[String]) -> Result<Vec<&'static Kind>> {
    let all = || KINDS.iter().map(|k| k.name).collect::<Vec<_>>().join(", ");
    if names.is_empty() {
        bail!("--kinds names nothing to measure; the kinds are {}", all());
    }
    // By INDEX, never by pointer identity. `KINDS` is a `const`, so every use
    // site may get its own copy of the slice and `ptr::eq` between two of them
    // is false — which made this function silently return the kinds in the
    // order they were typed. Caught by the ordering test, not by the compiler.
    let mut idx: Vec<usize> = Vec::new();
    for n in names {
        let i = KINDS
            .iter()
            .position(|k| k.name.eq_ignore_ascii_case(n))
            .ok_or_else(|| anyhow!("no contract kind called {n:?}; the kinds are {}", all()))?;
        if idx.contains(&i) {
            bail!("--kinds names {n:?} twice");
        }
        idx.push(i);
    }
    idx.sort_unstable();
    Ok(idx.into_iter().map(|i| &KINDS[i]).collect())
}

/// Each measured kind's artefact, refused unless it is the one the caller says
/// it is.
///
/// `--expect-sha` is `<kind>=<sha256 prefix>`, and EVERY measured kind needs
/// one. Measuring four contracts is four chances to time a build nobody ships,
/// and a check that may be omitted is one nobody can tell was skipped: a run
/// with no check and a run whose check passed print the same thing.
///
/// The three other wasms are taken from the directory `--wasm` names rather
/// than from three more flags. One `freenet-contracts/build.sh` writes all
/// four, so separate paths could only ever disagree with it — and a run that
/// took Block from today's build and Set from a directory left over from last
/// week would print one table.
fn load_codes(
    selected: &[&'static Kind],
    block_wasm: &str,
    expect: &[String],
) -> Result<HashMap<&'static str, Arc<ContractCode<'static>>>> {
    let dir = std::path::Path::new(block_wasm)
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."));
    let mut want: HashMap<String, String> = HashMap::new();
    for e in expect {
        let (k, v) = e
            .split_once('=')
            .ok_or_else(|| anyhow!("--expect-sha {e:?} is not <kind>=<sha256 prefix>"))?;
        if want.insert(k.to_ascii_lowercase(), v.to_string()).is_some() {
            bail!("--expect-sha names {k:?} twice");
        }
    }
    // Every kind is matched to its hash BEFORE anything is read. Interleaved,
    // a missing entry for the third kind is reported only after the first two
    // artefacts have loaded — and if one of those paths is wrong, the error
    // names a file and the operator never learns the flag was incomplete.
    let mut plan = Vec::new();
    for k in selected {
        let sha = want.get(&k.name.to_ascii_lowercase()).ok_or_else(|| {
            anyhow!(
                "--expect-sha has no entry for {}. Pass {}=<sha256 prefix>, the hash \
                 freenet-contracts/build.sh printed for build/{}.",
                k.name,
                k.name,
                k.wasm
            )
        })?;
        plan.push((*k, sha.clone()));
    }
    let mut out = HashMap::new();
    for (k, sha) in plan {
        let path = dir.join(k.wasm);
        let bytes = crate::wasm_check::load(&path.to_string_lossy(), &sha)?;
        out.insert(k.name, Arc::new(ContractCode::from(bytes)));
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
pub async fn run(
    ws: &str,
    wasm: &str,
    delegate_wasm: &str,
    kinds: &[String],
    expect_sha: &[String],
    samples: usize,
    sizes: &[usize],
    parallel: &[usize],
    parallel_size: usize,
    max_k: usize,
    only: Part,
    return_code: bool,
    budget_secs: u64,
    wait: Duration,
) -> Result<()> {
    if samples == 0 {
        bail!("--samples 0 measures nothing");
    }
    let selected = select_kinds(kinds)?;
    let codes = load_codes(&selected, wasm, expect_sha)?;
    // Parts 3 to 6 are about Block specifically. If Block is not being
    // measured its artefact was never loaded, and those parts say so rather
    // than loading one nobody checked.
    let block_code = codes.get(KINDS[0].name).cloned();
    let version = node_version();
    describe_environment(&version);

    // One deadline for the whole run, not one per part. A budget that resets
    // between parts is not a budget: four parts of "at most ten minutes" is
    // forty, and the reason to have one at all is that nobody is sitting here
    // watching. 0 turns it off.
    let budget = (budget_secs > 0).then(|| Instant::now() + Duration::from_secs(budget_secs));
    match budget {
        Some(_) => println!("budget:   {budget_secs} s for the whole run; what is not measured by then is reported as not measured"),
        None => println!("budget:   none (--budget-secs 0)"),
    }
    let spent = || match budget {
        Some(d) => Instant::now() >= d,
        None => false,
    };

    let mut client = crate::connect(ws).await?;
    let mut minted = Minted::default();

    // 1 & 2. Put, then warm get, every measured kind at every size it can hold.
    let mut series = Vec::new();
    // Sizes a kind's own format refuses. Reported under the table, never
    // silently dropped: a row missing from a ladder reads as a measurement
    // that failed, and this one was never possible.
    let mut skipped: Vec<String> = Vec::new();
    if only.wants(Part::Put) || only.wants(Part::Get) {
        for kind in &selected {
            for &size in sizes {
                if let Some(note) = skip_note(kind, size) {
                    skipped.push(note);
                    continue;
                }
                let s = measure_series(
                    &mut client,
                    kind,
                    &codes[kind.name],
                    SeriesSpec {
                        size,
                        n: samples,
                        return_code,
                        deadline: budget,
                    },
                    wait,
                    &mut minted,
                )
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
    if only.wants(Part::Readable) && spent() {
        println!("part readable: SKIPPED — the run reached its budget before it started");
    } else if only.wants(Part::Readable) && block_code.is_none() {
        println!(
            "part readable: SKIPPED — it measures {} and --kinds did not name it",
            KINDS[0].name
        );
    } else if only.wants(Part::Readable) {
        let code = block_code.clone().expect("checked just above");
        let mut reader = crate::connect(ws).await?;
        for kind in &KINDS[..1] {
            for &size in sizes {
                if size > kind.cap {
                    continue;
                }
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
    if only.wants(Part::Parallel) && spent() {
        println!("part parallel: SKIPPED — the run reached its budget before it started");
    } else if only.wants(Part::Parallel) && block_code.is_none() {
        println!(
            "part parallel: SKIPPED — it measures {} and --kinds did not name it",
            KINDS[0].name
        );
    } else if only.wants(Part::Parallel) {
        let code = block_code.clone().expect("checked just above");
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
    if only.wants(Part::DelegatePut) && spent() {
        println!("part delegate-put: SKIPPED — the run reached its budget before it started");
    } else if only.wants(Part::DelegatePut) {
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
        println!("2. GET latency (ms) — warm: a contract this node just put");
        print_series(&series, |s| &s.get);
    }
    for line in &skipped {
        println!("{line}");
    }
    if !skipped.is_empty() {
        println!();
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
        [
            "kind", "body", "state", "asked", "n", "errors", ">=240s", ">10xp50",
        ]
        .into_iter()
        .chain(Summary::HEADINGS),
    );
    let mut notes = Vec::new();
    for s in series {
        let samples = pick(s);
        let lat = latencies(samples);
        let errs = failures(samples);
        if s.stale > 0 {
            notes.push(format!(
                "{} {}: {} late answer(s) to requests already given up on were discarded, \
                 not charged to a later sample",
                s.kind,
                kib(s.size),
                s.stale
            ));
        }
        if samples.len() < s.wanted {
            notes.push(format!(
                "{} {}: {} of {} samples taken — the run reached its budget, \
                 the rest are NOT within it",
                s.kind,
                kib(s.size),
                samples.len(),
                s.wanted
            ));
        }
        let head = vec![
            s.kind.to_string(),
            kib(s.size),
            kib(s.state_bytes),
            s.wanted.to_string(),
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

/// Put latency, readable-here latency, and above all the PER-SAMPLE
/// difference between them.
///
/// Two independent medians cannot answer "is the block readable before the
/// ack?" — that is a question about each sample, and a distribution of
/// differences is not recoverable from a difference of distributions. The
/// column that decides the design question is `read<ack`.
fn print_readable(rows: &[(&'static str, usize, Vec<Readable>)]) {
    let mut t = Table::new([
        "kind", "size", "n", "ack p50", "read p50", "d p50", "d p90", "d p99", "read<ack", "never",
    ]);
    for (kind, size, rs) in rows {
        let acks: Vec<Sample> = rs.iter().map(|r| r.put.clone()).collect();
        let reads: Vec<Sample> = rs.iter().map(|r| r.readable.clone()).collect();
        let deltas: Vec<f64> = rs.iter().filter_map(|r| r.delta_ms()).collect();
        let earlier = deltas.iter().filter(|d| **d < 0.0).count();
        let d = Summary::of(&deltas);
        let cell = |s: &Option<Summary>, f: fn(&Summary) -> f64| match s {
            Some(v) => format!("{:+.1}", f(v)),
            None => "-".to_string(),
        };
        let p50 = |v: &[Sample]| match Summary::of(&latencies(v)) {
            Some(s) => format!("{:.1}", s.p50),
            None => "-".to_string(),
        };
        t.row([
            kind.to_string(),
            kib(*size),
            deltas.len().to_string(),
            p50(&acks),
            p50(&reads),
            cell(&d, |s| s.p50),
            cell(&d, |s| s.p90),
            cell(&d, |s| s.p99),
            earlier.to_string(),
            failures(&reads).len().to_string(),
        ]);
    }
    print!("{t}");
    println!("   d = t_read - t_ack per sample, one clock, both from t0 (put request sent).");
    println!("   read<ack counts samples the node served BEFORE acknowledging the put.");
    println!(
        "   probe resolution {PROBE_GRID_MS:.0} ms: t_read is quantised to it. A read p50 \
sitting on a multiple of {PROBE_GRID_MS:.0} ms is instrument-limited, not measured, \
and d is only meaningful while t_ack is large against it."
    );
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

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(ack: f64, read: f64) -> Readable {
        Readable {
            put: Sample::Ms(ack),
            readable: Sample::Ms(read),
        }
    }

    /// The sign convention is the whole point: negative means the node served
    /// the block before it acknowledged the put.
    #[test]
    fn delta_is_read_minus_ack() {
        assert_eq!(pair(1000.0, 1500.0).delta_ms(), Some(500.0));
        assert_eq!(pair(1500.0, 1000.0).delta_ms(), Some(-500.0));
    }

    /// A sample missing either half has no difference — it must not be
    /// silently counted as zero, which would drag the median toward "same
    /// time" and hide the answer.
    #[test]
    fn a_half_measured_sample_has_no_delta() {
        let only_ack = Readable {
            put: Sample::Ms(10.0),
            readable: Sample::Failed("never readable".into()),
        };
        let only_read = Readable {
            put: Sample::Failed("put failed".into()),
            readable: Sample::Ms(10.0),
        };
        assert_eq!(only_ack.delta_ms(), None);
        assert_eq!(only_read.delta_ms(), None);
    }

    /// Medians of the two series can agree while every sample disagrees —
    /// which is exactly why the per-sample difference is reported.
    #[test]
    fn paired_difference_is_not_recoverable_from_two_medians() {
        let rows = [pair(100.0, 900.0), pair(900.0, 100.0)];
        let acks: Vec<f64> = rows
            .iter()
            .filter_map(|r| match r.put {
                Sample::Ms(v) => Some(v),
                _ => None,
            })
            .collect();
        let reads: Vec<f64> = rows
            .iter()
            .filter_map(|r| match r.readable {
                Sample::Ms(v) => Some(v),
                _ => None,
            })
            .collect();
        // Identical medians...
        assert_eq!(
            Summary::of(&acks).unwrap().p50,
            Summary::of(&reads).unwrap().p50
        );
        // ...yet no sample had t_read == t_ack, and one was served early.
        let deltas: Vec<f64> = rows.iter().filter_map(|r| r.delta_ms()).collect();
        assert_eq!(deltas, [800.0, -800.0]);
        assert_eq!(deltas.iter().filter(|d| **d < 0.0).count(), 1);
    }

    /// What actually happens on one connection carrying a whole series.
    ///
    /// Put 1 times out at its deadline and the series gives up on it. Put 2 is
    /// issued, and WHILE it is being timed, put 1's acknowledgement finally
    /// arrives. The question the instrument has to answer is what that is —
    /// and answering it wrong cost 5 of 30 hotspot samples, every one of them a
    /// slow sample, which biases a percentile in the flattering direction.
    fn script() -> Vec<Option<u8>> {
        vec![
            Some(1),  // put 1's ack, arriving after put 1 was abandoned
            None,     // something that is not a PutResponse at all
            Some(99), // an answer for a key this series has never heard of
            Some(2),  // and finally put 2's own answer
        ]
    }

    #[test]
    fn a_late_answer_for_an_earlier_key_is_discarded_and_counted_and_the_later_put_keeps_its_sample(
    ) {
        let mut w = Awaiting::new(2u8);
        let mut matched = None;
        for (i, ev) in script().iter().enumerate() {
            if w.offer(ev.as_ref()) {
                matched = Some(i);
                break;
            }
        }
        assert_eq!(matched, Some(3), "put 2 must still get its own sample");
        assert_eq!(w.stale, 3, "the three that were not put 2's are counted");
    }

    /// An answer for a key nobody is waiting for is a fact about the
    /// connection, not a failure of this sample. It is counted so a run can
    /// say how far ahead of the node it is running.
    #[test]
    fn an_unknown_key_is_counted_and_is_not_fatal() {
        let mut w = Awaiting::new(2u8);
        assert!(!w.offer(Some(&99)));
        assert!(!w.offer(None));
        assert_eq!(w.stale, 2);
        assert!(
            w.offer(Some(&2)),
            "and the wait continues to its own answer"
        );
    }

    /// THE CONTROL. The logic this replaced — the next response wins, anything
    /// else is an error — run against the same script. It must get it wrong, or
    /// the tests above are not evidence that anything was fixed.
    #[test]
    fn the_old_next_response_wins_logic_fails_this_script() {
        #[derive(Debug, PartialEq)]
        enum Old {
            Sample,
            Failed,
        }
        fn next_response_wins(want: u8, events: &[Option<u8>]) -> Old {
            match events.first() {
                Some(Some(k)) if *k == want => Old::Sample,
                _ => Old::Failed, // "unexpected response"
            }
        }
        assert_eq!(
            next_response_wins(2, &script()),
            Old::Failed,
            "the old logic loses put 2's sample to put 1's late ack"
        );
        // And the new one does not.
        let mut w = Awaiting::new(2u8);
        assert!(script().iter().any(|e| w.offer(e.as_ref())));
    }

    /// The count is what makes the loss visible in a table. A matcher that
    /// silently skipped would behave correctly and report nothing.
    #[test]
    fn nothing_is_discarded_silently() {
        let mut w = Awaiting::new(7u8);
        assert_eq!(w.stale, 0);
        assert!(w.offer(Some(&7)));
        assert_eq!(w.stale, 0, "a clean match discards nothing");
    }

    // ---- the kind table ---------------------------------------------------

    /// Any bytes: the validators below read the STATE and the PARAMS and never
    /// the code, and using a real artefact would make a unit test wait on a
    /// contract build.
    fn some_code() -> Arc<ContractCode<'static>> {
        Arc::new(ContractCode::from(vec![0u8; 8]))
    }

    /// The check `validate_state` itself performs, per kind.
    ///
    /// A fixture that builds a state its contract refuses produces a run of
    /// node errors that reads as a node fault. It has happened twice here: a
    /// 1 MiB RAW body Block refuses, and a pack 86 bytes over `MAX_PACK`.
    fn accepted(kind: &Kind, c: &ContractContainer, state: &[u8]) -> bool {
        let params = c.params();
        let p = params.as_ref();
        match kind.name {
            "Block" => block::check(p, state),
            "Register" => register_contract::read(p, state).is_some(),
            "Set" => set_contract::read(p, state).is_some(),
            "Bag" => bag_contract::read(p, state).is_some(),
            other => panic!(
                "no validator wired for {other}: a kind added to KINDS without one \
                 is measured but never checked"
            ),
        }
    }

    #[test]
    fn every_kind_builds_a_state_its_own_contract_accepts() {
        let code = some_code();
        for kind in KINDS {
            for size in [1usize, 1024, kind.cap] {
                let (c, state) = (kind.make)(&code, size)
                    .unwrap_or_else(|e| panic!("{} at {size} B: {e}", kind.name));
                assert!(
                    accepted(kind, &c, &state),
                    "{} at {size} B built a {} B state its own contract refuses",
                    kind.name,
                    state.len()
                );
            }
        }
    }

    /// The ceiling in [`KINDS`] has to be the CONTRACT's, not a number someone
    /// typed. One byte over it must be refused by the same validator —
    /// otherwise a cap set too low only shortens the table, and the test above
    /// passes while the real limit is somewhere else entirely.
    #[test]
    fn one_byte_over_a_kinds_cap_is_not_a_state_that_contract_accepts() {
        let code = some_code();
        for kind in KINDS {
            match (kind.make)(&code, kind.cap + 1) {
                // The fixture refused to build it: the cap bit here.
                Err(_) => {}
                Ok((c, state)) => assert!(
                    !accepted(kind, &c, &state),
                    "{}: cap {} is not this contract's limit — {} B was accepted",
                    kind.name,
                    kind.cap,
                    kind.cap + 1
                ),
            }
        }
    }

    /// Two samples of one series must address two DIFFERENT contracts. A
    /// repeated key makes the second put a MERGE into the first's state, which
    /// is a different and much cheaper operation — measured on the Register
    /// round-trip, where a 256-wide key space put 5 runs in 30 on top of each
    /// other.
    #[test]
    fn many_instances_of_a_kind_never_share_a_key() {
        // Forty, not two. Every kind here seeds from ONE byte somewhere —
        // `keyset_seeded`, `world_with` — and a 256-wide key space passes a
        // two-draw test 255 times in 256 while colliding at about nineteen
        // draws. On the Register round-trip that space put 5 runs in 30 on top
        // of each other, and the run read the previous run's final state.
        const DRAWS: usize = 40;
        let code = some_code();
        for kind in KINDS {
            let keys: HashSet<_> = (0..DRAWS)
                .map(|_| (kind.make)(&code, 64).unwrap().0.key())
                .collect();
            assert_eq!(
                keys.len(),
                DRAWS,
                "{}: {} of {DRAWS} fresh instances shared a contract key — a repeated \
                 key makes the second put a MERGE, which is a different operation",
                kind.name,
                DRAWS - keys.len()
            );
        }
    }

    /// One series, one weight. If a `size` encodes to two different lengths,
    /// the percentiles are over a mixture and the table's `state` column names
    /// neither of them.
    #[test]
    fn a_kinds_state_size_is_a_function_of_the_body_size() {
        let code = some_code();
        for kind in KINDS {
            for size in [1usize, 1000, kind.cap] {
                let (_, a) = (kind.make)(&code, size).unwrap();
                let (_, b) = (kind.make)(&code, size).unwrap();
                assert_eq!(
                    a.len(),
                    b.len(),
                    "{} at {size} B encodes to two different lengths",
                    kind.name
                );
            }
        }
    }

    /// A body bigger than the one asked for would make every row in the table
    /// understate what was sent.
    #[test]
    fn a_kinds_state_is_at_least_the_body_it_was_asked_to_carry() {
        let code = some_code();
        for kind in KINDS {
            let (_, state) = (kind.make)(&code, 4096.min(kind.cap)).unwrap();
            assert!(
                state.len() >= 4096.min(kind.cap),
                "{}: a {} B body encoded to {} B of state",
                kind.name,
                4096.min(kind.cap),
                state.len()
            );
        }
    }

    // ---- choosing kinds and checking their artefacts ----------------------

    #[test]
    fn an_unknown_kind_is_refused_and_names_the_ones_that_exist() {
        let e = select_kinds(&["Blorb".into()]).unwrap_err().to_string();
        assert!(e.contains("Blorb") && e.contains("Block"), "{e}");
    }

    #[test]
    fn a_kind_named_twice_is_refused() {
        let e = select_kinds(&["Block".into(), "block".into()])
            .unwrap_err()
            .to_string();
        assert!(e.contains("twice"), "{e}");
    }

    #[test]
    fn naming_no_kind_at_all_is_refused() {
        let e = select_kinds(&[]).unwrap_err().to_string();
        assert!(e.contains("nothing to measure"), "{e}");
    }

    /// The control for the three refusals above: they must fail for their own
    /// reason and not because `select_kinds` refuses everything.
    #[test]
    fn kinds_are_case_insensitive_and_come_back_in_table_order() {
        let got = select_kinds(&["bag".into(), "BLOCK".into()]).unwrap();
        assert_eq!(
            got.iter().map(|k| k.name).collect::<Vec<_>>(),
            ["Block", "Bag"]
        );
    }

    /// A directory holding a file per kind, and the hashes a build would have
    /// printed for them.
    fn artefacts(tag: &str) -> (std::path::PathBuf, Vec<String>) {
        let dir = std::env::temp_dir().join(format!("latency-kinds-{tag}"));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut expect = Vec::new();
        for k in KINDS {
            let bytes = format!("not a wasm, but the hash is real: {}", k.name).into_bytes();
            std::fs::write(dir.join(k.wasm), &bytes).unwrap();
            expect.push(format!(
                "{}={}",
                k.name,
                &crate::wasm_check::sha256_hex(&bytes)[..16]
            ));
        }
        (dir, expect)
    }

    /// The refusal has to name the KIND, and it has to happen before any file
    /// is opened.
    ///
    /// The artefacts deliberately do not exist here. Matched kind by kind as
    /// they load, the first thing to fail is Block's missing file and the
    /// operator is told a path is wrong when the real fault is an incomplete
    /// flag — so this test is about the ORDER, and it passes vacuously if the
    /// directory is one where the files are present.
    #[test]
    fn a_missing_expect_sha_is_refused_by_kind_before_any_artefact_is_opened() {
        let nowhere = std::env::temp_dir().join("latency-kinds-nowhere/block.wasm");
        let _ = std::fs::remove_dir_all(nowhere.parent().unwrap());
        let sel = select_kinds(&["Block".into(), "Set".into()]).unwrap();
        let e = load_codes(&sel, nowhere.to_str().unwrap(), &["Block=deadbeef".into()])
            .unwrap_err()
            .to_string();
        assert!(e.contains("Set"), "{e}");
        assert!(
            !e.contains("No such file"),
            "a file was opened before the flag was checked: {e}"
        );

        // Control: with the Set entry supplied, the same call DOES get as far
        // as opening a file — so the assertion above is about the missing
        // entry and not about `load_codes` refusing everything.
        let e = load_codes(
            &sel,
            nowhere.to_str().unwrap(),
            &["Block=deadbeef".into(), "Set=deadbeef".into()],
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("No such file"), "{e}");
    }

    #[test]
    fn an_expect_sha_that_is_not_kind_equals_hash_is_refused() {
        let (dir, _) = artefacts("malformed");
        let sel = select_kinds(&["Block".into()]).unwrap();
        let e = load_codes(
            &sel,
            dir.join("block.wasm").to_str().unwrap(),
            &["deadbeef01".into()],
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("<kind>=<sha256 prefix>"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Every kind's artefact is taken from the directory the Block wasm sits
    /// in, and each is checked against ITS OWN hash — swapping two of them has
    /// to be refused, or the "check" only proves the files exist.
    #[test]
    fn each_kinds_artefact_is_checked_against_its_own_hash() {
        let (dir, expect) = artefacts("swapped");
        let sel = select_kinds(&["Block".into(), "Set".into()]).unwrap();
        let path = dir.join("block.wasm");
        let path = path.to_str().unwrap();

        // Control: the right hashes load, so the refusal below is about the
        // swap and not about this fixture.
        load_codes(&sel, path, &expect).expect("the matching hashes must load");

        let swapped: Vec<String> = expect
            .iter()
            .map(|e| {
                let (k, h) = e.split_once('=').unwrap();
                match k {
                    "Block" => format!("Block={}", expect_hash_of(&expect, "Set")),
                    "Set" => format!("Set={}", expect_hash_of(&expect, "Block")),
                    _ => format!("{k}={h}"),
                }
            })
            .collect();
        let e = load_codes(&sel, path, &swapped).unwrap_err().to_string();
        assert!(e.contains("wasm mismatch"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn expect_hash_of(expect: &[String], kind: &str) -> String {
        expect
            .iter()
            .find_map(|e| e.strip_prefix(&format!("{kind}=")))
            .expect("every kind has an entry")
            .to_string()
    }

    /// A size the contract cannot hold is skipped, and the note says WHY —
    /// a row missing from a ladder with no reason reads as a measurement that
    /// failed.
    #[test]
    fn a_size_over_a_kinds_cap_is_skipped_with_its_reason() {
        for kind in KINDS {
            let note = skip_note(kind, kind.cap + 1).expect("one byte over must be skipped");
            assert!(
                note.contains(kind.name) && note.contains(kind.cap_why),
                "{note}"
            );
            // The control: at the cap, and below it, the kind IS measured.
            // Without this the function could skip everything and still pass.
            assert!(
                skip_note(kind, kind.cap).is_none(),
                "{} skipped its own cap",
                kind.name
            );
            assert!(skip_note(kind, 1).is_none(), "{} skipped 1 byte", kind.name);
        }
    }

    /// The mixture guard has to bite on a difference of ONE byte, and has to
    /// stay silent when there is none.
    #[test]
    fn a_series_whose_samples_change_weight_is_refused() {
        let k = &KINDS[0];
        same_weight(k, 4096, 4160, 4160, 2).expect("equal weights are a measurement");
        let e = same_weight(k, 4096, 4160, 4161, 7).unwrap_err().to_string();
        assert!(e.contains("sample 7") && e.contains("mixture"), "{e}");
    }
    /// `--only series` is parts 1 and 2 and NOTHING else. If it ever started
    /// wanting a part that needs the Block artefact, a run measuring Register
    /// alone would try to load a wasm nobody named.
    #[test]
    fn only_series_is_the_ladder_and_nothing_that_needs_block() {
        assert!(Part::Series.wants(Part::Put));
        assert!(Part::Series.wants(Part::Get));
        for p in [Part::Readable, Part::Parallel, Part::DelegatePut, Part::All] {
            assert!(!Part::Series.wants(p), "--only series wanted {p:?}");
        }
        // The control: `all` still wants everything, so the clause above did
        // not simply stop `wants` answering yes.
        for p in [Part::Put, Part::Get, Part::Readable, Part::Parallel] {
            assert!(Part::All.wants(p));
        }
    }

    /// The message a blocked send produces must describe the INSTRUMENT.
    ///
    /// The old one said "the node stopped accepting requests" and a 200-key
    /// run's only output was that sentence, about a node that was serving
    /// perfectly well. A message naming the wrong component sends the next
    /// person to the wrong machine.
    #[test]
    fn a_blocked_send_does_not_blame_the_node() {
        // The text is built by the same format the bail! uses, so this test
        // reads what a caller would actually see.
        let wait = Duration::from_secs(30);
        let what = "probe 7 of 32 this round, 200 key(s) still cold";
        let msg = format!(
            "this client's send did not complete within {} s{}{}. A blocked send is \
             backpressure on a socket this harness is not draining — it is NOT evidence \
             that the node refused anything. Show the harness was still collecting before \
             writing that it was.",
            wait.as_secs(),
            if what.is_empty() { "" } else { ", " },
            what
        );
        assert!(
            !msg.contains("the node stopped accepting"),
            "the message blames the node: {msg}"
        );
        assert!(msg.contains("this harness is not draining"), "{msg}");
        assert!(
            msg.contains("200 key(s) still cold"),
            "the caller's own state must reach the message: {msg}"
        );
    }
}
