//! The client connection, instrumented.
//!
//! Four runs were voided on 2026-09-20 for want of ONE number. A reader had
//! sent thousands of requests for keys no node held — requests nothing would
//! ever answer — and from outside it was indistinguishable from a reader doing
//! its job: no output, no error, a process that looked busy. What separates
//! them is OUTSTANDING, and it is a subtraction only because every request and
//! its response are one event type paired by id.
//!
//! So this wraps the connection rather than the call sites. Every send is an
//! `Edge` out, every response an `Edge` in, and the failure paths dump the
//! tail of the stream with the outstanding set at the top.
//!
//! **There is no ergonomic way to get an unprobed connection.** `connect`
//! returns a [`Client`]; the bare constructor is
//! `new_unprobed_for_benchmark`, named so it cannot pass review unnoticed.
//! That is the architect's first tier of enforcement — remove the bare path —
//! and it is stronger than any rule about remembering to use the fixture.

use std::sync::Arc;

use anyhow::Result;
use freenet_stdlib::client_api::{ClientRequest, HostResponse, WebApi};
use instrument::{
    dump::render,
    label::{Kind, Labels},
    vocab::{Dir, Key, Outcome, Site},
    Entry, Event, Label, OpId, Probe, Record, SyncRecorder,
};

pub const SEND: Site = Site::of("harness::client::send");
pub const RECV: Site = Site::of("harness::client::recv");

/// How many events one connection keeps. Generous: the harness is a test tool,
/// and a run that loses the start of its own story cannot explain a wedge.
const RING: usize = 1 << 16;

/// The accounting, separated from the socket.
///
/// Not tidiness: a `WebApi` needs a real connection, so anything that only
/// exists inside [`Client`] can be tested only against a live node — and the
/// failure this is built to catch is exactly the one a live node makes hard to
/// reproduce. The ledger is the part worth testing, so it is the part that can
/// be held on its own.
pub struct Ledger {
    rec: Arc<SyncRecorder>,
    /// The most recent request, so a caller can refine its outcome without
    /// every `send` in the harness changing shape to return a handle.
    last: std::sync::Mutex<Option<Label>>,
    /// The open requests, kept INCREMENTALLY.
    ///
    /// The recording can answer this by replaying its edges, and that is right
    /// for a dump — but it is O(ring) per call, and calling it once per
    /// response made the transport cost 978 MICROSECONDS a round trip, which
    /// would have moved every median in the latency tables. The cost test
    /// caught it. A push and a pop cost nothing and say the same thing.
    open: std::sync::Mutex<Vec<Label>>,
    /// Requests are labelled per connection — `req#3` — never by anything
    /// derived from the data. `Sync` because the harness is multi-threaded.
    labels: std::sync::Mutex<Labels<String>>,
    /// Which request this connection is on, so a send and its answer can be
    /// paired without the node echoing anything back.
    seq: std::sync::atomic::AtomicU64,
    /// Answers this connection gave up waiting for and is still OWED.
    ///
    /// A bounded wait expiring does not cancel anything. The node still owes
    /// that answer, it arrives later, and the client API carries no
    /// correlation id — so from the first timeout onwards, pairing an answer
    /// to a request BY POSITION is shifted by one. It does not go down:
    /// nothing can prove which later answer settled an owed one.
    owed: std::sync::atomic::AtomicU64,
}

impl Default for Ledger {
    fn default() -> Self {
        Ledger::new()
    }
}

impl Ledger {
    pub fn new() -> Ledger {
        Ledger {
            rec: Arc::new(SyncRecorder::with_capacity(RING)),
            open: std::sync::Mutex::new(Vec::new()),
            last: std::sync::Mutex::new(None),
            labels: std::sync::Mutex::new(Labels::new()),
            seq: std::sync::atomic::AtomicU64::new(0),
            owed: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Record a request going out: an edge AND the start of an operation.
    ///
    /// The two are different facts. An edge says "asked, not yet answered";
    /// a span says "an operation ran, and this is how it ended". A dump with
    /// only edges cannot tell twelve operations still running from twelve the
    /// caller abandoned from twelve whose answers arrived and were discarded
    /// as stale — and the third is what voided a run.
    pub fn request(&self, what: &'static str) -> Label {
        let n = self.seq.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let key = format!("{what}/{n}");
        let id = match self.labels.lock() {
            Ok(mut l) => l.label(Kind::Request, &key),
            // A probe must never panic, and a poisoned lock must not be the
            // thing that ends a run.
            Err(p) => p.into_inner().label(Kind::Request, &key),
        };
        self.rec.event(Event::Edge {
            site: SEND,
            dir: Dir::Request,
            id,
        });
        self.rec.event(Event::Counter {
            site: SEND,
            op: OpId::NONE,
            entry: Entry {
                key: Key::Sent,
                value: 1,
            },
        });
        self.rec.event(Event::Enter {
            site: SEND,
            op: OpId(id.ordinal),
        });
        if let Ok(mut l) = self.last.lock() {
            *l = Some(id);
        }
        match self.open.lock() {
            Ok(mut o) => o.push(id),
            Err(p) => p.into_inner().push(id),
        }
        id
    }

    /// Record a request for a key the CALLER can name, labelled by that key.
    ///
    /// The ordinary [`request`](Ledger::request) labels by a per-connection
    /// sequence, which is all a transport can know. But when the answer will
    /// name itself — a `PutResponse` carries the contract key — labelling the
    /// request by that key is what lets the recording say WHICH operation an
    /// answer ended, instead of pairing by position.
    ///
    /// The key itself never enters an event: it goes into `Labels` and only
    /// the ordinal comes out (`contract#3`).
    pub fn request_keyed(&self, what: &'static str, key: &str) -> Label {
        let id = match self.labels.lock() {
            Ok(mut l) => l.label(Kind::Contract, &key.to_string()),
            Err(p) => p.into_inner().label(Kind::Contract, &key.to_string()),
        };
        self.rec.event(Event::Edge {
            site: SEND,
            dir: Dir::Request,
            id,
        });
        self.rec.event(Event::Counter {
            site: SEND,
            op: id.op(),
            entry: Entry {
                key: Key::Sent,
                value: 1,
            },
        });
        self.rec.event(Event::Enter {
            site: SEND,
            op: id.op(),
        });
        let _ = what;
        if let Ok(mut l) = self.last.lock() {
            *l = Some(id);
        }
        match self.open.lock() {
            Ok(mut o) => o.push(id),
            Err(p) => p.into_inner().push(id),
        }
        id
    }

    /// Bytes this operation handed to the client API.
    pub fn offered(&self, id: Label, n: u64) {
        if n > 0 {
            self.rec.event(Event::Counter {
                site: SEND,
                op: id.op(),
                entry: Entry {
                    key: Key::BytesOut,
                    value: n,
                },
            });
        }
    }

    /// Bytes an answer carried back for this operation.
    ///
    /// Named `received_bytes`, not `received`: this ledger already has a
    /// `received()` that counts ANSWERS. Two methods a letter apart, one
    /// counting messages and one counting bytes, is a footgun in a file whose
    /// whole subject is numbers that must not be confused for each other.
    pub fn received_bytes(&self, id: Label, n: u64) {
        if n > 0 {
            self.rec.event(Event::Counter {
                site: RECV,
                op: id.op(),
                entry: Entry {
                    key: Key::BytesIn,
                    value: n,
                },
            });
        }
    }

    /// Record an answer that NAMED itself.
    ///
    /// This is the whole point of the keyed path: the answer closes the
    /// operation that asked for THIS key, whatever else is outstanding and
    /// however long ago it was given up on. No position, no count.
    pub fn answered(&self, key: &str) -> Label {
        let id = match self.labels.lock() {
            Ok(mut l) => l.label(Kind::Contract, &key.to_string()),
            Err(p) => p.into_inner().label(Kind::Contract, &key.to_string()),
        };
        self.rec.event(Event::Edge {
            site: RECV,
            dir: Dir::Response,
            id,
        });
        self.rec.event(Event::Counter {
            site: RECV,
            op: id.op(),
            entry: Entry {
                key: Key::Received,
                value: 1,
            },
        });
        if let Ok(mut o) = self.open.lock() {
            if let Some(i) = o.iter().position(|l| *l == id) {
                o.remove(i);
            }
        }
        id
    }

    /// What happened to every keyed operation — the projection that replaces
    /// a tool's own per-key map.
    ///
    /// A tool that keeps its own map keeps a SECOND account of the same facts,
    /// and the two disagree: one printed 99.5 % acked over a run whose records
    /// said 92.1 %. Both come from here now, so they cannot.
    pub fn answers(&self) -> Vec<(Label, instrument::Answered)> {
        self.rec.recording().answers()
    }

    /// The same data a per-key table reads, counted.
    pub fn answer_counts(&self) -> Vec<(instrument::Answered, usize)> {
        self.rec.recording().answer_counts()
    }

    /// Resolve a label back to the key it stands for — for the TOOL's own
    /// files, never for an event.
    pub fn key_of(&self, id: Label) -> Option<String> {
        match self.labels.lock() {
            Ok(l) => l.resolve(id).cloned(),
            Err(p) => p.into_inner().resolve(id).cloned(),
        }
    }

    /// Close an operation with the outcome the CALLER knows.
    ///
    /// The transport can see that an answer arrived; it cannot see that the
    /// answer carried no state (`Missing`), that the caller's bounded wait
    /// expired (`Timeout`), or that the bytes were not the ones asked for
    /// (`Refused`). Those live at the call site, so the transport carries the
    /// span and the call site refines it — rather than every subcommand
    /// growing its own bookkeeping beside this one.
    pub fn finish(&self, id: Label, outcome: Outcome) {
        self.rec.event(Event::Exit {
            site: SEND,
            op: OpId(id.ordinal),
            outcome,
        });
        // Ending an operation the caller never got an answer for does not end
        // the NODE's obligation. `Timeout` and `Blocked` are the two outcomes
        // where nothing came back, so from here on an answer may belong to an
        // operation this ledger has already closed, and pairing the next
        // answer to the oldest open request would hand it to the wrong one.
        // That is harness#38: fifteen accepted puts reported as failures
        // because every answer after the third was the previous put's.
        if matches!(outcome, Outcome::Timeout | Outcome::Blocked) {
            self.owed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            self.rec.event(Event::Counter {
                site: SEND,
                op: OpId::NONE,
                entry: Entry {
                    key: Key::Owed,
                    value: 1,
                },
            });
        }
        // An operation that ended is no longer outstanding, however it ended.
        // A timeout that left its edge open would be counted twice: once as a
        // failure and again as a request nobody answered.
        if let Ok(mut o) = self.open.lock() {
            if let Some(i) = o.iter().position(|l| *l == id) {
                o.remove(i);
            }
        }
    }

    /// How many operations ended each way.
    pub fn outcomes(&self) -> Vec<(Outcome, usize)> {
        self.rec.recording().outcomes()
    }

    /// Operations begun and never ended.
    pub fn unfinished(&self) -> usize {
        self.rec.recording().unfinished().len()
    }

    /// Record an answer arriving.
    ///
    /// The edge is closed by POSITION, not by matching the node's answer to a
    /// request: the client API carries no correlation id, so "one response
    /// closes the oldest open request" is the honest pairing. It is exactly
    /// right for the COUNT, which is the number that matters, and it does not
    /// claim to say WHICH request was answered.
    pub fn response(&self) {
        // Once an answer is owed to an operation nobody is waiting for any
        // more, position says nothing. Count the answer — it did arrive — and
        // count that it could not be attributed, but emit NO `Exit` for any
        // open operation: closing a running one as `Ok` on the strength of
        // another request's answer is the defect, not the diagnosis.
        if self.owed.load(std::sync::atomic::Ordering::Relaxed) > 0 {
            for key in [Key::Received, Key::Ambiguous] {
                self.rec.event(Event::Counter {
                    site: RECV,
                    op: OpId::NONE,
                    entry: Entry { key, value: 1 },
                });
            }
            return;
        }
        let oldest = {
            let mut o = match self.open.lock() {
                Ok(o) => o,
                Err(p) => p.into_inner(),
            };
            if o.is_empty() {
                None
            } else {
                Some(o.remove(0))
            }
        };
        if let Some(id) = oldest {
            self.rec.event(Event::Edge {
                site: RECV,
                dir: Dir::Response,
                id,
            });
            // The transport's own verdict: an answer came back. A caller that
            // knows better — no state, wrong bytes — calls `finish` and says
            // so; the Exit here is what makes a healthy run show every span
            // closed rather than merely every edge paired.
            self.rec.event(Event::Exit {
                site: SEND,
                op: OpId(id.ordinal),
                outcome: Outcome::Ok,
            });
        }
        self.rec.event(Event::Counter {
            site: RECV,
            op: OpId::NONE,
            entry: Entry {
                key: Key::Received,
                value: 1,
            },
        });
    }

    pub fn outstanding(&self) -> Vec<Label> {
        match self.open.lock() {
            Ok(o) => o.clone(),
            Err(p) => p.into_inner().clone(),
        }
    }
    pub fn sent(&self) -> u64 {
        self.rec.recording().total(Key::Sent)
    }
    pub fn received(&self) -> u64 {
        self.rec.recording().total(Key::Received)
    }
    /// Answers still owed to operations this connection gave up on.
    pub fn owed(&self) -> u64 {
        self.rec.recording().total(Key::Owed)
    }
    /// Answers that arrived while [`owed`](Ledger::owed) was non-zero.
    pub fn ambiguous(&self) -> u64 {
        self.rec.recording().total(Key::Ambiguous)
    }
    /// The recording, for TESTS to read back. Not on the probe path: the trait
    /// instrumented code holds has no read-back, so a probe can never become
    /// an input.
    #[cfg(test)]
    pub fn recording_for_test(&self) -> instrument::SyncRecording<'_> {
        self.rec.recording()
    }

    pub fn dump(&self, what: &'static str) -> String {
        render(&self.rec.recording(), what, 40)
    }

    /// One line for a progress heartbeat: a PROJECTION of the stream, not a
    /// second set of counters kept beside it.
    pub fn line(&self) -> String {
        let out = self.outstanding();
        let ids: Vec<String> = out.iter().take(4).map(|l| l.to_string()).collect();
        let ended: Vec<String> = self
            .outcomes()
            .iter()
            .map(|(o, n)| format!("{o:?}={n}"))
            .collect();
        let open_spans = self.unfinished();
        let owed = self.owed();
        format!(
            "sent {} received {} OUTSTANDING {} running {}{}{}{}",
            self.sent(),
            self.received(),
            out.len(),
            open_spans,
            // Printed only when it happened, and then loudly: every line after
            // this one is describing a stream whose answers can no longer be
            // matched to their requests by position.
            if owed == 0 {
                String::new()
            } else {
                format!(" owed {owed} ambiguous {}", self.ambiguous())
            },
            if ended.is_empty() {
                String::new()
            } else {
                format!(" ended[{}]", ended.join(" "))
            },
            if ids.is_empty() {
                String::new()
            } else {
                format!(
                    " [{}{}]",
                    ids.join(" "),
                    if out.len() > ids.len() { " …" } else { "" }
                )
            }
        )
    }
}

/// A connection that records what was asked of it and what came back.
pub struct Client {
    inner: WebApi,
    ledger: Ledger,
}

impl Client {
    /// Wrap a connection. Callers use [`crate::connect`].
    pub fn new(inner: WebApi) -> Client {
        Client {
            inner,
            ledger: Ledger::new(),
        }
    }

    /// The raw connection, for a benchmark that is measuring the transport
    /// itself and must not have a probe in the loop.
    ///
    /// Named to be noticed, and UNUSED on purpose: its job is to be the only
    /// bare path, so that writing one is a deliberate act a reviewer can see.
    /// The architect ranked this above any rule about remembering to use the
    /// probed fixture, and a rule nobody can forget beats a rule nobody breaks
    /// today.
    #[allow(dead_code)]
    pub fn new_unprobed_for_benchmark(inner: WebApi) -> WebApi {
        inner
    }

    /// Send, handing back the operation's [`Label`] BEFORE the future is
    /// awaited.
    ///
    /// The label has to be available without awaiting, because the caller that
    /// most needs it is the one whose await never returns: a send that sits in
    /// backpressure past its bound is dropped mid-future, and it must still be
    /// able to say WHICH operation ended. `finish_last` used to stand in for
    /// that — "the last request sent on this connection" — and it was wrong in
    /// the way that cost harness#38: under a concurrent batch the last request
    /// sent is not the one that timed out.
    ///
    /// [`Sent`] is awaitable, so the twenty call sites that do not care are
    /// unchanged; the two that refine an outcome bind it first and keep `id`.
    pub fn send(&mut self, req: ClientRequest<'static>) -> Sent<'_> {
        let id = self.ledger.request(describe(&req));
        self.ledger.offered(id, offered_bytes(&req));
        Sent {
            id,
            fut: Box::pin(async move { self.inner.send(req).await.map_err(Into::into) }),
        }
    }

    pub async fn recv(&mut self) -> Result<HostResponse, anyhow::Error> {
        let got = self.inner.recv().await;
        match &got {
            // An answer that NAMES itself is paired here, at the boundary,
            // rather than at each call site that remembers to. That is the
            // whole argument for boundary middleware: the call sites which
            // forgot are what harness#38 and harness#39 run 1 were.
            Ok(r) => match names_key(r) {
                Some(k) => {
                    let id = self.ledger.answered(&k);
                    self.ledger.received_bytes(id, received_bytes(r));
                }
                None => self.ledger.response(),
            },
            Err(_) => self.ledger.response(),
        }
        got.map_err(Into::into)
    }

    /// One line for a heartbeat, and the tail of the stream for a failure.
    ///
    /// Both are PROJECTIONS of the recording, not counters kept beside it, so
    /// a progress line and a dump cannot disagree about what is outstanding.
    pub fn line(&self) -> String {
        self.ledger.line()
    }

    pub fn dump(&self, what: &'static str) -> String {
        self.ledger.dump(what)
    }

    /// Send, labelling the operation by a key the ANSWER will name.
    ///
    /// Use this wherever the response carries an identifier — a `PutResponse`
    /// carries the contract key. It is what makes the recording able to say
    /// which operation an answer ended.
    pub fn send_keyed(&mut self, req: ClientRequest<'static>, key: &str) -> Sent<'_> {
        let id = self.ledger.request_keyed(describe(&req), key);
        self.ledger.offered(id, offered_bytes(&req));
        Sent {
            id,
            fut: Box::pin(async move { self.inner.send(req).await.map_err(Into::into) }),
        }
    }

    // `answered` is deliberately NOT exposed on the client. `recv` pairs a
    // self-naming answer at the boundary, so a call site cannot forget to —
    // and a call site that called it anyway would record the same answer twice.
    // Removing the public path is the enforcement; a comment asking people to
    // remember is not.

    /// What happened to every keyed operation. ONE projection — a tool that
    /// keeps its own per-key map keeps a second account that can disagree.
    pub fn answers(&self) -> Vec<(Label, instrument::Answered)> {
        self.ledger.answers()
    }

    pub fn answer_counts(&self) -> Vec<(instrument::Answered, usize)> {
        self.ledger.answer_counts()
    }

    pub fn key_of(&self, id: Label) -> Option<String> {
        self.ledger.key_of(id)
    }

    /// Say how a NAMED operation ended, when the caller knows better than the
    /// transport can: no state came back, a bounded wait expired, the bytes
    /// were not the ones asked for.
    ///
    /// By id, never "the last one". A caller that can identify its own answer
    /// — a `PutResponse` carries the key — is the only thing that can close a
    /// specific operation once an answer is owed, because by then position
    /// has stopped meaning anything.
    pub fn finish(&self, id: Label, outcome: Outcome) {
        self.ledger.finish(id, outcome)
    }
}

/// A send in progress, carrying the [`Label`] of the operation it started.
///
/// Awaitable, so `client.send(req).await` still reads as it did.
pub struct Sent<'a> {
    pub id: Label,
    fut: std::pin::Pin<Box<dyn core::future::Future<Output = Result<(), anyhow::Error>> + 'a>>,
}

impl core::future::Future for Sent<'_> {
    type Output = Result<(), anyhow::Error>;
    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<Self::Output> {
        self.fut.as_mut().poll(cx)
    }
}

/// The payload bytes this operation hands to the client API.
///
/// **Named for what it is.** It is not bytes on the socket: the wire framing
/// and its encoding happen inside `WebApi`, and re-encoding a request purely to
/// measure it would double the cost of every send to learn a number a few
/// percent different. It is the contract code, parameters, state and delta —
/// the parts the caller supplies, which dominate, and which are known exactly
/// and for free.
///
/// The one thing it must never be mistaken for is what a NODE sends
/// peer-to-peer. Six external instruments were rejected trying to infer that
/// from outside (freenet-contracts#39); only the node can count it.
fn offered_bytes(req: &ClientRequest<'static>) -> u64 {
    use freenet_stdlib::client_api::ContractRequest;
    let container = |c: &freenet_stdlib::prelude::ContractContainer| -> u64 {
        match c {
            freenet_stdlib::prelude::ContractContainer::Wasm(
                freenet_stdlib::prelude::ContractWasmAPIVersion::V1(w),
            ) => w.code().data().len() as u64 + w.params().as_ref().len() as u64,
            _ => 0,
        }
    };
    match req {
        ClientRequest::ContractOp(ContractRequest::Put {
            contract,
            state,
            related_contracts,
            ..
        }) => {
            let _ = related_contracts;
            container(contract) + state.as_ref().len() as u64
        }
        ClientRequest::ContractOp(ContractRequest::Update { data, .. }) => match data {
            freenet_stdlib::prelude::UpdateData::State(s) => s.as_ref().len() as u64,
            freenet_stdlib::prelude::UpdateData::Delta(d) => d.as_ref().len() as u64,
            _ => 0,
        },
        _ => 0,
    }
}

/// The payload bytes an answer carried back.
fn received_bytes(r: &HostResponse) -> u64 {
    use freenet_stdlib::client_api::ContractResponse;
    match r {
        HostResponse::ContractResponse(ContractResponse::GetResponse { state, .. }) => {
            state.as_ref().len() as u64
        }
        _ => 0,
    }
}

/// The contract key an answer NAMES, when it names one.
///
/// This is what makes the transport able to pair without the call site
/// remembering to: a `PutResponse` and a `GetResponse` both carry their key.
fn names_key(r: &HostResponse) -> Option<String> {
    use freenet_stdlib::client_api::ContractResponse;
    match r {
        HostResponse::ContractResponse(ContractResponse::PutResponse { key })
        | HostResponse::ContractResponse(ContractResponse::GetResponse { key, .. }) => {
            Some(key.id().to_string())
        }
        _ => None,
    }
}

/// A fixed word per request kind, from the vocabulary rather than the data.
fn describe(req: &ClientRequest<'static>) -> &'static str {
    use freenet_stdlib::client_api::{ContractRequest, DelegateRequest};
    match req {
        ClientRequest::ContractOp(ContractRequest::Put { .. }) => "put",
        ClientRequest::ContractOp(ContractRequest::Get { .. }) => "get",
        ClientRequest::ContractOp(ContractRequest::Update { .. }) => "update",
        ClientRequest::ContractOp(ContractRequest::Subscribe { .. }) => "subscribe",
        ClientRequest::ContractOp(_) => "contract",
        ClientRequest::DelegateOp(DelegateRequest::RegisterDelegate { .. }) => "register-delegate",
        ClientRequest::DelegateOp(_) => "delegate",
        ClientRequest::Disconnect { .. } => "disconnect",
        _ => "other",
    }
}

/// Print the connection's stream when the thread is panicking.
///
/// It holds the RECORDER, not the client. Borrowing the client would make the
/// guard unusable: every caller needs `&mut` on the connection to send, and a
/// guard holding `&Client` would lock that out for its whole scope. The
/// recorder is already behind an `Arc`, so the guard costs a clone of a
/// pointer and the client stays free.
pub struct DumpOnPanic {
    rec: Arc<SyncRecorder>,
    what: &'static str,
}

impl DumpOnPanic {
    pub fn new(client: &Client, what: &'static str) -> Self {
        DumpOnPanic {
            rec: client.ledger.rec.clone(),
            what,
        }
    }
}

impl Drop for DumpOnPanic {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!("{}", render(&self.rec.recording(), self.what, 40));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// THE failure, reproduced on purpose.
    ///
    /// On 2026-09-20 a reader sent thousands of GETs for keys no node held.
    /// Nothing answers such a request — not slowly, never — so the connection
    /// filled with requests that would never close, and from outside it was
    /// indistinguishable from a reader doing its job: no output, no error, a
    /// process that looked busy. Four runs were voided before anyone could say
    /// what was happening. This is what it looks like now.
    #[test]
    fn an_undrained_connection_prints_outstanding_with_ids() {
        let l = Ledger::new();
        for _ in 0..12 {
            l.request("get");
        }
        // Not one answer. That is the whole shape of the failure.
        assert_eq!(l.outstanding().len(), 12);
        assert_eq!(l.sent(), 12);
        assert_eq!(l.received(), 0);

        let line = l.line();
        assert!(line.contains("OUTSTANDING 12"), "{line}");
        // With IDS: "twelve of something" does not tell a reader which
        // requests are stuck, and a dump has to be actionable.
        assert!(line.contains("req#0"), "{line}");
        assert!(line.contains('…'), "and it says there are more: {line}");

        let text = l.dump("undrained");
        assert!(text.contains("OUTSTANDING 12"), "{text}");
        assert!(text.contains("requests with no response"), "{text}");
    }

    /// The control: a healthy run prints 0, so the number above is the failure
    /// and not something every run says.
    #[test]
    fn a_healthy_connection_prints_zero() {
        let l = Ledger::new();
        for _ in 0..12 {
            l.request("get");
            l.response();
        }
        assert_eq!(l.outstanding().len(), 0);
        assert_eq!(l.sent(), 12);
        assert_eq!(l.received(), 12);
        let line = l.line();
        assert!(line.contains("OUTSTANDING 0"), "{line}");
        assert!(!line.contains("req#"), "no ids to name: {line}");
    }

    /// Falling behind — the real shape of a run that is slow rather than
    /// wedged — is reported as the difference, not as a verdict.
    #[test]
    fn falling_behind_is_the_difference_not_a_verdict() {
        let l = Ledger::new();
        for _ in 0..10 {
            l.request("put");
        }
        for _ in 0..7 {
            l.response();
        }
        assert_eq!(l.outstanding().len(), 3, "sent 10, answered 7");
        assert!(l.line().contains("OUTSTANDING 3"), "{}", l.line());
    }

    /// A request label carries a vocabulary word and a counter, never data.
    ///
    /// The probes ship, so a label that could carry a key, a contract id or a
    /// body would be a leak with a nice name.
    #[test]
    fn a_request_label_carries_a_vocabulary_word_and_a_counter() {
        let l = Ledger::new();
        let a = l.request("put");
        let b = l.request("get");
        assert_ne!(a, b, "two requests get two labels");
        assert_eq!(a.to_string(), "req#0");
        assert_eq!(b.to_string(), "req#1");
        let text = l.dump("labels");
        assert!(text.contains("req#0") && text.contains("req#1"), "{text}");
    }

    /// The heartbeat is a PROJECTION of the stream, not a second set of
    /// counters kept beside it — so it cannot disagree with the dump.
    #[test]
    fn the_heartbeat_and_the_dump_cannot_disagree() {
        let l = Ledger::new();
        for _ in 0..5 {
            l.request("get");
        }
        l.response();
        let n = l.outstanding().len();
        assert!(l.line().contains(&format!("OUTSTANDING {n}")));
        assert!(l.dump("x").contains(&format!("OUTSTANDING {n}")));
    }

    /// An OPEN EDGE does not say how an operation ended, and the three shapes
    /// that leave the same edges open want different responses.
    #[test]
    fn a_timeout_and_a_slow_node_leave_different_dumps() {
        // Still running: asked, no answer yet. Nobody has given up.
        let running = Ledger::new();
        for _ in 0..3 {
            running.request("get");
        }
        assert_eq!(running.outstanding().len(), 3);
        assert_eq!(running.unfinished(), 3, "three operations are still open");
        assert!(running.outcomes().is_empty(), "none of them ENDED");

        // Abandoned: the caller's bounded wait expired. The edges must not
        // still be counted as outstanding — that would report the same failure
        // twice, once as a timeout and again as a request nobody answered.
        let gave_up = Ledger::new();
        for _ in 0..3 {
            let id = gave_up.request("get");
            gave_up.finish(id, Outcome::Timeout);
        }
        assert_eq!(
            gave_up.outstanding().len(),
            0,
            "they ended, so they are not open"
        );
        assert_eq!(gave_up.unfinished(), 0);
        assert_eq!(gave_up.outcomes(), vec![(Outcome::Timeout, 3)]);

        // And the two dumps say different things, which is the whole point.
        assert!(
            running.line().contains("OUTSTANDING 3"),
            "{}",
            running.line()
        );
        assert!(!running.line().contains("ended["), "{}", running.line());
        assert!(
            gave_up.line().contains("OUTSTANDING 0"),
            "{}",
            gave_up.line()
        );
        assert!(gave_up.line().contains("Timeout=3"), "{}", gave_up.line());
        // Three answers were given up on, and the line says so: from here the
        // node may still answer, and nothing could say which one it settled.
        assert!(gave_up.line().contains("owed 3"), "{}", gave_up.line());
    }

    /// A node that answers "I do not have it" has ANSWERED. That is a miss,
    /// not a failure and not an open request.
    #[test]
    fn a_miss_is_an_outcome_not_an_open_edge() {
        let l = Ledger::new();
        let id = l.request("get");
        l.finish(id, Outcome::Missing);
        assert_eq!(l.outstanding().len(), 0);
        assert_eq!(l.outcomes(), vec![(Outcome::Missing, 1)]);
        assert!(l.line().contains("Missing=1"), "{}", l.line());
        assert!(
            l.dump("miss").contains("outcome Missing: 1"),
            "{}",
            l.dump("miss")
        );
    }

    /// A healthy run closes every span, not merely every edge.
    #[test]
    fn a_healthy_run_leaves_no_span_open() {
        let l = Ledger::new();
        for _ in 0..8 {
            l.request("put");
            l.response();
        }
        assert_eq!(l.outstanding().len(), 0);
        assert_eq!(l.unfinished(), 0, "every span closed");
        assert_eq!(l.outcomes(), vec![(Outcome::Ok, 8)]);
        assert!(
            l.dump("healthy").contains("unfinished spans 0"),
            "{}",
            l.dump("healthy")
        );
    }

    /// A caller's verdict overrides the transport's, and does not double-count.
    #[test]
    fn refining_an_outcome_does_not_end_the_operation_twice() {
        let l = Ledger::new();
        let id = l.request("get");
        l.finish(id, Outcome::Refused(7));
        // The caller spoke first; a later response must not add a second Exit
        // for an operation that already ended.
        let total = |l: &Ledger| l.outcomes().iter().map(|(_, n)| *n).sum::<usize>();
        assert_eq!(total(&l), 1, "one operation, one ending");
        assert_eq!(l.outstanding().len(), 0, "nothing is open to answer");

        // A response arriving after the caller gave up must not add a second
        // ending. Asserted as a NUMBER, not as `x == x`: the first version of
        // this compared a value with itself and would have passed whatever the
        // code did.
        l.response();
        assert_eq!(total(&l), 1, "a late answer added a second ending");
        assert_eq!(
            l.outcomes(),
            vec![(Outcome::Refused(7), 1)],
            "and it is still the caller's verdict, not the transport's"
        );
    }

    /// A late answer after a timeout must not close a DIFFERENT operation.
    ///
    /// The review's probe, exactly: request A, A times out, request B, then
    /// one response — A's late answer. Before the fix this printed
    /// `sent 2 received 1 OUTSTANDING 0 running 0 ended[Timeout=1 Ok=1]`:
    /// B was still running, and the ledger said it had ended `Ok`. That is
    /// harness#38 seen from inside the instrument built to show it.
    #[test]
    fn a_late_answer_does_not_close_a_different_operation() {
        let l = Ledger::new();
        let a = l.request("put");
        l.finish(a, Outcome::Timeout);
        let _b = l.request("put");
        // A's answer, arriving now. Nothing on the wire says so.
        l.response();

        assert_eq!(l.unfinished(), 1, "B is still running: {}", l.line());
        assert_eq!(
            l.outcomes(),
            vec![(Outcome::Timeout, 1)],
            "only A ended, and it ended in a timeout: {}",
            l.line()
        );
        assert_eq!(l.owed(), 1, "one answer is still owed: {}", l.line());
        assert_eq!(
            l.ambiguous(),
            1,
            "and one arrived that could not be attributed: {}",
            l.line()
        );
        assert!(
            l.line().contains("owed 1 ambiguous 1"),
            "the line must say the pairing is no longer trustworthy: {}",
            l.line()
        );
        assert_eq!(
            l.received(),
            1,
            "the answer still arrived, and is still counted: {}",
            l.line()
        );
    }

    /// Under a CONCURRENT batch, "the last request sent" is not the one that
    /// timed out — which is why the label travels with the operation.
    ///
    /// Four puts go out before any answer comes back. The first times out.
    /// A ledger that closed "the last one" would end the FOURTH, leaving the
    /// first open for ever and reporting a failure against an operation that
    /// was doing nothing wrong.
    #[test]
    fn under_a_concurrent_batch_the_last_request_is_not_the_one_that_failed() {
        let l = Ledger::new();
        let ids: Vec<_> = (0..4).map(|_| l.request("put")).collect();
        let (first, last) = (ids[0], ids[3]);
        assert_ne!(first, last, "the batch really is concurrent");

        l.finish(first, Outcome::Timeout);

        let open = l.outstanding();
        assert!(
            !open.contains(&first),
            "the operation that timed out is no longer open: {}",
            l.line()
        );
        assert!(
            open.contains(&last),
            "and the LAST one sent is untouched — it never failed: {}",
            l.line()
        );
        assert_eq!(open.len(), 3);

        // Three answers now arrive. Each of them MIGHT be the first put's, so
        // none of them may close anything: the honest report is that three
        // answers came back and the pairing cannot be trusted.
        for _ in 0..3 {
            l.response();
        }
        assert_eq!(l.ambiguous(), 3, "{}", l.line());
        assert_eq!(
            l.outcomes(),
            vec![(Outcome::Timeout, 1)],
            "no operation was closed on a guess: {}",
            l.line()
        );
        assert_eq!(l.unfinished(), 3, "{}", l.line());
    }

    /// A caller that can name its own answer closes its OWN operation, and
    /// that keeps working after the pairing has been lost.
    ///
    /// This is the other half of the fix: `Awaiting` matches a `PutResponse`
    /// by key, so the put path never has to ask the ledger to guess.
    #[test]
    fn a_caller_that_identifies_its_answer_closes_its_own_operation() {
        let l = Ledger::new();
        let a = l.request("put");
        l.finish(a, Outcome::Timeout);
        let b = l.request("put");
        // The caller matched this answer to B by key, so it says so itself.
        l.finish(b, Outcome::Ok);
        assert_eq!(l.unfinished(), 0, "both operations ended: {}", l.line());
        let mut got = l.outcomes();
        got.sort_by_key(|(o, _)| format!("{o:?}"));
        assert_eq!(got, vec![(Outcome::Ok, 1), (Outcome::Timeout, 1)]);
        assert_eq!(
            l.ambiguous(),
            0,
            "identifying the answer means nothing was guessed: {}",
            l.line()
        );
    }

    /// Bytes are attributed to the operation that offered them, and a WRONG
    /// count fails rather than being a plausible number nobody checks.
    ///
    /// A byte counter is the easiest kind of instrument to get quietly wrong,
    /// because any number it prints looks like a measurement. So the test
    /// asserts the EXACT total against what was handed in, not that it is
    /// "about right".
    #[test]
    fn bytes_are_attributed_to_the_operation_that_offered_them() {
        let l = Ledger::new();
        let a = l.request("put");
        l.offered(a, 101_641 + 32);
        let b = l.request("put");
        l.offered(b, 101_641 + 32);
        l.received_bytes(a, 1_025);

        let rec = l.recording_for_test();
        assert_eq!(
            rec.bytes(a.op()),
            (101_673, 1_025),
            "operation a's own bytes, not the connection's total"
        );
        assert_eq!(
            rec.bytes(b.op()),
            (101_673, 0),
            "b offered the same and received nothing"
        );
        assert_eq!(
            rec.total(Key::BytesOut),
            203_346,
            "and the whole-recording total is the sum of both"
        );
    }

    /// `offered_bytes` counts what it says it counts.
    ///
    /// The previous test exercised the LEDGER with a number handed to it, which
    /// left the function that computes that number — the part that can actually
    /// be wrong — untested. A byte counter nobody checks is a plausible-looking
    /// number, which is worse than none.
    #[test]
    fn offered_bytes_counts_the_contract_and_the_state_exactly() {
        use freenet_stdlib::client_api::ContractRequest;
        use freenet_stdlib::prelude::*;

        let code = ContractCode::from(vec![7u8; 101_641]);
        let params = Parameters::from(vec![0u8; 32]);
        let state = vec![9u8; 1_024];
        let contract = ContractContainer::Wasm(ContractWasmAPIVersion::V1(WrappedContract::new(
            std::sync::Arc::new(code),
            params,
        )));
        let req = ClientRequest::ContractOp(ContractRequest::Put {
            contract,
            state: WrappedState::from(state),
            related_contracts: RelatedContracts::default(),
            subscribe: false,
            blocking_subscribe: false,
        });

        assert_eq!(
            super::offered_bytes(&req),
            101_641 + 32 + 1_024,
            "code + parameters + state, exactly — this is the number every \
             per-operation byte figure is built from"
        );

        // A request that carries no payload of ours must count zero rather than
        // some incidental size, or every GET would inflate the total.
        let get = ClientRequest::ContractOp(ContractRequest::Get {
            key: ContractInstanceId::try_from(
                "9nPgCTfiuX3Zycngp3vvgFiY9aqUmvKG64y86t6qgyKi".to_string(),
            )
            .unwrap(),
            return_contract_code: false,
            subscribe: false,
            blocking_subscribe: false,
        });
        assert_eq!(super::offered_bytes(&get), 0);
    }

    /// What recording costs, measured against the grid it has to stay inside.
    ///
    /// The latency tables poll on a 250 ms grid, so the question is not "is
    /// the probe fast" but "can it move a median". Reported, not asserted as a
    /// threshold — except for the one comparison that IS the requirement.
    #[test]
    fn recording_cannot_move_a_latency_median() {
        use std::time::Instant;
        const OPS: usize = 50_000;
        let l = Ledger::new();
        let t = Instant::now();
        for _ in 0..OPS {
            l.request("get");
            l.response();
        }
        let per_pair = t.elapsed().as_secs_f64() / OPS as f64;

        // A generous run: 10,000 request/response pairs on one connection.
        let whole_run = per_pair * 10_000.0 * 1e3;
        // The grid the latency tables actually resolve to.
        let grid_ms = 250.0;
        println!(
            "probe cost: {:.0} ns per request/response pair; \
             {whole_run:.1} ms over a 10,000-pair run, against a {grid_ms:.0} ms grid",
            per_pair * 1e9
        );
        assert!(
            whole_run < grid_ms,
            "recording adds {whole_run:.1} ms over a long run, which is inside a \
             {grid_ms:.0} ms grid step only if it is smaller than one — it is not"
        );
    }
}
