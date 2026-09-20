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
        // An operation that ended is no longer outstanding, however it ended.
        // A timeout that left its edge open would be counted twice: once as a
        // failure and again as a request nobody answered.
        if let Ok(mut o) = self.open.lock() {
            if let Some(i) = o.iter().position(|l| *l == id) {
                o.remove(i);
            }
        }
    }

    /// Close the MOST RECENT operation with the caller's outcome.
    ///
    /// Honest about its limit: with several requests in flight, "the most
    /// recent" is not necessarily the one that failed. It is exactly right for
    /// the shapes that use it — a send that blocked, a single probe that went
    /// unanswered — because in both the caller sent one request and is
    /// standing over it. A caller pipelining several and wanting to refine one
    /// of them should keep the `Label` that `request` handed back.
    pub fn finish_last(&self, outcome: Outcome) {
        let id = match self.last.lock() {
            Ok(l) => *l,
            Err(p) => *p.into_inner(),
        };
        if let Some(id) = id {
            self.finish(id, outcome);
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
        format!(
            "sent {} received {} OUTSTANDING {} running {}{}{}",
            self.sent(),
            self.received(),
            out.len(),
            open_spans,
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

    pub fn send(
        &mut self,
        req: ClientRequest<'static>,
    ) -> impl core::future::Future<Output = Result<(), anyhow::Error>> + '_ {
        self.ledger.request(describe(&req));
        async move { self.inner.send(req).await.map_err(Into::into) }
    }

    pub async fn recv(&mut self) -> Result<HostResponse, anyhow::Error> {
        let got = self.inner.recv().await;
        self.ledger.response();
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

    /// Say how the operation just sent ended, when the caller knows better
    /// than the transport can: no state came back, a bounded wait expired, the
    /// bytes were not the ones asked for.
    pub fn finish_last(&self, outcome: Outcome) {
        self.ledger.finish_last(outcome)
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
            gave_up.request("get");
            gave_up.finish_last(Outcome::Timeout);
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
    }

    /// A node that answers "I do not have it" has ANSWERED. That is a miss,
    /// not a failure and not an open request.
    #[test]
    fn a_miss_is_an_outcome_not_an_open_edge() {
        let l = Ledger::new();
        l.request("get");
        l.finish_last(Outcome::Missing);
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
        l.request("get");
        l.finish_last(Outcome::Refused(7));
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
