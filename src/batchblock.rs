//! Does a batch of sends still block the client API? (freenet-harness#32)
//!
//! The issue recorded five of five runs of the batched form dying on loopback,
//! against zero of three for one-at-a-time, and named the reproducer to build:
//! send N requests with no interleaved `recv`, for keys that do not exist, and
//! count sends until one blocks. It was never built. This is it.
//!
//! **It is a re-measurement, not a fix.** The finding it is checking is old and
//! may already be gone, so the control matters as much as the arm: if the
//! batched form runs to the budget, the issue closes on evidence rather than on
//! the absence of a recent complaint.
//!
//! Three properties it needs, all learned the hard way in this repo:
//!
//! - **Every send has a deadline.** `WebApi::send` awaits the websocket sink,
//!   and a block there returns nothing at all — indistinguishable from slow.
//! - **The run has a total budget**, so it cannot become the thing it measures.
//! - **It prints as it goes.** A long run with no output is indistinguishable
//!   from a wedged one.

use anyhow::Result;
use std::time::{Duration, Instant};

use freenet_stdlib::{
    client_api::{ClientRequest, ContractRequest},
    prelude::ContractInstanceId,
};
use tokio::time::timeout;

use crate::latency::progress_pub;

/// How long a drain waits for the NEXT message before calling the batch drained.
///
/// Short on purpose: this is "read what came back", not "wait for answers".
const DRAIN_QUIET: Duration = Duration::from_millis(200);

/// A key nobody has ever put, so nothing can answer it.
///
/// Derived rather than random: a run that blocks is worth re-running against
/// the same ids, and a seed makes that possible.
fn absent_key(seed: u64, n: u64) -> ContractInstanceId {
    let mut b = [0u8; 32];
    b[..8].copy_from_slice(&seed.to_le_bytes());
    b[8..16].copy_from_slice(&n.to_le_bytes());
    // A marker, so one of these turning up in a node's logs is recognisable.
    b[16..20].copy_from_slice(b"h32!");
    ContractInstanceId::new(b)
}

fn get_of(id: ContractInstanceId) -> ClientRequest<'static> {
    ClientRequest::ContractOp(ContractRequest::Get {
        key: id,
        return_contract_code: false,
        subscribe: false,
        blocking_subscribe: false,
    })
}

/// What ended an arm.
#[derive(Debug)]
enum Ended {
    /// A send did not return within its deadline: the finding reproduces.
    SendBlocked {
        at_send: u64,
        in_round: u64,
        index: usize,
    },
    /// The arm ran to its send target without blocking.
    Completed { sends: u64 },
    /// The budget ran out first. NOT a pass: it is an inconclusive arm, and
    /// saying so is the difference between evidence and a shrug.
    OutOfBudget { sends: u64 },
}

/// One arm. `drain` = read one answer after each send (the control).
async fn arm(
    ws: &str,
    batch: usize,
    target_sends: u64,
    drain: bool,
    send_wait: Duration,
    deadline: Instant,
    seed: u64,
) -> Result<Ended> {
    let mut client = crate::connect(ws).await?;
    let mut sends: u64 = 0;
    let mut round: u64 = 0;

    while sends < target_sends {
        if Instant::now() >= deadline {
            return Ok(Ended::OutOfBudget { sends });
        }
        round += 1;
        for i in 0..batch {
            let req = get_of(absent_key(seed, sends));
            match timeout(send_wait, client.send(req)).await {
                Ok(Ok(())) => sends += 1,
                Ok(Err(e)) => {
                    // A refusal is an answer; it is not the block being hunted.
                    progress_pub(format_args!(
                        "send returned an error after {sends} sends: {e}"
                    ));
                    return Ok(Ended::Completed { sends });
                }
                Err(_) => {
                    return Ok(Ended::SendBlocked {
                        at_send: sends + 1,
                        in_round: round,
                        index: i + 1,
                    })
                }
            }
            if drain {
                // One answer, with a deadline. Nothing exists, so the node may
                // answer with an error or not at all; either is fine, the point
                // is that the client READ between sends.
                let _ = timeout(send_wait, client.recv()).await;
            }
        }
        if !drain {
            // Drain what came back FOR THIS BATCH, the way the original
            // pattern did: send the batch, then read what is there.
            //
            // A short per-message deadline, not the send deadline: waiting the
            // full send budget after every round would make the harness spend
            // its whole time asleep, and the arm would never reach a send
            // count worth reporting. These keys cannot exist, so the node may
            // answer with an error or not at all; the point of the arm is the
            // SENDS, not the answers.
            while timeout(DRAIN_QUIET, client.recv()).await.is_ok() {}
        }
        if round.is_multiple_of(20) {
            progress_pub(format_args!(
                "{} batch {batch}: {sends} sends, {round} rounds",
                if drain { "control" } else { "batched " }
            ));
        }
    }
    Ok(Ended::Completed { sends })
}

pub(crate) async fn run(
    ws: &str,
    batches: Vec<usize>,
    target_sends: u64,
    send_wait_secs: u64,
    budget_secs: u64,
) -> Result<()> {
    let send_wait = Duration::from_secs(send_wait_secs);
    let budget = Duration::from_secs(budget_secs);
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)?
        .as_secs();

    println!("# freenet-harness#32 re-measurement");
    println!("# ws {ws}");
    println!("# target {target_sends} sends per arm, send deadline {send_wait_secs}s, budget {budget_secs}s per arm");
    println!("# seed {seed}");
    println!();

    let mut any_blocked = false;
    for batch in batches {
        for drain in [false, true] {
            let started = Instant::now();
            let deadline = started + budget;
            let what = if drain {
                "one at a time"
            } else {
                "batched     "
            };
            let outcome = arm(ws, batch, target_sends, drain, send_wait, deadline, seed).await?;
            let secs = started.elapsed().as_secs_f64();
            match &outcome {
                Ended::SendBlocked { at_send, in_round, index } => {
                    any_blocked = true;
                    println!(
                        "batch {batch:>3}  {what}  BLOCKED at send {at_send} (round {in_round}, probe {index} of {batch}) after {secs:.0}s"
                    );
                }
                Ended::Completed { sends } => println!(
                    "batch {batch:>3}  {what}  completed {sends} sends in {secs:.0}s"
                ),
                Ended::OutOfBudget { sends } => println!(
                    "batch {batch:>3}  {what}  INCONCLUSIVE: budget ran out at {sends} sends ({secs:.0}s)"
                ),
            }
        }
    }

    println!();
    if any_blocked {
        println!("REPRODUCES: at least one batched arm blocked its own send.");
    } else {
        println!(
            "DOES NOT REPRODUCE at this send count. That is evidence the batched\n\
             form no longer blocks here, NOT proof it cannot: the original deaths\n\
             were non-deterministic, and two of five landed in the first round."
        );
    }
    Ok(())
}
