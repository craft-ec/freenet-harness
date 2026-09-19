//! `watch`: what does a SECOND node see?
//!
//! Local readability and local validation cost are both properties of the node
//! the client talks to. The question that decides whether a no-op update is a
//! node-local cost or a NETWORK cost is what some other node does about it —
//! and the only honest way to ask is from that other node.
//!
//! Cold-GET the contract (which makes this node a host), subscribe, then report
//! every update notification that arrives, with its offset from subscribe.
//! Silence is a result: it means the originating node did not send this one on.

use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use freenet_stdlib::{
    client_api::{ClientRequest, ContractRequest, ContractResponse, HostResponse},
    prelude::*,
};
use tokio::time::timeout;

use crate::latency::{ms_since, send_req};

pub async fn run(ws: &str, key_str: &str, secs: u64, wait: Duration) -> Result<()> {
    let id = ContractInstanceId::try_from(key_str.to_string())
        .map_err(|e| anyhow!("{key_str} is not a contract instance id: {e}"))?;
    let mut client = crate::connect(ws).await?;

    // Cold GET: this node has never seen the contract, so this both measures
    // the cold fetch and makes this node a host of it.
    let t = Instant::now();
    send_req(
        &mut client,
        ClientRequest::ContractOp(ContractRequest::Get {
            key: id,
            return_contract_code: true,
            subscribe: true,
            blocking_subscribe: false,
        }),
        wait,
    )
    .await?;
    // Drain until the GetResponse arrives. A subscription notification can
    // overtake it — treating the first message as the answer made the whole
    // far-node arm abort with "not hosting" while propagation was in fact
    // working, which is the failure this loop exists to prevent.
    let mut held: Option<usize> = None;
    let mut early_notifications = 0usize;
    let get_deadline = Instant::now() + wait;
    while Instant::now() < get_deadline {
        let Some(left) = get_deadline.checked_duration_since(Instant::now()) else {
            break;
        };
        match timeout(left, client.recv()).await {
            Ok(Ok(HostResponse::ContractResponse(ContractResponse::GetResponse {
                state, ..
            }))) => {
                held = Some(state.as_ref().len());
                println!(
                    "cold GET: {} bytes in {:.1} ms",
                    state.as_ref().len(),
                    ms_since(t)
                );
                break;
            }
            Ok(Ok(HostResponse::ContractResponse(ContractResponse::UpdateNotification {
                ..
            }))) => {
                early_notifications += 1;
            }
            Ok(Ok(_)) => {}
            Ok(Err(e)) => {
                println!("cold GET: node error: {e}");
                break;
            }
            Err(_) => {
                println!("cold GET: no response within {} s", wait.as_secs());
                break;
            }
        }
    }
    if early_notifications > 0 {
        println!("  ({early_notifications} update notification(s) arrived before the GetResponse)");
    }
    if held.is_none() {
        println!("not hosting — nothing to watch; the far-node arm cannot run");
        return Ok(());
    }

    // Notifications proved unreliable as an instrument: a positive control
    // (a CHANGED update) produced none either, so an absence could not be
    // read as "nothing propagated" — only as "this watcher sees nothing".
    // Polling the state directly does not depend on a subscription being
    // live, so a change is observable whatever the notification path does.
    println!("watching {secs} s, polling state every 1000 ms (notifications also reported)...");
    let mut last_len = held.unwrap_or(0);
    let start = Instant::now();
    let deadline = start + Duration::from_secs(secs);
    let (mut notifications, mut other_msgs) = (0usize, 0usize);
    let mut polls = 0usize;
    let mut changes = 0usize;
    while Instant::now() < deadline {
        // One poll per second, each bounded so a miss cannot become a
        // 60 s network search.
        tokio::time::sleep(Duration::from_millis(1000)).await;
        polls += 1;
        send_req(
            &mut client,
            ClientRequest::ContractOp(ContractRequest::Get {
                key: id,
                return_contract_code: false,
                subscribe: false,
                blocking_subscribe: false,
            }),
            wait,
        )
        .await?;
        let left = Duration::from_millis(2000);
        match timeout(left, client.recv()).await {
            Ok(Ok(HostResponse::ContractResponse(ContractResponse::GetResponse {
                state, ..
            }))) => {
                let len = state.as_ref().len();
                if len != last_len {
                    changes += 1;
                    println!(
                        "  +{:.1} ms  STATE CHANGED on this node: {last_len} -> {len} B",
                        ms_since(start)
                    );
                    last_len = len;
                }
            }
            Ok(Ok(HostResponse::ContractResponse(ContractResponse::UpdateNotification {
                key: k,
                ..
            }))) if k.id() == &id => {
                notifications += 1;
                println!(
                    "  +{:.1} ms  notification #{notifications}",
                    ms_since(start)
                );
            }
            Ok(Ok(_)) => other_msgs += 1,
            Ok(Err(e)) => {
                println!("  node error: {e}");
                break;
            }
            // A poll that does not answer in 2 s is not a stop condition.
            Err(_) => other_msgs += 1,
        }
    }
    let _ = client.send(ClientRequest::Disconnect { cause: None }).await;
    println!(
        "watched {:.1} s: {polls} polls, {changes} observed state change(s), \
         {notifications} notification(s), {other_msgs} other/timeout",
        ms_since(start) / 1000.0
    );
    println!("  final state on this node: {last_len} B");
    Ok(())
}
