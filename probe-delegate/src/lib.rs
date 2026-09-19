//! Probe delegate: exercises the host capabilities the engine and keepers
//! depend on, so we learn what the installed node really does.
//!
//! App messages (payload → reply):
//!   "wake" ‖ secs:u32le          → arm a wakeup; reply "armed" or "wake-err <code>"
//!   "get"  ‖ id:[u8;32]          → ask the node for a contract; the answer is recorded
//!   "putk" ‖ k:u8 ‖ nonce:[u8;16] ‖ block-wasm
//!                                → return k PutContractRequests from ONE process()
//!                                  call; every answer is tallied (F15)
//!   "stat"                       → "fired=<n> get=<r> asked=<k> ok=<a> err=<b>
//!                                   put=<a+b>/<k> errs=<text>"
//!
//! Everything observed is written to secrets, so the harness can poll `stat`
//! regardless of whether a late reply reaches the client that asked.

use std::sync::Arc;

use freenet_stdlib::prelude::*;

const FIRED: &[u8] = b"probe/fired";
const LASTGET: &[u8] = b"probe/lastget";
const PUT_ASKED: &[u8] = b"probe/put-asked";
const PUT_OK: &[u8] = b"probe/put-ok";
const PUT_ERR: &[u8] = b"probe/put-err";
const PUT_ERRS: &[u8] = b"probe/put-errs";

/// Same state layout as the Block contract: kind(1) ‖ body, keyed by
/// blake3(state). Spelled out rather than imported so the probe stays a single
/// self-contained wasm.
const KIND_RAW: u8 = 0;

fn reply(text: impl Into<Vec<u8>>) -> Vec<OutboundDelegateMsg> {
    vec![OutboundDelegateMsg::ApplicationMessage(
        ApplicationMessage::new(text.into()).processed(true),
    )]
}

fn counter(ctx: &mut DelegateCtx, name: &[u8]) -> u32 {
    ctx.get_secret(name)
        .and_then(|v| <[u8; 4]>::try_from(v).ok())
        .map(u32::from_le_bytes)
        .unwrap_or(0)
}

fn bump(ctx: &mut DelegateCtx, name: &[u8]) {
    let n = counter(ctx, name) + 1;
    ctx.set_secret(name, &n.to_le_bytes());
}

fn secret_text(ctx: &mut DelegateCtx, name: &[u8]) -> String {
    ctx.get_secret(name)
        .map(|v| String::from_utf8_lossy(&v).into_owned())
        .unwrap_or_default()
}

/// The k contracts of one `putk` round: distinct bodies, so k distinct keys,
/// so the host cannot collapse them into one op.
fn round(
    code: &Arc<ContractCode<'static>>,
    nonce: &[u8; 16],
    k: usize,
) -> Vec<OutboundDelegateMsg> {
    (0..k)
        .map(|i| {
            let mut state = vec![KIND_RAW];
            state.extend_from_slice(b"delegate-put ");
            state.extend_from_slice(nonce);
            state.push(i as u8);
            let params = Parameters::from(blake3::hash(&state).as_bytes().to_vec());
            let contract = ContractContainer::Wasm(ContractWasmAPIVersion::V1(
                WrappedContract::new(code.clone(), params),
            ));
            OutboundDelegateMsg::PutContractRequest(PutContractRequest::new(
                contract,
                WrappedState::from(state),
                RelatedContracts::default(),
            ))
        })
        .collect()
}

pub struct Probe;

#[delegate]
impl DelegateInterface for Probe {
    fn process(
        ctx: &mut DelegateCtx,
        _parameters: Parameters<'static>,
        _origin: Option<MessageOrigin>,
        message: InboundDelegateMsg,
    ) -> Result<Vec<OutboundDelegateMsg>, DelegateError> {
        match message {
            InboundDelegateMsg::ApplicationMessage(m) => {
                let p = m.payload.as_slice();
                if p.len() == 8 && &p[..4] == b"wake" {
                    let secs = u32::from_le_bytes(p[4..8].try_into().unwrap());
                    #[cfg(feature = "wakeup")]
                    return Ok(
                        match ctx
                            .schedule_wakeup(std::time::Duration::from_secs(secs as u64), b"probe")
                        {
                            Ok(()) => reply("armed"),
                            Err(code) => reply(format!("wake-err {code}")),
                        },
                    );
                    #[cfg(not(feature = "wakeup"))]
                    {
                        let _ = secs;
                        return Ok(reply("built without wakeup"));
                    }
                }
                if p.len() == 35 && &p[..3] == b"get" {
                    let id: [u8; 32] = p[3..35].try_into().unwrap();
                    ctx.set_secret(LASTGET, b"pending");
                    return Ok(vec![OutboundDelegateMsg::GetContractRequest(
                        GetContractRequest::new(ContractInstanceId::new(id)),
                    )]);
                }
                // "putk" ‖ k:u8 ‖ nonce:[u8;16] ‖ contract wasm
                if p.len() > 21 && &p[..4] == b"putk" {
                    let k = p[4] as usize;
                    let nonce: [u8; 16] = p[5..21].try_into().unwrap();
                    let code = Arc::new(ContractCode::from(p[21..].to_vec()));
                    // Reset the tally: each k is its own round, so a later
                    // round can never inherit an earlier one's answers.
                    ctx.set_secret(PUT_ASKED, &(k as u32).to_le_bytes());
                    ctx.set_secret(PUT_OK, &0u32.to_le_bytes());
                    ctx.set_secret(PUT_ERR, &0u32.to_le_bytes());
                    ctx.set_secret(PUT_ERRS, b"none");
                    return Ok(round(&code, &nonce, k));
                }
                if p == b"stat" || p == b"putstat" {
                    let n = counter(ctx, FIRED);
                    let g = ctx.get_secret(LASTGET).unwrap_or_else(|| b"none".to_vec());
                    let (asked, ok, err) = (
                        counter(ctx, PUT_ASKED),
                        counter(ctx, PUT_OK),
                        counter(ctx, PUT_ERR),
                    );
                    let errs = secret_text(ctx, PUT_ERRS);
                    // errs is free text and goes last, so every field before it
                    // stays parseable by splitting on whitespace.
                    return Ok(reply(format!(
                        "fired={n} get={} asked={asked} ok={ok} err={err} put={}/{asked} errs={}",
                        String::from_utf8_lossy(&g),
                        ok + err,
                        if errs.is_empty() { "none" } else { &errs },
                    )));
                }
                Ok(reply("unknown"))
            }
            InboundDelegateMsg::GetContractResponse(r) => {
                let text = match &r.state {
                    Some(s) => format!("ok:{}", s.as_ref().len()),
                    None => "notfound".to_string(),
                };
                ctx.set_secret(LASTGET, text.as_bytes());
                Ok(reply(format!("got {text}")))
            }
            InboundDelegateMsg::PutContractResponse(r) => {
                let outcome = match &r.result {
                    Ok(()) => {
                        bump(ctx, PUT_OK);
                        format!("ok:{}", r.contract_id)
                    }
                    Err(e) => {
                        bump(ctx, PUT_ERR);
                        // The node's own words: a refusal we paraphrased would
                        // be a guess about why, and this probe exists to stop
                        // guessing.
                        let mut seen = secret_text(ctx, PUT_ERRS);
                        if seen.is_empty() || seen == "none" {
                            seen.clear();
                        } else {
                            seen.push(';');
                        }
                        seen.push_str(&e.replace(char::is_whitespace, "_"));
                        ctx.set_secret(PUT_ERRS, seen.as_bytes());
                        format!("err:{e}")
                    }
                };
                Ok(reply(format!("put {outcome}")))
            }
            InboundDelegateMsg::WakeupFired { .. } => {
                bump(ctx, FIRED);
                Ok(vec![])
            }
            _ => Ok(vec![]),
        }
    }
}
