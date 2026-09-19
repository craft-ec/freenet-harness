//! Probe delegate: exercises the host capabilities the engine and keepers
//! depend on, so we learn what the installed node really does.
//!
//! App messages (payload → reply):
//!   "wake" ‖ secs:u32le  → arm a wakeup; reply "armed" or "wake-err <code>"
//!   "get"  ‖ id:[u8;32]  → ask the node for a contract; the answer is recorded
//!   "stat"               → "fired=<n> get=<result>"
//!
//! Everything observed is written to secrets, so the harness can poll `stat`
//! regardless of whether a late reply reaches the client that asked.

use freenet_stdlib::prelude::*;

const FIRED: &[u8] = b"probe/fired";
const LASTGET: &[u8] = b"probe/lastget";

fn reply(text: impl Into<Vec<u8>>) -> Vec<OutboundDelegateMsg> {
    vec![OutboundDelegateMsg::ApplicationMessage(
        ApplicationMessage::new(text.into()).processed(true),
    )]
}

fn fired(ctx: &mut DelegateCtx) -> u32 {
    ctx.get_secret(FIRED)
        .and_then(|v| v.try_into().ok())
        .map(u32::from_le_bytes)
        .unwrap_or(0)
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
                if p == b"stat" {
                    let n = fired(ctx);
                    let g = ctx.get_secret(LASTGET).unwrap_or_else(|| b"none".to_vec());
                    return Ok(reply(format!(
                        "fired={n} get={}",
                        String::from_utf8_lossy(&g)
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
            InboundDelegateMsg::WakeupFired { .. } => {
                let n = fired(ctx) + 1;
                ctx.set_secret(FIRED, &n.to_le_bytes());
                Ok(vec![])
            }
            _ => Ok(vec![]),
        }
    }
}
