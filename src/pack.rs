//! `pack`: what a PACK block may carry, held against a live node.
//!
//! PACK is a block KIND, not a contract — there is no `pack.wasm`. So every
//! case here is a Block put on the block path, and what is being measured is
//! which of them the node keeps.
//!
//! Each refusal is paired with the control that differs in exactly the one
//! offending property, because "the node did not store it" is also what a
//! broken fixture, a wrong key and a dropped request look like. The sharpest
//! pair is PARITY: since freenet-contracts#29 a parity body is ACCEPTED as its
//! own Block (length-only rule) and is still REFUSED as a pack member. Nothing
//! but a paired run can show that the member-kind list is its own rule rather
//! than a restatement of `well_formed`.

use std::{sync::Arc, time::Duration};

use anyhow::{anyhow, bail, Result};
use craftec_block_contract as block;
use freenet_prolly::node::{NodeBuilder, Value};
use freenet_stdlib::{
    client_api::{ClientRequest, ContractRequest, ContractResponse, HostResponse, WebApi},
    prelude::*,
};
use tokio::time::timeout;

use crate::latency::send_req;

/// Every wait in this run. Local mode answers in tens of milliseconds; two
/// seconds is the deadline at which a missing answer is recorded as missing.
const STEP: Duration = Duration::from_secs(2);

/// Write a pack body member for member, in the order given.
///
/// [`block::pack::build`] sorts and DE-DUPLICATES, which is right for a caller
/// and useless here: the cases that matter are the ones a correct builder
/// refuses to produce. This is the harness's own encoder, and
/// `the_hand_encoder_agrees_with_build` is what stops it becoming a second
/// opinion about the format.
fn wire(members: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::from(&block::pack::MAGIC[..]);
    out.extend_from_slice(&(members.len() as u16).to_le_bytes());
    for (k, b) in members {
        out.push(*k);
        out.extend_from_slice(&(b.len() as u32).to_le_bytes());
        out.extend_from_slice(b);
    }
    out
}

/// Members in the order the format requires: ascending by their own block id.
fn ordered(members: &[(u8, Vec<u8>)]) -> Vec<(u8, Vec<u8>)> {
    let mut v = members.to_vec();
    v.sort_by_key(|(k, b)| freenet_prolly::block_id(*k, b));
    v
}

/// A pack state built by the harness's own encoder, in wire order.
fn packed(members: &[(u8, Vec<u8>)]) -> Vec<u8> {
    block::encode(block::kind::PACK, &wire(&ordered(members)))
}

/// A RAW member whose bytes are this run's alone, so every case gets a key no
/// node has seen and no earlier run can have answered for.
fn raw(salt: &[u8; 8], tag: &str) -> (u8, Vec<u8>) {
    let mut b = tag.as_bytes().to_vec();
    b.extend_from_slice(salt);
    (block::kind::RAW, b)
}

/// A leaf the tree library itself produced — two entries sharing the prefix
/// `k/`, salted so it is this run's node.
fn leaf(salt: &[u8; 8]) -> Result<Vec<u8>> {
    let hex: String = salt.iter().map(|b| format!("{b:02x}")).collect();
    let mut b = NodeBuilder::leaf();
    for (k, v) in [("a", "one"), ("b", "two")] {
        b.push(
            format!("k/{k}{hex}").as_bytes(),
            Value::Inline(v.as_bytes()),
        )
        .map_err(|e| anyhow!("building the fixture leaf: {e:?}"))?;
    }
    b.finish()
        .map_err(|e| anyhow!("finishing the fixture leaf: {e:?}"))
}

/// The same node with one interior byte flipped: still node-shaped, no longer
/// a node. A member that is invalid for a reason only a parse can find.
fn corrupted(node: &[u8]) -> Vec<u8> {
    let mut v = node.to_vec();
    let at = v.len() / 2;
    v[at] ^= 0xff;
    v
}

/// One thing offered to the node, and what must happen to it.
struct Case {
    name: String,
    state: Vec<u8>,
    /// `true` = the node must keep it and read it back byte-exact.
    keep: bool,
}

fn case(name: impl Into<String>, state: Vec<u8>, keep: bool) -> Case {
    Case {
        name: name.into(),
        state,
        keep,
    }
}

/// Offer one state and report whether the node kept it.
///
/// A block's params ARE the hash of its state, so each case addresses its own
/// contract and no case can answer for another.
async fn offer(
    client: &mut WebApi,
    code: &Arc<ContractCode<'static>>,
    state: &[u8],
) -> Result<Offer> {
    let params = Parameters::from(blake3::hash(state).as_bytes().to_vec());
    let contract = ContractContainer::Wasm(ContractWasmAPIVersion::V1(WrappedContract::new(
        code.clone(),
        params,
    )));
    let key = contract.key();
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
    .await?;
    // The PUT answer is recorded, not gated on: a refusal may arrive as an
    // error, as nothing at all, or as an acknowledgement the node then declines
    // to honour, and which of those it is turns out to differ between cases.
    // What settles the question is whether the bytes can be read back, which is
    // the same gate the rest of the harness uses.
    let put = match timeout(STEP, client.recv()).await {
        Ok(Ok(HostResponse::ContractResponse(ContractResponse::PutResponse { .. }))) => "ack",
        Ok(Ok(_)) => "other",
        Ok(Err(_)) => "error",
        Err(_) => "silence",
    };
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
    let deadline = std::time::Instant::now() + STEP;
    while let Some(left) = deadline.checked_duration_since(std::time::Instant::now()) {
        match timeout(left, client.recv()).await {
            Ok(Ok(HostResponse::ContractResponse(ContractResponse::GetResponse {
                key: k,
                state: got,
                ..
            }))) if k.id() == key.id() => {
                return Ok(Offer {
                    put,
                    readable: got.as_ref() == state,
                })
            }
            Ok(Ok(_)) => continue,
            _ => break,
        }
    }
    Ok(Offer {
        put,
        readable: false,
    })
}

/// What the node did with one offered state: how it answered the PUT, and
/// whether the bytes could then be read back.
struct Offer {
    put: &'static str,
    readable: bool,
}

fn verdict(ok: bool) -> &'static str {
    if ok {
        "PASS"
    } else {
        "FAIL"
    }
}

pub async fn run(ws: &str, wasm: &str, expect_sha: &str, wait: Duration) -> Result<()> {
    let _ = wait;
    let bytes = crate::wasm_check::load(wasm, expect_sha)?;
    let code = Arc::new(ContractCode::from(bytes));

    let mut salt = [0u8; 8];
    getrandom::getrandom(&mut salt)?;
    let node = leaf(&salt)?;
    let bad = corrupted(&node);
    let one = raw(&salt, "one");
    let two = raw(&salt, "two");
    let good_node = (block::kind::TREE_NODE, node.clone());
    let bad_node = (block::kind::TREE_NODE, bad.clone());
    let parity_body = {
        let mut v = b"parity".to_vec();
        v.extend_from_slice(&salt);
        v
    };

    // A fixture that is wrong in the same direction as the bug it looks for
    // proves nothing, so every premise this run depends on is asserted before
    // the node is asked anything.
    if node == bad {
        bail!("the corrupted node equals the good one — the fixture cannot refuse anything");
    }
    let pair = [one.clone(), two.clone()];
    let built = block::pack::build(&pair)
        .map_err(|e| anyhow!("pack::build refused the control pair: {e:?}"))?;
    if built != wire(&ordered(&pair)) {
        bail!("the hand encoder disagrees with pack::build — the negative cases mean nothing");
    }

    let mut cases = vec![
        case(
            "a valid pack: two RAW members and a TREE_NODE",
            packed(&[one.clone(), two.clone(), good_node.clone()]),
            true,
        ),
        case(
            "a member that is not a node: the SAME pack, one byte of the node flipped",
            packed(&[one.clone(), two.clone(), bad_node.clone()]),
            false,
        ),
        case(
            "  CONTROL — those corrupted bytes as their OWN Block",
            block::encode(block::kind::TREE_NODE, &bad),
            false,
        ),
        case(
            "  CONTROL — the same bytes uncorrupted, as their own Block",
            block::encode(block::kind::TREE_NODE, &node),
            true,
        ),
        case(
            "a duplicate member: the same RAW block twice",
            packed(&[one.clone(), one.clone()]),
            false,
        ),
        case(
            "  CONTROL — two members, same shape, different bodies",
            packed(&[one.clone(), two.clone()]),
            true,
        ),
        case(
            "a pack inside a pack",
            packed(&[
                one.clone(),
                (
                    block::kind::PACK,
                    wire(&ordered(std::slice::from_ref(&two))),
                ),
            ]),
            false,
        ),
        case(
            "a PARITY member",
            packed(&[one.clone(), (block::kind::PARITY, parity_body.clone())]),
            false,
        ),
        case(
            "  CONTROL — that SAME parity body as its own Block (#29: length-only)",
            block::encode(block::kind::PARITY, &parity_body),
            true,
        ),
    ];

    // Kinds whose formats have not landed: refused as members and as blocks.
    // Both doors, because a rule that held at one and not the other would be
    // invisible from either on its own.
    for (name, k) in [
        ("MEDIA_CHUNK", block::kind::MEDIA_CHUNK),
        ("FRAGMENT", block::kind::FRAGMENT),
        ("SCHEMA", block::kind::SCHEMA),
    ] {
        let body = {
            let mut v = name.as_bytes().to_vec();
            v.extend_from_slice(&salt);
            v
        };
        cases.push(case(
            format!("an un-landed kind as a member: {name}"),
            packed(&[one.clone(), (k, body.clone())]),
            false,
        ));
        cases.push(case(
            format!("  CONTROL — {name} as its own Block, still refused"),
            block::encode(k, &body),
            false,
        ));
    }

    // The parity length boundary, on the block path. MAX_PARITY is a ceiling
    // the rule is made of, so it has to be exercised ON the bound and one byte
    // past it; a fixture in the interior would pass with the check deleted.
    let mut at_cap = vec![0u8; block::MAX_PARITY];
    at_cap[..8].copy_from_slice(&salt);
    let mut over_cap = vec![0u8; block::MAX_PARITY + 1];
    over_cap[..8].copy_from_slice(&salt);
    cases.push(case(
        format!(
            "a PARITY body of exactly MAX_PARITY ({}) bytes",
            block::MAX_PARITY
        ),
        block::encode(block::kind::PARITY, &at_cap),
        true,
    ));
    cases.push(case(
        "a PARITY body one byte over MAX_PARITY",
        block::encode(block::kind::PARITY, &over_cap),
        false,
    ));

    // The contract's own `check`, run in-process on every case before the node
    // is asked. Two jobs: a case the harness built wrong shows up as a fixture
    // error rather than as a verdict about the node, and a disagreement
    // between this crate and the compiled artefact is exactly the stale-wasm
    // failure `--expect-sha` exists for, one level deeper.
    for c in &cases {
        let params = blake3::hash(&c.state).as_bytes().to_vec();
        let said = block::check(&params, &c.state);
        if said != c.keep {
            bail!(
                "fixture error: the linked contract says check()={said} for {:?}, \
                 but this run expects keep={}. Either the case is built wrong or the \
                 crate and build/block.wasm have diverged.",
                c.name,
                c.keep
            );
        }
    }

    println!(
        "{} cases, salt {}  (every case is its own contract: a block's key IS the hash of its state)",
        cases.len(),
        salt.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );

    let mut client = crate::connect(ws).await?;
    let mut failed = 0usize;
    for (i, c) in cases.iter().enumerate() {
        let o = offer(&mut client, &code, &c.state).await?;
        let ok = o.readable == c.keep;
        if !ok {
            failed += 1;
        }
        println!(
            "{:>2}. {}: {}  (expected {}, node {} it; put answer: {}; state {} B)",
            i + 1,
            c.name,
            verdict(ok),
            if c.keep { "kept" } else { "refused" },
            if o.readable { "kept" } else { "refused" },
            o.put,
            c.state.len()
        );
    }

    println!();
    if failed == 0 {
        println!("pack acceptance: PASS ({} cases)", cases.len());
        Ok(())
    } else {
        bail!("pack acceptance: FAIL ({failed} of {} cases)", cases.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn members() -> Vec<(u8, Vec<u8>)> {
        vec![
            (block::kind::RAW, b"one".to_vec()),
            (block::kind::RAW, b"two".to_vec()),
            (block::kind::TREE_NODE, leaf(&[7u8; 8]).unwrap()),
        ]
    }

    /// The hand encoder exists to write packs `build` refuses to produce. It is
    /// only worth anything if it agrees with `build` everywhere `build` will
    /// speak — otherwise a refusal says "the harness cannot encode", not "the
    /// contract refuses this".
    #[test]
    fn the_hand_encoder_agrees_with_build() {
        let m = members();
        assert_eq!(wire(&ordered(&m)), block::pack::build(&m).unwrap());
    }

    /// And the packs it builds are ones the contract accepts, so a FAIL in the
    /// run is about the node rather than about this file.
    #[test]
    fn a_hand_encoded_pack_is_accepted_by_the_contract() {
        let s = packed(&members());
        assert!(block::check(blake3::hash(&s).as_bytes(), &s));
    }

    /// Ordering is by block id, not by the order given: two callers listing the
    /// same set differently must produce the same bytes.
    #[test]
    fn the_order_given_does_not_change_the_pack() {
        let m = members();
        let mut r = m.clone();
        r.reverse();
        assert_eq!(packed(&m), packed(&r));
    }

    /// The duplicate case has to be a pack of TWO members that differs from the
    /// one-member pack — a hand encoder that quietly de-duplicated would make
    /// the case vacuous and it would still print "refused".
    #[test]
    fn the_duplicate_fixture_really_contains_the_member_twice() {
        let one = (block::kind::RAW, b"one".to_vec());
        let dup = packed(&[one.clone(), one.clone()]);
        assert_eq!(u16::from_le_bytes([dup[5], dup[6]]), 2, "count must be 2");
        assert_ne!(dup, packed(&[one]));
        assert!(!block::check(blake3::hash(&dup).as_bytes(), &dup));
    }

    /// The premise of the sharpest pair in the run.
    #[test]
    fn parity_is_a_block_but_never_a_member() {
        let body = b"parity bytes".to_vec();
        let alone = block::encode(block::kind::PARITY, &body);
        assert!(
            block::check(blake3::hash(&alone).as_bytes(), &alone),
            "since #29 a parity body is a valid Block on its own"
        );
        let inside = packed(&[
            (block::kind::RAW, b"x".to_vec()),
            (block::kind::PARITY, body),
        ]);
        assert!(
            !block::check(blake3::hash(&inside).as_bytes(), &inside),
            "and is still not packable"
        );
    }

    #[test]
    fn a_corrupted_node_is_refused_at_both_doors() {
        let node = leaf(&[3u8; 8]).unwrap();
        let bad = corrupted(&node);
        assert_ne!(node, bad);
        let good_block = block::encode(block::kind::TREE_NODE, &node);
        let bad_block = block::encode(block::kind::TREE_NODE, &bad);
        assert!(block::check(
            blake3::hash(&good_block).as_bytes(),
            &good_block
        ));
        assert!(!block::check(
            blake3::hash(&bad_block).as_bytes(),
            &bad_block
        ));
        let in_pack = packed(&[
            (block::kind::RAW, b"x".to_vec()),
            (block::kind::TREE_NODE, bad),
        ]);
        assert!(!block::check(blake3::hash(&in_pack).as_bytes(), &in_pack));
    }
}
