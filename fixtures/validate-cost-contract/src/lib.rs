//! Measurement fixture, not a Craftec contract. **Never deploy this.**
//!
//! It exists to answer one question the source can only half-answer: when the
//! host re-runs `validate_state` over the full state after every
//! `update_state`, what does that actually cost, and how does it scale?
//!
//! Shape:
//! - **State** is a raw append-only byte string. No framing, so state length is
//!   exactly the quantity validation cost should track.
//! - **Params** are `[mode, repeat_le32, salt..]`. The salt is load-bearing:
//!   a contract's key is `hash(code, params)`, so without it every run with the
//!   same settings addresses the SAME instance and the seed put silently
//!   becomes a merge into the previous run's state.
//!   - `mode = 0` — `validate_state` does the proportional work, `update_state`
//!     is cheap. This is the shape a signature-checking Set has.
//!   - `mode = 1` — the mirror: `update_state` does the work, `validate_state`
//!     is trivial. Running both separates "the host re-validates" from "the
//!     merge itself is expensive", which a single arm cannot.
//!   - `repeat` — how many BLAKE3 passes over the whole state per call. The
//!     calibration constant; the harness reports it beside every table.
//! - **Deltas** are tagged by their first byte:
//!   - `0x01` — append the remainder. State grows.
//!   - `0xFF` — NO-OP: return the current state unchanged, whatever follows.
//!     The tail can vary, which is the point: distinct bytes with an identical
//!     outcome is the one shape the node's `broadcast_dedup_cache` cannot
//!     collapse (it hashes the payload, not the result), so this is how a
//!     no-op reaches `update_state` at all.
//!
//! Work is BLAKE3 over the entire state, `repeat` times, with the digest folded
//! back into the next pass so nothing can be optimised away or hoisted.

use freenet_stdlib::prelude::*;

/// Delta tags.
const TAG_APPEND: u8 = 0x01;
const TAG_NOOP: u8 = 0xFF;

/// `[mode, repeat_le32, salt..]`; anything shorter is rejected rather than
/// defaulted, so a mis-encoded fixture fails loudly instead of measuring the
/// wrong thing. Bytes past the first five are the per-run salt and are not read.
fn params_of(p: &[u8]) -> Option<(u8, u32)> {
    if p.len() < 5 {
        return None;
    }
    Some((p[0], u32::from_le_bytes(p[1..5].try_into().ok()?)))
}

/// BLAKE3 over the whole state, `repeat` times, chained so the optimiser
/// cannot drop passes or hoist them out of the loop.
fn burn(state: &[u8], repeat: u32) -> u8 {
    let mut carry = [0u8; 32];
    for _ in 0..repeat {
        let mut h = blake3::Hasher::new();
        h.update(&carry);
        h.update(state);
        carry = *h.finalize().as_bytes();
    }
    carry[0]
}

pub struct ValidateCost;

#[contract]
impl ContractInterface for ValidateCost {
    fn validate_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        _related: RelatedContracts<'static>,
    ) -> Result<ValidateResult, ContractError> {
        let Some((mode, repeat)) = params_of(parameters.as_ref()) else {
            return Ok(ValidateResult::Invalid);
        };
        if mode == 0 {
            // Fold the result into the verdict so the work is load-bearing.
            if burn(state.as_ref(), repeat) == 0xAB && state.as_ref().is_empty() {
                return Ok(ValidateResult::Invalid);
            }
        }
        Ok(ValidateResult::Valid)
    }

    fn update_state(
        parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        let Some((mode, repeat)) = params_of(parameters.as_ref()) else {
            return Err(ContractError::InvalidUpdate);
        };
        let mut next = state.as_ref().to_vec();
        for item in data {
            // A full state is ADOPTED wholesale — it is not a tagged delta.
            // The host hands `update_state` an `UpdateData::State` on the
            // merge path of a PUT, so tag-parsing it rejects every re-put.
            let bytes = match &item {
                UpdateData::State(s) => {
                    next = s.as_ref().to_vec();
                    continue;
                }
                UpdateData::Delta(d) => d.as_ref(),
                UpdateData::StateAndDelta { state, .. } => {
                    next = state.as_ref().to_vec();
                    continue;
                }
                _ => continue,
            };
            match bytes.first() {
                // A no-op that still had to be merged to be recognised as one:
                // exactly what the host cannot know before calling us.
                Some(&TAG_NOOP) => {}
                Some(&TAG_APPEND) => next.extend_from_slice(&bytes[1..]),
                _ => return Err(ContractError::InvalidUpdate),
            }
        }
        if mode == 1 && burn(&next, repeat) == 0xAB && next.is_empty() {
            return Err(ContractError::InvalidUpdate);
        }
        Ok(UpdateModification::valid(State::from(next)))
    }

    /// Length-prefixed, so a summary is cheap and says nothing about content.
    fn summarize_state(
        _parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        Ok(StateSummary::from(
            (state.as_ref().len() as u64).to_le_bytes().to_vec(),
        ))
    }

    /// Everything past the peer's known length. Cheap by construction.
    fn get_state_delta(
        _parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        let known = summary
            .as_ref()
            .try_into()
            .map(u64::from_le_bytes)
            .unwrap_or(0) as usize;
        let s = state.as_ref();
        if known >= s.len() {
            return Ok(StateDelta::from(Vec::new()));
        }
        let mut d = vec![TAG_APPEND];
        d.extend_from_slice(&s[known..]);
        Ok(StateDelta::from(d))
    }
}
