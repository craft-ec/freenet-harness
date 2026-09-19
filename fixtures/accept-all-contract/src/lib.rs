//! Measurement fixture, not a Craftec contract. **Never deploy this.**
//!
//! It accepts any state from anyone, which is exactly what makes it useless as
//! a contract and useful as a control: it is the smallest wasm the node will
//! load, so putting the same bodies under it and under `block.wasm` isolates
//! what a put costs for the *contract code* from what it costs for the *body*.
//!
//! Every `ContractRequest::Put` carries the whole contract, so a put of a 4 KiB
//! body under a 123 KiB contract puts ~127 KiB on the wire. Whether that is
//! what makes puts expensive is the question this fixture exists to answer, and
//! it can only be answered by a second contract of a very different size.

use freenet_stdlib::prelude::*;

pub struct AcceptAll;

#[contract]
impl ContractInterface for AcceptAll {
    /// Everything is valid. A real contract must never do this.
    fn validate_state(
        _parameters: Parameters<'static>,
        _state: State<'static>,
        _related: RelatedContracts<'static>,
    ) -> Result<ValidateResult, ContractError> {
        Ok(ValidateResult::Valid)
    }

    /// First state wins, like a Block, so a put is a first write and a repeat
    /// is a no-op — the same shape the measurement assumes.
    fn update_state(
        _parameters: Parameters<'static>,
        state: State<'static>,
        data: Vec<UpdateData<'static>>,
    ) -> Result<UpdateModification<'static>, ContractError> {
        if !state.as_ref().is_empty() {
            return Ok(UpdateModification::valid(state));
        }
        for item in data {
            let bytes = match &item {
                UpdateData::State(s) => s.as_ref(),
                UpdateData::Delta(d) => d.as_ref(),
                UpdateData::StateAndDelta { state, .. } => state.as_ref(),
                _ => continue,
            };
            if !bytes.is_empty() {
                return Ok(UpdateModification::valid(State::from(bytes.to_vec())));
            }
        }
        Ok(UpdateModification::valid(state))
    }

    /// One byte: held or not. Enough for the node to decide whether to send.
    fn summarize_state(
        _parameters: Parameters<'static>,
        state: State<'static>,
    ) -> Result<StateSummary<'static>, ContractError> {
        Ok(StateSummary::from(vec![u8::from(
            !state.as_ref().is_empty(),
        )]))
    }

    fn get_state_delta(
        _parameters: Parameters<'static>,
        state: State<'static>,
        summary: StateSummary<'static>,
    ) -> Result<StateDelta<'static>, ContractError> {
        if summary.as_ref() == [1] || state.as_ref().is_empty() {
            return Ok(StateDelta::from(Vec::new()));
        }
        Ok(StateDelta::from(state.as_ref().to_vec()))
    }
}
