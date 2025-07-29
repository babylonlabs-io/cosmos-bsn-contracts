use crate::state::config::Params;
use crate::{error::ContractError, state::staking::BtcDelegation};
use babylon_apis::btc_staking_api::{ActiveBtcDelegation, NewFinalityProvider};
use bitcoin::Transaction;
use cosmwasm_std::Binary;

pub fn verify_new_fp(_new_fp: &NewFinalityProvider) -> Result<(), ContractError> {
    // No-op
    Ok(())
}

pub fn verify_active_delegation(
    _params: &Params,
    _active_delegation: &ActiveBtcDelegation,
    _staking_tx: &Transaction,
) -> Result<(), ContractError> {
    // No-op
    Ok(())
}

pub fn verify_undelegation(
    _params: &Params,
    _btc_del: &BtcDelegation,
    _sig: &Binary,
) -> Result<(), ContractError> {
    // No-op
    Ok(())
}

pub fn verify_slashed_delegation(
    _active_delegation: &BtcDelegation,
    _slashed_fp_sk_hex: &str,
) -> Result<(), ContractError> {
    // No-op
    Ok(())
}
