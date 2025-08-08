use crate::{
    error::ContractError,
    state::{config::Config, staking::BtcDelegation},
};
use babylon_apis::btc_staking_api::{ActiveBtcDelegation, NewFinalityProvider};
use bitcoin::Transaction;
use cosmwasm_std::Binary;

pub fn verify_new_fp(_new_fp: &NewFinalityProvider) -> Result<(), ContractError> {
    // No-op
    Ok(())
}

pub fn verify_active_delegation(
    _cfg: &Config,
    _active_delegation: &ActiveBtcDelegation,
    _staking_tx: &Transaction,
) -> Result<(), ContractError> {
    // No-op
    Ok(())
}

pub fn verify_undelegation(
    _cfg: &Config,
    _btc_del: &BtcDelegation,
    _sig: &Binary,
) -> Result<(), ContractError> {
    // No-op
    Ok(())
}
