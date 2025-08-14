use crate::error::ContractError;
use crate::state::config::Config;
use crate::state::staking::BtcDelegation;
use babylon_apis::btc_staking_api::{ActiveBtcDelegation, NewFinalityProvider};
use bitcoin::Transaction;

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

pub fn verify_undelegation(_cfg: &Config, _btc_del: &BtcDelegation) -> Result<(), ContractError> {
    // No-op
    Ok(())
}
