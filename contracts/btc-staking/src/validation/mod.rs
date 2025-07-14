#[cfg(feature = "full-validation")]
mod full;

use crate::state::config::Params;
use crate::{error::ContractError, state::staking::BtcDelegation};
use babylon_apis::btc_staking_api::{ActiveBtcDelegation, NewFinalityProvider};
use bitcoin::Transaction;
use cosmwasm_std::Binary;

/// Verifies the new finality provider data (full validation version).
// TODO: fix contract size when full-validation is enabled
#[cfg(feature = "full-validation")]
pub fn verify_new_fp(new_fp: &NewFinalityProvider) -> Result<(), ContractError> {
    self::full::verify_new_fp(new_fp)
}

#[cfg(not(feature = "full-validation"))]
pub fn verify_new_fp(_new_fp: &NewFinalityProvider) -> Result<(), ContractError> {
    // No-op
    Ok(())
}

/// Verifies the active delegation data.
#[cfg(feature = "full-validation")]
// TODO: fix contract size when full-validation is enabled
pub fn verify_active_delegation(
    params: &Params,
    active_delegation: &ActiveBtcDelegation,
    staking_tx: &Transaction,
) -> Result<(), ContractError> {
    self::full::verify_active_delegation(params, active_delegation, staking_tx)
}

#[cfg(not(feature = "full-validation"))]
pub fn verify_active_delegation(
    _params: &Params,
    _active_delegation: &ActiveBtcDelegation,
    _staking_tx: &Transaction,
) -> Result<(), ContractError> {
    // No-op
    Ok(())
}

#[cfg(feature = "full-validation")]
// TODO: fix contract size when full-validation is enabled
pub fn verify_undelegation(
    params: &Params,
    btc_del: &BtcDelegation,
    sig: &Binary,
) -> Result<(), ContractError> {
    self::full::verify_undelegation(params, btc_del, sig)
}

#[cfg(not(feature = "full-validation"))]
pub fn verify_undelegation(
    _params: &Params,
    _btc_del: &BtcDelegation,
    _sig: &Binary,
) -> Result<(), ContractError> {
    // No-op
    Ok(())
}

#[cfg(feature = "full-validation")]
// TODO: fix contract size when full-validation is enabled
pub fn verify_slashed_delegation(
    active_delegation: &BtcDelegation,
    slashed_fp_sk_hex: &str,
) -> Result<(), ContractError> {
    self::full::verify_slashed_delegation(active_delegation, slashed_fp_sk_hex)
}

#[cfg(not(feature = "full-validation"))]
pub fn verify_slashed_delegation(
    _active_delegation: &BtcDelegation,
    _slashed_fp_sk_hex: &str,
) -> Result<(), ContractError> {
    // No-op
    Ok(())
}
