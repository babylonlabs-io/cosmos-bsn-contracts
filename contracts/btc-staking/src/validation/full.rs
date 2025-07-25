use crate::state::config::Params;
use crate::{error::ContractError, state::staking::BtcDelegation};
use babylon_apis::btc_staking_api::{ActiveBtcDelegation, NewFinalityProvider};
use bitcoin::Transaction;
use cosmwasm_std::Binary;
use {
    babylon_btcstaking::staking::enc_verify_transaction_sig_with_output,
    babylon_schnorr_adaptor_signature::AdaptorSignature,
    bitcoin::consensus::deserialize,
    k256::schnorr::{Signature, VerifyingKey},
};

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum FullValidationError {
    #[error("Covenant public key not found in params")]
    MissingCovenantPublicKeyInParams,

    #[error("Failed to parse slashing rate: {0}")]
    InvalidSlashingRate(#[from] std::num::ParseFloatError),

    #[error("Unbonding transaction must spend staking output")]
    UnbondingTxMustSpendStakingOutput,

    #[error("Invalid BTC sig type: {0}")]
    InvalidBtcSigType(String),

    #[error("The finality provider corresponding to signing key {0} is not among the staker's delegated FPs.")]
    FpNotInDelegationList(String),
}

/// Verifies the new finality provider data.
/// TODO: Implement validation logic for the new finality provider.
pub fn verify_new_fp(new_fp: &NewFinalityProvider) -> Result<(), ContractError> {
    verifying_key_from_hex(&new_fp.btc_pk_hex)?;

    Ok(())
}

fn verifying_key_from_hex(v: impl AsRef<[u8]>) -> Result<VerifyingKey, ContractError> {
    let pk_bytes = hex::decode(v)?;
    VerifyingKey::from_bytes(&pk_bytes).map_err(Into::into)
}

fn decode_pks(
    staker_pk_hex: &str,
    fp_pk_hex_list: &[String],
    cov_pk_hex_list: &[String],
) -> Result<(VerifyingKey, Vec<VerifyingKey>, Vec<VerifyingKey>), ContractError> {
    let staker_pk = verifying_key_from_hex(staker_pk_hex)?;

    let fp_pks: Vec<VerifyingKey> = fp_pk_hex_list
        .iter()
        .map(verifying_key_from_hex)
        .collect::<Result<Vec<_>, _>>()?;

    let cov_pks: Vec<VerifyingKey> = cov_pk_hex_list
        .iter()
        .map(verifying_key_from_hex)
        .collect::<Result<Vec<_>, _>>()?;

    Ok((staker_pk, fp_pks, cov_pks))
}

/// Verifies the active delegation data.
pub fn verify_active_delegation(
    params: &Params,
    active_delegation: &ActiveBtcDelegation,
    staking_tx: &Transaction,
) -> Result<(), ContractError> {
    let (staker_pk, fp_pks, cov_pks) = decode_pks(
        &active_delegation.btc_pk_hex,
        &active_delegation.fp_btc_pk_list,
        &params.covenant_pks,
    )?;

    // Check if data provided in request, matches data to which staking tx is
    // committed

    // TODO: Check staking tx time-lock has correct values (#7.1)
    // get start_height and end_height of the time-lock

    // TODO: Ensure staking tx is k-deep (#7.1)

    // TODO: Ensure staking tx time-lock has more than w BTC blocks left (#7.1)

    // TODO: Verify staking tx info, i.e. inclusion proof (#7.1)

    // Check slashing tx and its consistency with staking tx
    let slashing_tx: Transaction = deserialize(&active_delegation.slashing_tx)?;

    // decode slashing address
    let slashing_pk_script = hex::decode(&params.slashing_pk_script)?;

    // Check slashing tx and staking tx are valid and consistent
    let slashing_rate = params
        .slashing_rate()
        .map_err(FullValidationError::InvalidSlashingRate)?;

    babylon_btcstaking::staking::check_slashing_tx_match_funding_tx(
        &slashing_tx,
        staking_tx,
        active_delegation.staking_output_idx,
        params.min_slashing_tx_fee_sat,
        slashing_rate,
        &slashing_pk_script,
        &staker_pk,
        active_delegation.unbonding_time as u16,
    )?;

    /*
        verify staker signature against slashing path of the staking tx script
    */

    // get the slashing path script
    let staking_output = &staking_tx.output[active_delegation.staking_output_idx as usize];
    let staking_time = (active_delegation.end_height - active_delegation.start_height) as u16;
    let babylon_script_paths = babylon_btcstaking::types::BabylonScriptPaths::new(
        &staker_pk,
        &fp_pks,
        &cov_pks,
        params.covenant_quorum as usize,
        staking_time,
    )?;

    // get the staker's signature on the slashing tx
    let staker_sig =
        k256::schnorr::Signature::try_from(active_delegation.delegator_slashing_sig.as_slice())?;

    // Verify the staker's signature
    babylon_btcstaking::staking::verify_transaction_sig_with_output(
        &slashing_tx,
        staking_output,
        babylon_script_paths.slashing_path_script(),
        &staker_pk,
        &staker_sig,
    )?;

    /*
        Verify covenant signatures over slashing tx
    */
    for cov_sig in active_delegation.covenant_sigs.iter() {
        let cov_pk = VerifyingKey::from_bytes(&cov_sig.cov_pk)?;
        if !params.contains_covenant_pk(&cov_pk) {
            return Err(FullValidationError::MissingCovenantPublicKeyInParams.into());
        }
        for (sig, fp_pk) in cov_sig.adaptor_sigs.iter().zip(fp_pks.iter()) {
            enc_verify_transaction_sig_with_output(
                &slashing_tx,
                staking_output,
                babylon_script_paths.slashing_path_script(),
                &cov_pk,
                fp_pk,
                &AdaptorSignature::new(sig.as_slice())?,
            )?;
        }
    }

    // TODO: Check unbonding time (staking time from unbonding tx) is larger than min unbonding time (#7.1)
    // which is larger value from:
    // - MinUnbondingTime
    // - CheckpointFinalizationTimeout

    // At this point, we know that unbonding time in request:
    // - is larger than min unbonding time
    // - is smaller than math.MaxUint16 (due to check in req.ValidateBasic())

    /*
        Early unbonding logic
    */

    let unbonding_tx: Transaction = deserialize(&active_delegation.undelegation_info.unbonding_tx)?;

    // Check that the unbonding tx input is pointing to staking tx
    if unbonding_tx.input[0].previous_output.txid != staking_tx.compute_txid()
        || unbonding_tx.input[0].previous_output.vout != active_delegation.staking_output_idx
    {
        return Err(FullValidationError::UnbondingTxMustSpendStakingOutput.into());
    }

    // TODO: Check unbonding tx fees against staking tx (#7.1)
    // - Fee is greater than 0.
    // - Unbonding output value is at least `MinUnbondingValue` percentage of staking output value.

    // TODO: Ensure the unbonding tx has valid unbonding output, and get the unbonding output (#7.1)
    // index (#7.1)
    let unbonding_output_idx = 0;
    let unbonding_output = &unbonding_tx.output[unbonding_output_idx as usize];

    let unbonding_slashing_tx: Transaction =
        deserialize(&active_delegation.undelegation_info.slashing_tx)?;

    // Check that unbonding tx and unbonding slashing tx are consistent
    babylon_btcstaking::staking::check_slashing_tx_match_funding_tx(
        &unbonding_slashing_tx,
        &unbonding_tx,
        unbonding_output_idx,
        params.min_slashing_tx_fee_sat,
        slashing_rate,
        &slashing_pk_script,
        &staker_pk,
        active_delegation.unbonding_time as u16,
    )?;

    /*
        Check staker signature against slashing path of the unbonding tx
    */
    // get the staker's signature on the unbonding slashing tx
    let unbonding_slashing_sig = active_delegation
        .undelegation_info
        .delegator_slashing_sig
        .as_slice();
    let unbonding_slashing_sig = k256::schnorr::Signature::try_from(unbonding_slashing_sig)?;
    // The unbonding slashing and regular slashing share the same script structure,
    // the only difference is in the timelock value.
    let unbonding_slashing_path_script = babylon_script_paths.slashing_path_script();

    // Verify the staker's signature
    babylon_btcstaking::staking::verify_transaction_sig_with_output(
        &unbonding_slashing_tx,
        &unbonding_tx.output[unbonding_output_idx as usize],
        unbonding_slashing_path_script,
        &staker_pk,
        &unbonding_slashing_sig,
    )?;

    /*
        verify covenant signatures over unbonding tx
    */
    let unbonding_path_script = babylon_script_paths.unbonding_path_script.as_script();
    for cov_sig in active_delegation
        .undelegation_info
        .covenant_unbonding_sig_list
        .iter()
    {
        // get covenant public key
        let cov_pk = VerifyingKey::from_bytes(&cov_sig.pk)?;
        if !params.contains_covenant_pk(&cov_pk) {
            return Err(FullValidationError::MissingCovenantPublicKeyInParams.into());
        }
        // get covenant signature
        let sig = Signature::try_from(cov_sig.sig.as_slice())?;
        // Verify the covenant member's signature
        babylon_btcstaking::staking::verify_transaction_sig_with_output(
            staking_tx,
            staking_output,
            unbonding_path_script,
            &cov_pk,
            &sig,
        )?;
    }

    /*
        Verify covenant signatures over unbonding slashing tx
    */
    for cov_sig in active_delegation
        .undelegation_info
        .covenant_slashing_sigs
        .iter()
    {
        let cov_pk = VerifyingKey::from_bytes(&cov_sig.cov_pk)?;
        if !params.contains_covenant_pk(&cov_pk) {
            return Err(FullValidationError::MissingCovenantPublicKeyInParams.into());
        }
        for (sig, fp_pk) in cov_sig.adaptor_sigs.iter().zip(fp_pks.iter()) {
            enc_verify_transaction_sig_with_output(
                &unbonding_slashing_tx,
                unbonding_output,
                unbonding_slashing_path_script,
                &cov_pk,
                fp_pk,
                &AdaptorSignature::new(sig.as_slice())?,
            )?;
        }
    }

    Ok(())
}

pub fn verify_undelegation(
    params: &Params,
    btc_del: &BtcDelegation,
    staker_sig: &Binary,
) -> Result<(), ContractError> {
    /*
        Verify the signature on the unbonding tx is from the delegator
    */

    let (staker_pk, fp_pks, cov_pks) = decode_pks(
        &btc_del.btc_pk_hex,
        &btc_del.fp_btc_pk_list,
        &params.covenant_pks,
    )?;

    // get the unbonding path script
    let staking_tx: Transaction = deserialize(&btc_del.staking_tx)?;
    let staking_output = &staking_tx.output[btc_del.staking_output_idx as usize];
    let staking_time = (btc_del.end_height - btc_del.start_height) as u16;
    let babylon_script_paths = babylon_btcstaking::types::BabylonScriptPaths::new(
        &staker_pk,
        &fp_pks,
        &cov_pks,
        params.covenant_quorum as usize,
        staking_time,
    )?;
    let unbonding_path_script = babylon_script_paths.unbonding_path_script;

    let unbonding_tx: Transaction = deserialize(&btc_del.undelegation_info.unbonding_tx)?;

    // Verify the signature
    babylon_btcstaking::staking::verify_transaction_sig_with_output(
        &unbonding_tx,
        staking_output,
        unbonding_path_script.as_script(),
        &staker_pk,
        &k256::schnorr::Signature::try_from(staker_sig.as_slice())?,
    )?;

    Ok(())
}

pub fn verify_slashed_delegation(
    active_delegation: &BtcDelegation,
    slashed_fp_sk_hex: &str,
) -> Result<(), ContractError> {
    if !active_delegation.matches_delegated_fp(slashed_fp_sk_hex)? {
        return Err(
            FullValidationError::FpNotInDelegationList(slashed_fp_sk_hex.to_string()).into(),
        );
    }

    Ok(())
}
