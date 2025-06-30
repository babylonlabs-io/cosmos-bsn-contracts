use crate::state::config::Params;
use crate::{error::ContractError, state::staking::BtcDelegation};
use babylon_apis::btc_staking_api::{ActiveBtcDelegation, NewFinalityProvider};
use bitcoin::Transaction;
use cosmwasm_std::Binary;

#[cfg(feature = "full-validation")]
use {
    babylon_apis::btc_staking_api::{BTCSigType, ProofOfPossessionBtc},
    babylon_bitcoin::schnorr::verify_digest,
    babylon_btcstaking::adaptor_sig::AdaptorSignature,
    babylon_btcstaking::sig_verify::enc_verify_transaction_sig_with_output,
    bitcoin::consensus::deserialize,
    cosmwasm_std::CanonicalAddr,
    hex::ToHex,
    k256::schnorr::{Signature, SigningKey, VerifyingKey},
    k256::sha2::{Digest, Sha256},
};

/// verify_pop verifies the proof of possession of the given address.
#[cfg(feature = "full-validation")]
fn verify_pop(
    btc_pk: &VerifyingKey,
    address: CanonicalAddr,
    pop: &ProofOfPossessionBtc,
) -> Result<(), ContractError> {
    // get signed msg, i.e., the hash of the canonicalised address
    let address_bytes = address.as_slice();
    let msg_hash: [u8; 32] = Sha256::new_with_prefix(address_bytes).finalize().into();

    // verify PoP
    let btc_sig_type = BTCSigType::try_from(pop.btc_sig_type)
        .map_err(|e| ContractError::FinalityProviderVerificationError(e.to_string()))?;
    match btc_sig_type {
        BTCSigType::BIP340 => {
            let pop_sig = Signature::try_from(pop.btc_sig.as_slice())
                .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;
            verify_digest(btc_pk, &msg_hash, &pop_sig)
                .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;
        }
        BTCSigType::BIP322 => {
            // TODO?: implement BIP322 verification (#7.0)
            return Ok(());
        }
        BTCSigType::ECDSA => {
            // TODO?: implement ECDSA verification (#7.0)
            return Ok(());
        }
    }

    Ok(())
}

#[cfg(feature = "full-validation")]
fn decode_pks(
    staker_pk_hex: &str,
    fp_pk_hex_list: &[String],
    cov_pk_hex_list: &[String],
) -> Result<(VerifyingKey, Vec<VerifyingKey>, Vec<VerifyingKey>), ContractError> {
    // get staker's public key
    let staker_pk_bytes =
        hex::decode(&staker_pk_hex).map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;
    let staker_pk = VerifyingKey::from_bytes(&staker_pk_bytes)
        .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;

    // get all FP's public keys
    let fp_pks: Vec<VerifyingKey> = fp_pk_hex_list
        .iter()
        .map(|pk_hex| {
            let pk_bytes =
                hex::decode(pk_hex).map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;
            VerifyingKey::from_bytes(&pk_bytes)
                .map_err(|e| ContractError::SecP256K1Error(e.to_string()))
        })
        .collect::<Result<Vec<VerifyingKey>, ContractError>>()?;
    // get all covenant members' public keys
    let cov_pks: Vec<VerifyingKey> = cov_pk_hex_list
        .iter()
        .map(|pk_hex| {
            let pk_bytes =
                hex::decode(pk_hex).map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;
            VerifyingKey::from_bytes(&pk_bytes)
                .map_err(|e| ContractError::SecP256K1Error(e.to_string()))
        })
        .collect::<Result<Vec<VerifyingKey>, ContractError>>()?;

    Ok((staker_pk, fp_pks, cov_pks))
}

/// verify_new_fp verifies the new finality provider data (full validation version)
pub fn verify_new_fp(new_fp: &NewFinalityProvider) -> Result<(), ContractError> {
    // The following code is marked with `#[cfg(feature = "full-validation")]`
    // so that it is included in the build if the `full-validation` feature is
    // enabled.
    // TODO: fix contract size when full-validation is enabled
    #[cfg(feature = "full-validation")]
    {
        // get FP's PK
        use babylon_apis::to_canonical_addr;
        let fp_pk_bytes = hex::decode(&new_fp.btc_pk_hex)
            .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;
        let fp_pk = VerifyingKey::from_bytes(&fp_pk_bytes)
            .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;

        // get canonical FP address
        // FIXME: parameterise `bbn` prefix
        let addr = new_fp.addr.clone();
        let address = to_canonical_addr(&addr, "bbn")?;

        // get FP's PoP
        let pop = new_fp
            .pop
            .clone()
            .ok_or(ContractError::FinalityProviderVerificationError(
                "proof of possession is missing".to_string(),
            ))?;

        // verify PoP
        verify_pop(&fp_pk, address, &pop)?;
    }

    // make static analyser happy with unused parameters
    #[cfg(not(feature = "full-validation"))]
    let _ = new_fp;

    Ok(())
}

/// verify_active_delegation verifies the active delegation data
pub fn verify_active_delegation(
    params: &Params,
    active_delegation: &ActiveBtcDelegation,
    staking_tx: &Transaction,
) -> Result<(), ContractError> {
    // The following code is marked with `#[cfg(feature = "full-validation")]`
    // so that it is included in the build if the `full-validation` feature is
    // enabled.
    // TODO: fix contract size when full-validation is enabled
    #[cfg(feature = "full-validation")]
    {
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
        let slashing_tx: Transaction = deserialize(&active_delegation.slashing_tx)
            .map_err(|_| ContractError::InvalidBtcTx(active_delegation.slashing_tx.encode_hex()))?;

        // decode slashing address
        let slashing_pk_script = hex::decode(&params.slashing_pk_script)
            .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;

        // Check slashing tx and staking tx are valid and consistent
        let slashing_rate = params
            .slashing_rate
            .parse::<f64>()
            .map_err(|_| ContractError::InvalidBtcTx("invalid slashing rate".to_string()))?;
        babylon_btcstaking::tx_verify::check_transactions(
            &slashing_tx,
            staking_tx,
            active_delegation.staking_output_idx,
            params.min_slashing_tx_fee_sat,
            slashing_rate,
            &slashing_pk_script,
            &staker_pk,
            active_delegation.unbonding_time as u16,
        )?;

        // TODO: Verify proof of possession (#7.1)

        /*
            verify staker signature against slashing path of the staking tx script
        */

        // get the slashing path script
        let staking_output = &staking_tx.output[active_delegation.staking_output_idx as usize];
        let staking_time = (active_delegation.end_height - active_delegation.start_height) as u16;
        let babylon_script_paths = babylon_btcstaking::scripts_utils::BabylonScriptPaths::new(
            &staker_pk,
            &fp_pks,
            &cov_pks,
            params.covenant_quorum as usize,
            staking_time,
        )?;
        let slashing_path_script = babylon_script_paths.slashing_path_script;

        // get the staker's signature on the slashing tx
        let staker_sig =
            k256::schnorr::Signature::try_from(active_delegation.delegator_slashing_sig.as_slice())
                .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;
        // Verify the staker's signature
        babylon_btcstaking::sig_verify::verify_transaction_sig_with_output(
            &slashing_tx,
            staking_output,
            slashing_path_script.as_script(),
            &staker_pk,
            &staker_sig,
        )
        .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;

        /*
            Verify covenant signatures over slashing tx
        */
        for cov_sig in active_delegation.covenant_sigs.iter() {
            let cov_pk = VerifyingKey::from_bytes(&cov_sig.cov_pk)
                .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;
            // Check if the covenant public key is in the params.covenant_pks
            if !params
                .covenant_pks
                .contains(&hex::encode(cov_sig.cov_pk.as_slice()))
            {
                return Err(ContractError::InvalidCovenantSig(
                    "Covenant public key not found in params".to_string(),
                ));
            }
            let sigs = cov_sig
                .adaptor_sigs
                .iter()
                .map(|sig| {
                    AdaptorSignature::new(sig.as_slice())
                        .map_err(|e| ContractError::SecP256K1Error(e.to_string()))
                })
                .collect::<Result<Vec<AdaptorSignature>, ContractError>>()?;
            for (idx, sig) in sigs.iter().enumerate() {
                enc_verify_transaction_sig_with_output(
                    &slashing_tx,
                    staking_output,
                    slashing_path_script.as_script(),
                    &cov_pk,
                    &fp_pks[idx],
                    &sig,
                )
                .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;
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

        // decode unbonding tx
        let unbonding_tx = &active_delegation.undelegation_info.unbonding_tx;
        let unbonding_tx: Transaction = deserialize(unbonding_tx)
            .map_err(|_| ContractError::InvalidBtcTx(unbonding_tx.encode_hex()))?;
        // decode unbonding slashing tx
        let unbonding_slashing_tx = &active_delegation.undelegation_info.slashing_tx;
        let unbonding_slashing_tx: Transaction = deserialize(unbonding_slashing_tx)
            .map_err(|_| ContractError::InvalidBtcTx(unbonding_slashing_tx.encode_hex()))?;

        // Check that the unbonding tx input is pointing to staking tx
        if unbonding_tx.input[0].previous_output.txid != staking_tx.compute_txid()
            || unbonding_tx.input[0].previous_output.vout != active_delegation.staking_output_idx
        {
            return Err(ContractError::InvalidBtcTx(
                "Unbonding transaction must spend staking output".to_string(),
            ));
        }

        // TODO: Check unbonding tx fees against staking tx (#7.1)
        // - Fee is greater than 0.
        // - Unbonding output value is at least `MinUnbondingValue` percentage of staking output value.

        let babylon_unbonding_script_paths =
            babylon_btcstaking::scripts_utils::BabylonScriptPaths::new(
                &staker_pk,
                &fp_pks,
                &cov_pks,
                params.covenant_quorum as usize,
                staking_time,
            )?;

        // TODO: Ensure the unbonding tx has valid unbonding output, and get the unbonding output (#7.1)
        // index (#7.1)
        let unbonding_output_idx = 0;
        let unbonding_output = &unbonding_tx.output[unbonding_output_idx as usize];

        let unbonding_time = active_delegation.unbonding_time as u16;

        // Check that unbonding tx and unbonding slashing tx are consistent
        babylon_btcstaking::tx_verify::check_transactions(
            &unbonding_slashing_tx,
            &unbonding_tx,
            unbonding_output_idx,
            params.min_slashing_tx_fee_sat,
            slashing_rate,
            &slashing_pk_script,
            &staker_pk,
            unbonding_time,
        )?;

        /*
            Check staker signature against slashing path of the unbonding tx
        */
        // get unbonding slashing path script
        let unbonding_slashing_path_script = babylon_unbonding_script_paths.slashing_path_script;
        // get the staker's signature on the unbonding slashing tx
        let unbonding_slashing_sig = active_delegation
            .undelegation_info
            .delegator_slashing_sig
            .as_slice();
        let unbonding_slashing_sig = k256::schnorr::Signature::try_from(unbonding_slashing_sig)
            .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;
        // Verify the staker's signature
        babylon_btcstaking::sig_verify::verify_transaction_sig_with_output(
            &unbonding_slashing_tx,
            &unbonding_tx.output[unbonding_output_idx as usize],
            unbonding_slashing_path_script.as_script(),
            &staker_pk,
            &unbonding_slashing_sig,
        )
        .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;

        /*
            verify covenant signatures over unbonding tx
        */
        let unbonding_path_script = babylon_script_paths.unbonding_path_script;
        for cov_sig in active_delegation
            .undelegation_info
            .covenant_unbonding_sig_list
            .iter()
        {
            // get covenant public key
            let cov_pk = VerifyingKey::from_bytes(&cov_sig.pk)
                .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;
            // ensure covenant public key is in the params
            if !params
                .covenant_pks
                .contains(&hex::encode(cov_pk.to_bytes()))
            {
                return Err(ContractError::InvalidCovenantSig(
                    "Covenant public key not found in params".to_string(),
                ));
            }
            // get covenant signature
            let sig = Signature::try_from(cov_sig.sig.as_slice())
                .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;
            // Verify the covenant member's signature
            babylon_btcstaking::sig_verify::verify_transaction_sig_with_output(
                &staking_tx,
                &staking_output,
                unbonding_path_script.as_script(),
                &cov_pk,
                &sig,
            )
            .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;
        }

        /*
            Verify covenant signatures over unbonding slashing tx
        */
        for cov_sig in active_delegation
            .undelegation_info
            .covenant_slashing_sigs
            .iter()
        {
            let cov_pk = VerifyingKey::from_bytes(&cov_sig.cov_pk)
                .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;
            // Check if the covenant public key is in the params.covenant_pks
            if !params
                .covenant_pks
                .contains(&hex::encode(cov_sig.cov_pk.as_slice()))
            {
                return Err(ContractError::InvalidCovenantSig(
                    "Covenant public key not found in params".to_string(),
                ));
            }
            let sigs = cov_sig
                .adaptor_sigs
                .iter()
                .map(|sig| {
                    AdaptorSignature::new(sig.as_slice())
                        .map_err(|e| ContractError::SecP256K1Error(e.to_string()))
                })
                .collect::<Result<Vec<AdaptorSignature>, ContractError>>()?;
            for (idx, sig) in sigs.iter().enumerate() {
                enc_verify_transaction_sig_with_output(
                    &unbonding_slashing_tx,
                    unbonding_output,
                    &unbonding_slashing_path_script.as_script(),
                    &cov_pk,
                    &fp_pks[idx],
                    &sig,
                )
                .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;
            }
        }
    }

    // make static analyser happy with unused parameters
    #[cfg(not(feature = "full-validation"))]
    let _ = (params, active_delegation, staking_tx);

    Ok(())
}

pub fn verify_undelegation(
    params: &Params,
    btc_del: &BtcDelegation,
    sig: &Binary,
) -> Result<(), ContractError> {
    // The following code is marked with `#[cfg(feature = "full-validation")]`
    // so that it is included in the build if the `full-validation` feature is
    // enabled.
    // TODO: fix contract size when full-validation is enabled
    #[cfg(feature = "full-validation")]
    {
        /*
            Verify the signature on the unbonding tx is from the delegator
        */

        // get keys
        let (staker_pk, fp_pks, cov_pks) = decode_pks(
            &btc_del.btc_pk_hex,
            &btc_del.fp_btc_pk_list,
            &params.covenant_pks,
        )?;

        // get the unbonding path script
        let staking_tx: Transaction = deserialize(&btc_del.staking_tx)
            .map_err(|_| ContractError::InvalidBtcTx(btc_del.staking_tx.encode_hex()))?;
        let staking_output = &staking_tx.output[btc_del.staking_output_idx as usize];
        let staking_time = (btc_del.end_height - btc_del.start_height) as u16;
        let babylon_script_paths = babylon_btcstaking::scripts_utils::BabylonScriptPaths::new(
            &staker_pk,
            &fp_pks,
            &cov_pks,
            params.covenant_quorum as usize,
            staking_time,
        )?;
        let unbonding_path_script = babylon_script_paths.unbonding_path_script;

        // get unbonding tx
        let unbonding_tx: Transaction = deserialize(&btc_del.undelegation_info.unbonding_tx)
            .map_err(|_| {
                ContractError::InvalidBtcTx(btc_del.undelegation_info.unbonding_tx.encode_hex())
            })?;

        // get the staker's signature on the unbonding tx
        let staker_sig = k256::schnorr::Signature::try_from(sig.as_slice())
            .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;

        // Verify the signature
        babylon_btcstaking::sig_verify::verify_transaction_sig_with_output(
            &unbonding_tx,
            staking_output,
            unbonding_path_script.as_script(),
            &staker_pk,
            &staker_sig,
        )
        .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;
    }

    // make static analyser happy with unused parameters
    #[cfg(not(feature = "full-validation"))]
    let _ = (params, btc_del, sig);

    Ok(())
}

pub fn verify_slashed_delegation(
    active_delegation: &BtcDelegation,
    slashed_fp_sk_hex: &str,
) -> Result<(), ContractError> {
    // The following code is marked with `#[cfg(feature = "full-validation")]`
    // so that it is included in the build if the `full-validation` feature is
    // enabled.
    // TODO: fix contract size when full-validation is enabled
    #[cfg(feature = "full-validation")]
    {
        /*
            check if the SK corresponds to a FP PK that the delegation restakes to
        */

        // get the slashed FP's SK
        let slashed_fp_sk = hex::decode(&slashed_fp_sk_hex)
            .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;
        let slashed_fp_sk = SigningKey::from_bytes(&slashed_fp_sk)
            .map_err(|e| ContractError::SecP256K1Error(e.to_string()))?;

        // calculate the corresponding VerifyingKey
        let slashed_fp_pk = slashed_fp_sk.verifying_key();
        let slashed_fp_pk_hex = hex::encode(slashed_fp_pk.to_bytes());

        // check if the PK corresponds to a FP PK that the delegation restakes to
        if !active_delegation
            .fp_btc_pk_list
            .contains(&slashed_fp_pk_hex)
        {
            return Err(ContractError::FinalityProviderNotFound(
                slashed_fp_pk_hex.to_string(),
            ));
        }
    }

    // make static analyser happy with unused parameters
    #[cfg(not(feature = "full-validation"))]
    let _ = (active_delegation, slashed_fp_sk_hex);

    Ok(())
}
