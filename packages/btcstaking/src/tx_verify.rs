use crate::error::Error;
use crate::scripts_utils;
use crate::Result;

use bitcoin::Transaction;
use k256::schnorr::VerifyingKey;
use rust_decimal::{prelude::*, Decimal};

/// Maximum transaction weight allowed in Babylon system.
/// This matches the MaxStandardTxWeight constant from Babylon Genesis.
const MAX_STANDARD_TX_WEIGHT: usize = 400000;

/// Maximum transaction version allowed in Babylon system.
/// This matches the maxTxVersion constant from Babylon Genesis.
const MAX_TX_VERSION: i32 = 2;

/// Checks pre-signed transaction sanity (matches Babylon Genesis CheckPreSignedTxSanity)
fn check_pre_signed_tx_sanity(
    tx: &Transaction,
    num_inputs: usize,
    num_outputs: usize,
    min_tx_version: i32,
    max_tx_version: i32,
) -> Result<()> {
    if tx.input.len() != num_inputs {
        return Err(Error::TxInputCountMismatch(num_inputs, tx.input.len()));
    }

    if tx.output.len() != num_outputs {
        return Err(Error::TxOutputCountMismatch(num_outputs, tx.output.len()));
    }

    // Pre-signed tx must not have locktime (this requirement makes every pre-signed tx final)
    if tx.lock_time.to_consensus_u32() != 0 {
        return Err(Error::TxHasLocktime {});
    }

    // Check transaction version
    let version = tx.version.0;
    if version > max_tx_version || version < min_tx_version {
        return Err(Error::InvalidTxVersion(version, min_tx_version, max_tx_version));
    }

    // Check transaction weight (matches Babylon Genesis CheckPreSignedTxSanity)
    let tx_weight = tx.weight().to_wu() as usize;
    if tx_weight > MAX_STANDARD_TX_WEIGHT {
        return Err(Error::TransactionWeightExceedsLimit(tx_weight, MAX_STANDARD_TX_WEIGHT));
    }

    // Check that all inputs are non-replaceable (final)
    for input in &tx.input {
        if input.sequence.is_rbf() {
            return Err(Error::TxIsReplaceable {});
        }

        // Pre-signed tx must not have signature script (all babylon pre-signed transactions use witness)
        if !input.script_sig.is_empty() {
            return Err(Error::TxHasSignatureScript {});
        }
    }

    Ok(())
}

/// Checks pre-signed unbonding transaction sanity
pub fn check_pre_signed_unbonding_tx_sanity(tx: &Transaction) -> Result<()> {
    check_pre_signed_tx_sanity(
        tx,
        1, // num_inputs
        1, // num_outputs
        MAX_TX_VERSION, // min_tx_version (unbonding tx is always version 2)
        MAX_TX_VERSION, // max_tx_version
    )
}

/// Checks pre-signed slashing transaction sanity
pub fn check_pre_signed_slashing_tx_sanity(tx: &Transaction) -> Result<()> {
    check_pre_signed_tx_sanity(
        tx,
        1, // num_inputs
        2, // num_outputs
        1, // min_tx_version (slashing tx version can be between 1 and 2)
        MAX_TX_VERSION, // max_tx_version
    )
}

/// Checks if a transaction has exactly one input and one output.
fn is_transfer_tx(tx: &Transaction) -> Result<()> {
    if tx.input.len() != 1 {
        return Err(Error::TxInputCountMismatch(1, tx.input.len()));
    }

    if tx.output.len() != 1 {
        return Err(Error::TxOutputCountMismatch(1, tx.output.len()));
    }

    Ok(())
}

/// Checks if a transaction is a simple transfer, meaning it has exactly one input and one output,
/// is not replaceable (sequence number is max), and has no locktime.
#[allow(dead_code)]
fn is_simple_transfer(tx: &Transaction) -> Result<()> {
    is_transfer_tx(tx)?; // Reuse the is_transfer_tx check and propagate error if any

    if !tx.input[0].sequence.is_rbf() {
        return Err(Error::TxIsReplaceable {});
    }

    if tx.lock_time.to_consensus_u32() > 0 {
        return Err(Error::TxHasLocktime {});
    }

    Ok(())
}

/// Validates a slashing transaction with strict criteria
#[allow(clippy::too_many_arguments)]
fn validate_slashing_tx(
    slashing_tx: &Transaction,
    slashing_pk_script: &[u8],
    slashing_rate: f64,
    slashing_tx_min_fee: u64,
    staking_output_value: u64,
    staker_pk: &VerifyingKey,
    slashing_change_lock_time: u16,
) -> Result<()> {
    // Check pre-signed slashing transaction sanity (includes weight, version, locktime, etc.)
    check_pre_signed_slashing_tx_sanity(slashing_tx)?;

    let expected_slashing_amount = (staking_output_value as f64 * slashing_rate).round() as u64;
    if slashing_tx.output[0].value.to_sat() < expected_slashing_amount {
        return Err(Error::InsufficientSlashingAmount(expected_slashing_amount));
    }

    // Verify that the first output pays to the provided slashing address.
    if slashing_tx.output[0].script_pubkey.as_bytes() != slashing_pk_script {
        return Err(Error::InvalidSlashingPkScript {});
    }

    // Verify that the second output pays to the taproot address which locks funds for
    // slashingChangeLockTime
    // Build script based on the timelock details
    let expected_pk_script =
        scripts_utils::build_relative_time_lock_pk_script(staker_pk, slashing_change_lock_time)?;
    if slashing_tx.output[1].script_pubkey.ne(&expected_pk_script) {
        println!("expected_pk_script: {:?}", expected_pk_script);
        println!(
            "slashing_tx.output[1].script_pubkey: {:?}",
            slashing_tx.output[1].script_pubkey
        );
        return Err(Error::InvalidSlashingTxChangeOutputScript {});
    }

    // Check for dust outputs
    if slashing_tx
        .output
        .iter()
        .any(|out| out.value.to_sat() <= 546)
    {
        return Err(Error::TxContainsDustOutputs {});
    }

    // Check fees
    let total_output_value: u64 = slashing_tx
        .output
        .iter()
        .map(|out| out.value.to_sat())
        .sum();
    if staking_output_value <= total_output_value {
        return Err(Error::SlashingTxOverspend {});
    }

    let calculated_fee = staking_output_value - total_output_value;
    if calculated_fee < slashing_tx_min_fee {
        return Err(Error::InsufficientSlashingFee(slashing_tx_min_fee));
    }

    Ok(())
}

/// Checks if the given rate is between the valid range i.e., (0,1) with a precision of at most 2 decimal places.
fn is_rate_valid(rate: f64) -> bool {
    // Check if the slashing rate is between 0 and 1
    if rate <= 0.0 || rate >= 1.0 {
        return false;
    }

    // Multiply by 100 to move the decimal places and check if precision is at most 2 decimal places
    let multiplied_rate = Decimal::from_f64(rate * 100.0).unwrap();

    // Truncate the rate to remove decimal places
    let truncated_rate = multiplied_rate.trunc();

    // Check if the truncated rate is equal to the original rate
    multiplied_rate == truncated_rate
}

/// Validates all relevant data of slashing and funding transactions.
#[allow(clippy::too_many_arguments)]
pub fn check_transactions(
    slashing_tx: &Transaction,
    funding_transaction: &Transaction,
    funding_output_idx: u32,
    slashing_tx_min_fee: u64,
    slashing_rate: f64,
    slashing_pk_script: &[u8],
    staker_pk: &VerifyingKey,
    slashing_change_lock_time: u16,
) -> Result<()> {
    // Check if slashing tx min fee is valid
    if slashing_tx_min_fee == 0 {
        return Err(Error::InsufficientSlashingFee(0));
    }

    // Check if slashing rate is in the valid range (0,1)
    if !is_rate_valid(slashing_rate) {
        return Err(Error::InvalidSlashingRate {});
    }

    if funding_output_idx >= funding_transaction.output.len() as u32 {
        return Err(Error::InvalidFundingOutputIndex(
            funding_output_idx,
            funding_transaction.output.len(),
        ));
    }

    let staking_output = &funding_transaction.output[funding_output_idx as usize];

    // Check if slashing transaction is valid
    validate_slashing_tx(
        slashing_tx,
        slashing_pk_script,
        slashing_rate,
        slashing_tx_min_fee,
        staking_output.value.to_sat(),
        staker_pk,
        slashing_change_lock_time,
    )?;

    // Check that slashing transaction input is pointing to staking transaction
    let staking_tx_hash = funding_transaction.compute_txid(); // Hash of the funding transaction
    if slashing_tx.input[0]
        .previous_output
        .txid
        .ne(&staking_tx_hash)
    {
        return Err(Error::StakingOutputNotSpentBySlashingTx {});
    }

    // Check that index of the funding output matches index of the input in slashing transaction
    if slashing_tx.input[0].previous_output.vout != funding_output_idx {
        return Err(Error::StakingOutputNotSpentBySlashingTx {});
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use self::scripts_utils::BabylonScriptPaths;
    use super::*;
    use crate::adaptor_sig::AdaptorSignature;
    use crate::sig_verify::{
        enc_verify_transaction_sig_with_output, verify_transaction_sig_with_output,
    };
    use bitcoin::consensus::deserialize;
    use bitcoin::{ScriptBuf, TxIn, TxOut, Sequence, OutPoint, Amount};
    use bitcoin::absolute::LockTime;

    use babylon_test_utils::{get_btc_delegation, get_params};

    #[test]
    fn test_check_transactions() {
        let btc_del = get_btc_delegation(1, vec![1]);
        let params = get_params();

        let staking_tx: Transaction = deserialize(&btc_del.staking_tx).unwrap();
        let slashing_tx: Transaction = deserialize(&btc_del.slashing_tx).unwrap();
        let funding_out_idx: u32 = 0;
        let slashing_tx_min_fee: u64 = 1;
        let slashing_rate: f64 = 0.01;
        let slashing_pk_script = &params.slashing_pk_script;
        let staker_pk: VerifyingKey = VerifyingKey::from_bytes(&btc_del.btc_pk).unwrap();
        let slashing_change_lock_time: u16 = 101;

        // test check_transactions
        check_transactions(
            &slashing_tx,
            &staking_tx,
            funding_out_idx,
            slashing_tx_min_fee,
            slashing_rate,
            slashing_pk_script,
            &staker_pk,
            slashing_change_lock_time,
        )
        .unwrap();
    }

    #[test]
    fn test_pre_signed_tx_sanity() {
        let btc_del = get_btc_delegation(1, vec![1]);
        let slashing_tx: Transaction = deserialize(&btc_del.slashing_tx).unwrap();

        // Test 1: Valid slashing transaction should pass
        check_pre_signed_tx_sanity(&slashing_tx, 1, 2, 1, 2).unwrap();

        // Test 2: Valid unbonding transaction should pass
        if let Some(undelegation_info) = &btc_del.btc_undelegation {
            let unbonding_tx: Transaction = deserialize(&undelegation_info.unbonding_tx).unwrap();
            check_pre_signed_tx_sanity(&unbonding_tx, 1, 1, 2, 2).unwrap();
        }

        // Test 3: Wrong number of inputs should fail
        let mut invalid_tx = slashing_tx.clone();
        invalid_tx.input.push(TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: bitcoin::Witness::new(),
        });
        assert!(check_pre_signed_tx_sanity(&invalid_tx, 1, 2, 1, 2).is_err());

        // Test 4: Wrong number of outputs should fail
        let mut invalid_tx = slashing_tx.clone();
        invalid_tx.output.push(TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: ScriptBuf::new(),
        });
        assert!(check_pre_signed_tx_sanity(&invalid_tx, 1, 2, 1, 2).is_err());

        // Test 5: Non-zero locktime should fail
        let mut invalid_tx = slashing_tx.clone();
        invalid_tx.lock_time = LockTime::from_consensus(100);
        assert!(check_pre_signed_tx_sanity(&invalid_tx, 1, 2, 1, 2).is_err());

        // Test 6: Invalid transaction version should fail (too high)
        let mut invalid_tx = slashing_tx.clone();
        invalid_tx.version = bitcoin::transaction::Version(MAX_TX_VERSION + 1);
        assert!(check_pre_signed_tx_sanity(&invalid_tx, 1, 2, 1, 2).is_err());

        // Test 7: Invalid transaction version should fail (too low for slashing)
        let mut invalid_tx = slashing_tx.clone();
        invalid_tx.version = bitcoin::transaction::Version(0);
        assert!(check_pre_signed_tx_sanity(&invalid_tx, 1, 2, 1, 2).is_err());

        // Test 8: RBF enabled should fail
        let mut invalid_tx = slashing_tx.clone();
        invalid_tx.input[0].sequence = Sequence::from_consensus(0xFFFFFFFD); // RBF enabled (< 0xFFFFFFFE)
        assert!(check_pre_signed_tx_sanity(&invalid_tx, 1, 2, 1, 2).is_err());

        // Test 9: Non-empty signature script should fail
        let mut invalid_tx = slashing_tx.clone();
        invalid_tx.input[0].script_sig = ScriptBuf::from_hex("0014abcd").unwrap();
        assert!(check_pre_signed_tx_sanity(&invalid_tx, 1, 2, 1, 2).is_err());
    }

    #[test]
    fn test_verify_unbonding_tx_schnorr_sig() {
        let btc_del = get_btc_delegation(1, vec![1]);
        let params = get_params();

        let staking_tx: Transaction = deserialize(&btc_del.staking_tx).unwrap();
        let funding_out_idx: u32 = 0;
        let staker_pk: VerifyingKey = VerifyingKey::from_bytes(&btc_del.btc_pk).unwrap();

        let fp_pks: Vec<VerifyingKey> = btc_del
            .fp_btc_pk_list
            .iter()
            .map(|bytes| VerifyingKey::from_bytes(bytes).expect("Invalid public key bytes"))
            .collect();
        let cov_pks: Vec<VerifyingKey> = params
            .covenant_pks
            .iter()
            .map(|bytes| VerifyingKey::from_bytes(bytes).expect("Invalid public key bytes"))
            .collect();

        let babylon_script_paths = BabylonScriptPaths::new(
            &staker_pk,
            &fp_pks,
            &cov_pks,
            params.covenant_quorum as usize,
            5, // TODO: parameterise
        )
        .unwrap();

        // test verifying Schnorr signature, i.e., covenant signatures over unbonding tx
        let btc_undel_info = &btc_del.btc_undelegation.unwrap();
        let unbonding_tx: Transaction = deserialize(&btc_undel_info.unbonding_tx).unwrap();
        let staking_out = &staking_tx.output[funding_out_idx as usize];
        let unbonding_pk_script = babylon_script_paths.unbonding_path_script;
        for cov_unbonding_tx_sig_info in &btc_undel_info.covenant_unbonding_sig_list {
            let cov_pk = VerifyingKey::from_bytes(&cov_unbonding_tx_sig_info.pk).unwrap();

            let cov_sig =
                k256::schnorr::Signature::try_from(&cov_unbonding_tx_sig_info.sig[..]).unwrap();
            verify_transaction_sig_with_output(
                &unbonding_tx,
                staking_out,
                unbonding_pk_script.as_script(),
                &cov_pk,
                &cov_sig,
            )
            .unwrap();
        }
    }

    #[test]
    fn test_verify_slashing_tx_adaptor_sig() {
        let btc_del = get_btc_delegation(1, vec![1]);
        let params = get_params();

        let staking_tx: Transaction = deserialize(&btc_del.staking_tx).unwrap();
        let slashing_tx: Transaction = deserialize(&btc_del.slashing_tx).unwrap();
        let funding_out_idx: u32 = 0;
        let staker_pk: VerifyingKey = VerifyingKey::from_bytes(&btc_del.btc_pk).unwrap();
        let staking_out = &staking_tx.output[funding_out_idx as usize];

        let fp_pks: Vec<VerifyingKey> = btc_del
            .fp_btc_pk_list
            .iter()
            .map(|bytes| VerifyingKey::from_bytes(bytes).expect("Invalid public key bytes"))
            .collect();
        let cov_pks: Vec<VerifyingKey> = params
            .covenant_pks
            .iter()
            .map(|bytes| VerifyingKey::from_bytes(bytes).expect("Invalid public key bytes"))
            .collect();

        let babylon_script_paths = BabylonScriptPaths::new(
            &staker_pk,
            &fp_pks,
            &cov_pks,
            params.covenant_quorum as usize,
            5, // TODO: parameterise
        )
        .unwrap();

        // test verifying adaptor signature, i.e., covenant signatures over slashing tx
        for cov_slashing_tx_info in btc_del.covenant_sigs {
            let cov_pk = VerifyingKey::from_bytes(&cov_slashing_tx_info.cov_pk).unwrap();
            for (idx, cov_asig_bytes) in cov_slashing_tx_info.adaptor_sigs.iter().enumerate() {
                let cov_asig = AdaptorSignature::new(cov_asig_bytes).unwrap();
                enc_verify_transaction_sig_with_output(
                    &slashing_tx,
                    staking_out,
                    babylon_script_paths.slashing_path_script.as_script(),
                    &cov_pk,
                    &fp_pks[idx],
                    &cov_asig,
                )
                .unwrap();
            }
        }
    }

    #[test]
    fn test_verify_unbonding_slashing_tx_adaptor_sig() {
        let btc_del = get_btc_delegation(1, vec![1]);
        let params = get_params();

        let btc_undel = btc_del.btc_undelegation.unwrap();
        let unbonding_tx: Transaction = deserialize(&btc_undel.unbonding_tx).unwrap();
        let unbonding_slashing_tx: Transaction = deserialize(&btc_undel.slashing_tx).unwrap();
        let funding_out_idx: u32 = 0;
        let staker_pk: VerifyingKey = VerifyingKey::from_bytes(&btc_del.btc_pk).unwrap();
        let unbonding_out = &unbonding_tx.output[funding_out_idx as usize];

        let fp_pks: Vec<VerifyingKey> = btc_del
            .fp_btc_pk_list
            .iter()
            .map(|bytes| VerifyingKey::from_bytes(bytes).expect("Invalid public key bytes"))
            .collect();
        let cov_pks: Vec<VerifyingKey> = params
            .covenant_pks
            .iter()
            .map(|bytes| VerifyingKey::from_bytes(bytes).expect("Invalid public key bytes"))
            .collect();

        let babylon_unbonding_script_paths = BabylonScriptPaths::new(
            &staker_pk,
            &fp_pks,
            &cov_pks,
            params.covenant_quorum as usize,
            101, // TODO: parameterise
        )
        .unwrap();

        // test verifying adaptor signature, i.e., covenant signatures over slashing tx
        for cov_unbonding_slashing_tx_info in btc_undel.covenant_slashing_sigs {
            let cov_pk = VerifyingKey::from_bytes(&cov_unbonding_slashing_tx_info.cov_pk).unwrap();
            for (idx, cov_asig_bytes) in cov_unbonding_slashing_tx_info
                .adaptor_sigs
                .iter()
                .enumerate()
            {
                let cov_asig = AdaptorSignature::new(cov_asig_bytes).unwrap();
                enc_verify_transaction_sig_with_output(
                    &unbonding_slashing_tx,
                    unbonding_out,
                    babylon_unbonding_script_paths
                        .slashing_path_script
                        .as_script(),
                    &cov_pk,
                    &fp_pks[idx],
                    &cov_asig,
                )
                .unwrap();
            }
        }
    }
}
