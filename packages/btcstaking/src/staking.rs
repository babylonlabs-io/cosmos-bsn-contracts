use crate::errors::Error;
use crate::Result;

use crate::types::is_rate_valid;
use babylon_schnorr_adaptor_signature::{verify_digest, AdaptorSignature};
use bitcoin::hashes::Hash;
use bitcoin::opcodes::all::OP_RETURN;
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::{Script, Transaction, TxOut};
use k256::schnorr::Signature as SchnorrSignature;
use k256::schnorr::VerifyingKey;

/// Maximum transaction weight allowed in Babylon system.
/// This matches the MaxStandardTxWeight constant from Babylon Genesis.
const MAX_STANDARD_TX_WEIGHT: usize = 400000;

/// Maximum transaction version allowed in Babylon system.
/// This matches the maxTxVersion constant from Babylon Genesis.
const MAX_TX_VERSION: i32 = 2;

/// Dust threshold defines the maximum value of an output to be considered a dust output.
const DUST_THRESHOLD: u64 = 546;

/// Checks if a script is an OP_RETURN output
fn is_op_return_output(script: &bitcoin::ScriptBuf) -> bool {
    let script_bytes = script.as_bytes();
    !script_bytes.is_empty() && script_bytes[0] == OP_RETURN.to_u8()
}

/// Checks pre-signed transaction sanity
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
        return Err(Error::InvalidTxVersion(
            version,
            min_tx_version,
            max_tx_version,
        ));
    }

    // Check transaction weight
    let tx_weight = tx.weight().to_wu() as usize;
    if tx_weight > MAX_STANDARD_TX_WEIGHT {
        return Err(Error::TransactionWeightExceedsLimit(
            tx_weight,
            MAX_STANDARD_TX_WEIGHT,
        ));
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
        1,              // num_inputs
        1,              // num_outputs
        MAX_TX_VERSION, // min_tx_version (unbonding tx is always version 2)
        MAX_TX_VERSION, // max_tx_version
    )
}

/// Checks pre-signed slashing transaction sanity
pub fn check_pre_signed_slashing_tx_sanity(tx: &Transaction) -> Result<()> {
    check_pre_signed_tx_sanity(
        tx,
        1,              // num_inputs
        2,              // num_outputs
        1,              // min_tx_version (slashing tx version can be between 1 and 2)
        MAX_TX_VERSION, // max_tx_version
    )
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
    let expected_pk_script = crate::types::build_relative_timelock_taproot_script_pk_script(
        staker_pk,
        slashing_change_lock_time,
    )?;
    if slashing_tx.output[1].script_pubkey.ne(&expected_pk_script) {
        return Err(Error::InvalidSlashingTxChangeOutputScript {
            expected: expected_pk_script.to_bytes(),
            actual: slashing_tx.output[1].script_pubkey.to_bytes(),
        });
    }

    // Verify that none of the outputs is a dust output
    for output in &slashing_tx.output {
        // OP_RETURN outputs can be dust and are considered standard (skip them like Babylon Genesis)
        if is_op_return_output(&output.script_pubkey) {
            continue;
        }

        // Use the standard dust threshold (546 satoshis for non-OP_RETURN outputs)
        if output.value.to_sat() <= DUST_THRESHOLD {
            return Err(Error::TxContainsDustOutputs {});
        }
    }

    // Check that values of slashing and staking transaction are larger than 0
    if slashing_tx.output[0].value.to_sat() == 0 || staking_output_value == 0 {
        return Err(Error::InvalidSlashingAmount {});
    }

    // Check fees
    let total_output_value: u64 = slashing_tx
        .output
        .iter()
        .map(|out| out.value.to_sat())
        .sum();

    // Ensure that the staking transaction value is larger than the sum of slashing transaction output values
    if staking_output_value <= total_output_value {
        return Err(Error::SlashingTxOverspend {});
    }

    // Ensure that the slashing transaction fee is larger than the specified minimum fee
    let calculated_fee = staking_output_value - total_output_value;
    if calculated_fee < slashing_tx_min_fee {
        return Err(Error::InsufficientSlashingFee(slashing_tx_min_fee));
    }

    Ok(())
}

/// Validates all relevant data of slashing and funding transactions.
#[allow(clippy::too_many_arguments)]
pub fn check_slashing_tx_match_funding_tx(
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

fn calc_sighash(
    transaction: &Transaction,
    funding_output: &TxOut,
    path_script: &Script,
) -> Result<[u8; 32]> {
    // Check for incorrect input count
    if transaction.input.len() != 1 {
        return Err(Error::TxInputCountMismatch(1, transaction.input.len()));
    }

    // calculate tap leaf hash for the given path of the script
    let tap_leaf_hash = path_script.tapscript_leaf_hash();

    // calculate the sig hash of the tx with the given funding output
    let mut sighash_cache = SighashCache::new(transaction);
    let sighash = sighash_cache
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[funding_output]),
            tap_leaf_hash,
            bitcoin::TapSighashType::Default,
        )
        .unwrap();

    Ok(sighash.to_raw_hash().to_byte_array())
}

/// verify_transaction_sig_with_output verifies the validity of a Schnorr signature for a given transaction
pub fn verify_transaction_sig_with_output(
    transaction: &Transaction,
    funding_output: &TxOut,
    path_script: &Script,
    pub_key: &VerifyingKey,
    signature: &SchnorrSignature,
) -> Result<()> {
    // calculate the sig hash of the tx for the given spending path
    let sighash = calc_sighash(transaction, funding_output, path_script)?;

    verify_digest(pub_key, &sighash, signature)
        .map_err(|e| Error::InvalidSchnorrSignature(e.to_string()))
}

/// `enc_verify_transaction_sig_with_output` verifies the validity of a Schnorr adaptor signature
/// for a given transaction
pub fn enc_verify_transaction_sig_with_output(
    transaction: &Transaction,
    funding_output: &TxOut,
    path_script: &Script,
    pub_key: &VerifyingKey,
    enc_key: &VerifyingKey,
    signature: &AdaptorSignature,
) -> Result<()> {
    // calculate the sig hash of the tx for the given spending path
    let sighash_msg = calc_sighash(transaction, funding_output, path_script)?;

    // verify the signature w.r.t. the signature, the sig hash, and the public key
    signature
        .verify(pub_key, enc_key, sighash_msg)
        .map_err(|e| Error::InvalidSchnorrSignature(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::BabylonScriptPaths;
    use babylon_schnorr_adaptor_signature::AdaptorSignature;
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::deserialize;
    use bitcoin::hashes::Hash;
    use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut};

    use babylon_test_utils::{get_btc_delegation, get_params};

    #[test]
    fn test_check_slashing_tx_match_funding_tx() {
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

        // Test 1: Valid case should pass
        check_slashing_tx_match_funding_tx(
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

        // Test 2: Zero slashing tx min fee should fail
        let result = check_slashing_tx_match_funding_tx(
            &slashing_tx,
            &staking_tx,
            funding_out_idx,
            0, // Zero minimum fee
            slashing_rate,
            slashing_pk_script,
            &staker_pk,
            slashing_change_lock_time,
        );
        assert!(matches!(result, Err(Error::InsufficientSlashingFee(0))));

        // Test 3: Invalid slashing rate (exactly 0) should fail
        let result = check_slashing_tx_match_funding_tx(
            &slashing_tx,
            &staking_tx,
            funding_out_idx,
            slashing_tx_min_fee,
            0.0, // Invalid rate (exactly 0)
            slashing_pk_script,
            &staker_pk,
            slashing_change_lock_time,
        );
        assert!(matches!(result, Err(Error::InvalidSlashingRate {})));

        // Test 4: Invalid slashing rate (> 1) should fail
        let result = check_slashing_tx_match_funding_tx(
            &slashing_tx,
            &staking_tx,
            funding_out_idx,
            slashing_tx_min_fee,
            1.5, // Invalid rate (> 1)
            slashing_pk_script,
            &staker_pk,
            slashing_change_lock_time,
        );
        assert!(matches!(result, Err(Error::InvalidSlashingRate {})));

        // Test 5: Invalid slashing rate (too many decimal places) should fail
        let result = check_slashing_tx_match_funding_tx(
            &slashing_tx,
            &staking_tx,
            funding_out_idx,
            slashing_tx_min_fee,
            0.12345, // Invalid rate (5 decimal places)
            slashing_pk_script,
            &staker_pk,
            slashing_change_lock_time,
        );
        assert!(matches!(result, Err(Error::InvalidSlashingRate {})));

        // Test 6: Out-of-bounds funding output index should fail
        let result = check_slashing_tx_match_funding_tx(
            &slashing_tx,
            &staking_tx,
            999, // Invalid index (way beyond bounds)
            slashing_tx_min_fee,
            slashing_rate,
            slashing_pk_script,
            &staker_pk,
            slashing_change_lock_time,
        );
        assert!(matches!(
            result,
            Err(Error::InvalidFundingOutputIndex(999, _))
        ));

        // Test 7: Slashing tx not spending correct funding transaction should fail
        let mut invalid_slashing_tx = slashing_tx.clone();
        // Change the input to point to a different transaction (all zeros)
        invalid_slashing_tx.input[0].previous_output.txid = bitcoin::Txid::from_raw_hash(
            bitcoin::hashes::sha256d::Hash::from_byte_array([0u8; 32]),
        );
        let result = check_slashing_tx_match_funding_tx(
            &invalid_slashing_tx,
            &staking_tx,
            funding_out_idx,
            slashing_tx_min_fee,
            slashing_rate,
            slashing_pk_script,
            &staker_pk,
            slashing_change_lock_time,
        );
        assert!(matches!(
            result,
            Err(Error::StakingOutputNotSpentBySlashingTx {})
        ));

        // Test 8: Slashing tx spending wrong output index should fail
        let mut invalid_slashing_tx = slashing_tx.clone();
        invalid_slashing_tx.input[0].previous_output.vout = 999; // Wrong output index
        let result = check_slashing_tx_match_funding_tx(
            &invalid_slashing_tx,
            &staking_tx,
            funding_out_idx,
            slashing_tx_min_fee,
            slashing_rate,
            slashing_pk_script,
            &staker_pk,
            slashing_change_lock_time,
        );
        assert!(matches!(
            result,
            Err(Error::StakingOutputNotSpentBySlashingTx {})
        ));
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

    #[test]
    fn test_validate_slashing_tx() {
        let btc_del = get_btc_delegation(1, vec![1]);
        let params = get_params();

        let staking_tx: Transaction = deserialize(&btc_del.staking_tx).unwrap();
        let slashing_tx: Transaction = deserialize(&btc_del.slashing_tx).unwrap();
        let staker_pk: VerifyingKey = VerifyingKey::from_bytes(&btc_del.btc_pk).unwrap();
        let slashing_rate: f64 = 0.01;
        let slashing_tx_min_fee: u64 = 1;
        // Use the actual staking output value from the test data
        let staking_output_value: u64 = staking_tx.output[0].value.to_sat();
        let slashing_change_lock_time: u16 = 101;
        let slashing_pk_script = &params.slashing_pk_script;
        let op_return_script = ScriptBuf::from_hex("6a0548656c6c6f").unwrap(); // OP_RETURN "Hello"

        // Test 1: Valid slashing transaction should pass
        validate_slashing_tx(
            &slashing_tx,
            slashing_pk_script,
            slashing_rate,
            slashing_tx_min_fee,
            staking_output_value,
            &staker_pk,
            slashing_change_lock_time,
        )
        .unwrap();

        // Test 2: Zero slashing output value should fail with InvalidSlashingAmount
        let mut invalid_tx = slashing_tx.clone();
        invalid_tx.output[0] = TxOut {
            value: Amount::from_sat(0),
            script_pubkey: op_return_script.clone(),
        };
        let result = validate_slashing_tx(
            &invalid_tx,
            op_return_script.as_bytes(),
            0.0,
            slashing_tx_min_fee,
            staking_output_value,
            &staker_pk,
            slashing_change_lock_time,
        );
        assert!(matches!(result, Err(Error::InvalidSlashingAmount {})));

        // Test 3: Zero staking output value should fail with InvalidSlashingAmount
        let result = validate_slashing_tx(
            &slashing_tx,
            slashing_pk_script,
            slashing_rate,
            slashing_tx_min_fee,
            0, // Zero staking output value
            &staker_pk,
            slashing_change_lock_time,
        );
        assert!(matches!(result, Err(Error::InvalidSlashingAmount {})));

        // Test 4: Regular dust outputs should fail
        let mut invalid_tx = slashing_tx.clone();
        invalid_tx.output[0].value = Amount::from_sat(DUST_THRESHOLD - 1); // Below 546 sat threshold
        let result = validate_slashing_tx(
            &invalid_tx,
            slashing_pk_script,
            0.0,
            slashing_tx_min_fee,
            staking_output_value,
            &staker_pk,
            slashing_change_lock_time,
        );
        assert!(matches!(result, Err(Error::TxContainsDustOutputs {})));

        // Test 5: OP_RETURN dust outputs should pass validation (exemption from dust check)
        let mut tx_with_op_return_slashing = slashing_tx.clone();

        // Replace the first output (slashing output) with an OP_RETURN dust output
        tx_with_op_return_slashing.output[0] = TxOut {
            value: Amount::from_sat(50), // Well below 546 sat dust threshold
            script_pubkey: op_return_script.clone(),
        };

        // This should succeed because OP_RETURN outputs are exempt from dust validation
        validate_slashing_tx(
            &tx_with_op_return_slashing,
            op_return_script.as_bytes(), // Pass OP_RETURN script as expected slashing script
            0.0,
            slashing_tx_min_fee,
            staking_output_value,
            &staker_pk,
            slashing_change_lock_time,
        )
        .unwrap();

        // Test 6: Insufficient slashing amount should fail
        let result = validate_slashing_tx(
            &slashing_tx,
            slashing_pk_script,
            0.99, // 99% slashing rate - way more than the output can provide
            slashing_tx_min_fee,
            staking_output_value,
            &staker_pk,
            slashing_change_lock_time,
        );
        assert!(matches!(result, Err(Error::InsufficientSlashingAmount(_))));

        // Test 7: Invalid slashing pk script should fail
        let wrong_pk_script = b"wrong_script";
        let result = validate_slashing_tx(
            &slashing_tx,
            wrong_pk_script,
            slashing_rate,
            slashing_tx_min_fee,
            staking_output_value,
            &staker_pk,
            slashing_change_lock_time,
        );
        assert!(matches!(result, Err(Error::InvalidSlashingPkScript {})));

        // Test 8: Insufficient fee should fail
        let result = validate_slashing_tx(
            &slashing_tx,
            slashing_pk_script,
            slashing_rate,
            staking_output_value - 1000, // Very high minimum fee (almost all the staking value)
            staking_output_value,
            &staker_pk,
            slashing_change_lock_time,
        );
        assert!(matches!(result, Err(Error::InsufficientSlashingFee(_))));

        // Test 9: Slashing transaction spending more than staking should fail
        let mut overspend_tx = slashing_tx.clone();
        // Set outputs to values that total more than the staking output
        let half_staking = staking_output_value / 2;
        overspend_tx.output[0].value = Amount::from_sat(half_staking);
        overspend_tx.output[1].value = Amount::from_sat(half_staking + 1); // Total > staking_output_value
        let result = validate_slashing_tx(
            &overspend_tx,
            slashing_pk_script,
            slashing_rate,
            slashing_tx_min_fee,
            staking_output_value,
            &staker_pk,
            slashing_change_lock_time,
        );
        assert!(matches!(result, Err(Error::SlashingTxOverspend {})));
    }

    #[test]
    fn test_op_return_detection() {
        // Test OP_RETURN script detection
        let op_return_script = ScriptBuf::from_hex("6a0548656c6c6f").unwrap(); // OP_RETURN "Hello"
        assert!(is_op_return_output(&op_return_script));

        // Test non-OP_RETURN scripts
        let p2pkh_script =
            ScriptBuf::from_hex("76a914abc123456789abcdef123456789abcdef12345678988ac").unwrap();
        assert!(!is_op_return_output(&p2pkh_script));

        let empty_script = ScriptBuf::new();
        assert!(!is_op_return_output(&empty_script));

        // Test script that starts with OP_RETURN
        let simple_op_return = ScriptBuf::from_hex("6a").unwrap(); // Just OP_RETURN
        assert!(is_op_return_output(&simple_op_return));
    }
}
