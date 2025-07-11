use crate::adaptor_sig::AdaptorSignature;
use crate::error::Error;
use crate::Result;
use bitcoin::hashes::Hash;
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::{Script, TxOut};
use bitcoin::{ScriptBuf, Transaction};

use k256::schnorr::Signature as SchnorrSignature;
use k256::schnorr::VerifyingKey;

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

pub fn get_output_idx(tx: &Transaction, pk_script: ScriptBuf) -> Result<u32> {
    let output_idx = tx
        .output
        .iter()
        .position(|output| output.script_pubkey == *pk_script);
    match output_idx {
        Some(idx) => Ok(idx as u32),
        None => Err(Error::TxOutputIndexNotFound {}),
    }
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

    crate::schnorr::verify_digest(pub_key, &sighash, signature)
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
    signature.verify(pub_key, enc_key, sighash_msg)
}
