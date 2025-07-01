use babylon_bitcoin::BlockHeader;
use babylon_proto::babylon::btccheckpoint::v1::TransactionInfo;
use babylon_proto::babylon::checkpointing::v1::{RawCheckpoint, CURRENT_VERSION};
use babylon_proto::babylon::epoching::v1::Epoch;
use babylon_proto::babylon::zoneconcierge::v1::ProofEpochSealed;
use prost::Message;

pub const NUM_BTC_TXS: usize = 2;

/// Ensures the given raw checkpoint is sealed, i.e., BLS-signed, by the validator set of the given epoch.
/// reference implementation: https://github.com/babylonlabs-io/babylon/blob/v0.5.0/x/zoneconcierge/keeper/proof_epoch_sealed.go
pub fn verify_epoch_sealed(
    epoch: &Epoch,
    raw_ckpt: &RawCheckpoint,
    proof: &ProofEpochSealed,
) -> Result<(), String> {
    // ensure epoch number is same in epoch and raw checkpoint
    if epoch.epoch_number != raw_ckpt.epoch_num {
        return Err(format!(
            "epoch's epoch number ({}) is not equal to raw_ckpt's epoch number ({})",
            epoch.epoch_number, raw_ckpt.epoch_num
        ));
    }

    // ensure the raw checkpoint's block_hash is same as in the header of the epoch metadata
    // NOTE: since this proof is assembled by a Babylon node who has verified the checkpoint,
    // the two lch values should always be the same, otherwise this Babylon node is malicious.
    // This is different from the checkpoint verification rules in checkpointing,
    // where a checkpoint with valid BLS multisig but different lch signals a dishonest majority equivocation.
    let block_hash_in_ckpt: &[u8] = raw_ckpt.block_hash.as_ref();
    let block_hash_in_epoch: &[u8] = epoch.sealer_block_hash.as_ref();
    if !block_hash_in_ckpt.eq(block_hash_in_epoch) {
        return Err(format!(
            "checkpoint's block_hash ({}) is not equal to epoch's sealer_block_hash ({})",
            hex::encode(block_hash_in_ckpt),
            hex::encode(block_hash_in_epoch)
        ));
    }

    /*
        Ensure more than 1/3 (in voting power) validators of this epoch have
        signed (epoch_num || app_hash) in the raw checkpoint
    */
    let val_set = babylon_proto::babylon::checkpointing::v1::ValidatorWithBlsKeySet {
        val_set: proof.validator_set.clone(),
    };
    let (signer_set, signer_set_power) = val_set
        .find_subset_with_power_sum(&raw_ckpt.bitmap)
        .map_err(|err| format!("failed to get voted subset: {err:?}"))?;

    // ensure the signerSet has > 2/3 voting power
    if signer_set_power * 3 <= val_set.get_total_power() * 2 {
        return Err("the BLS signature involves insufficient voting power".to_string());
    }
    // verify BLS multisig
    super::bls::verify_multisig(&raw_ckpt.bls_multi_sig, &signer_set, &raw_ckpt.signed_msg())?;

    // Ensure The epoch metadata is committed to the app_hash of the sealer header
    let root = &epoch.sealer_app_hash;
    let epoch_info_key = super::cosmos_store::get_epoch_info_key(epoch.epoch_number);
    let epoch_merkle_proof = proof
        .proof_epoch_info
        .as_ref()
        .ok_or("missing merkle proof epoch info")?;
    // NOTE: the proof is generated at the 1st header of the next epoch
    // At that time, the sealer header is not assigned to the epoch metadata
    // and the proof does not include the sealer header.
    // Thus, we need to unassign here
    let mut epoch_no_sealer = epoch.clone();
    epoch_no_sealer.sealer_app_hash = vec![].into();
    let epoch_bytes = epoch_no_sealer.encode_to_vec();
    super::cosmos_store::verify_store(
        root,
        super::cosmos_store::EPOCHING_STORE_KEY,
        &epoch_info_key,
        &epoch_bytes,
        epoch_merkle_proof,
    )?;

    // Ensure The validator set is committed to the app_hash of the sealer header
    let valset_key = super::cosmos_store::get_valset_key(epoch.epoch_number);
    let valset_bytes = val_set.encode_to_vec();
    let valset_merkle_proof = proof
        .proof_epoch_val_set
        .as_ref()
        .ok_or("missing merkle proof epoch val set")?;
    super::cosmos_store::verify_store(
        root,
        super::cosmos_store::CHECKPOINTING_STORE_KEY,
        &valset_key,
        &valset_bytes,
        valset_merkle_proof,
    )?;

    Ok(())
}

/// Ensures the given raw checkpoint is submitted, i.e., whose two txs are in the given 2 BTC headers.
/// reference implementation: https://github.com/babylonlabs-io/babylon/blob/v0.5.0/x/zoneconcierge/keeper/proof_epoch_submitted.go
pub fn verify_checkpoint_submitted(
    raw_ckpt: &RawCheckpoint,
    txs_info: &[TransactionInfo; NUM_BTC_TXS],
    btc_headers: &[BlockHeader; NUM_BTC_TXS],
    babylon_tag: &[u8],
) -> Result<(), String> {
    // decoded checkpoint data
    let mut checkpoint_data_arr: Vec<Vec<u8>> = vec![];

    // for each tx info, verify the Merkle proof and extract checkpoint data
    for i in 0..NUM_BTC_TXS {
        let tx_info = &txs_info[i];
        let btc_header = &btc_headers[i];
        // verify Merkle proof and extract BTC tx
        let btc_tx = super::bitcoin::parse_tx_info(tx_info, btc_header)?;
        // extract OP_RETURN data
        let checkpoint_data = super::bitcoin::extract_checkpoint_data(&btc_tx, babylon_tag, i)?;
        checkpoint_data_arr.push(checkpoint_data);
    }

    // decode checkpoint_data array to raw checkpoint
    let decode_raw_ckpt = RawCheckpoint::from_checkpoint_data(
        CURRENT_VERSION,
        checkpoint_data_arr[0].clone(),
        checkpoint_data_arr[1].clone(),
    )?;

    // check if the decoded raw checkpoint is same as the given one
    if decode_raw_ckpt.ne(raw_ckpt) {
        return Err(
            "Raw checkpoint decoded from BTC txs is different from the given one".to_string(),
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_utils::get_btc_timestamp_and_headers;

    #[test]
    fn verify_epoch_sealed_works() {
        let (btc_ts, _) = get_btc_timestamp_and_headers();
        let epoch = btc_ts.epoch_info.unwrap();
        let raw_ckpt = btc_ts.raw_checkpoint.unwrap();
        let proof = btc_ts.proof.unwrap().proof_epoch_sealed.unwrap();
        verify_epoch_sealed(&epoch, &raw_ckpt, &proof).unwrap();
    }

    #[test]
    fn verify_checkpoint_submitted_works() {
        let (btc_ts, header_map) = get_btc_timestamp_and_headers();
        let raw_ckpt = btc_ts.raw_checkpoint.unwrap();
        let txs_info = btc_ts.proof.unwrap().proof_epoch_submitted;
        let txs_info_arr: &[TransactionInfo; NUM_BTC_TXS] =
            &[txs_info[0].clone(), txs_info[1].clone()];

        // get 2 btc headers
        let k1: &[u8] = &txs_info[0].clone().key.unwrap().hash;
        let k2: &[u8] = &txs_info[1].clone().key.unwrap().hash;
        let btc_headers: &[BlockHeader; 2] =
            &[*header_map.get(k1).unwrap(), *header_map.get(k2).unwrap()];

        let babylon_tag = vec![0x1, 0x2, 0x3, 0x4];
        verify_checkpoint_submitted(&raw_ckpt, txs_info_arr, btc_headers, &babylon_tag).unwrap();
    }

    // TODO: more tests on different scenarios
}
