use crate::error;
use babylon_proto::babylon::epoching::v1::Epoch;
use babylon_proto::babylon::zoneconcierge::v1::IndexedHeader;
use prost::Message;
use tendermint_proto::crypto::ProofOps;

/// Verifies whether a tx with tx_hash is committed to the Merkle root hash of a Tendermint block.
pub fn verify_consumer_header_in_epoch(
    consumer_header: &IndexedHeader,
    epoch: &Epoch,
    proof_consumer_header_in_epoch: &ProofOps,
) -> Result<(), error::ConsumerHeaderChainError> {
    // Verify that the Consumer header has the correct epoch number
    if consumer_header.babylon_epoch != epoch.epoch_number {
        return Err(error::ConsumerHeaderChainError::EpochNumberError {});
    }

    // Ensure the Consumer header is committed to the app_hash of the sealer header
    let root = &epoch.sealer_app_hash;
    let consumer_header_key = super::cosmos_store::get_consumer_header_key(
        &consumer_header.consumer_id,
        consumer_header.height,
    );
    let consumer_header_bytes = consumer_header.encode_to_vec();
    super::cosmos_store::verify_store(
        root,
        super::cosmos_store::ZONECONCIERGE_STORE_KEY,
        &consumer_header_key,
        &consumer_header_bytes,
        proof_consumer_header_in_epoch,
    )
    .map_err(|_| error::ConsumerHeaderChainError::ProofError {})?;

    Ok(())
}

// TODO: test
