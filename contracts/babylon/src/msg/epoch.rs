use babylon_proto::babylon::checkpointing::v1::RawCheckpoint;
use babylon_proto::babylon::epoching::v1::Epoch;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::Timestamp;
use hex::ToHex;

/// Babylon epoch.
///
/// This struct is for use in RPC requests and responses. It has convenience helpers to convert
/// to and from the internal representation (`Epoch`).
/// Adapted from `Epoch`.
#[cw_serde]
pub struct EpochResponse {
    pub epoch_number: u64,
    pub current_epoch_interval: u64,
    pub first_block_height: u64,
    /// The time of the last block in this epoch.
    ///
    /// Babylon needs to remember the last header's time of each epoch to complete
    /// unbonding validators/delegations when a previous epoch's checkpoint is
    /// finalised. The `last_block_time` field is nil in the epoch's beginning, and
    /// is set upon the end of this epoch
    pub last_block_time: Option<Timestamp>,
    /// sealer is the last block of the sealed epoch.
    /// `sealer_app_hash` points to the sealer but stored in the first header of the next epoch.
    /// Hex-encoded string
    pub sealer_app_hash: String,
    /// The hash of the sealer.
    ///
    /// The validator set has generated a BLS multisig on the hash, i.e. the hash of the last block
    /// in the epoch in hex-encoded string.
    pub sealer_block_hash: String,
}

impl From<&Epoch> for EpochResponse {
    fn from(epoch: &Epoch) -> Self {
        EpochResponse {
            epoch_number: epoch.epoch_number,
            current_epoch_interval: epoch.current_epoch_interval,
            first_block_height: epoch.first_block_height,
            last_block_time: epoch
                .last_block_time
                .as_ref()
                .map(|t| Timestamp::from_seconds(t.seconds as u64).plus_nanos(t.nanos as u64)),
            sealer_app_hash: epoch.sealer_app_hash.encode_hex(),
            sealer_block_hash: epoch.sealer_block_hash.encode_hex(),
        }
    }
}

impl From<Epoch> for EpochResponse {
    fn from(epoch: Epoch) -> Self {
        Self::from(&epoch)
    }
}

/// CheckpointResponse wraps the BLS multi sig with metadata.
///
/// Adapted from `RawCheckpoint`.
#[cw_serde]
pub struct CheckpointResponse {
    /// The epoch number the raw checkpoint is for.
    pub epoch_num: u64,
    /// Defines the 'BlockID.Hash', which is the hash of the block that individual BLS sigs
    /// are signed on, in hex-encoded string.
    pub block_hash: String,
    /// Defines the bitmap that indicates the signers of the BLS multi sig, in hex-encoded string.
    pub bitmap: String,
    /// Defines the multi sig that is aggregated from individual BLS sigs, in hex-encoded string.
    pub bls_multi_sig: String,
}

impl From<&RawCheckpoint> for CheckpointResponse {
    fn from(checkpoint: &RawCheckpoint) -> Self {
        Self {
            epoch_num: checkpoint.epoch_num,
            block_hash: checkpoint.block_hash.encode_hex(),
            bitmap: checkpoint.bitmap.encode_hex(),
            bls_multi_sig: checkpoint.bls_multi_sig.encode_hex(),
        }
    }
}

impl From<RawCheckpoint> for CheckpointResponse {
    fn from(checkpoint: RawCheckpoint) -> Self {
        Self::from(&checkpoint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_to_epoch_reponse_works() {
        let epoch = Epoch {
            epoch_number: 1,
            current_epoch_interval: 2,
            first_block_height: 3,
            last_block_time: Some(::pbjson_types::Timestamp {
                seconds: 4,
                nanos: 5,
            }),
            sealer_app_hash: prost::bytes::Bytes::from("sealer_app_hash".as_bytes()),
            sealer_block_hash: prost::bytes::Bytes::from("sealer_block_hash".as_bytes()),
        };

        let epoch_response = EpochResponse::from(&epoch);
        assert_eq!(epoch_response.epoch_number, 1);
        assert_eq!(epoch_response.current_epoch_interval, 2);
        assert_eq!(epoch_response.first_block_height, 3);
        assert_eq!(
            epoch_response.last_block_time.unwrap(),
            Timestamp::from_seconds(4).plus_nanos(5)
        );
        assert_eq!(
            epoch_response.sealer_app_hash,
            hex::encode("sealer_app_hash")
        );
        assert_eq!(
            epoch_response.sealer_block_hash,
            hex::encode("sealer_block_hash")
        );
    }

    #[test]
    fn raw_checkpoint_to_checkpoint_response_works() {
        let checkpoint = RawCheckpoint {
            epoch_num: 1,
            block_hash: prost::bytes::Bytes::from("block_hash".as_bytes()),
            bitmap: prost::bytes::Bytes::from("bitmap".as_bytes()),
            bls_multi_sig: prost::bytes::Bytes::from("bls_multi_sig".as_bytes()),
        };

        let checkpoint_response = CheckpointResponse::from(&checkpoint);
        assert_eq!(checkpoint_response.epoch_num, 1);
        assert_eq!(checkpoint_response.block_hash, hex::encode("block_hash"));
        assert_eq!(checkpoint_response.bitmap, hex::encode("bitmap"));
        assert_eq!(
            checkpoint_response.bls_multi_sig,
            hex::encode("bls_multi_sig")
        );
    }
}
