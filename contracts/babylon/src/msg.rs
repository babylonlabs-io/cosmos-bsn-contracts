//! Types and messages for the Babylon contract API.

#[cfg(not(target_arch = "wasm32"))]
use crate::state::Config;
use babylon_apis::finality_api::Evidence;
use babylon_proto::babylon::checkpointing::v1::RawCheckpoint;
use babylon_proto::babylon::epoching::v1::Epoch;
use babylon_proto::babylon::zoneconcierge::v1::IndexedHeader;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Binary, Decimal, StdError, StdResult, Timestamp, Uint128};
use hex::ToHex;

pub type TransferInfoResponse = Option<String>;

#[cw_serde]
pub struct InstantiateMsg {
    pub network: btc_light_client::BitcoinNetwork,
    pub btc_confirmation_depth: u32,
    pub checkpoint_finalization_timeout: u32,
    /// If set, this will instantiate a BTC light client contract
    pub btc_light_client_code_id: u64,
    /// If set, this will define the instantiation message for the BTC light client contract.
    /// This message is opaque to the Babylon contract, and depends on the specific light client
    /// being instantiated
    pub btc_light_client_msg: Option<Binary>,
    /// If set, this will instantiate a BTC staking contract for BTC re-staking
    pub btc_staking_code_id: u64,
    /// If set, this will define the instantiation message for the BTC staking contract.
    /// This message is opaque to the Babylon contract, and depends on the specific staking contract
    /// being instantiated
    pub btc_staking_msg: Option<Binary>,
    /// If set, this will instantiate a BTC finality contract
    pub btc_finality_code_id: u64,
    /// If set, this will define the instantiation message for the BTC finality contract.
    /// This message is opaque to the Babylon contract, and depends on the specific finality contract
    /// being instantiated
    pub btc_finality_msg: Option<Binary>,
    /// If set, this will be the Wasm migration / upgrade admin of the BTC staking contract and the
    /// BTC finality contract
    pub admin: Option<String>,
    /// Name of the consumer
    pub consumer_name: String,
    /// Description of the consumer
    pub consumer_description: String,
    /// IBC information for ICS-020 rewards transfer.
    /// Required for rewards distribution on Babylon Genesis
    pub ics20_channel_id: String,
    /// IBC packet timeout in days
    /// If not set, the default value (28 days) will be used
    pub ibc_packet_timeout_days: Option<u64>,
    /// Babylon module name for receiving ICS-20 transfers
    pub destination_module: String,
}

impl InstantiateMsg {
    #[cfg(any(test, feature = "library"))]
    pub fn new_test() -> Self {
        Self {
            network: btc_light_client::BitcoinNetwork::Regtest,
            btc_confirmation_depth: 1,
            checkpoint_finalization_timeout: 1,
            btc_light_client_code_id: 2,
            btc_light_client_msg: None,
            btc_staking_code_id: 3,
            btc_staking_msg: None,
            btc_finality_code_id: 4,
            btc_finality_msg: None,
            admin: None,
            consumer_name: "default-consumer".to_string(),
            consumer_description: "default-consumer-description".to_string(),
            ics20_channel_id: "channel-0".to_string(),
            ibc_packet_timeout_days: None,
            destination_module: "btcstaking".to_string(),
        }
    }

    pub fn validate(&self) -> StdResult<()> {
        if self.consumer_name.trim().is_empty() {
            return Err(StdError::generic_err("Consumer name cannot be empty"));
        }

        if self.consumer_description.trim().is_empty() {
            return Err(StdError::generic_err(
                "Consumer description cannot be empty",
            ));
        }

        // Validate that ICS-020 channel ID is not empty
        if self.ics20_channel_id.trim().is_empty() {
            return Err(StdError::generic_err("ICS-020 channel_id cannot be empty"));
        }

        Ok(())
    }
}

#[cw_serde]
pub struct MigrateMsg {}

#[cw_serde]
pub enum ExecuteMsg {
    /// Slashing event from the BTC staking contract.
    ///
    /// This will be forwarded over IBC to the Babylon side for propagation to other Consumers, and
    /// Babylon itself
    Slashing { evidence: Evidence },
    /// Message sent by the finality contract, to send rewards to distribute to Babylon Genesis
    RewardsDistribution {
        /// List of finality providers and their rewards
        fp_distribution: Vec<RewardInfo>,
    },
}

#[cw_serde]
pub struct RewardInfo {
    pub fp_pubkey_hex: String,
    pub reward: Uint128,
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    /// Returns the current configuration of the babylon-contract.
    #[returns(Config)]
    Config {},
    /// Returns the base Babylon epoch stored in the contract.
    #[returns(EpochResponse)]
    BabylonBaseEpoch {},
    /// Returns the last babylon finalized epoch stored in the contract.
    #[returns(EpochResponse)]
    BabylonLastEpoch {},
    /// Returns the Babylon epoch stored in the contract, by epoch number.
    #[returns(EpochResponse)]
    BabylonEpoch { epoch_number: u64 },
    /// Returns the Babylon checkpoint stored in the contract, by epoch number.
    #[returns(EpochResponse)]
    BabylonCheckpoint { epoch_number: u64 },
    /// Returns the last Consumer epoch stored in the contract.
    #[returns(ConsumerHeaderResponse)]
    LastConsumerHeader {},
    /// Returns the last Consumer height stored in the contract.
    #[returns(ConsumerHeightResponse)]
    LastConsumerHeight {},
    /// Returns the Consumer header stored in the contract, by Consumer height.
    #[returns(ConsumerHeaderResponse)]
    ConsumerHeader { height: u64 },
    /// Returns the IBC transfer information stored in the contract
    /// for ICS-020 rewards transfer.
    #[returns(Option<String>)]
    TransferInfo {},
}

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

/// Metadata of a Consumer header.
///
/// This struct is for use in RPC requests and responses. It has convenience helpers to convert
/// from the internal representation (`IndexedHeader`).
///
/// Adapted from `IndexedHeader`.
#[cw_serde]
pub struct ConsumerHeaderResponse {
    /// Unique ID of the consumer
    pub consumer_id: String,
    /// Hash of this header.
    /// Hex-encoded string of 32 bytes
    pub hash: String,
    /// Height of this header in the Consumer's ledger.
    /// (hash, height) jointly provides the position of the header on the Consumer ledger
    pub height: u64,
    /// Timestamp of this header in the Consumer's ledger.
    /// It's necessary for the Consumer to unbond all mature validators/delegations before this
    /// timestamp when this header is BTC-finalised
    pub time: Option<Timestamp>,
    /// Hash of the babylon block that includes this Consumer header.
    /// Hex-encoded string of 32 bytes
    pub babylon_header_hash: String,
    /// Height of the babylon block that includes this Consumer header
    pub babylon_header_height: u64,
    /// Epoch number of this header in the Babylon ledger
    pub babylon_epoch: u64,
    /// Hash of the tx that includes this header.
    /// (babylon_block_height, babylon_tx_hash) jointly provides the position of
    /// Header in the Babylon ledger.
    /// Hex-encoded string of 32 bytes
    pub babylon_tx_hash: String,
}

/// Metadata of a Consumer height.
///
/// This struct is for use in RPC requests and responses. It is a convenience, efficient way to
/// return the height of the last finalised Consumer header.
///
/// Adapted from `ConsumerHeaderResponse`.
#[cw_serde]
pub struct ConsumerHeightResponse {
    pub height: u64,
}

/// Convert from `&IndexedHeader` to `ConsumerHeaderResponse`.
impl From<&IndexedHeader> for ConsumerHeaderResponse {
    fn from(header: &IndexedHeader) -> Self {
        ConsumerHeaderResponse {
            consumer_id: header.consumer_id.clone(),
            hash: header.hash.encode_hex(),
            height: header.height,
            time: header
                .time
                .as_ref()
                .map(|t| Timestamp::from_seconds(t.seconds as u64).plus_nanos(t.nanos as u64)),
            babylon_header_hash: header.babylon_header_hash.encode_hex(),
            babylon_header_height: header.babylon_header_height,
            babylon_epoch: header.babylon_epoch,
            babylon_tx_hash: header.babylon_tx_hash.encode_hex(),
        }
    }
}

/// Convert from `IndexedHeader` to `ConsumerHeaderResponse`.
impl From<IndexedHeader> for ConsumerHeaderResponse {
    fn from(header: IndexedHeader) -> Self {
        Self::from(&header)
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

#[cw_serde]
pub struct BtcTimestampResponse {
    pub placeholder: String,
}

/// Defines the callback structures used for IBC transfers to Babylon,
/// specifically for reward distribution and staking operations.
///
/// Reference: https://github.com/babylonlabs-io/babylon/blob/fa63f5eadc697dc17773de2ef4fc6d972a5e1618/x/btcstaking/types/ibc_callbacks.go
#[cw_serde]
pub struct CallbackMemo {
    pub action: String,
    pub dest_callback: CallbackInfo,
}

impl CallbackMemo {
    /// Action for adding BSN rewards
    const ADD_BSN_REWARDS_ACTION: &str = "add_bsn_rewards";

    /// Creates a new callback memo for adding Cosmos BSN rewards
    ///
    /// # Arguments
    ///
    /// * `address` - Address that calls the callback
    /// * `fp_ratios` - The FP ratios for the rewards
    pub fn new_add_cosmos_bsn_rewards(address: String, fp_ratios: Vec<FpRatio>) -> Self {
        Self {
            action: Self::ADD_BSN_REWARDS_ACTION.to_string(),
            dest_callback: CallbackInfo {
                address,
                add_bsn_rewards: BsnRewards::new_cosmos(fp_ratios),
            },
        }
    }
}

#[cw_serde]
pub struct CallbackInfo {
    pub address: String,
    pub add_bsn_rewards: BsnRewards,
}

#[cw_serde]
pub struct BsnRewards {
    /// If set, this stores the address of the Babylon consumer contract on the Consumer.
    /// Cosmos BSN should always use `None`
    pub bsn_consumer_id: Option<String>,
    /// The FP ratios for the rewards
    pub fp_ratios: Vec<FpRatio>,
}

impl BsnRewards {
    /// Creates a new BSN rewards struct for Cosmos BSN
    ///
    /// # Arguments
    ///
    /// * `fp_ratios` - The FP ratios for the rewards
    pub fn new_cosmos(fp_ratios: Vec<FpRatio>) -> Self {
        Self {
            // Cosmos BSN should always use `None` for `bsn_consumer_id`
            // because Babylon Genesis will use IBC modules to determine
            // the consumer ID
            bsn_consumer_id: None,
            fp_ratios,
        }
    }
}

#[cw_serde]
pub struct FpRatio {
    // FP BTC public key, encoded in hex
    pub btc_pk: String,
    pub ratio: Decimal,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexed_header_to_indexed_header_response_works() {
        let indexed_header = IndexedHeader {
            consumer_id: "consumer_id".to_string(),
            hash: prost::bytes::Bytes::from("hash"),
            height: 1,
            time: Some(::pbjson_types::Timestamp {
                seconds: 2,
                nanos: 3,
            }),
            babylon_header_hash: prost::bytes::Bytes::from("babylon_header_hash"),
            babylon_header_height: 4,
            babylon_epoch: 5,
            babylon_tx_hash: prost::bytes::Bytes::from("babylon_tx_hash"),
        };

        let indexed_header_response = ConsumerHeaderResponse::from(&indexed_header);

        assert_eq!(indexed_header_response.consumer_id, "consumer_id");
        assert_eq!(indexed_header_response.hash, hex::encode("hash"));
        assert_eq!(indexed_header_response.height, 1);
        assert_eq!(
            indexed_header_response.time.unwrap(),
            Timestamp::from_seconds(2).plus_nanos(3)
        );
        assert_eq!(
            indexed_header_response.babylon_header_hash,
            hex::encode("babylon_header_hash")
        );
        assert_eq!(indexed_header_response.babylon_header_height, 4);
        assert_eq!(indexed_header_response.babylon_epoch, 5);
        assert_eq!(
            indexed_header_response.babylon_tx_hash,
            hex::encode("babylon_tx_hash")
        );
    }

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
