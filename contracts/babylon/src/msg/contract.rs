use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Binary, StdError, StdResult, Uint128};

use babylon_apis::finality_api::Evidence;

#[cfg(not(target_arch = "wasm32"))]
use {
    crate::msg::consumer_header::{ConsumerHeaderResponse, ConsumerHeightResponse},
    crate::msg::epoch::EpochResponse,
    crate::state::config::Config,
};

const BABYLON_TAG_BYTES: usize = 4;

// Common functions for contract messages
pub trait ContractMsg {
    fn validate(&self) -> StdResult<()>;
    fn babylon_tag_to_bytes(&self) -> StdResult<Vec<u8>>;
}

#[cw_serde]
pub struct InstantiateMsg {
    pub network: btc_light_client::BitcoinNetwork,
    /// A string encoding four bytes used for identification / tagging of the Babylon zone.
    /// NOTE: this is a hex string, not raw bytes
    pub babylon_tag: String,
    pub btc_confirmation_depth: u32,
    pub checkpoint_finalization_timeout: u32,
    /// Whether to send Cosmos zone messages notifying BTC-finalised headers.
    /// NOTE: If set to true, then the Cosmos zone needs to integrate the corresponding message handler
    /// as well
    pub notify_cosmos_zone: bool,
    /// If set, this will instantiate a BTC light client contract
    pub btc_light_client_code_id: Option<u64>,
    /// If set, this will define the instantiation message for the BTC light client contract.
    /// This message is opaque to the Babylon contract, and depends on the specific light client
    /// being instantiated
    pub btc_light_client_msg: Option<Binary>,
    /// If set, this will instantiate a BTC staking contract for BTC re-staking
    pub btc_staking_code_id: Option<u64>,
    /// If set, this will define the instantiation message for the BTC staking contract.
    /// This message is opaque to the Babylon contract, and depends on the specific staking contract
    /// being instantiated
    pub btc_staking_msg: Option<Binary>,
    /// If set, this will instantiate a BTC finality contract
    pub btc_finality_code_id: Option<u64>,
    /// If set, this will define the instantiation message for the BTC finality contract.
    /// This message is opaque to the Babylon contract, and depends on the specific finality contract
    /// being instantiated
    pub btc_finality_msg: Option<Binary>,
    /// If set, this will be the Wasm migration / upgrade admin of the BTC staking contract and the
    /// BTC finality contract
    pub admin: Option<String>,
    /// Name of the consumer
    pub consumer_name: Option<String>,
    /// Description of the consumer
    pub consumer_description: Option<String>,
    /// IBC information for ICS-020 rewards transfer.
    /// Required for rewards distribution on Babylon Genesis
    pub ics20_channel_id: String,
}

impl InstantiateMsg {
    #[cfg(any(test, feature = "library"))]
    pub fn new_test() -> Self {
        Self {
            network: btc_light_client::BitcoinNetwork::Regtest,
            babylon_tag: "01020304".to_string(),
            btc_confirmation_depth: 1,
            checkpoint_finalization_timeout: 1,
            notify_cosmos_zone: false,
            btc_light_client_code_id: None,
            btc_light_client_msg: None,
            btc_staking_code_id: None,
            btc_staking_msg: None,
            btc_finality_code_id: None,
            btc_finality_msg: None,
            admin: None,
            consumer_name: None,
            consumer_description: None,
            ics20_channel_id: "channel-0".to_string(),
        }
    }
}

impl ContractMsg for InstantiateMsg {
    fn validate(&self) -> StdResult<()> {
        if self.babylon_tag.len() != BABYLON_TAG_BYTES * 2 {
            return Err(StdError::invalid_data_size(
                BABYLON_TAG_BYTES * 2,
                self.babylon_tag.len(),
            ));
        }
        let _ = self.babylon_tag_to_bytes()?;

        if self.btc_staking_code_id.is_some() {
            if let (Some(consumer_name), Some(consumer_description)) =
                (&self.consumer_name, &self.consumer_description)
            {
                if consumer_name.trim().is_empty() {
                    return Err(StdError::generic_err("Consumer name cannot be empty"));
                }
                if consumer_description.trim().is_empty() {
                    return Err(StdError::generic_err(
                        "Consumer description cannot be empty",
                    ));
                }
            } else {
                return Err(StdError::generic_err(
                    "Consumer name and description are required when btc_staking_code_id is set",
                ));
            }
        }

        // Validate that ICS-020 channel ID is not empty
        if self.ics20_channel_id.trim().is_empty() {
            return Err(StdError::generic_err("ICS-020 channel_id cannot be empty"));
        }

        Ok(())
    }

    fn babylon_tag_to_bytes(&self) -> StdResult<Vec<u8>> {
        hex::decode(&self.babylon_tag).map_err(|_| {
            StdError::generic_err(format!(
                "babylon_tag is not a valid hex string: {}",
                self.babylon_tag
            ))
        })
    }
}

#[cw_serde]
pub enum ExecuteMsg {
    /// Slashing event from the BTC staking contract.
    ///
    /// This will be forwarded over IBC to the Babylon side for propagation to other Consumers, and
    /// Babylon itself
    Slashing { evidence: Evidence },
    /// Message sent by the finality contract, to send rewards to distribute to Babylon Genesis
    DistributeRewards {
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
