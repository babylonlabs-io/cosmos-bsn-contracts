use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Binary, StdError, StdResult};

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
pub struct BtcLightClientInitMsg {
    pub btc_light_client_code_id: u64,
    /// This message is opaque to the Babylon contract, and depends on the specific light client
    /// being instantiated
    pub btc_light_client_msg: Option<Binary>,
}

#[cw_serde]
pub struct InstantiateMsg {
    pub network: babylon_bitcoin::chain_params::Network,
    /// babylon_tag is a string encoding four bytes used for identification / tagging of the Babylon zone.
    /// NOTE: this is a hex string, not raw bytes
    pub babylon_tag: String,
    pub btc_confirmation_depth: u32,
    pub checkpoint_finalization_timeout: u32,
    /// notify_cosmos_zone indicates whether to send Cosmos zone messages notifying BTC-finalised
    /// headers.
    /// NOTE: If set to true, then the Cosmos zone needs to integrate the corresponding message handler
    /// as well
    pub notify_cosmos_zone: bool,
    /// If set, this will define the instantiation message for the BTC light client contract.
    pub btc_light_client_init_msg: Option<BtcLightClientInitMsg>,
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
    /// If not set, distributed rewards will be native to the Consumer
    pub ics20_channel_id: Option<String>,
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

        if let Some(channel_id) = &self.ics20_channel_id {
            if channel_id.trim().is_empty() {
                return Err(StdError::generic_err("ICS-020 channel_id cannot be empty"));
            }
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
    /// `slashing` is a slashing event from the BTC staking contract.
    ///
    /// This will be forwarded over IBC to the Babylon side for propagation to other Consumers, and
    /// Babylon itself
    Slashing { evidence: Evidence },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    /// Config returns the current configuration of the babylon-contract
    #[returns(Config)]
    Config {},
    /// BabylonBaseEpoch returns the base Babylon epoch stored in the contract
    #[returns(EpochResponse)]
    BabylonBaseEpoch {},
    /// BabylonLastEpoch returns the last babylon finalized epoch stored in the contract
    #[returns(EpochResponse)]
    BabylonLastEpoch {},
    /// BabylonEpoch returns the Babylon epoch stored in the contract, by epoch number.
    #[returns(EpochResponse)]
    BabylonEpoch { epoch_number: u64 },
    /// BabylonCheckpoint returns the Babylon checkpoint stored in the contract, by epoch number.
    #[returns(EpochResponse)]
    BabylonCheckpoint { epoch_number: u64 },
    /// LastConsumerHeader returns the last Consumer epoch stored in the contract
    #[returns(ConsumerHeaderResponse)]
    LastConsumerHeader {},
    /// LastConsumerHeight returns the last Consumer height stored in the contract
    #[returns(ConsumerHeightResponse)]
    LastConsumerHeight {},
    /// ConsumerHeader returns the Consumer header stored in the contract, by Consumer height.
    #[returns(ConsumerHeaderResponse)]
    ConsumerHeader { height: u64 },
    /// TransferInfo returns the IBC transfer information stored in the contract
    /// for ICS-020 rewards transfer.
    #[returns(Option<String>)]
    TransferInfo {},
}
