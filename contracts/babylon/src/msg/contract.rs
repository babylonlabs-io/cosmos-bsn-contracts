use babylon_apis::finality_api::Evidence;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Binary, StdError, StdResult, Uint128};
#[cfg(not(target_arch = "wasm32"))]
use {
    crate::msg::consumer_header::{ConsumerHeaderResponse, ConsumerHeightResponse},
    crate::msg::epoch::EpochResponse,
    crate::state::config::Config,
};

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
}

impl InstantiateMsg {
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
    /// Update the configuration parameters
    /// Only admin can update the config
    UpdateConfig {
        btc_confirmation_depth: Option<u32>,
        checkpoint_finalization_timeout: Option<u32>,
        consumer_name: Option<String>,
        consumer_description: Option<String>,
        ibc_packet_timeout_days: Option<u64>,
        destination_module: Option<String>,
    },
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
    /// Returns the current admin of the contract.
    #[returns(cw_controllers::AdminResponse)]
    Admin {},
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
