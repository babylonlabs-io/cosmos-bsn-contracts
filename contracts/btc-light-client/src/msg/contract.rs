use crate::error::ContractError;
use crate::msg::btc_header::BtcHeader;
use cosmwasm_schema::{cw_serde, QueryResponses};
#[cfg(not(target_arch = "wasm32"))]
use {
    crate::msg::btc_header::{BtcHeaderResponse, BtcHeadersResponse},
    crate::state::Config,
    cw_controllers::AdminResponse,
};

#[cw_serde]
pub struct InstantiateMsg {
    pub network: crate::state::BitcoinNetwork,
    pub btc_confirmation_depth: u32,
    pub checkpoint_finalization_timeout: u32,
    pub admin: Option<String>,
}

impl InstantiateMsg {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.btc_confirmation_depth == 0 {
            return Err(ContractError::ZeroConfirmationDepth);
        }

        if self.checkpoint_finalization_timeout == 0 {
            return Err(ContractError::ZeroCheckpointFinalizationTimeout);
        }

        // TODO: the height should be larger than a recent block?

        Ok(())
    }
}

#[cw_serde]
pub enum ExecuteMsg {
    /// Submit new BTC headers to the light client.
    /// If not initialized, this will initialize the light client with
    /// the provided headers.
    /// Otherwise, it will update the existing chain with the new headers
    BtcHeaders {
        headers: Vec<BtcHeader>,
        /// The work of the epoch boundary header for the batch.
        /// Used during / for auto-initialization of the light client
        #[serde(skip_serializing_if = "Option::is_none")]
        first_work: Option<String>,
        /// The epoch boundary height for the batch.
        /// Used during / for auto-initialization of the light client
        #[serde(skip_serializing_if = "Option::is_none")]
        first_height: Option<u32>,
    },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    /// Returns the current admin of the contract.
    #[returns(AdminResponse)]
    Admin {},
    #[returns(BtcHeaderResponse)]
    BtcBaseHeader {},
    #[returns(BtcHeaderResponse)]
    BtcTipHeader {},
    #[returns(BtcHeaderResponse)]
    BtcHeader { height: u32 },
    #[returns(BtcHeaderResponse)]
    BtcHeaderByHash { hash: String },
    #[returns(BtcHeadersResponse)]
    BtcHeaders {
        start_after: Option<u32>,
        limit: Option<u32>,
        reverse: Option<bool>,
    },
    #[returns(Config)]
    Config {},
}

#[cw_serde]
pub struct MigrateMsg {}
