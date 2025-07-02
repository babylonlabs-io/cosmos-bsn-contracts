use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Binary, StdError, StdResult};

use crate::msg::btc_header::BtcHeader;
#[cfg(not(target_arch = "wasm32"))]
use {
    crate::msg::btc_header::{BtcHeaderResponse, BtcHeadersResponse},
    crate::state::config::Config,
};

#[cw_serde]
pub struct InstantiateMsg {
    pub network: babylon_bitcoin::chain_params::Network,
    pub btc_confirmation_depth: u32,
    pub checkpoint_finalization_timeout: u32,
    pub headers: Vec<BtcHeader>,
    pub first_work: Binary,
    pub first_height: u32,
}

impl InstantiateMsg {
    pub fn validate(&self) -> StdResult<()> {
        if self.btc_confirmation_depth == 0 {
            return Err(StdError::generic_err(
                "BTC confirmation depth must be greater than 0",
            ));
        }
        if self.checkpoint_finalization_timeout == 0 {
            return Err(StdError::generic_err(
                "Checkpoint finalization timeout must be greater than 0",
            ));
        }
        // TODO: validate headers, first work and first height?
        Ok(())
    }
}

#[cw_serde]
pub enum ExecuteMsg {
    /// Add BTC headers to the light client. If not initialized, this will initialize
    /// the light client with the provided headers. Otherwise, it will update the
    /// existing chain with the new headers.
    BtcHeaders { headers: Vec<BtcHeader> },
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
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
