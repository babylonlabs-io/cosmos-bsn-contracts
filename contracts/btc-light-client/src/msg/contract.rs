use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::Binary;

use crate::{error::InitError, msg::btc_header::BtcHeader};
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
    /// A sequence of initial BTC headers used to bootstrap the light client.
    ///
    /// Must include at least `btc_confirmation_depth` headers following the base header.
    pub headers: Vec<BtcHeader>,
    /// Total accumulated work of the first (base) BTC header, encoded as big-endian bytes.
    pub first_work: Binary,
    /// Height of the first (base) BTC header.
    pub first_height: u32,
}

impl InstantiateMsg {
    pub fn validate(&self) -> Result<(), InitError> {
        if self.btc_confirmation_depth == 0 {
            return Err(InitError::ZeroConfirmationDepth);
        }

        if self.checkpoint_finalization_timeout == 0 {
            return Err(InitError::ZeroCheckpointFinalizationTimeout);
        }

        // Check if there are enough headers for initialization
        if self.headers.len() < self.btc_confirmation_depth as usize {
            return Err(InitError::NotEnoughHeaders {
                got: self.headers.len(),
                required: self.btc_confirmation_depth,
            });
        }

        // TODO: validate headers, first work and first height? For example, the base header
        // should be on the difficulty boundary.

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
