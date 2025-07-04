use babylon_proto::babylon::btclightclient::v1::BtcHeaderInfo;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::Binary;

use crate::bitcoin::total_work;
use crate::{
    error::{ContractError, InitError},
    msg::btc_header::BtcHeader,
};
#[cfg(not(target_arch = "wasm32"))]
use {
    crate::msg::btc_header::{BtcHeaderResponse, BtcHeadersResponse},
    crate::state::config::Config,
};

#[cw_serde]
pub struct InitialHeader {
    /// Initial BTC header to initialize the light client.
    pub header: BtcHeader,
    /// Total accumulated work of the initial header, encoded as big-endian bytes.
    pub total_work: Binary,
    /// Height of the initial header.
    pub height: u32,
}

impl InitialHeader {
    pub fn to_btc_header_info(&self) -> Result<BtcHeaderInfo, ContractError> {
        let total_work = total_work(&self.total_work)?;
        self.header.to_btc_header_info(self.height, total_work)
    }
}

impl TryFrom<BtcHeaderInfo> for InitialHeader {
    type Error = ContractError;
    fn try_from(header_info: BtcHeaderInfo) -> Result<Self, Self::Error> {
        let total_work: Binary = header_info.work.to_vec().into();
        let height = header_info.height;
        Ok(Self {
            header: header_info.try_into()?,
            total_work,
            height,
        })
    }
}

#[cw_serde]
pub struct InstantiateMsg {
    pub network: babylon_bitcoin::Network,
    pub btc_confirmation_depth: u32,
    pub checkpoint_finalization_timeout: u32,
    /// Initial BTC header.
    pub initial_header: InitialHeader,
}

impl InstantiateMsg {
    pub fn validate(&self) -> Result<(), InitError> {
        if self.btc_confirmation_depth == 0 {
            return Err(InitError::ZeroConfirmationDepth);
        }

        if self.checkpoint_finalization_timeout == 0 {
            return Err(InitError::ZeroCheckpointFinalizationTimeout);
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
