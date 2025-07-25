use babylon_proto::babylon::btclightclient::v1::BtcHeaderInfo;
use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::Binary;

use crate::bitcoin::total_work;
use crate::{error::ContractError, msg::btc_header::BtcHeader};
#[cfg(not(target_arch = "wasm32"))]
use {
    crate::msg::btc_header::{BtcHeaderResponse, BtcHeadersResponse},
    crate::state::Config,
};

#[cw_serde]
pub struct BaseHeader {
    /// Initial BTC header to initialize the light client.
    pub header: BtcHeader,
    /// Total accumulated work of the initial header, encoded as big-endian bytes.
    pub total_work: Binary,
    /// Height of the initial header.
    pub height: u32,
}

impl BaseHeader {
    pub fn to_btc_header_info(&self) -> Result<BtcHeaderInfo, ContractError> {
        let total_work = total_work(&self.total_work)?;
        self.header.to_btc_header_info(self.height, total_work)
    }
}

impl TryFrom<BtcHeaderInfo> for BaseHeader {
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
    pub network: crate::state::BitcoinNetwork,
    pub btc_confirmation_depth: u32,
    pub checkpoint_finalization_timeout: u32,
    /// Initial BTC header.
    /// If not provided, the light client will rely on and trust Babylon's provided initial header
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_header: Option<BaseHeader>,
}

impl InstantiateMsg {
    pub fn validate(&self) -> Result<(), ContractError> {
        if self.btc_confirmation_depth == 0 {
            return Err(ContractError::ZeroConfirmationDepth);
        }

        if self.checkpoint_finalization_timeout == 0 {
            return Err(ContractError::ZeroCheckpointFinalizationTimeout);
        }

        #[cfg(feature = "full-validation")]
        {
            // In full validation mode, base header must be provided
            if self.base_header.is_none() {
                return Err(ContractError::InitialHeaderRequired);
            }
        }

        if let Some(ref base_header) = self.base_header {
            if !crate::bitcoin::is_retarget_block(base_header.height, &self.network.chain_params())
            {
                return Err(ContractError::NotOnDifficultyBoundary(base_header.height));
            }
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
