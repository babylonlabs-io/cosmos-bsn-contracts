use babylon_bitcoin::Work;
use cosmwasm_std::StdError;
use cw_utils::ParseReplyError;
use hex::FromHexError;
use std::str::Utf8Error;
use thiserror::Error;

/// Error type for the contract initialization.
#[derive(Error, Debug, PartialEq)]
pub enum InitError {
    #[error("Missing base work during initialization")]
    MissingBaseWork,
    #[error("Missing base height during initialization")]
    MissingBaseHeight,
    #[error("Missing tip header")]
    MissingTipHeader,
    #[error("Not enough headers (expected at least {0})")]
    NotEnoughHeaders(u32),
}

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("The given headers during initialization cannot be verified: {0:?}")]
    Init(#[from] InitError),

    #[error("The BTC header cannot be decoded: {0}")]
    BTCHeaderDecodeError(String),

    #[error("The BTC header is not being sent")]
    BTCHeaderEmpty {},

    #[error("The BTC header info {0} cumulative work is wrong. Expected {1}, got {2}")]
    BTCWrongCumulativeWork(usize, Work, Work),

    #[error("The BTC header info {0} height is wrong. Expected {1}, got {2}")]
    BTCWrongHeight(usize, u32, u32),

    #[error("The new chain's work ({0}), is not better than the current chain's work ({1})")]
    BTCChainWithNotEnoughWork(Work, Work),

    #[error(transparent)]
    Std(#[from] StdError),

    #[error(transparent)]
    ParseReply(#[from] ParseReplyError),

    #[error(transparent)]
    HashError(#[from] babylon_bitcoin::HexError),

    #[error(transparent)]
    DecodeHexError(#[from] FromHexError),

    #[error(transparent)]
    DecodeUtf8Error(#[from] Utf8Error),

    #[error(transparent)]
    BtcLightClient(#[from] babylon_bitcoin::error::Error),

    #[error(transparent)]
    Store(#[from] crate::state::btc_light_client::StoreError),
}

impl From<babylon_bitcoin::EncodeError> for ContractError {
    fn from(e: babylon_bitcoin::EncodeError) -> Self {
        Self::BTCHeaderDecodeError(e.to_string())
    }
}
