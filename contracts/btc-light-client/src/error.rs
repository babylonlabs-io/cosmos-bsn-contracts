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
    #[error("BTC confirmation depth must be greater than 0")]
    ZeroConfirmationDepth,
    #[error("Checkpoint finalization timeout must be greater than 0")]
    ZeroCheckpointFinalizationTimeout,
    #[error("Not enough headers (expected at least {required}, got: {got})")]
    NotEnoughHeaders { got: usize, required: u32 },
}

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("The given headers during initialization cannot be verified: {0:?}")]
    Init(#[from] InitError),

    #[error("The BTC header cannot be decoded: {0}")]
    BTCHeaderDecodeError(String),

    #[error("The BTC header is not being sent")]
    BTCHeaderEmpty {},

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

    /// Header verification error.
    #[error(transparent)]
    Header(#[from] crate::bitcoin::HeaderError),

    #[error(transparent)]
    Store(#[from] crate::state::btc_light_client::StoreError),
}

impl From<babylon_bitcoin::EncodeError> for ContractError {
    fn from(e: babylon_bitcoin::EncodeError) -> Self {
        Self::BTCHeaderDecodeError(e.to_string())
    }
}
