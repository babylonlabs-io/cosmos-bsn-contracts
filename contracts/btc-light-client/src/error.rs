use babylon_bitcoin::Work;
use cosmwasm_std::StdError;
use cw_utils::ParseReplyError;
use hex::FromHexError;
use prost::DecodeError;
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
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("{0}")]
    ParseReply(#[from] ParseReplyError),

    #[error("Invalid reply id: {0}")]
    InvalidReplyId(u64),

    #[error("Unauthorized")]
    Unauthorized {},

    #[error("Invalid configuration: {msg}")]
    InvalidConfig { msg: String },

    #[error("The given headers during initialization cannot be verified: {0:?}")]
    Init(#[from] InitError),

    #[error("The bytes cannot be decoded")]
    DecodeError(#[from] DecodeError),

    #[error("{0}")]
    HashError(#[from] babylon_bitcoin::HexError),

    #[error("The hex cannot be decoded")]
    DecodeHexError(#[from] FromHexError),

    #[error("The bytes cannot be decoded as string")]
    DecodeUtf8Error(#[from] Utf8Error),

    #[error("The BTC header cannot be decoded")]
    BTCHeaderDecodeError {},

    #[error("The BTC header is not being sent")]
    BTCHeaderEmpty {},

    #[error("The BTC header does not satisfy the difficulty requirement or is not consecutive")]
    BTCHeaderError {},

    #[error("The BTC header with hash {hash} is not found in the storage")]
    BTCHeaderNotFoundError { hash: String },

    #[error("The BTC height {height} is not found in the storage")]
    BTCHeightNotFoundError { height: u32 },

    #[error("The BTC header info cumulative work encoding is wrong")]
    BTCWrongCumulativeWorkEncoding {},

    #[error("The BTC header info {0} cumulative work is wrong. Expected {1}, got {2}")]
    BTCWrongCumulativeWork(usize, Work, Work),

    #[error("The BTC header info {0} height is wrong. Expected {1}, got {2}")]
    BTCWrongHeight(usize, u32, u32),

    #[error("The work is invalid")]
    InvalidWork {},

    #[error("The new chain's work ({0}), is not better than the current chain's work ({1})")]
    BTCChainWithNotEnoughWork(Work, Work),
}
