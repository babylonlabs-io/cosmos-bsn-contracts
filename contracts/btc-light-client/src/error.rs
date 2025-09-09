use bitcoin::Work;
use cosmwasm_std::StdError;
use cw_controllers::AdminError;
use cw_utils::ParseReplyError;
use hex::FromHexError;
use std::str::Utf8Error;
use thiserror::Error;

/// Error type for the base headers auto-initialization
#[derive(Error, Debug, PartialEq)]
pub enum InitHeadersError {
    #[error("Missing base work during initialization")]
    MissingBaseWork,
    #[error("Missing base height during initialization")]
    MissingBaseHeight,
    #[error("Insufficient headers provided (required {0}, got: {1})")]
    InsufficientHeaders(u32, usize),
}

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("The given headers during initialization cannot be verified: {0:?}")]
    Init(#[from] InitHeadersError),

    #[error("{0}")]
    Admin(#[from] AdminError),

    #[error("BTC confirmation depth must be greater than 0")]
    ZeroConfirmationDepth,

    #[error("Checkpoint finalization timeout must be greater than 0")]
    ZeroCheckpointFinalizationTimeout,

    #[error("Header {0} is not on the difficulty boundary")]
    NotOnDifficultyBoundary(u32),

    #[error("Initial header is required")]
    InitialHeaderRequired,

    #[error("The BTC header cannot be decoded: {0}")]
    BitcoinEncode(String),

    #[error("The BTC header is not being sent")]
    EmptyHeaders {},

    #[error("Rejected chain reorg: total work {0} not greater than current {1}")]
    InsufficientWork(Work, Work),

    #[error(transparent)]
    BitcoinHex(#[from] bitcoin::hashes::hex::HexToArrayError),

    #[error(transparent)]
    Hex(#[from] FromHexError),

    #[error(transparent)]
    ParseReply(#[from] ParseReplyError),

    #[error(transparent)]
    Std(#[from] StdError),

    #[error(transparent)]
    Utf8(#[from] Utf8Error),

    #[error(transparent)]
    ProstEncode(#[from] prost::EncodeError),

    /// Header verification error.
    #[error(transparent)]
    Header(#[from] crate::bitcoin::HeaderError),

    #[error(transparent)]
    Store(#[from] crate::state::StoreError),

    #[error("Unauthorized: sender {0} is not authorized to call this function")]
    Unauthorized(String),

    #[error("Cannot migrate from different contract. Expected: {expected}, found: {actual}")]
    InvalidContractName { expected: String, actual: String },
}

impl From<bitcoin::consensus::encode::Error> for ContractError {
    fn from(e: bitcoin::consensus::encode::Error) -> Self {
        Self::BitcoinEncode(e.to_string())
    }
}
