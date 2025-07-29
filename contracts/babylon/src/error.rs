use babylon_apis::error::StakingApiError;
use btc_light_client::error::ContractError as BTCLightclientError;
use cosmwasm_std::StdError;
use cw_utils::{ParseReplyError, PaymentError};

use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    StdError(#[from] StdError),
    #[error("{0}")]
    ParseReply(#[from] ParseReplyError),
    #[error("Invalid reply id: {0}")]
    InvalidReplyId(u64),
    #[error("The BTC header is empty")]
    BtcHeaderEmpty {},
    #[error("BTC light client init message is missing")]
    MissingBtcLightClientInitMsg,
    #[error("The BTC light client contract is not set")]
    BtcLightClientNotSet {},
    #[error("Missing base_header in the response of BTC light client contract instantiation")]
    MissingBaseHeaderInBtcLightClientResponse,
    #[error("{0}")]
    BtcError(#[from] BTCLightclientError),
    #[error("{0}")]
    BabylonEpochError(#[from] BabylonEpochChainError),
    #[error("{0}")]
    ConsumerHeaderError(#[from] ConsumerHeaderChainError),
    #[error("{0}")]
    Payment(#[from] PaymentError),
    #[error("API error: {0}")]
    ApiError(#[from] StakingApiError),
    #[error("Contract already has an open IBC channel")]
    IbcChannelAlreadyOpen {},
    #[error("The contract only supports ordered channels")]
    IbcUnorderedChannel {},
    #[error("Counterparty version must be `{version}`")]
    IbcInvalidCounterPartyVersion { version: String },
    #[error("IBC method is not supported")]
    IbcUnsupportedMethod {},
    #[error("IBC send timed out: dest: channel {0}, port {1}")]
    IbcTimeout(String, String),
    #[error("Unauthorized")]
    Unauthorized {},
    #[error("The BTC staking contract is not set")]
    BtcStakingNotSet {},
    #[error("The BTC finality contract is not set")]
    BtcFinalityNotSet {},
    #[error("Invalid configuration: {msg}")]
    InvalidConfig { msg: String },
    #[error("IBC transfer info not set")]
    IbcTransferInfoNotSet {},
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
    #[error(transparent)]
    ProstEncode(#[from] prost::EncodeError),
    #[error(transparent)]
    ProstDecode(#[from] prost::DecodeError),
    #[error("SerdeJson error: {0}")]
    SerdeJson(String),
}

impl From<serde_json::Error> for ContractError {
    fn from(e: serde_json::Error) -> Self {
        Self::SerdeJson(e.to_string())
    }
}

#[derive(Error, Debug, PartialEq)]
pub enum ConsumerHeaderChainError {
    #[error("{0}")]
    StdError(#[from] StdError),
    #[error("The given headers during initialization cannot be verified")]
    InitError {},
    #[error("The bytes cannot be decoded")]
    DecodeError(#[from] prost::DecodeError),
    #[error("The header is not checkpointed in the given epoch")]
    EpochNumberError {},
    #[error("The Proof cannot be verified")]
    ProofError {},
    #[error("The Consumer header with height {height} is not found in the storage")]
    ConsumerHeaderNotFoundError { height: u64 },
    #[error("There is no finalized Consumer header yet")]
    NoConsumerHeader {},
}

#[derive(Error, Debug, PartialEq)]
pub enum BabylonEpochChainError {
    #[error("{0}")]
    StdError(#[from] StdError),
    #[error("The bytes cannot be decoded")]
    DecodeError(#[from] prost::DecodeError),
    #[error("Bitcoin light client error: {0}")]
    BTCLightClientError(#[from] BTCLightclientError),
    #[error("The epoch {epoch_number} is not found in the storage")]
    EpochNotFoundError { epoch_number: u64 },
    #[error("There is no finalized epoch yet")]
    NoFinalizedEpoch {},
    #[error(
        "The checkpoint is for epoch {ckpt_epoch_number} rather than the given epoch {epoch_number}"
    )]
    CheckpointNotMatchError {
        ckpt_epoch_number: u64,
        epoch_number: u64,
    },
    #[error("The checkpoint of epoch {epoch_number} is not found in the storage")]
    CheckpointNotFoundError { epoch_number: u64 },
    #[error("The BTC headers are not {w}-deep")]
    BTCHeaderNotDeepEnough { w: u32 },
    #[error("The checkpoint is not in the given BTC headers: {err_msg}")]
    CheckpointNotSubmitted { err_msg: String },
    #[error("The epoch is not sealed by the epoch's validator set: {err_msg}")]
    EpochNotSealed { err_msg: String },
    #[error("Transaction key is empty")]
    EmptyTxKey {},
    #[error("The BTC header cannot be decoded: {0}")]
    BTCHeaderDecodeError(String),
    #[error("Failed to query header {hash} from LC contract: {err}")]
    HeaderUnavailableInLightClientContract { hash: String, err: String },
}
