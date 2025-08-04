use hex::FromHexError;
use prost::DecodeError;
use thiserror::Error;

use bitcoin::hashes::FromSliceError;
use bitcoin::hex::HexToArrayError;

use cosmwasm_std::StdError;
use cw_controllers::AdminError;
use cw_utils::PaymentError;

use babylon_apis::error::StakingApiError;
use babylon_merkle::MerkleError;

// TODO: Consider merging `crate::finality::PubRandCommitError` and `crate::finality::FinalitySigError`
// into `ContractError`, or alternatively, split `ContractError` into them completely.
#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Finality provider not found: {0}")]
    FinalityProviderNotFound(String),
    #[error("The finality provider {0} does not have voting power at height {1}")]
    NoVotingPower(String, u64),
    #[error("The chain has not reached the given height yet")]
    HeightTooHigh,
    #[error("The request contains too few public randomness. Required minimum: {0}, actual: {1}")]
    TooFewPubRand(u64, u64),
    #[error("The start height ({0}) has overlap with the height of the highest public randomness committed ({1})")]
    InvalidPubRandHeight(u64, u64),
    #[error("start height {start_height} is too far into the future, current height: {current_height}, max offset: {max_offset}")]
    FuturePubRandStartHeight {
        start_height: u64,
        current_height: u64,
        max_offset: u64,
    },
    #[error("Public randomness not found for finality provider {0} at height {1}")]
    MissingPubRandCommit(String, u64),
    #[error("The inclusion proof for height {0} does not correspond to the given height ({1})")]
    InvalidFinalitySigHeight(u64, u64),
    #[error("The total amount of public randomnesses in the proof ({0}) does not match the amount of public committed randomness ({1})")]
    InvalidFinalitySigAmount(u64, u64),
    #[error("Failed to verify EOTS signature")]
    FailedToVerifyEots,
    #[error("Block {0} is finalized, but last finalized height does not reach here")]
    FinalisedBlockWithFinalityProviderSet(u64),
    #[error("Block {0} is finalized, but does not have a finality provider set")]
    FinalisedBlockWithoutFinalityProviderSet(u64),
    #[error("Block {0} is not found: {1}")]
    BlockNotFound(u64, String),
    #[error("The finality provider {0} has already been slashed")]
    FinalityProviderAlreadySlashed(String),
    #[error("Failed to extract secret key: {0}")]
    SecretKeyExtractionError(String),
    #[error("{0}")]
    PubRandCommitNotBTCTimestamped(String),
    #[error("Jail for {0} did not yet expire")]
    JailPeriodNotPassed(String),
    #[error("Cannot unjail FP who's been jailed forever")]
    JailedForever {},
    #[error(transparent)]
    PubRandCommit(#[from] crate::finality::PubRandCommitError),
    #[error(transparent)]
    FinalitySig(#[from] crate::finality::FinalitySigError),
    #[error(transparent)]
    Admin(#[from] AdminError),
    #[error(transparent)]
    Std(#[from] StdError),
    #[error(transparent)]
    Payment(#[from] PaymentError),
    #[error("error converting from hex to array: {0}")]
    HexArrayError(#[from] HexToArrayError),
    #[error(transparent)]
    SliceError(#[from] FromSliceError),
    #[error(transparent)]
    StakingError(#[from] StakingApiError),
    #[error(transparent)]
    MerkleError(#[from] MerkleError),
    #[error(transparent)]
    ProtoError(#[from] DecodeError),
    #[error(transparent)]
    HexError(#[from] FromHexError),
    #[error("EOTS error: {0}")]
    EotsError(#[from] eots::Error),
}
