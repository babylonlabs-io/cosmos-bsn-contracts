use hex::FromHexError;
use prost::DecodeError;
use thiserror::Error;

use bitcoin::hashes::FromSliceError;
use bitcoin::hex::HexToArrayError;

use cosmwasm_std::{ConversionOverflowError, StdError, Uint128};
use cw_controllers::AdminError;
use cw_utils::PaymentError;

use babylon_apis::error::StakingApiError;
use babylon_merkle::error::MerkleError;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Admin(#[from] AdminError),
    #[error("{0}")]
    Std(#[from] StdError),
    #[error("{0}")]
    Payment(#[from] PaymentError),
    #[error("{0}")]
    BTCStaking(#[from] babylon_btcstaking::error::Error),
    #[error("error converting from hex to array: {0}")]
    HexArrayError(#[from] HexToArrayError),
    #[error("{0}")]
    SliceError(#[from] FromSliceError),
    #[error("{0}")]
    StakingError(#[from] StakingApiError),
    #[error("{0}")]
    MerkleError(#[from] MerkleError),
    #[error("{0}")]
    ProtoError(#[from] DecodeError),
    #[error("{0}")]
    HexError(#[from] FromHexError),
    #[error("EOTS error: {0}")]
    EotsError(#[from] eots::Error),
    #[error("{0}")]
    Conversion(#[from] ConversionOverflowError),
    #[error("{0}")]
    SecP256K1Error(String), // TODO: inherit errors from k256
    #[error("Unauthorized")]
    Unauthorized,
    #[error("Failed to verify the finality provider registration request: {0}")]
    FinalityProviderVerificationError(String),
    #[error("Finality provider already exists: {0}")]
    FinalityProviderAlreadyExists(String),
    #[error("No finality providers are registered in this Consumer")]
    FinalityProviderNotRegistered,
    #[error("Finality provider not found: {0}")]
    FinalityProviderNotFound(String),
    #[error("Staking tx hash already exists: {0}")]
    DelegationAlreadyExists(String),
    #[error("Delegation with staking tx hash {0} already delegated to FP {1}")]
    DelegationToFpAlreadyExists(String, String),
    #[error("BTC delegation is not active: {0}")]
    DelegationIsNotActive(String),
    #[error("Invalid covenant signature: {0}")]
    InvalidCovenantSig(String),
    #[error("Invalid Btc tx: {0}")]
    InvalidBtcTx(String),
    #[error("Empty signature from the delegator")]
    EmptySignature,
    #[error("Invalid lock type: seconds")]
    ErrInvalidLockType,
    #[error("Invalid lock time blocks: {0}, max: {1}")]
    ErrInvalidLockTime(u32, u32),
    #[error("The finality provider {0} does not have voting power at height {1}")]
    NoVotingPower(String, u64),
    #[error("The chain has not reached the given height yet")]
    HeightTooHigh,
    #[error("The finality provider {0} signed two different blocks at height {1}")]
    DuplicateFinalityVote(String, u64),
    #[error("The request contains too few public randomness. Required minimum: {0}, actual: {1}")]
    TooFewPubRand(u64, u64),
    #[error("The start height ({0}) has overlap with the height of the highest public randomness committed ({1})")]
    InvalidPubRandHeight(u64, u64),
    #[error("Invalid signature over the public randomness list")]
    InvalidPubRandSignature,
    #[error("Public randomness not found for finality provider {0} at height {1}")]
    MissingPubRandCommit(String, u64),
    #[error("The inclusion proof for height {0} does not correspond to the given height ({1})")]
    InvalidFinalitySigHeight(u64, u64),
    #[error("The total amount of public randomnesses in the proof ({0}) does not match the amount of public committed randomness ({1})")]
    InvalidFinalitySigAmount(u64, u64),
    #[error("Invalid finality signature: {0}")]
    InvalidSignature(String),
    #[error("Failed to verify signature: {0}")]
    FailedSignatureVerification(String),
    #[error("Block {0} is finalized, but last finalized height does not reach here")]
    FinalisedBlockWithFinalityProviderSet(u64),
    #[error("Block {0} is finalized, but does not have a finality provider set")]
    FinalisedBlockWithoutFinalityProviderSet(u64),
    #[error("Block {0} is not found: {1}")]
    BlockNotFound(u64, String),
    #[error("The finality provider {0} has already been slashed")]
    FinalityProviderAlreadySlashed(String),
    #[error("Failed to slash finality provider: {0}")]
    FailedToSlashFinalityProvider(String),
    #[error("Failed to extract secret key: {0}")]
    SecretKeyExtractionError(String),
    #[error("Hash length error: {0}")]
    WrongHashLength(String),
    #[error("Sent funds ({0}) don't match rewards to distribute {1}")]
    InvalidRewardsAmount(Uint128, Uint128),
    #[error("No rewards to withdraw")]
    NoRewards,
    #[error("No recipient address for rewards withdrawal provided")]
    RecipientRequired,
    #[error("Delegation {0} to FP {1} not found")]
    DelegationToFpNotFound(String, String),
}
