use babylon_apis::error::StakingApiError;
use babylon_merkle::MerkleError;
use bitcoin::hashes::FromSliceError;
use bitcoin::hex::HexToArrayError;
use cosmwasm_std::{ConversionOverflowError, StdError};
use cw_controllers::AdminError;
use cw_utils::PaymentError;
use hex::FromHexError;
use prost::DecodeError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum ContractError {
    #[error("{0}")]
    Admin(#[from] AdminError),
    #[error("{0}")]
    Std(#[from] StdError),
    #[error("{0}")]
    Payment(#[from] PaymentError),
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
    #[error("EOTS error: {0}")]
    EotsError(#[from] eots::Error),
    #[error("{0}")]
    Conversion(#[from] ConversionOverflowError),
    #[error("Unauthorized")]
    Unauthorized,
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
    #[error("Failed to verify signature: {0}")]
    FailedSignatureVerification(String),
    #[error("The finality provider {0} has already been slashed")]
    FinalityProviderAlreadySlashed(String),
    #[error("Delegation {0} to FP {1} not found")]
    DelegationToFpNotFound(String, String),
    #[error("Ecdsa error: {0}")]
    Ecdsa(String),
    #[error("Bitcoin encode error: {0}")]
    BitcoinEncode(String),
    #[error(transparent)]
    HexError(#[from] FromHexError),
}

impl From<bitcoin::consensus::encode::Error> for ContractError {
    fn from(e: bitcoin::consensus::encode::Error) -> Self {
        Self::BitcoinEncode(e.to_string())
    }
}

impl From<k256::ecdsa::Error> for ContractError {
    fn from(e: k256::ecdsa::Error) -> Self {
        Self::Ecdsa(e.to_string())
    }
}
