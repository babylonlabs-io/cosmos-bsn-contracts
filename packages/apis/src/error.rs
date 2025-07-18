use cosmwasm_std::StdError;
use hex::FromHexError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum StakingApiError {
    #[error("{0}")]
    Std(#[from] StdError),
    #[error("Invalid address string: {0}")]
    InvalidAddressString(String),
    #[error("{0}")]
    HexError(#[from] FromHexError),
    #[error("Staking tx hash hex string is not {0} chars long")]
    InvalidStakingTxHash(usize),
    #[error("Invalid Btc tx: {0}")]
    InvalidBtcTx(String),
    #[error("Empty Btc public key")]
    EmptyBtcPk,
    #[error("Empty Btc private key")]
    EmptyBtcSk,
    #[error("Empty proof of possession")]
    MissingPop,
    #[error("Empty chain id")]
    EmptyChainId,
    #[error("No Finality Providers Btc public keys")]
    EmptyBtcPkList,
    #[error("Duplicate Finality Provider Btc public key: {0}")]
    DuplicatedBtcPk(String),
    #[error("Empty Staking tx")]
    EmptyStakingTx,
    #[error("Empty Slashing tx")]
    EmptySlashingTx,
    #[error("Empty unbonding tx")]
    EmptyUnbondingTx,
    #[error("Invalid unbonding time blocks: {0}, max: {1}")]
    ErrInvalidUnbondingTime(u32, u32),
    #[error("Empty signature from the delegator")]
    EmptySignature,
    #[error("Description error: {0}")]
    DescriptionErr(String),
}

impl StakingApiError {
    pub fn description_err(msg: impl Into<String>) -> Self {
        StakingApiError::DescriptionErr(msg.into())
    }
}
