use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum Error {
    #[error("Failed to parse public key: {0}")]
    FailedToParsePublicKey(String),
    #[error("Cannot create multisig script with less than 2 keys")]
    InsufficientMultisigKeys {},
    #[error("Duplicate key in list of keys")]
    DuplicateKeys {},
    #[error("Threshold {threshold} cannot be greater than the number of keys {keys_count}")]
    ThresholdExceedsKeyCount { threshold: usize, keys_count: usize },
    #[error("No keys provided")]
    NoKeysProvided {},
    #[error("Failed to add leaf")]
    AddLeafFailed {},
    #[error("Failed to finalize taproot")]
    FinalizeTaprootFailed {},
    #[error("Tx input count mismatch: expected {0}, got {1}")]
    TxInputCountMismatch(usize, usize),
    #[error("Tx output count mismatch: expected {0}, got {1}")]
    TxOutputCountMismatch(usize, usize),
    #[error("Tx output index not found")]
    TxOutputIndexNotFound {},
    #[error("Invalid schnorr signature: {0}")]
    InvalidSchnorrSignature(String),
    #[error("Transaction is replaceable.")]
    TxIsReplaceable {},
    #[error("Transaction has locktime.")]
    TxHasLocktime {},
    #[error("Slashing transaction must slash at least {0} satoshis")]
    InsufficientSlashingAmount(u64),
    #[error("Slashing transaction must pay to the provided slashing pk script")]
    InvalidSlashingPkScript {},
    #[error("Invalid slashing tx change output script, expected: {expected:?}, got: {actual:?}")]
    InvalidSlashingTxChangeOutputScript { expected: Vec<u8>, actual: Vec<u8> },
    #[error("Transaction contains dust outputs")]
    TxContainsDustOutputs {},
    #[error("Slashing transaction fee must be larger than {0}")]
    InsufficientSlashingFee(u64),
    #[error("Slashing transaction must not spend more than the staking transaction")]
    SlashingTxOverspend {},
    #[error("Invalid slashing rate")]
    InvalidSlashingRate {},
    #[error("Invalid funding output index {0}, tx has {1} outputs")]
    InvalidFundingOutputIndex(u32, usize),
    #[error("Slashing transaction must spend staking output")]
    StakingOutputNotSpentBySlashingTx {},
    #[error("Transaction weight {0} exceeds maximum standard weight {1}")]
    TransactionWeightExceedsLimit(usize, usize),
    #[error("Invalid transaction version {0}, must be between {1} and {2}")]
    InvalidTxVersion(i32, i32, i32),
    #[error("Pre-signed transaction must not have signature script")]
    TxHasSignatureScript {},
    #[error("Slashing or staking transaction values must be larger than 0")]
    InvalidSlashingAmount {},
    #[error(transparent)]
    SighashTaproot(#[from] bitcoin::sighash::TaprootError),
    #[error(transparent)]
    Tx(#[from] crate::staking::TxError),
}
