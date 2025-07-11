use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum Error {
    #[error("Failed to decompress bytes to a projective point")]
    DecompressPointFailed {},
    #[error("Point {0} is at infinity")]
    PointAtInfinity(String),
    #[error("Point {0} has odd y axis")]
    PointWithOddY(String),
    #[error("Failed to verify adaptor signature")]
    VerifyAdaptorSigFailed {},
    #[error("Malformed adaptor signature: expected {0} bytes, got {1}")]
    MalformedAdaptorSignature(usize, usize),
    #[error("Invalid first byte of adaptor signature: expected 0x02 or 0x03, got {0}")]
    InvalidAdaptorSignatureFirstByte(u8),
    #[error("Failed to parse bytes as a mod n scalar")]
    FailedToParseScalar {},
    #[error("Failed to parse public key: {0}")]
    FailedToParsePublicKey(String),
    #[error("Cannot create multisig script with less than 2 keys")]
    InsufficientMultisigKeys {},
    #[error("Duplicate key in list of keys")]
    DuplicateKeys {},
    #[error("Quorum cannot be greater than the number of keys")]
    QuorumExceedsKeyCount {},
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
    #[error("Invalid slashing tx change output script")]
    InvalidSlashingTxChangeOutputScript {},
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
}
