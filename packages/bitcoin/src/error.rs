use bitcoin::block::ValidationError;
use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum Error {
    #[error("Failed to parse public key")]
    FailedToParsePublicKey(String),
    #[error("Invalid schnorr signature")]
    InvalidSchnorrSignature(String),
    #[error("Header's target is larger then pow_limit'")]
    TargetTooLarge,
    #[error("proof-of-work validation failed: {0:?}")]
    InvalidProofOfWork(ValidationError),
    #[error("the header is not consecutive to the previous header")]
    PreHeaderHashMismatch,
    #[error("difficulty not relevant to parent difficulty")]
    BadDifficulty,
}
