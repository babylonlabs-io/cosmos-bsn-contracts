use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum Error {
    #[error("Invalid input length: expected 32 bytes, got {0}")]
    InvalidInputLength(usize),
    #[error("Failed to parse secret randomness")]
    SecretRandomnessParseFailed {},
    #[error("Failed to parse public randomness")]
    PublicRandomnessParseFailed {},
    #[error("Failed to parse signature")]
    SignatureParseFailed {},
    #[error("Failed to parse secret key")]
    SecretKeyParseFailed {},
    #[error("Failed to parse public key")]
    PublicKeyParseFailed {},
    #[error("Invalid hex string: {0}")]
    InvalidHexString(#[from] hex::FromHexError),
    #[error("Elliptic curve error: {0}")]
    EllipticCurveError(String),
}
