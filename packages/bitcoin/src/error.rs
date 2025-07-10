use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum Error {
    #[error("Failed to parse public key")]
    FailedToParsePublicKey(String),
    #[error("Invalid schnorr signature")]
    InvalidSchnorrSignature(String),
}
