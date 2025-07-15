use thiserror::Error;

#[derive(Error, Debug, PartialEq)]
pub enum Error {
    #[error("Invalid schnorr signature: {0}")]
    InvalidSchnorrSignature(String),
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
    #[error("Old format requires negation byte")]
    InvalidNeedsNegationByte,
}

pub type Result<T> = std::result::Result<T, Error>;
