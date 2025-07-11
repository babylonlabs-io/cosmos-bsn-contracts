pub mod adaptor_sig;
pub mod error;
pub mod schnorr;
pub mod scripts_utils;
pub mod sig_verify;
pub mod tx_verify;
pub type Result<T> = std::result::Result<T, error::Error>;
