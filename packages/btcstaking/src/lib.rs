pub mod error;
pub mod scripts_utils;
pub mod staking;
pub mod types;
pub type Result<T> = std::result::Result<T, error::Error>;
