pub mod errors;
pub mod scripts_utils;
pub mod staking;
pub mod types;
pub type Result<T> = std::result::Result<T, errors::Error>;
