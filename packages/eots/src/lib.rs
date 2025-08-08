pub mod eots;
pub mod error;

#[cfg(feature = "rand")]
pub use eots::rand_gen;
pub use eots::{tagged_hash, PrivateRand, PubRand, PublicKey, SecretKey, Signature, CHALLENGE_TAG};
pub use error::Error;
pub type Result<T> = std::result::Result<T, Error>;
