//! A Rust-native implementation of the CometBFT Merkle library.
//!
//! This crate provides a direct translation of the Merkle implementation from
//! [`cometbft/cometbft`](https://github.com/cometbft/cometbft/tree/v0.38.17/crypto/merkle),
//! intended for compatibility and correctness when verifying Tendermint-style Merkle proofs.
//!
//! We opted to reimplement it in Rust due to the lack of a drop-in Merkle library
//! that fully matches CometBFT's behavior and structure.
//!
//! **Note:** This crate is intended as a stopgap. Once a suitable external Merkle library
//! is available that provides full compatibility with CometBFT’s Merkle proof format,
//! we plan to replace this implementation.
//!
//! ## Exports
//! - [`MerkleError`](self::error::MerkleError): Errors encountered during proof verification or tree operations.
//! - [`Proof`](self::proof::Proof): Structure and logic for Merkle proofs.

mod error;
mod hash;
mod proof;
mod tree;

pub use self::error::MerkleError;
pub use self::proof::Proof;
pub use self::tree::hash_from_byte_slices;
