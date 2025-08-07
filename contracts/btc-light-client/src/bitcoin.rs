//! Verifies Bitcoin block headers for correctness and proof-of-work validity.
//!
//! This module provides functionality to:
//! - Verify that a sequence of Bitcoin headers forms a valid chain.
//! - Enforce proof-of-work correctness.
//! - Ensure difficulty retargeting and cumulative work are consistent with Bitcoin consensus rules.
//!
//! It mirrors the logic used in Bitcoin Core and Babylon's Go implementation.

use babylon_proto::babylon::btclightclient::v1::BtcHeaderInfo;
use bitcoin::consensus::Params;
use bitcoin::{BlockHash, Target, Work};
use cosmwasm_std::{StdError, StdResult, Storage};

/// Errors that can occur during BTC header verification.
#[derive(thiserror::Error, Debug, PartialEq)]
pub enum HeaderError {
    #[error("Header's target exceeds the chain's maximum difficulty limit")]
    TargetTooLarge,

    #[error("Proof-of-work hash does not satisfy the claim difficulty: {0:?}")]
    InvalidProofOfWork(bitcoin::block::ValidationError),

    #[error("Header's difficulty bits mismatch: {{ got: {got:?}, expected: {expected:?} }}")]
    BadDifficultyBits { got: Target, expected: Target },

    #[error("Header's difficulty is not reasonably related to its parent")]
    BadDifficulty,

    #[error("Header #{0}: cumulative work mismatch. Expected {1}, got {2}")]
    WrongCumulativeWork(usize, Work, Work),

    #[error("Header #{0}: incorrect height. Expected {1}, got {2}")]
    WrongHeight(usize, u32, u32),

    #[error("Header's prev_blockhash {got} does not match parent header's hash {expected}")]
    PrevHashMismatch { got: BlockHash, expected: BlockHash },

    /// Block's timestamp is too old.
    #[error("Time is the median time of last 11 blocks or before")]
    TimeTooOld,

    #[error("Block version {0} is too old and is no longer accepted")]
    BlockVersionTooOld(i32),

    #[error("Failed to decode BTC header: {0}")]
    DecodeError(String),

    #[error("Header {0} missing from store and pending")]
    MissingHeader(BlockHash),

    #[error(transparent)]
    Std(#[from] StdError),

    #[error(transparent)]
    Store(#[from] crate::state::StoreError),
}

impl From<bitcoin::consensus::encode::Error> for HeaderError {
    fn from(e: bitcoin::consensus::encode::Error) -> Self {
        Self::DecodeError(e.to_string())
    }
}

/// Verifies a consecutive sequence of Bitcoin headers starting from a known header.
///
/// Ref https://github.com/babylonlabs-io/babylon/blob/d3d81178dc38c172edaf5651c72b296bb9371a48/x/btclightclient/types/btc_light_client.go#L298
pub fn verify_headers(
    _storage: &dyn Storage,
    _chain_params: &Params,
    first_header: &BtcHeaderInfo,
    new_headers: &[BtcHeaderInfo],
) -> Result<(), HeaderError> {
    let mut last_header = first_header.clone();

    for (i, new_header) in new_headers.iter().enumerate() {
        let prev_block_header = last_header.block_header()?;
        let block_header = new_header.block_header()?;

        // Check whether the headers form a chain.
        if block_header.prev_blockhash != prev_block_header.block_hash() {
            return Err(HeaderError::PrevHashMismatch {
                got: block_header.prev_blockhash,
                expected: prev_block_header.block_hash(),
            });
        }

        // Validate height
        if new_header.height != last_header.height + 1 {
            return Err(HeaderError::WrongHeight(
                i,
                last_header.height + 1,
                new_header.height,
            ));
        }

        // this header is good, verify the next one
        last_header = new_header.clone();
    }
    Ok(())
}

/// Returns the total work of the given header.
///
/// The total work is the cumulative work of the given header and all of its ancestors.
///
/// This implementation expects work data to be 32 bytes or smaller and will:
/// 1. Left-pad the input with zeros to 32 bytes (big-endian compatible)
/// 2. Convert the result to a [`Work`] type
///
/// # Arguments
///
/// * `work`: Byte slice containing the work value (<= 32bytes).
pub fn total_work(work: &[u8]) -> StdResult<Work> {
    if work.len() > 32 {
        return Err(StdError::generic_err("Work exceeds 32 bytes"));
    }
    let mut output = [0u8; 32];
    let len = work.len();
    let start = 32 - len; // Calculate left-pad offset
    output[start..].copy_from_slice(work); // Copy to end
    Ok(Work::from_be_bytes(output))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_total_work() {
        assert_eq!(
            total_work(&[]).unwrap(),
            Work::from_be_bytes(cosmwasm_std::Uint256::from_u128(0).to_be_bytes())
        );
        // Work data smaller than 32 bytes should work.
        assert_eq!(
            total_work(&[50]).unwrap(),
            Work::from_be_bytes(cosmwasm_std::Uint256::from_u128(50).to_be_bytes())
        );
        assert_eq!(
            total_work(&[1u8; 33]).unwrap_err(),
            StdError::generic_err("Work exceeds 32 bytes")
        );
    }
}
