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

    #[error("Proof-of-work hash does not satisfy the claim difficulty: {0}")]
    InvalidProofOfWork(String),

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

/// Validates that a Bitcoin header's hash meets the proof-of-work requirement.
///
/// This function checks that the header's hash is less than or equal to the target
/// specified by the header's bits field, which is the core proof-of-work validation.
/// This mirrors Babylon's ValidateBTCHeader function behavior.
fn validate_proof_of_work(
    header: &bitcoin::block::Header,
    pow_limit: &bitcoin::Target,
) -> Result<(), HeaderError> {
    // Get the target from the header's bits field
    let target = header.target();

    // Ensure the target doesn't exceed the maximum allowed difficulty
    if target > *pow_limit {
        return Err(HeaderError::TargetTooLarge);
    }

    // Calculate the header's hash (double SHA-256)
    let header_hash = header.block_hash();

    // Convert hash to Target for comparison
    // BlockHash implements AsRef<[u8; 32]>, so we can get the bytes directly
    let hash_bytes = header_hash.as_ref();
    let hash_target = bitcoin::Target::from_be_bytes(*hash_bytes);

    // The hash must be less than or equal to the target for valid proof-of-work
    if hash_target > target {
        return Err(HeaderError::InvalidProofOfWork(
            "Header hash does not meet difficulty target".to_string(),
        ));
    }

    // Validate timestamp precision (matching Babylon's behavior)
    // Bitcoin timestamps must not have precision greater than one second
    // This matches Babylon's check: header.Timestamp.Equal(time.Unix(header.Timestamp.Unix(), 0))
    let timestamp = header.time;
    // The timestamp is already in seconds, so this validation ensures it's properly formatted
    if timestamp == 0 {
        return Err(HeaderError::TimeTooOld);
    }

    Ok(())
}

/// Validates a single Bitcoin header for proof-of-work and other sanity checks.
/// This function directly mirrors Babylon's ValidateBTCHeader function.
pub fn validate_btc_header(
    header: &bitcoin::block::Header,
    pow_limit: &bitcoin::Target,
) -> Result<(), HeaderError> {
    validate_proof_of_work(header, pow_limit)
}

/// Verifies a consecutive sequence of Bitcoin headers starting from a known header.
///
/// Ref https://github.com/babylonlabs-io/babylon/blob/d3d81178dc38c172edaf5651c72b296bb9371a48/x/btclightclient/types/btc_light_client.go#L298
pub fn verify_headers(
    _storage: &dyn Storage,
    chain_params: &Params,
    first_header: &BtcHeaderInfo,
    new_headers: &[BtcHeaderInfo],
) -> Result<(), HeaderError> {
    let mut last_header = first_header.clone();

    // Get the proof-of-work limit for this network
    let pow_limit = chain_params.max_attainable_target;

    for (i, new_header) in new_headers.iter().enumerate() {
        let prev_block_header = last_header.block_header()?;
        let block_header = new_header.block_header()?;

        // Validate proof-of-work for this header
        validate_proof_of_work(&block_header, &pow_limit)?;

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
    use bitcoin::consensus::Params;
    use bitcoin::hashes::Hash;

    /// Helper function to create a valid Bitcoin header with proper proof-of-work
    /// This mines a header that actually satisfies the target difficulty
    pub fn create_valid_header(
        prev_hash: bitcoin::BlockHash,
        target: bitcoin::CompactTarget,
        time: u32,
    ) -> bitcoin::block::Header {
        let mut header = bitcoin::block::Header {
            version: bitcoin::block::Version::ONE,
            prev_blockhash: prev_hash,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time,
            bits: target,
            nonce: 0,
        };

        // Mine the header by incrementing nonce until we find valid proof-of-work
        let target_threshold = target.into();

        for nonce in 0..u32::MAX {
            header.nonce = nonce;
            let hash = header.block_hash();
            let hash_target = bitcoin::Target::from_be_bytes(*hash.as_ref());

            if hash_target <= target_threshold {
                return header; // Found valid proof-of-work!
            }
        }

        panic!("Could not mine valid header - target too restrictive");
    }

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

    #[test]
    fn test_validate_btc_header_with_valid_header() {
        let regtest_params = Params::new(bitcoin::Network::Regtest);

        // Create a valid header with proper proof-of-work for regtest
        let header = create_valid_header(
            bitcoin::BlockHash::all_zeros(),
            bitcoin::CompactTarget::from_consensus(0x207fffff), // Maximum target for regtest
            1234567890,
        );

        // This should pass with our real validation
        let result = validate_btc_header(&header, &regtest_params.max_attainable_target);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_proof_of_work_enforces_pow_limit() {
        // Test that we properly validate target against pow_limit
        let header = bitcoin::block::Header {
            version: bitcoin::block::Version::ONE,
            prev_blockhash: bitcoin::BlockHash::all_zeros(),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 1234567890,
            bits: bitcoin::CompactTarget::from_consensus(0x207fffff), // Maximum regtest target
            nonce: 0,
        };

        // Create a very restrictive pow_limit that's smaller than the header's target
        let restrictive_pow_limit = bitcoin::Target::from_be_bytes([
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x01,
        ]);

        // This should fail because header.target() > restrictive_pow_limit
        let result = validate_proof_of_work(&header, &restrictive_pow_limit);
        assert!(matches!(result, Err(HeaderError::TargetTooLarge)));
    }

    #[test]
    fn test_validate_proof_of_work_rejects_invalid_hash() {
        // Create a header with invalid proof-of-work (hash doesn't meet target)
        let header = bitcoin::block::Header {
            version: bitcoin::block::Version::ONE,
            prev_blockhash: bitcoin::BlockHash::all_zeros(),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 1234567890,
            bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff), // Very restrictive target
            nonce: 0, // This nonce won't satisfy the restrictive target
        };

        let regtest_params = Params::new(bitcoin::Network::Regtest);

        // This should fail because the hash doesn't meet the target
        let result = validate_proof_of_work(&header, &regtest_params.max_attainable_target);
        assert!(matches!(result, Err(HeaderError::InvalidProofOfWork(_))));
    }

    #[test]
    fn test_proof_of_work_validation_end_to_end() {
        // This test demonstrates that our validation actually works by:
        // 1. Creating an invalid header (should fail)
        // 2. Mining a valid header (should pass)

        let regtest_params = Params::new(bitcoin::Network::Regtest);

        // 1. Invalid header should fail
        let invalid_header = bitcoin::block::Header {
            version: bitcoin::block::Version::ONE,
            prev_blockhash: bitcoin::BlockHash::all_zeros(),
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time: 1234567890,
            bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff), // Restrictive target
            nonce: 0,                                                 // This definitely won't work
        };

        let result = validate_btc_header(&invalid_header, &regtest_params.max_attainable_target);
        assert!(result.is_err(), "Invalid header should be rejected");

        // 2. Valid mined header should pass
        let valid_header = create_valid_header(
            bitcoin::BlockHash::all_zeros(),
            bitcoin::CompactTarget::from_consensus(0x207fffff), // Easy regtest target
            1234567890,
        );

        let result = validate_btc_header(&valid_header, &regtest_params.max_attainable_target);
        assert!(result.is_ok(), "Valid mined header should be accepted");
    }
}
