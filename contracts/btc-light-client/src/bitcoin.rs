//! Verifies Bitcoin block headers for correctness and proof-of-work validity.
//!
//! This module provides functionality to:
//! - Verify that a sequence of Bitcoin headers forms a valid chain.
//! - Enforce proof-of-work correctness.
//! - Ensure difficulty retargeting and cumulative work are consistent with Bitcoin consensus rules.
//!
//! It mirrors the logic used in Bitcoin Core and Babylon's Go implementation.

use crate::state::{get_header, get_header_by_hash};
use babylon_proto::babylon::btclightclient::v1::BtcHeaderInfo;
use bitcoin::block::Header as BlockHeader;
use bitcoin::consensus::{deserialize, Params};
use bitcoin::{BlockHash, Target, Work};
use cosmwasm_std::{StdError, StdResult};
use cosmwasm_std::{Storage, Uint256};
use std::collections::BTreeMap;

/// bip-0113 defines the median of the last 11 blocks instead of the block's timestamp for lock-time calculations.
const MEDIAN_TIME_SPAN: usize = 11;

type PendingHeaders = BTreeMap<BlockHash, (BlockHeader, u32)>;

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
    Store(#[from] crate::state::btc_light_client::StoreError),
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
    storage: &dyn Storage,
    chain_params: &Params,
    first_header: &BtcHeaderInfo,
    new_headers: &[BtcHeaderInfo],
) -> Result<(), HeaderError> {
    let mut last_header = first_header.clone();
    let mut cum_work_old = total_work(last_header.work.as_ref())?;

    // A collection of headers that have been verified but not yet committed to storage.
    // This is necessary for the `calculate_median_time_past` function, which needs
    // to look at the last 11 headers. Some of those headers might be in the
    // `new_headers` slice, which is not yet in storage.
    let mut pending_headers = BTreeMap::new();

    for (i, new_header) in new_headers.iter().enumerate() {
        let prev_block_header: BlockHeader = deserialize(last_header.header.as_ref())?;
        let block_header: BlockHeader = deserialize(new_header.header.as_ref())?;

        // Check whether the headers form a chain.
        if block_header.prev_blockhash != prev_block_header.block_hash() {
            return Err(HeaderError::PrevHashMismatch {
                got: block_header.prev_blockhash,
                expected: prev_block_header.block_hash(),
            });
        }

        check_header(
            storage,
            chain_params,
            last_header.height,
            &prev_block_header,
            &block_header,
            &pending_headers,
        )?;

        let cum_work = total_work(new_header.work.as_ref())?;

        // Validate cumulative work
        let cum_work_new = cum_work_old + block_header.work();
        if cum_work_new != cum_work {
            return Err(HeaderError::WrongCumulativeWork(i, cum_work_new, cum_work));
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
        cum_work_old = cum_work;
        last_header = new_header.clone();
        pending_headers.insert(block_header.block_hash(), (block_header, new_header.height));
    }
    Ok(())
}

/// This functions mirrors the `checkHeader` in babylon golang implmentation.
///
/// https://github.com/babylonlabs-io/babylon/blob/48617fb852e9cae4ea7ea38c80793cdcb6f2668c/x/btclightclient/types/btc_light_client.go#L416
fn check_header(
    storage: &dyn Storage,
    chain_params: &Params,
    prev_block_height: u32,
    prev_block_header: &BlockHeader,
    header: &BlockHeader,
    pending_headers: &PendingHeaders,
) -> Result<(), HeaderError> {
    check_block_header_context(
        storage,
        chain_params,
        prev_block_height,
        prev_block_header,
        header,
        pending_headers,
    )?;

    // Perform proof-of-work check as specified in:
    // https://pkg.go.dev/github.com/btcsuite/btcd@v0.24.2/blockchain#CheckBlockHeaderSanity
    check_proof_of_work(chain_params, header)?;

    Ok(())
}

/// Ensures the header's hash <= the header's target <= pow limit.
pub(crate) fn check_proof_of_work(
    chain_params: &bitcoin::consensus::Params,
    header: &BlockHeader,
) -> Result<(), HeaderError> {
    let target = header.target();

    // ensure the target <= pow_limit
    if target > chain_params.max_attainable_target {
        return Err(HeaderError::TargetTooLarge);
    }

    // ensure the header's hash <= target
    // NOTE: validate_pow ensures two things
    // - the given required_target is same
    // - the header hash is smaller than required_target
    // The former must be true since we give this header's target
    // Here we are interested in the latter check, in which the code is private
    header
        .validate_pow(target)
        .map_err(HeaderError::InvalidProofOfWork)?;

    Ok(())
}

/// > Ensure the difficulty specified in the block header matches
/// > the calculated difficulty based on the previous block and
/// > difficulty retarget rules.
///
/// Note: While the naming mirrors the btcd implementation, this function only performs
/// the difficulty adjustment check (not the full header context validation in btcd).
///
/// https://pkg.go.dev/github.com/btcsuite/btcd@v0.24.2/blockchain#CheckBlockHeaderContext
fn check_block_header_context(
    storage: &dyn Storage,
    chain_params: &Params,
    prev_block_height: u32,
    prev_block_header: &BlockHeader,
    header: &BlockHeader,
    pending_headers: &PendingHeaders,
) -> Result<(), HeaderError> {
    let expected_target =
        get_next_work_required(storage, prev_block_height, prev_block_header, chain_params)?;

    let expected_bits = expected_target.to_compact_lossy().to_consensus();

    let actual_target = header.target();
    let actual_bits = actual_target.to_compact_lossy().to_consensus();

    if actual_bits != expected_bits {
        return Err(HeaderError::BadDifficultyBits {
            got: actual_target,
            expected: expected_target,
        });
    }

    let block_height = prev_block_height + 1;

    let mtp = calculate_median_time_past(storage, header, block_height, pending_headers)?;
    if header.time <= mtp {
        return Err(HeaderError::TimeTooOld);
    }

    let block_version = header.version.to_consensus();
    if (block_version < 2 && block_height >= chain_params.bip34_height)
        || (block_version < 3 && block_height >= chain_params.bip66_height)
        || (block_version < 4 && block_height >= chain_params.bip65_height)
    {
        return Err(HeaderError::BlockVersionTooOld(block_version));
    }

    Ok(())
}

/// Calculates the median time of the previous few blocks prior to the header (inclusive).
// TODO: Added `header_height` to make the loop exit condition more robust when fetching previous
// timestamps, since relying on `BlockHash::all_zeros()` isn't reliable with the current test data.
// We may remove it in future if the test data is updated.
fn calculate_median_time_past(
    storage: &dyn Storage,
    header: &BlockHeader,
    header_height: u32,
    pending_headers: &PendingHeaders,
) -> Result<u32, HeaderError> {
    let mut timestamps = Vec::with_capacity(MEDIAN_TIME_SPAN);

    timestamps.push(header.time);

    let mut block_hash = header.prev_blockhash;
    let mut block_height = header_height - 1;

    while timestamps.len() < MEDIAN_TIME_SPAN {
        // Genesis block
        if block_height == 0 {
            break;
        }

        let header: BlockHeader = match get_header_by_hash(storage, block_hash.as_ref()) {
            Ok(raw_header) => deserialize(raw_header.header.as_ref())?,
            Err(_) => pending_headers
                .get(&block_hash)
                .map(|(header, _height)| header)
                .cloned()
                .ok_or(HeaderError::MissingHeader(block_hash))?,
        };

        timestamps.push(header.time);

        block_hash = header.prev_blockhash;
        block_height -= 1;
    }

    timestamps.sort_unstable();

    Ok(timestamps
        .get(timestamps.len() / 2)
        .copied()
        .expect("Timestamps must be non-empty; qed"))
}

/// Usually, it's just the target of last block. However, if we are in a retarget period,
/// it will be calculated from the last 2016 blocks (about two weeks for Bitcoin mainnet).
///
/// <https://github.com/bitcoin/bitcoin/blob/89b910711c004c21b7d67baa888073742f7f94f0/src/pow.cpp#L13>
fn get_next_work_required(
    storage: &dyn Storage,
    last_block_height: u32,
    last_block: &BlockHeader,
    params: &Params,
) -> Result<Target, HeaderError> {
    if params.no_pow_retargeting {
        return Ok(last_block.target());
    }

    let height = last_block_height + 1;

    let difficulty_adjustment_interval = params.difficulty_adjustment_interval() as u32;

    // Only change once per difficulty adjustment interval.
    if height >= difficulty_adjustment_interval && height % difficulty_adjustment_interval == 0 {
        let last_retarget_height = height - difficulty_adjustment_interval;

        let retarget_header_info = get_header(storage, last_retarget_height)?;
        let retarget_header: BlockHeader =
            bitcoin::consensus::deserialize(&retarget_header_info.header)?;

        let first_block_time = retarget_header.time;

        // timestamp of last block
        let last_block_time = last_block.time;

        Ok(calculate_next_work_required(
            Uint256::from_be_bytes(last_block.target().to_be_bytes()),
            first_block_time.into(),
            last_block_time.into(),
            params,
        ))
    } else {
        // Not on a boundary, difficulty should be the same as parent
        Ok(last_block.target())
    }
}

// <https://github.com/bitcoin/bitcoin/blob/89b910711c004c21b7d67baa888073742f7f94f0/src/pow.cpp#L49-L72>
// TODO: see if we can directly reuse the rust-bitcoin API https://github.com/rust-bitcoin/rust-bitcoin/blob/f7274a57c36d0b8d8cc528426e269c27d496bd5f/bitcoin/src/pow.rs#L374
fn calculate_next_work_required(
    previous_target: Uint256,
    first_block_time: u64,
    last_block_time: u64,
    params: &Params,
) -> Target {
    let mut actual_timespan = last_block_time.saturating_sub(first_block_time);

    let pow_target_timespan = params.pow_target_timespan;

    // Limit adjustment step.
    //
    // Note: The new difficulty is in [Difficulty_old * 1/4, Difficulty_old * 4].
    if actual_timespan < pow_target_timespan / 4 {
        actual_timespan = pow_target_timespan / 4;
    }

    if actual_timespan > pow_target_timespan * 4 {
        actual_timespan = pow_target_timespan * 4;
    }

    let pow_limit = params.max_attainable_target;

    // Retarget.
    let target = previous_target * Uint256::from_u128(actual_timespan.into());
    let target = target / Uint256::from_u128(pow_target_timespan.into());
    let target = Target::from_be_bytes(target.to_be_bytes());

    if target > pow_limit {
        pow_limit
    } else {
        target
    }
}

/// Returns the total work of the given header.
/// The total work is the cumulative work of the given header and all of its ancestors.
pub fn total_work(work: &[u8]) -> StdResult<Work> {
    Ok(Work::from_be_bytes(work.try_into().map_err(|e| {
        StdError::generic_err(format!("Invalid work: {e:?}"))
    })?))
}

/// Checks if a Bitcoin header is on a difficulty change boundary.
///
/// In Bitcoin, difficulty is adjusted every 2016 blocks (approximately every 2 weeks).
/// A header is on a difficulty change boundary if its height is divisible by 2016.
pub fn is_difficulty_change_boundary(height: u32, chain_params: &Params) -> bool {
    let difficulty_adjustment_interval = chain_params.difficulty_adjustment_interval() as u32;

    // A header is on a difficulty change boundary if:
    // 1. The height is >= difficulty_adjustment_interval (2016 for mainnet)
    // 2. The height is divisible by difficulty_adjustment_interval
    height >= difficulty_adjustment_interval && height % difficulty_adjustment_interval == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::btc_light_client::handle_btc_headers_from_babylon;
    use crate::state::btc_light_client::tests::{init_contract, setup};
    use babylon_test_utils::get_btc_lc_headers;
    use bitcoin::block::Header as BlockHeader;
    use bitcoin::block::Version;
    use bitcoin::hashes::Hash;
    use bitcoin::{BlockHash, CompactTarget};
    use cosmwasm_std::testing::{mock_dependencies, MockStorage};
    use std::collections::BTreeMap;

    fn make_header(time: u32, prev_blockhash: BlockHash) -> BlockHeader {
        BlockHeader {
            version: Version::TWO,
            prev_blockhash,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time,
            bits: CompactTarget::from_consensus(0x1d00ffff), // Bitcoin mainnet initial difficulty
            nonce: 0,
        }
    }

    fn test_headers(times: Vec<u32>) -> (BlockHeader, PendingHeaders) {
        let mut pending_headers = BTreeMap::new();
        let mut prev_hash = BlockHash::all_zeros();

        let mut last_header = None;
        for (i, &t) in times.iter().enumerate() {
            let header = make_header(t, prev_hash);
            prev_hash = header.block_hash();
            pending_headers.insert(header.block_hash(), (header, i as u32 + 1));
            last_header = Some(header);
        }
        let header = last_header.unwrap();

        (header, pending_headers)
    }

    #[test]
    fn test_median_time_past_fewer_than_11() {
        let storage = MockStorage::default();
        let mut times = vec![1000, 1010, 1020, 1030, 1040];
        let (header, pending_headers) = test_headers(times.clone());
        let mtp = calculate_median_time_past(&storage, &header, 5, &pending_headers).unwrap();
        times.reverse(); // because we build chain backwards
        times.sort_unstable();
        assert_eq!(mtp, times[times.len() / 2]);
    }

    #[test]
    fn test_median_time_past_exactly_11() {
        let storage = MockStorage::default();
        let mut times = vec![
            1000, 1010, 1020, 1030, 1040, 1050, 1060, 1070, 1080, 1090, 1100,
        ];
        let (header, pending_headers) = test_headers(times.clone());
        let mtp = calculate_median_time_past(&storage, &header, 11, &pending_headers).unwrap();
        times.reverse();
        times.sort_unstable();
        assert_eq!(mtp, times[times.len() / 2]);
    }

    #[test]
    fn test_median_time_past_more_than_11() {
        let storage = MockStorage::default();
        let mut times = (1000..=1020).step_by(2).collect::<Vec<u32>>(); // 1000, 1002, ..., 1020 (11 values)
        times.extend(&[1030, 1040, 1050]); // now 14 values
        let (header, pending_headers) = test_headers(times);
        // Only the most recent 11 timestamps should be used
        let mut walk_hash = header.block_hash();
        let mut used_times = Vec::new();
        for _ in 0..MEDIAN_TIME_SPAN {
            let h = pending_headers.get(&walk_hash).unwrap();
            used_times.push(h.0.time);
            walk_hash = h.0.prev_blockhash;
        }
        used_times.sort_unstable();
        let mtp = calculate_median_time_past(&storage, &header, 14, &pending_headers).unwrap();
        assert_eq!(mtp, used_times[used_times.len() / 2]);
    }

    #[test]
    fn median_time_check_should_work_when_there_are_less_than_11_headers_in_store() {
        let deps = mock_dependencies();
        let mut storage = deps.storage;
        setup(&mut storage);

        let test_headers = get_btc_lc_headers();

        // Initialize the contract with only the base header.
        let initial_headers = vec![test_headers[0].clone()];
        init_contract(&mut storage, &initial_headers).unwrap();

        // Submit one header.
        let new_headers = vec![test_headers[1].clone()];
        handle_btc_headers_from_babylon(&mut storage, &new_headers).unwrap();
    }
}
