//! This module provides some Bitcoin related helper functions.

use crate::error::ContractError;
use crate::state::get_header;
use babylon_bitcoin::{deserialize, BlockHeader, Work};
use babylon_bitcoin::{Params, Uint256 as U256};
use babylon_proto::babylon::btclightclient::v1::BtcHeaderInfo;
use bitcoin::Target;
use cosmwasm_std::Storage;
use cosmwasm_std::{StdError, StdResult};

// RetargetAdjustmentFactor in https://github.com/btcsuite/btcd/blob/master/chaincfg/params.go
// Its value is always 4
const RETARGET_ADJUSTMENT_FACTOR: u64 = 4;

/// Verifies whether `new_headers` are valid consecutive headers
/// after the given `first_header`.
pub fn verify_headers(
    storage: &dyn Storage,
    chain_params: &Params,
    first_header: &BtcHeaderInfo,
    new_headers: &[BtcHeaderInfo],
) -> Result<(), ContractError> {
    // verify each new header iteratively
    let mut last_header = first_header.clone();
    let mut cum_work_old = total_work(last_header.work.as_ref())?;
    for (i, new_header) in new_headers.iter().enumerate() {
        let last_btc_header: BlockHeader = deserialize(last_header.header.as_ref())?;
        let btc_header: BlockHeader = deserialize(new_header.header.as_ref())?;

        check_header(
            storage,
            chain_params,
            last_header.height,
            &last_btc_header,
            &btc_header,
        )?;

        let header_work = btc_header.work();
        let cum_work = total_work(new_header.work.as_ref())?;

        // Validate cumulative work
        if cum_work_old + header_work != cum_work {
            return Err(ContractError::BTCWrongCumulativeWork(
                i,
                cum_work_old + header_work,
                cum_work,
            ));
        }
        cum_work_old = cum_work;
        // Validate height
        if new_header.height != last_header.height + 1 {
            return Err(ContractError::BTCWrongHeight(
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

// https://github.com/babylonlabs-io/babylon/blob/48617fb852e9cae4ea7ea38c80793cdcb6f2668c/x/btclightclient/types/btc_light_client.go#L416
fn check_header(
    storage: &dyn Storage,
    chain_params: &Params,
    prev_block_height: u32,
    prev_block_header: &BlockHeader,
    header: &BlockHeader,
) -> Result<(), ContractError> {
    check_block_header_context(
        storage,
        chain_params,
        prev_block_height,
        prev_block_header,
        header,
    )?;

    check_block_header_sanity(chain_params, prev_block_header, header)?;

    Ok(())
}

// https://pkg.go.dev/github.com/btcsuite/btcd@v0.24.2/blockchain#CheckBlockHeaderSanity
fn check_block_header_sanity(
    chain_params: &Params,
    prev_block_header: &BlockHeader,
    header: &BlockHeader,
) -> Result<(), ContractError> {
    /* This check should be done much eariler.
    // ensure the header is adjacent to last_btc_header
    if !prev_header.block_hash().eq(&header.prev_blockhash) {
        return Err(Error::PreHeaderHashMismatch);
    }
    */

    // Check proof-of-work
    babylon_bitcoin::pow::verify_header_pow(chain_params, header)?;

    // if the chain does not allow reduced difficulty after 10min, ensure
    // the new header's target is within the [0.25, 4] range
    if !chain_params.allow_min_difficulty_blocks {
        let retarget_adjustment_factor_u256 =
            cosmwasm_std::Uint256::from(RETARGET_ADJUSTMENT_FACTOR);
        let old_target =
            cosmwasm_std::Uint256::from_be_bytes(prev_block_header.target().to_be_bytes());
        let cur_target = cosmwasm_std::Uint256::from_be_bytes(header.target().to_be_bytes());
        let max_cur_target = old_target * retarget_adjustment_factor_u256;
        let min_cur_target = old_target / retarget_adjustment_factor_u256;
        if cur_target > max_cur_target || cur_target < min_cur_target {
            return Err(ContractError::BadDifficulty);
        }
    }

    Ok(())
}

/// Ensures the difficulty specified in the block header complies with the protocol.
// https://pkg.go.dev/github.com/btcsuite/btcd@v0.24.2/blockchain#CheckBlockHeaderContext
fn check_block_header_context(
    storage: &dyn Storage,
    chain_params: &Params,
    prev_block_height: u32,
    prev_block_header: &BlockHeader,
    header: &BlockHeader,
) -> Result<(), ContractError> {
    let expected_target =
        get_next_work_required(storage, prev_block_height, prev_block_header, chain_params)?;

    let expected_bits = expected_target.to_compact_lossy().to_consensus();

    let actual_target = header.target();

    if actual_target.to_compact_lossy().to_consensus() != expected_bits {
        return Err(ContractError::BadDifficultyBits {
            got: actual_target,
            expected: expected_target,
        });
    }

    Ok(())
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
) -> Result<Target, ContractError> {
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
            U256::from_be_bytes(last_block.target().to_be_bytes()),
            first_block_time.into(),
            last_block_time.into(),
            params,
        ))
    } else {
        Ok(last_block.target())
    }
}

// <https://github.com/bitcoin/bitcoin/blob/89b910711c004c21b7d67baa888073742f7f94f0/src/pow.cpp#L49-L72>
fn calculate_next_work_required(
    previous_target: U256,
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
    let target = previous_target * U256::from_u128(actual_timespan.into());
    let target = target / U256::from_u128(pow_target_timespan.into());
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
