use crate::error::ContractError;
use crate::state::finality::{get_power_table_at_height, BLOCKS, NEXT_HEIGHT, SIGNATURES};
use babylon_apis::finality_api::IndexedBlock;
use cosmwasm_std::Order::Ascending;
use cosmwasm_std::{DepsMut, Env, Event, StdResult, Storage};
use std::cmp::{max, min};
use std::collections::{HashMap, HashSet};

// Setting max amount of finalized blocks per EndBlock to 1_000 to cap processing time,
// mirroring Babylon's `MaxFinalizedRewardedBlocksPerEndBlock`.
// https://github.com/babylonlabs-io/babylon/blob/53d1a8e211f5c9d8b369397bde1f6cf05c7038ad/x/finality/types/constants.go#L7
// Setting a smaller value here because the cost in CosmWasm is higher than in Go module.
const MAX_FINALIZED_REWARDED_BLOCKS_PER_END_BLOCK: u64 = 1_000;

/// Tries to finalise all blocks that are non-finalised AND have a non-nil
/// finality provider set, from the earliest to the latest.
///
/// This function is invoked upon each `EndBlock`, after the BTC staking protocol is activated.
/// It ensures that at height `h`, the ancestor chain `[activated_height, h-1]` contains either
/// - finalised blocks (i.e., blocks with a finality provider set AND QC of this finality provider set),
/// - non-finalisable blocks (i.e. blocks with no active finality providers),
///   but no blocks that have a finality provider set and do not receive a QC
///
/// It must be invoked only after the BTC staking protocol is activated.
pub fn tally_blocks(
    deps: &mut DepsMut,
    env: &Env,
    start_height: u64,
) -> Result<Vec<Event>, ContractError> {
    // Start finalising blocks since max(start_height, next_height)
    let next_height = NEXT_HEIGHT.may_load(deps.storage)?.unwrap_or(0);
    let start_height = max(start_height, next_height);

    // Find all blocks that are non-finalised AND have a finality provider set since
    // max(activated_height, last_finalized_height + 1)
    // There are 4 different scenarios:
    // - Has finality providers, non-finalised: Tally and try to finalise.
    // - Does not have finality providers, non-finalised: Non-finalisable, continue.
    // - Has finality providers, finalised: Impossible, panic.
    // - Does not have finality providers, finalised: Impossible, panic.
    // After this for loop, the blocks since the earliest activated height are either finalised or
    // non-finalisable
    let mut events = vec![];
    // Process at most `max_blocks` heights to cap per-block processing time
    let end_height_inclusive = min(
        env.block.height,
        start_height.saturating_add(MAX_FINALIZED_REWARDED_BLOCKS_PER_END_BLOCK.saturating_sub(1)),
    );
    for h in start_height..=end_height_inclusive {
        let mut indexed_block = BLOCKS.load(deps.storage, h)?;
        // Get the finality provider set of this block
        let fp_power_table = get_power_table_at_height(deps.storage, h)?;
        let has_fp = !fp_power_table.is_empty();

        match (has_fp, indexed_block.finalized) {
            (true, false) => {
                // Has finality providers, non-finalised: tally and try to finalise the block
                let voter_btc_pks = SIGNATURES
                    .prefix(indexed_block.height)
                    .keys(deps.storage, None, None, Ascending)
                    .collect::<StdResult<Vec<_>>>()?;
                if tally(&fp_power_table, &voter_btc_pks) {
                    // If this block gets >2/3 votes, finalise it
                    let ev = finalize_block(deps.storage, &mut indexed_block, &voter_btc_pks)?;
                    events.push(ev);
                } else {
                    // If not, then this block and all subsequent blocks should not be finalised.
                    // Thus, we need to break here
                    break;
                }
            }
            (false, false) => {
                // Does not have finality providers, non-finalised: not finalisable,
                // Increment the next height to finalise and continue
                NEXT_HEIGHT.save(deps.storage, &(indexed_block.height + 1))?;
                continue;
            }
            (true, true) => {
                // Has finality providers and the block is finalised.
                // This can only be a programming error
                return Err(ContractError::FinalisedBlockWithFinalityProviderSet(
                    indexed_block.height,
                ));
            }
            (false, true) => {
                // Does not have finality providers, finalised: impossible to happen
                return Err(ContractError::FinalisedBlockWithoutFinalityProviderSet(
                    indexed_block.height,
                ));
            }
        }
    }

    Ok(events)
}

/// Checks whether a block with the given finality provider set and votes reaches a quorum or not.
fn tally(fp_power_table: &HashMap<String, u64>, voters: &[String]) -> bool {
    let voters: HashSet<_> = voters.iter().collect();
    let mut total_power = 0;
    let mut voted_power = 0;
    for (fp_btc_pk_hex, power) in fp_power_table {
        total_power += power;
        if voters.contains(fp_btc_pk_hex) {
            voted_power += power;
        }
    }
    voted_power * 3 > total_power * 2
}

/// Sets a block to be finalised.
fn finalize_block(
    store: &mut dyn Storage,
    block: &mut IndexedBlock,
    _voters: &[String],
) -> Result<Event, ContractError> {
    // Set block to be finalised
    block.finalized = true;
    BLOCKS.save(store, block.height, block)?;

    // Set the next height to finalise as height+1
    NEXT_HEIGHT.save(store, &(block.height + 1))?;

    // Record the last finalized height metric
    let ev = Event::new("finalize_block")
        .add_attribute("module", "finality")
        .add_attribute("finalized_height", block.height.to_string());
    Ok(ev)
}
