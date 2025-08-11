//! https://github.com/babylonlabs-io/babylon/blob/ff15aa54445a82de9705beec2f4072bfc2a6db0c/x/finality/keeper/tallying.go

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
    tally_blocks_with_max_finalized_blocks(
        deps,
        env,
        start_height,
        MAX_FINALIZED_REWARDED_BLOCKS_PER_END_BLOCK,
    )
}

pub(crate) fn tally_blocks_with_max_finalized_blocks(
    deps: &mut DepsMut,
    env: &Env,
    start_height: u64,
    max_finalized_blocks: u64,
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
        start_height.saturating_add(max_finalized_blocks.saturating_sub(1)),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::finality::set_voting_power_table;
    use cosmwasm_std::testing::{mock_dependencies, mock_env};
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};
    use std::collections::HashMap;

    fn gen_random_bytes(seed: u64, len: usize) -> Vec<u8> {
        let mut rng = StdRng::seed_from_u64(seed);
        (0..len).map(|_| rng.gen()).collect()
    }

    fn gen_random_btc_pk(seed: u64) -> String {
        let bytes = gen_random_bytes(seed, 32);
        hex::encode(bytes)
    }

    // Gives QC to a height.
    fn give_qc_to_height(storage: &mut dyn Storage, height: u64, num_votes: usize) {
        let mut power_table = HashMap::new();

        // Add `num_votes` voting finality providers.
        for i in 0..num_votes {
            let fp_pk = gen_random_btc_pk(height + i as u64);
            power_table.insert(fp_pk.clone(), 1);

            // Add signature for this finality provider.
            let sig = gen_random_bytes(height + i as u64, 32);
            SIGNATURES.save(storage, (height, &fp_pk), &sig).unwrap();
        }

        // Add one non-voting finality provider.
        let non_voting_fp = gen_random_btc_pk(height + 1000);
        power_table.insert(non_voting_fp, 1);

        set_voting_power_table(storage, height, power_table).unwrap();
    }

    // Gives no QC to a height.
    fn give_no_qc_to_height(storage: &mut dyn Storage, height: u64) {
        let mut power_table = HashMap::new();

        // Add 1 voting finality provider (insufficient for quorum).
        let voted_fp = gen_random_btc_pk(height);
        power_table.insert(voted_fp.clone(), 1);

        // Add signature for this finality provider.
        let sig = gen_random_bytes(height, 32);
        SIGNATURES.save(storage, (height, &voted_fp), &sig).unwrap();

        // Add 3 non-voting finality providers.
        for i in 0..3 {
            let fp_pk = gen_random_btc_pk(height + 1000 + i as u64);
            power_table.insert(fp_pk, 1);
        }

        set_voting_power_table(storage, height, power_table).unwrap();
    }

    fn insert_indexed_block_at(storage: &mut dyn Storage, height: u64) {
        let block = IndexedBlock {
            height,
            app_hash: gen_random_bytes(height, 32),
            finalized: false,
        };

        BLOCKS.save(storage, height, &block).unwrap();
    }

    #[test]
    fn test_tallying_finalizing_no_block() {
        let mut deps = mock_dependencies();
        let mut env = mock_env();

        // Activate BTC staking protocol at height 5.
        let activated_height = 5;
        env.block.height = activated_height + 10 - 1;

        // Index blocks without giving them QCs.
        for i in activated_height..activated_height + 10 {
            insert_indexed_block_at(&mut deps.storage, i);
            give_no_qc_to_height(&mut deps.storage, i);
        }

        // Tally blocks - none should be finalized.
        let events = tally_blocks(&mut deps.as_mut(), &env, activated_height).unwrap();

        // Verify no blocks were finalized.
        for i in activated_height..activated_height + 10 {
            let block = BLOCKS.load(&deps.storage, i).unwrap();
            assert!(!block.finalized);
        }

        assert!(events.is_empty());
    }

    #[test]
    fn test_tallying_finalizing_some_blocks() {
        let mut deps = mock_dependencies();
        let mut env = mock_env();

        let activated_height = 5;
        let num_with_qcs = 3; // First 3 blocks will have QCs
        env.block.height = activated_height + 10 - 1;

        // Index blocks, give some of them QCs
        for i in activated_height..activated_height + 10 {
            insert_indexed_block_at(&mut deps.storage, i);

            if i < activated_height + num_with_qcs {
                give_qc_to_height(&mut deps.storage, i, 3);
            } else {
                give_no_qc_to_height(&mut deps.storage, i);
            }
        }

        let events = tally_blocks(&mut deps.as_mut(), &env, activated_height).unwrap();

        // Verify blocks with QCs were finalized.
        for i in activated_height..activated_height + num_with_qcs {
            let block = BLOCKS.load(&deps.storage, i).unwrap();
            assert!(block.finalized);
        }

        // Verify blocks without QCs were not finalized.
        for i in activated_height + num_with_qcs..activated_height + 10 {
            let block = BLOCKS.load(&deps.storage, i).unwrap();
            assert!(!block.finalized);
        }

        assert_eq!(events.len(), num_with_qcs as usize);
    }

    #[test]
    fn test_tallying_finalizing_at_most_max_finalized_blocks() {
        let mut deps = mock_dependencies();
        let mut env = mock_env();

        let activated_height = 5;
        let limit = 15;
        let num_with_qcs = 80;
        let total_blocks = 150;
        env.block.height = activated_height + total_blocks - 1;

        // Index blocks, give some of them QCs.
        for i in activated_height..activated_height + total_blocks {
            insert_indexed_block_at(&mut deps.storage, i);

            if i < activated_height + num_with_qcs {
                give_qc_to_height(&mut deps.storage, i, 3);
            } else {
                give_no_qc_to_height(&mut deps.storage, i);
            }
        }

        // Verify all blocks are initially not finalized.
        for i in activated_height..activated_height + total_blocks {
            assert!(!BLOCKS.load(&deps.storage, i).unwrap().finalized);
        }

        // Tally blocks with limit - only blocks up to limit should be finalized.
        let events = tally_blocks_with_max_finalized_blocks(
            &mut deps.as_mut(),
            &env,
            activated_height,
            limit,
        )
        .unwrap();

        // Verify only limit blocks were finalized.
        for i in activated_height..activated_height + total_blocks {
            let block = BLOCKS.load(&deps.storage, i).unwrap();
            if i < activated_height + limit {
                assert!(block.finalized);
            } else {
                assert!(!block.finalized);
            }
        }

        // Verify events were generated for finalized blocks.
        assert_eq!(events.len(), limit as usize);

        // Next batch of blocks should be finalized.
        let events2 = tally_blocks_with_max_finalized_blocks(
            &mut deps.as_mut(),
            &env,
            activated_height,
            limit,
        )
        .unwrap();

        // Verify next limit blocks were finalized.
        for i in activated_height + limit..activated_height + total_blocks {
            let block = BLOCKS.load(&deps.storage, i).unwrap();
            if i < activated_height + 2 * limit {
                assert!(block.finalized);
            } else {
                assert!(!block.finalized);
            }
        }

        // Verify events were generated for the second batch.
        assert_eq!(events2.len(), limit as usize);
    }

    #[test]
    fn test_consecutive_finalization() {
        let mut deps = mock_dependencies();
        let mut env = mock_env();

        // Activate BTC staking protocol at height 5.
        let activated_height = 5;
        let num_blocks_to_inspect = 30;
        let first_non_finalized_block = activated_height + 1 + 15; // Block 21 will not be finalized.
        env.block.height = activated_height + num_blocks_to_inspect - 1;

        // Index blocks
        for i in activated_height..activated_height + num_blocks_to_inspect {
            insert_indexed_block_at(&mut deps.storage, i);

            if i == first_non_finalized_block {
                give_no_qc_to_height(&mut deps.storage, i);
            } else {
                give_qc_to_height(&mut deps.storage, i, 3);
            }
        }

        let events = tally_blocks(&mut deps.as_mut(), &env, activated_height).unwrap();

        // All blocks up to firstNonFinalizedBlock must be finalized.
        for i in activated_height..first_non_finalized_block {
            assert!(BLOCKS.load(&deps.storage, i).unwrap().finalized);
        }

        // All blocks from the firstNonFinalizedBlock must not be finalized.
        for i in first_non_finalized_block..activated_height + num_blocks_to_inspect {
            assert!(!BLOCKS.load(&deps.storage, i).unwrap().finalized);
        }

        let expected_finalized = (first_non_finalized_block - activated_height) as usize;
        assert_eq!(events.len(), expected_finalized);
    }

    #[test]
    fn test_tally() {
        let mut power_table = HashMap::new();
        power_table.insert("fp1".to_string(), 10);
        power_table.insert("fp2".to_string(), 10);
        power_table.insert("fp3".to_string(), 10);

        // Test case 1: More than 2/3 voting power.
        let voters = vec!["fp1".to_string(), "fp2".to_string(), "fp3".to_string()];
        assert!(tally(&power_table, &voters), "30/30 > 2/3, should pass");

        // Test case 2: Exactly 2/3 voting power.
        let voters_exact = vec!["fp1".to_string(), "fp2".to_string()];
        assert!(
            !tally(&power_table, &voters_exact),
            "20/30 = 2/3, should fail"
        );

        // Test case 3: Less than 2/3 voting power.
        let voters_less = vec!["fp1".to_string()];
        assert!(
            !tally(&power_table, &voters_less),
            "10/30 < 2/3, should fail"
        );

        // Test case 4: No voters
        assert!(!tally(&power_table, &[]), "0/30 < 2/3, should fail");
    }

    #[test]
    fn test_finalize_block() {
        let mut deps = mock_dependencies();

        let mut block = IndexedBlock {
            height: 100,
            app_hash: gen_random_bytes(100, 32),
            finalized: false,
        };

        let voters = vec!["fp1".to_string(), "fp2".to_string()];

        let event = finalize_block(&mut deps.storage, &mut block, &voters).unwrap();

        assert!(BLOCKS.load(&deps.storage, 100).unwrap().finalized);

        let next_height = NEXT_HEIGHT.load(&deps.storage).unwrap();
        assert_eq!(next_height, 101);

        assert_eq!(event.ty, "finalize_block");
        assert_eq!(event.attributes.len(), 2);
        assert_eq!(event.attributes[0].key, "module");
        assert_eq!(event.attributes[0].value, "finality");
        assert_eq!(event.attributes[1].key, "finalized_height");
        assert_eq!(event.attributes[1].value, "100");
    }
}
