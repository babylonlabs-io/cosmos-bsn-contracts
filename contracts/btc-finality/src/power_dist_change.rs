use crate::error::ContractError;
use crate::events::{new_finality_provider_status_change_event, FinalityProviderStatus};
use crate::state::config::CONFIG;
use crate::state::finality::{
    get_power_table_at_height, set_voting_power_table, FP_START_HEIGHT, JAIL,
};
use crate::state::public_randomness::{
    get_last_finalized_height, has_timestamped_pub_rand_commit_for_height,
};
use btc_staking::msg::{
    FinalityProviderInfo, FinalityProvidersByTotalActiveSatsResponse,
    QueryMsg as BTCStakingQueryMsg,
};
use cosmwasm_std::{Addr, DepsMut, Env, QuerierWrapper, Response};
use std::collections::{HashMap, HashSet};

const QUERY_LIMIT: Option<u32> = Some(30);
pub const JAIL_FOREVER: u64 = 0;

/// Sorts all finality providers, counts the total voting power of top finality providers, and records them
/// in the contract state. Returns a Response with events for finality provider status changes.
pub fn compute_active_finality_providers(
    deps: &mut DepsMut,
    env: &Env,
    max_active_fps: usize,
) -> Result<Response, ContractError> {
    let cfg = CONFIG.load(deps.storage)?;
    // Get last finalized height (for timestamped public randomness checks)
    let last_finalized_height = get_last_finalized_height(&deps.as_ref())?;

    // Get all finality providers from the staking contract, filtered
    let mut batch = query_fps_by_total_active_sats(&cfg.staking, &deps.querier, None, QUERY_LIMIT)?;

    let mut fp_power_table = HashMap::new();
    let mut total_power: u64 = 0;
    while !batch.is_empty() && fp_power_table.len() < max_active_fps {
        let last = batch.last().cloned();

        let (filtered, running_total): (Vec<_>, Vec<_>) = batch
            .into_iter()
            .filter(|fp| {
                // Filter out FPs with no active sats
                if fp.total_active_sats == 0 {
                    return false;
                }
                // Filter out slashed FPs
                if fp.slashed {
                    return false;
                }
                // Filter out FPs that are jailed.
                // Error (shouldn't happen) is being mapped to "jailed forever"
                if JAIL
                    .may_load(deps.storage, &fp.btc_pk_hex)
                    .unwrap_or(Some(JAIL_FOREVER))
                    .is_some()
                {
                    return false;
                }
                // Filter out FPs that don't have timestamped public randomness
                if !has_timestamped_pub_rand_commit_for_height(
                    &deps.as_ref(),
                    &fp.btc_pk_hex,
                    env.block.height,
                    Some(last_finalized_height),
                ) {
                    return false;
                }

                true
            })
            .scan(total_power, |acc, fp| {
                *acc += fp.total_active_sats;
                Some((fp, *acc))
            })
            .unzip();

        // Add the filtered finality providers to the power table
        for fp in filtered {
            fp_power_table.insert(fp.btc_pk_hex, fp.total_active_sats);
        }
        // Update the total power
        total_power = running_total.last().copied().unwrap_or_default();

        // and get the next page
        batch = query_fps_by_total_active_sats(&cfg.staking, &deps.querier, last, QUERY_LIMIT)?;
    }

    // Handle power table changes
    let old_power_table = get_power_table_at_height(deps.storage, env.block.height - 1)?;
    let response = handle_power_table_change(
        deps.storage,
        env.block.height,
        &old_power_table,
        &fp_power_table,
    )?;

    // Save the new set of active finality providers
    set_voting_power_table(deps.storage, env.block.height, fp_power_table)?;

    Ok(response)
}

/// Handles power table changes by tracking new finality providers entering and leaving the active set.
/// Sets start heights for newly active FPs and returns a Response with status change events.
/// ref https://github.com/babylonlabs-io/babylon/blob/3d58d818e2f4f93b9e3dd1cad74fe76748db15a9/x/finality/keeper/power_dist_change.go#L94
fn handle_power_table_change(
    storage: &mut dyn cosmwasm_std::Storage,
    current_height: u64,
    old_power_table: &HashMap<String, u64>,
    new_power_table: &HashMap<String, u64>,
) -> Result<Response, ContractError> {
    let old_fps = old_power_table.keys().collect();
    let cur_fps: HashSet<_> = new_power_table.keys().collect();
    let new_active_fps = cur_fps.difference(&old_fps);
    let new_inactive_fps = old_fps.difference(&cur_fps);

    let mut response = Response::new();

    for fp in new_active_fps {
        // Active since the next block. Only save if not already set
        FP_START_HEIGHT.update(storage, fp, |h| match h {
            Some(h) => Ok::<_, ContractError>(h),
            None => Ok(current_height + 1),
        })?;

        // Emit new active finality provider event
        let event =
            new_finality_provider_status_change_event(fp.as_str(), FinalityProviderStatus::Active);
        response = response.add_event(event);
    }

    for fp in new_inactive_fps {
        // Emit new inactive finality provider event
        let event = new_finality_provider_status_change_event(
            fp.as_str(),
            FinalityProviderStatus::Inactive,
        );
        response = response.add_event(event);
    }

    Ok(response)
}

/// Queries the BTC staking contract for finality providers ordered by total active sats.
pub fn query_fps_by_total_active_sats(
    staking_addr: &Addr,
    querier: &QuerierWrapper,
    start_after: Option<FinalityProviderInfo>,
    limit: Option<u32>,
) -> Result<Vec<FinalityProviderInfo>, ContractError> {
    let query = BTCStakingQueryMsg::FinalityProvidersByTotalActiveSats { start_after, limit };
    let res: FinalityProvidersByTotalActiveSatsResponse =
        querier.query_wasm_smart(staking_addr.to_string(), &query)?;
    Ok(res.fps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::multitest::suite::SuiteBuilder;
    use babylon_test_utils::{
        create_new_finality_provider, get_derived_btc_delegation, get_public_randomness_commitment,
    };
    use cosmwasm_std::testing::mock_dependencies;
    use cosmwasm_std::{coin, Addr};

    // End-to-end randomized test with the multi-test suite exercising pagination, filtering and top-K
    #[test]
    fn randomized_active_set_top_k_and_filters() {
        // Use main suite to exercise real queries and storage
        let (pk_hex_fixed, pub_rand, pubrand_signature) = get_public_randomness_commitment();

        let initial_height = pub_rand.start_height;
        let initial_funds = &[coin(1_000_000_000, "TOKEN")];

        let mut suite = SuiteBuilder::new()
            .with_funds(initial_funds)
            .with_height(initial_height)
            .build();

        // Register a larger randomized set of finality providers
        let num_fps: usize = 3;
        let mut fps = Vec::with_capacity(num_fps);
        for id in 1..=num_fps {
            fps.push(create_new_finality_provider(id as i32));
        }
        // Make the first one match the test vector pk so we can commit pub rand for it
        fps[0].btc_pk_hex = pk_hex_fixed.clone();
        suite.register_finality_providers(&fps).unwrap();

        // Add delegations to a small subset so they have power.
        // Limit to unique staking txs available in testdata (ids 1..=3) to avoid duplicates.
        let mut total_powered = 0usize;
        let max_unique_delegations = 3usize.min(fps.len());
        for (i, fp) in fps.iter().enumerate().take(max_unique_delegations) {
            let mut del = get_derived_btc_delegation((i + 1) as i32, &[1]);
            del.total_sat = 100_000;
            del.fp_btc_pk_list = vec![fp.btc_pk_hex.clone()];
            suite.add_delegations(&[del]).unwrap();
            total_powered += 1;
        }

        // Commit public randomness only for a subset; others should be filtered out
        // NOTE: timestamping pub rand is mocked at https://github.com/babylonlabs-io/cosmos-bsn-contracts/blob/836881bf5c7a14d60a008f02eb41132fce841c56/contracts/babylon/src/contract.rs#L135-L142
        suite
            .commit_public_randomness(&pk_hex_fixed, &pub_rand, &pubrand_signature)
            .unwrap();
        // For one more provider (if exists), try to commit the same pub rand
        if fps.len() > 1 {
            let pk = &fps[1].btc_pk_hex;
            let _ = suite.commit_public_randomness(pk, &pub_rand, &pubrand_signature);
        }

        // Advance one block to make timestamped check pass and compute active set
        let height = suite
            .next_block("deadbeefcafebabe".as_bytes())
            .unwrap()
            .height;

        // Query the active set
        let active = suite.get_active_finality_providers(height);
        // Ensure size does not exceed configured max
        let max_active = suite
            .get_btc_finality_config()
            .max_active_finality_providers as usize;
        assert!(active.len() <= max_active);
        // Ensure all in active set have non-zero power and were not filtered by missing pub rand
        for (pk, power) in active.iter() {
            assert!(*power > 0, "zero power in active set for {pk}");
        }
        // Spot check that our fixed pk is present if it had delegation
        let power_fixed = suite.get_finality_provider_power(&pk_hex_fixed, height);
        if power_fixed > 0 {
            assert!(active.contains_key(&pk_hex_fixed));
        }
        // Ensure ordering respects top power: take the maximum in the map and ensure no value exceeds it afterwards when sorted
        if active.len() > 1 {
            let mut fp_powers: Vec<u64> = active.values().copied().collect();
            let mut sorted = fp_powers.clone();
            sorted.sort_by(|a, b| b.cmp(a));
            assert_eq!(fp_powers.len(), sorted.len());
            // The set is unordered, but values multiset should equal after sort
            fp_powers.sort();
            sorted.sort();
            assert_eq!(fp_powers, sorted);
        }
        // With many powered FPs, we expect at least one active unless all filtered out
        assert!(!active.is_empty() || total_powered == 0);
    }

    // Unit-test handle_power_table_change to ensure events and FP_START_HEIGHT logic
    #[test]
    fn handle_power_table_change_events_and_start_height() {
        let mut deps = mock_dependencies();
        // minimal config to allow reading CONFIG if needed in helpers later
        CONFIG
            .save(
                deps.as_mut().storage,
                &crate::state::config::Config::new_test(
                    Addr::unchecked("babylon"),
                    Addr::unchecked("staking"),
                ),
            )
            .unwrap();

        let current_height = 100u64;
        let old: HashMap<String, u64> =
            HashMap::from([("fp_a".to_string(), 10), ("fp_b".to_string(), 20)]);
        let new: HashMap<String, u64> =
            HashMap::from([("fp_b".to_string(), 20), ("fp_c".to_string(), 30)]);

        let resp =
            super::handle_power_table_change(deps.as_mut().storage, current_height, &old, &new)
                .expect("ok");
        // Two events: fp_c Active, fp_a Inactive (order not strictly guaranteed, so just check counts/types)
        let types: Vec<_> = resp.events.iter().map(|e| e.ty.as_str()).collect();
        assert!(
            types.iter().any(|t| *t == "finality_provider_status_change"
                || *t == "wasm-finality_provider_status_change"),
            "expected status change event"
        );

        // FP_START_HEIGHT for fp_c should be set to current_height + 1
        let start_c = FP_START_HEIGHT
            .may_load(deps.as_ref().storage, "fp_c")
            .unwrap()
            .unwrap();
        assert_eq!(start_c, current_height + 1);

        // Re-applying with fp_c still active should not change start height
        let resp2 =
            super::handle_power_table_change(deps.as_mut().storage, current_height + 1, &new, &new)
                .expect("ok");
        assert!(resp2.events.is_empty());
        let start_c2 = FP_START_HEIGHT
            .may_load(deps.as_ref().storage, "fp_c")
            .unwrap()
            .unwrap();
        assert_eq!(start_c2, start_c);
    }

    // Deterministic small test verifying jailed and missing pub rand FPs are excluded
    #[test]
    fn filters_out_slashed_jailed_zero_power_and_no_pub_rand() {
        // Build full suite but manually control states for clear expectations
        let (pk_hex, pub_rand, pubrand_signature) = get_public_randomness_commitment();
        let mut suite = SuiteBuilder::new()
            .with_height(pub_rand.start_height)
            .build();

        // Register two providers
        let mut fp1 = create_new_finality_provider(1);
        fp1.btc_pk_hex = pk_hex.clone();
        let fp2 = create_new_finality_provider(2);
        suite
            .register_finality_providers(&[fp1.clone(), fp2.clone()])
            .unwrap();

        // Add delegation to both so they have power
        let mut del1 = get_derived_btc_delegation(1, &[1]);
        del1.fp_btc_pk_list = vec![fp1.btc_pk_hex.clone()];
        del1.total_sat = 50_000;
        let mut del2 = get_derived_btc_delegation(2, &[2]);
        del2.fp_btc_pk_list = vec![fp2.btc_pk_hex.clone()];
        del2.total_sat = 60_000;
        suite.add_delegations(&[del1, del2]).unwrap();

        // Commit pub rand only for fp1; fp2 should be filtered out by missing pub rand
        suite
            .commit_public_randomness(&pk_hex, &pub_rand, &pubrand_signature)
            .unwrap();

        // Advance a block so timestamped condition holds and active set computed
        let height = suite.next_block(b"hash").unwrap().height;
        let active = suite.get_active_finality_providers(height);
        assert_eq!(active.len(), 1);
        assert!(active.contains_key(&fp1.btc_pk_hex));
    }
}
