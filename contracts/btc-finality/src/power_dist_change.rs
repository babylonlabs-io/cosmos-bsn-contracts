use crate::contract::encode_smart_query;
use crate::error::ContractError;
use crate::events::{new_finality_provider_status_change_event, FinalityProviderStatus};
use crate::state::config::CONFIG;
use crate::state::finality::{
    get_power_table_at_height, set_voting_power_table, FP_START_HEIGHT, JAIL,
};
use crate::state::public_randomness::{
    get_last_finalized_height, has_timestamped_pub_rand_commit_for_height,
};
use btc_staking::msg::{FinalityProviderInfo, FinalityProvidersByTotalActiveSatsResponse};
use cosmwasm_std::{Addr, DepsMut, Env, QuerierWrapper, Response, StdResult};
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
) -> StdResult<Vec<FinalityProviderInfo>> {
    let query = encode_smart_query(
        staking_addr,
        &btc_staking::msg::QueryMsg::FinalityProvidersByTotalActiveSats { start_after, limit },
    )?;
    let res: FinalityProvidersByTotalActiveSatsResponse = querier.query(&query)?;
    Ok(res.fps)
}
