use crate::contract::encode_smart_query;
use crate::error::ContractError;
use crate::state::config::CONFIG;
use crate::state::finality::{
    get_power_table_at_height, set_voting_power_table, FP_START_HEIGHT, JAIL,
};
use crate::state::public_randomness::{
    get_last_finalized_height, has_timestamped_pub_rand_commit_for_height,
};
use btc_staking::msg::{FinalityProviderInfo, FinalityProvidersByTotalActiveSatsResponse};
use cosmwasm_std::{Addr, DepsMut, Env, QuerierWrapper, StdResult};
use std::collections::{HashMap, HashSet};

const QUERY_LIMIT: Option<u32> = Some(30);
pub const JAIL_FOREVER: u64 = 0;

/// Sorts all finality providers, counts the total voting power of top finality providers, and records them
/// in the contract state.
pub fn compute_active_finality_providers(
    deps: &mut DepsMut,
    env: &Env,
    max_active_fps: usize,
) -> Result<(), ContractError> {
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

    // Online FPs verification
    // Store starting heights of fps entering the active set
    let old_power_table = get_power_table_at_height(deps.storage, env.block.height - 1)?;
    let old_fps = old_power_table.keys().collect();
    let cur_fps: HashSet<_> = fp_power_table.keys().collect();
    let new_fps = cur_fps.difference(&old_fps);
    for fp in new_fps {
        // Active since the next block. Only save if not already set
        FP_START_HEIGHT.update(deps.storage, fp, |h| match h {
            Some(h) => Ok::<_, ContractError>(h),
            None => Ok(env.block.height + 1),
        })?;
    }

    // Save the new set of active finality providers
    set_voting_power_table(deps.storage, env.block.height, fp_power_table)?;

    Ok(())
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