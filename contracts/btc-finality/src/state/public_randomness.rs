use crate::error::ContractError;
use crate::state::config::CONFIG;
use babylon_apis::finality_api::PubRandCommit;
use babylon_contract::msg::ConsumerHeightResponse;
use cosmwasm_std::Order::{Ascending, Descending};
use cosmwasm_std::{Deps, StdResult, Storage};
use cw_storage_plus::{Bound, Map};

/// Map of public randomness commitments by fp and block height
pub const PUB_RAND_COMMITS: Map<(&str, u64), PubRandCommit> = Map::new("fp_pub_rand_commit");
/// Map of public randomness values by fp and block height
pub const PUB_RAND_VALUES: Map<(&str, u64), Vec<u8>> = Map::new("fp_pub_rand");

pub fn get_pub_rand_commit_for_height(
    storage: &dyn Storage,
    fp_btc_pk_hex: &str,
    height: u64,
) -> Result<PubRandCommit, ContractError> {
    let end_at = Some(Bound::inclusive(height));
    let res = PUB_RAND_COMMITS
        .prefix(fp_btc_pk_hex)
        .range_raw(storage, None, end_at, Descending)
        .filter(|item| {
            match item {
                Ok((_, value)) => value.in_range(height),
                Err(_) => true, // if we can't parse, we keep it
            }
        })
        .take(1)
        .map(|item| {
            let (_, value) = item?;
            Ok(value)
        })
        .collect::<StdResult<Vec<_>>>()?;

    res.into_iter()
        .next()
        .ok_or_else(|| ContractError::MissingPubRandCommit(fp_btc_pk_hex.to_string(), height))
}

// Finds the public randomness commitment that includes the given height for the given finality provider.
pub fn get_timestamped_pub_rand_commit_for_height(
    deps: &Deps,
    fp_btc_pk_hex: &str,
    height: u64,
) -> Result<PubRandCommit, ContractError> {
    let pr_commit = get_pub_rand_commit_for_height(deps.storage, fp_btc_pk_hex, height)?;

    // Ensure the finality provider's corresponding randomness commitment is already finalised by
    // BTC timestamping
    let finalized_height = get_last_finalized_height(deps)?;
    if finalized_height == 0 {
        return Err(ContractError::PubRandCommitNotBTCTimestamped(
            "No finalized height yet".into(),
        ));
    }
    if finalized_height < pr_commit.height {
        return Err(ContractError::PubRandCommitNotBTCTimestamped(format!(
            "The finality provider {0} last committed height: {1}, last finalized height: {2}",
            fp_btc_pk_hex, pr_commit.height, finalized_height
        )));
    }

    Ok(pr_commit)
}

// Checks that the FP has timestamped public randomness commitment for the given height
// and (optionally given) last finalized height. If the last finalized height is not given,
// it will be queried from the babylon contract.
pub fn has_timestamped_pub_rand_commit_for_height(
    deps: &Deps,
    fp_btc_pk_hex: &str,
    height: u64,
    last_finalized_height: Option<u64>,
) -> bool {
    let pr_commit = match get_pub_rand_commit_for_height(deps.storage, fp_btc_pk_hex, height) {
        Ok(pr_commit) => pr_commit,
        Err(_) => return false,
    };

    // Ensure the finality provider's corresponding randomness commitment is already finalised by
    // BTC timestamping
    let finalized_height =
        last_finalized_height.unwrap_or(get_last_finalized_height(deps).unwrap_or(0));

    finalized_height >= pr_commit.height
}

pub fn get_first_pub_rand_commit(
    storage: &dyn Storage,
    fp_btc_pk_hex: &str,
) -> Result<Option<PubRandCommit>, ContractError> {
    let res = get_pub_rand_commit(storage, fp_btc_pk_hex, None, Some(1), Some(false))?;
    Ok(res.into_iter().next())
}

pub fn get_last_pub_rand_commit(
    storage: &dyn Storage,
    fp_btc_pk_hex: &str,
) -> Result<Option<PubRandCommit>, ContractError> {
    let res = get_pub_rand_commit(storage, fp_btc_pk_hex, None, Some(1), Some(true))?;
    Ok(res.into_iter().next())
}

pub fn get_last_finalized_height(deps: &Deps) -> Result<u64, ContractError> {
    let cfg = CONFIG.load(deps.storage)?;
    // Query the last finalized height of this Consumer from the babylon contract
    let last_consumer_height: ConsumerHeightResponse = deps.querier.query_wasm_smart(
        cfg.babylon,
        &babylon_contract::msg::QueryMsg::LastConsumerHeight {},
    )?;

    Ok(last_consumer_height.height)
}

// Settings for pagination
const MAX_LIMIT: u32 = 30;
const DEFAULT_LIMIT: u32 = 10;

pub fn get_pub_rand_commit(
    storage: &dyn Storage,
    fp_btc_pk_hex: &str,
    start_after: Option<u64>,
    limit: Option<u32>,
    reverse: Option<bool>,
) -> Result<Vec<PubRandCommit>, ContractError> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
    let start_after = start_after.map(Bound::exclusive);
    let (start, end, order) = if reverse.unwrap_or(false) {
        (None, start_after, Descending)
    } else {
        (start_after, None, Ascending)
    };
    let res = PUB_RAND_COMMITS
        .prefix(fp_btc_pk_hex)
        .range_raw(storage, start, end, order)
        .take(limit)
        .map(|item| {
            let (_, value) = item?;
            Ok(value)
        })
        .collect::<StdResult<Vec<_>>>()?;

    // Return the results or an empty vector if no results found
    Ok(res)
}
