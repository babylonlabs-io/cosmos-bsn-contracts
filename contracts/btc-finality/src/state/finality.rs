use crate::error::ContractError;
use babylon_apis::finality_api::{Evidence, IndexedBlock};
use cosmwasm_std::Order::Ascending;
use cosmwasm_std::{StdResult, Storage, Uint128};
use cw_storage_plus::{Item, Map};
use std::collections::HashMap;

/// Map of signatures by block height and FP
pub const SIGNATURES: Map<(u64, &str), Vec<u8>> = Map::new("fp_sigs");

/// Map of blocks information by height
pub const BLOCKS: Map<u64, IndexedBlock> = Map::new("blocks");

/// Next height to finalise
pub const NEXT_HEIGHT: Item<u64> = Item::new("next_height");

/// `FP_POWER_TABLE` is the map of finality providers to their total active sats at a given height
pub const FP_POWER_TABLE: Map<(u64, &str), u64> = Map::new("fp_power_table");

/// Map of finality providers to block height they initially entered the active set.
/// If an FP isn't in this map, he was not in the active finality provider set,
/// since forever, or since its latest unjailing.
pub const FP_START_HEIGHT: Map<&str, u64> = Map::new("start_height");

/// Map of finality providers to block heights they had last signed a block,
/// since the beginning, or since their last unjailing.
pub const FP_BLOCK_SIGNER: Map<&str, u64> = Map::new("block_signer");

/// Map of jailed FPs to jail expiration time.
/// If an FP doesn't appear in this map, it is not jailed.
/// The value is the time in seconds since UNIX epoch when the FP will be released from jail.
/// If it's zero, the FP will be jailed forever.
pub const JAIL: Map<&str, u64> = Map::new("jail");

/// Map of double signing evidence by FP and block height
pub const EVIDENCES: Map<(&str, u64), Evidence> = Map::new("evidences");

/// Accumulated voting weights for each FP since last reward distribution
/// Maps FP btc_pk_hex to their accumulated voting power across the current reward interval
pub const ACCUMULATED_VOTING_WEIGHTS: Map<&str, u128> = Map::new("accumulated_voting_weights");

pub fn get_power_table_at_height(
    storage: &dyn Storage,
    height: u64,
) -> StdResult<HashMap<String, u64>> {
    FP_POWER_TABLE
        .prefix(height)
        .range(storage, None, None, Ascending)
        .collect::<StdResult<HashMap<String, u64>>>()
}

pub fn get_fp_power(
    storage: &dyn Storage,
    height: u64,
    fp_btc_pk_hex: &str,
) -> Result<u64, ContractError> {
    let power = FP_POWER_TABLE.may_load(storage, (height, fp_btc_pk_hex))?;
    power.ok_or_else(|| ContractError::NoVotingPower(fp_btc_pk_hex.to_string(), height))
}

pub fn get_last_signed_height(
    storage: &dyn Storage,
    fp_btc_pk_hex: &str,
) -> cosmwasm_std::StdResult<Option<u64>> {
    match FP_BLOCK_SIGNER.may_load(storage, fp_btc_pk_hex)? {
        Some(v) => Ok(Some(v)),
        None => {
            // Not a block signer yet, check their start height instead
            FP_START_HEIGHT.may_load(storage, fp_btc_pk_hex)
        }
    }
}

/// Collects all accumulated voting weights and calculates the total in a single iteration
pub fn collect_accumulated_voting_weights(
    storage: &dyn Storage,
) -> cosmwasm_std::StdResult<(Vec<(String, Uint128)>, Uint128)> {
    let mut total_accumulated_weight = Uint128::zero();
    let mut fp_entries = Vec::new();

    for item in
        ACCUMULATED_VOTING_WEIGHTS.range(storage, None, None, cosmwasm_std::Order::Ascending)
    {
        let (fp_btc_pk_hex, weight) = item?;
        let weight_uint128 = Uint128::from(weight);
        total_accumulated_weight = total_accumulated_weight.checked_add(weight_uint128)?;
        fp_entries.push((fp_btc_pk_hex, weight_uint128));
    }

    Ok((fp_entries, total_accumulated_weight))
}
