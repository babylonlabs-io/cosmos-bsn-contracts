use crate::error::ContractError;
use babylon_apis::finality_api::{Evidence, IndexedBlock};
use cosmwasm_std::Order::Ascending;
use cosmwasm_std::Uint128;
use cosmwasm_std::{StdResult, Storage};
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

/// Map of pending finality provider rewards
pub const REWARDS: Map<&str, Uint128> = Map::new("rewards");

/// Total pending rewards
pub const TOTAL_PENDING_REWARDS: Item<Uint128> = Item::new("pending_rewards");

pub fn get_power_table_at_height(
    storage: &dyn Storage,
    height: u64,
) -> StdResult<HashMap<String, u64>> {
    FP_POWER_TABLE
        .prefix(height)
        .range(storage, None, None, Ascending)
        .collect::<StdResult<HashMap<String, u64>>>()
}

pub fn ensure_fp_has_power(
    storage: &mut dyn Storage,
    height: u64,
    fp_btc_pk_hex: &str,
) -> Result<(), ContractError> {
    let power = FP_POWER_TABLE.may_load(storage, (height, fp_btc_pk_hex))?;
    if power.is_none() {
        return Err(ContractError::NoVotingPower(
            fp_btc_pk_hex.to_string(),
            height,
        ));
    }
    Ok(())
}

pub fn get_last_signed_height(
    storage: &dyn Storage,
    fp_btc_pk_hex: &str,
) -> cosmwasm_std::StdResult<Option<u64>> {
    let mut last_sign_height = FP_BLOCK_SIGNER.may_load(storage, fp_btc_pk_hex)?;
    if last_sign_height.is_none() {
        // Not a block signer yet, check their start height instead
        last_sign_height = FP_START_HEIGHT.may_load(storage, fp_btc_pk_hex)?;
    }

    Ok(last_sign_height)
}
