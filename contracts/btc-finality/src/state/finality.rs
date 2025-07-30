use cosmwasm_std::Uint128;

use cw_storage_plus::{Item, Map};

use babylon_apis::finality_api::{Evidence, IndexedBlock};
use btc_staking::msg::FinalityProviderInfo;

/// Map of signatures by block height and FP
pub const SIGNATURES: Map<(u64, &str), Vec<u8>> = Map::new("fp_sigs");

/// Map of blocks information by height
pub const BLOCKS: Map<u64, IndexedBlock> = Map::new("blocks");

/// Next height to finalise
pub const NEXT_HEIGHT: Item<u64> = Item::new("next_height");

/// `FP_SET` is the calculated list of the active finality providers by height
pub const FP_SET: Map<u64, Vec<FinalityProviderInfo>> = Map::new("fp_set");

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
pub const TOTAL_REWARDS: Item<Uint128> = Item::new("total_rewards");
