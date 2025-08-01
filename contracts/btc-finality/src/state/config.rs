use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;
use cw_controllers::Admin;
use cw_storage_plus::Item;

pub(crate) const CONFIG: Item<Config> = Item::new("config");
pub(crate) const ADMIN: Admin = Admin::new("admin");

pub const DEFAULT_MAX_ACTIVE_FINALITY_PROVIDERS: u32 = 100;
pub const DEFAULT_MIN_PUB_RAND: u64 = 1;
pub const DEFAULT_REWARD_INTERVAL: u64 = 50;
pub const DEFAULT_MISSED_BLOCKS_WINDOW: u64 = 250;
pub const DEFAULT_JAIL_DURATION: u64 = 86400;

/// Config are Babylon-selectable BTC finality configuration
#[cw_serde]
pub struct Config {
    pub denom: String,
    pub babylon: Addr,
    pub staking: Addr,
    /// Maximum number of active finality providers in the BTC staking protocol.
    pub max_active_finality_providers: u32,
    /// Minimum amount of public randomness each public randomness commitment should commit.
    pub min_pub_rand: u64,
    /// Number of blocks that define the rewards distribution interval
    pub reward_interval: u64,
    /// Missed number of blocks an FP can be jailed for due to offline detection
    pub missed_blocks_window: u64,
    /// Minimum period of time in seconds that a finality provider remains jailed (in case
    /// of being automatically jailed because of offline detection).
    pub jail_duration: u64,
}
