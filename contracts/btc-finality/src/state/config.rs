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
/// TODO: set this to 1 for now, but need to revisit this
pub const DEFAULT_FINALITY_ACTIVATION_HEIGHT: u64 = 1;
pub const DEFAULT_MAX_PUB_RAND_COMMIT_OFFSET: u64 = 1_600_000;

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
    /// Block height at which the finality module will start to accept finality voting
    /// and the minimum allowed value for the public randomness commit start height.
    pub finality_activation_height: u64,
    /// Maximum number of blocks into the future that a public randomness commitment start height can target.
    /// This limit prevents abuse by capping the size of the commitments index, protecting against potential
    /// memory exhaustion or performance degradation caused by excessive future commitments.
    pub max_pub_rand_commit_offset: u64,
}

impl Config {
    #[cfg(test)]
    pub fn new_test(babylon: Addr, staking: Addr) -> Self {
        Self {
            denom: "TOKEN".to_string(),
            babylon,
            staking,
            max_active_finality_providers: DEFAULT_MAX_ACTIVE_FINALITY_PROVIDERS,
            min_pub_rand: DEFAULT_MIN_PUB_RAND,
            reward_interval: DEFAULT_REWARD_INTERVAL,
            missed_blocks_window: DEFAULT_MISSED_BLOCKS_WINDOW,
            jail_duration: DEFAULT_JAIL_DURATION,
            finality_activation_height: DEFAULT_FINALITY_ACTIVATION_HEIGHT,
            max_pub_rand_commit_offset: DEFAULT_MAX_PUB_RAND_COMMIT_OFFSET,
        }
    }
}
