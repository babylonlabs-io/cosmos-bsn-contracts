use derivative::Derivative;

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Decimal};

use cw_controllers::Admin;
use cw_storage_plus::Item;

pub(crate) const CONFIG: Item<Config> = Item::new("config");
pub(crate) const PARAMS: Item<Params> = Item::new("params");
/// Storage for admin
pub(crate) const ADMIN: Admin = Admin::new("admin");

/// Config are Babylon-selectable BTC finality configuration
#[cw_serde]
pub struct Config {
    pub denom: String,
    pub blocks_per_year: u64,
    pub babylon: Addr,
    pub staking: Addr,
}

#[cw_serde]
#[derive(Derivative)]
#[derivative(Default)]
pub struct Params {
    /// Maximum number of active finality providers in the BTC staking protocol.
    #[derivative(Default(value = "100"))]
    pub max_active_finality_providers: u32,
    /// Minimum amount of public randomness each public randomness commitment should commit.
    #[derivative(Default(value = "1"))]
    pub min_pub_rand: u64,
    /// Inflation rate for finality providers' block rewards.
    #[derivative(Default(value = "Decimal::permille(35)"))] // 3.5 % by default
    pub finality_inflation_rate: Decimal,
    /// Number of blocks that defines an epoch.
    #[derivative(Default(value = "50"))] // 50 * ~6.5s = ~5min
    pub epoch_length: u64,
    /// Missed number of blocks an FP can be jailed for due to offline detection
    #[derivative(Default(value = "250"))]
    pub missed_blocks_window: u64,
    /// Minimum period of time in seconds that a finality provider remains jailed (in case
    /// of being automatically jailed because of offline detection).
    #[derivative(Default(value = "86400"))]
    pub jail_duration: u64,
}
