use cosmwasm_schema::cw_serde;
use cw_storage_plus::Item;

#[cw_serde]
pub struct Config {
    pub network: crate::state::BitcoinNetwork,
    pub btc_confirmation_depth: u32,
    pub checkpoint_finalization_timeout: u32,
}

pub const CONFIG: Item<Config> = Item::new("config");
