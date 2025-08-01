use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;
use cw_controllers::Admin;
use cw_storage_plus::Item;

pub(crate) const CONFIG: Item<Config> = Item::new("config");
pub(crate) const ADMIN: Admin = Admin::new("admin");

/// Config are Babylon-selectable BTC staking configuration
#[cw_serde]
pub struct Config {
    pub btc_light_client: Addr,
    pub babylon: Addr,
    pub finality: Addr,
    pub denom: String,
}
