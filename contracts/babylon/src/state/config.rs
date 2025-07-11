use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;
use cw_storage_plus::Item;

pub(crate) const CONFIG: Item<Config> = Item::new("config");

#[cw_serde]
pub struct Config {
    pub network: btc_light_client::BitcoinNetwork,
    pub babylon_tag: Vec<u8>,
    pub btc_confirmation_depth: u32,
    pub checkpoint_finalization_timeout: u32,
    /// Whether to send Cosmos zone messages notifying BTC-finalised headers.
    /// NOTE: if set to true, then the Cosmos zone needs to integrate the corresponding message
    /// handler as well
    pub notify_cosmos_zone: bool,
    /// If set, this stores a BTC light client contract used for BTC light client on the Consumer
    pub btc_light_client: Option<Addr>,
    /// If set, this stores a BTC staking contract used for BTC re-staking
    pub btc_staking: Option<Addr>,
    /// If set, this stores a BTC finality contract used for BTC finality on the Consumer
    pub btc_finality: Option<Addr>,
    /// Consumer name
    pub consumer_name: Option<String>,
    /// Consumer description
    pub consumer_description: Option<String>,
    pub denom: String,
}
