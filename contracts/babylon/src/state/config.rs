use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;
use cw_storage_plus::Item;

pub const DEFAULT_IBC_PACKET_TIMEOUT_DAYS: u64 = 28; // 28 days

pub(crate) const CONFIG: Item<Config> = Item::new("config");

#[cw_serde]
pub struct Config {
    pub network: btc_light_client::BitcoinNetwork,
    pub btc_confirmation_depth: u32,
    pub checkpoint_finalization_timeout: u32,
    /// If set, this stores the address of the BTC light client contract on the Consumer.
    pub btc_light_client: Option<Addr>,
    /// If set, this stores a BTC staking contract used for BTC re-staking
    pub btc_staking: Option<Addr>,
    /// If set, this stores a BTC finality contract used for BTC finality on the Consumer
    pub btc_finality: Option<Addr>,
    /// Consumer name
    pub consumer_name: String,
    /// Consumer description
    pub consumer_description: String,
    pub denom: String,
    /// IBC packet timeout in days
    pub ibc_packet_timeout_days: u64,
    /// Babylon module name for receiving ICS-20 transfers
    pub destination_module: String,
}
