use btc_light_client::BitcoinNetwork;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::Addr;

use cw_controllers::Admin;
use cw_storage_plus::Item;
use derivative::Derivative;

pub(crate) const CONFIG: Item<Config> = Item::new("config");
pub(crate) const PARAMS: Item<Params> = Item::new("params");
/// Storage for admin
pub(crate) const ADMIN: Admin = Admin::new("admin");

/// Config are Babylon-selectable BTC staking configuration
#[cw_serde]
pub struct Config {
    pub btc_light_client: Addr,
    pub babylon: Addr,
    pub finality: Addr,
    pub denom: String,
}

/// Params define Consumer-selectable BTC staking parameters
#[cw_serde]
#[derive(Derivative)]
#[derivative(Default)]
pub struct Params {
    /// List of public keys held by the covenant committee each PK
    /// follows encoding in BIP-340 spec on Bitcoin
    pub covenant_pks: Vec<String>,
    /// Minimum number of signatures needed for the covenant multi-signature.
    pub covenant_quorum: u32,
    /// Network the BTC staking protocol is running on.
    #[derivative(Default(value = "BitcoinNetwork::Regtest"))]
    pub btc_network: BitcoinNetwork,
    // Chain-wide minimum commission rate that a finality provider can charge their delegators.
    // pub min_commission_rate: Decimal,
    /// Pk script that the slashed BTC goes to, in string format on Bitcoin.
    #[derivative(Default(
        value = "String::from(\"76a914010101010101010101010101010101010101010188ab\")"
    ))]
    pub slashing_pk_script: String,
    /// Minimum amount of tx fee (quantified in Satoshi) needed for the pre-signed slashing tx.
    #[derivative(Default(value = "1000"))]
    pub min_slashing_tx_fee_sat: u64,
    /// Portion of the staked amount to be slashed, expressed as a decimal (e.g. 0.5 for 50%).
    #[derivative(Default(value = "String::from(\"0.1\")"))]
    pub slashing_rate: String,
}

impl Params {
    /// Check if the covenant public key is in the params.covenant_pks
    #[cfg(feature = "full-validation")]
    pub fn contains_covenant_pk(&self, pk: &k256::schnorr::VerifyingKey) -> bool {
        self.covenant_pks.contains(&hex::encode(pk.to_bytes()))
    }

    pub fn slashing_rate(&self) -> Result<f64, std::num::ParseFloatError> {
        self.slashing_rate.parse::<f64>()
    }
}
