pub mod btc_light_client;
pub mod config;

use bitcoin::params::Params;
pub use btc_light_client::{get_base_header, get_header, get_header_by_hash, get_headers, get_tip};
pub use config::{Config, CONFIG};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// we re-implement the enum here since `rust-bitcoin`'s enum implementation
// does not implement the trait `JsonSchema`.
#[derive(Serialize, Deserialize, Copy, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BitcoinNetwork {
    Mainnet,
    Testnet,
    Signet,
    Regtest,
}

impl BitcoinNetwork {
    pub fn bitcoin_network(&self) -> bitcoin::Network {
        match self {
            Self::Mainnet => bitcoin::Network::Bitcoin,
            Self::Testnet => bitcoin::Network::Testnet,
            Self::Signet => bitcoin::Network::Signet,
            Self::Regtest => bitcoin::Network::Regtest,
        }
    }

    pub fn chain_params(&self) -> Params {
        match self {
            Self::Mainnet => Params::new(bitcoin::Network::Bitcoin),
            Self::Testnet => Params::new(bitcoin::Network::Testnet),
            Self::Signet => Params::new(bitcoin::Network::Signet),
            Self::Regtest => Params::new(bitcoin::Network::Regtest),
        }
    }
}
