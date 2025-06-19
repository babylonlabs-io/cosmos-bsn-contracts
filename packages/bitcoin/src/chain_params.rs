pub use bitcoin::consensus::Params;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

// we re-implement the enum here since `rust-bitcoin`'s enum implementation
// does not have `#[derive(Serialize, Deserialize)]
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Network {
    Mainnet,
    Testnet,
    Signet,
    Regtest,
}

impl Network {
    pub fn chain_params(&self) -> Params {
        match self {
            Self::Mainnet => Params::new(bitcoin::Network::Bitcoin),
            Self::Testnet => Params::new(bitcoin::Network::Testnet),
            Self::Signet => Params::new(bitcoin::Network::Signet),
            Self::Regtest => Params::new(bitcoin::Network::Regtest),
        }
    }

    pub fn bitcoin_network(&self) -> bitcoin::Network {
        match self {
            Self::Mainnet => bitcoin::Network::Bitcoin,
            Self::Testnet => bitcoin::Network::Testnet,
            Self::Signet => bitcoin::Network::Signet,
            Self::Regtest => bitcoin::Network::Regtest,
        }
    }
}
