//! This module includes custom messages that the Babylon contract will send to the Cosmos zone.
//! The messages include:
//! - ForkHeader: reporting a fork that has a valid quorum certificate
//! - FinalizedHeader: reporting a BTC-finalised header.

use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Coin, CosmosMsg, Empty};

/// Message that the Babylon contract can send to the Cosmos zone.
/// The Cosmos zone has to integrate https://github.com/babylonlabs-io/wasmbinding for
/// handling these messages
#[cw_serde]
pub enum BabylonMsg {
    /// Mints the requested block rewards for the finality providers.
    /// It can only be sent from the finality contract.
    /// The rewards are minted to the staking contract address, so that they
    /// can be distributed across the active finality provider set
    MintRewards { amount: Coin, recipient: String },
}

pub type BabylonSudoMsg = Empty;
pub type BabylonQuery = Empty;

// make BabylonMsg to implement CosmosMsg::CustomMsg
impl cosmwasm_std::CustomMsg for BabylonMsg {}

impl From<BabylonMsg> for CosmosMsg<BabylonMsg> {
    fn from(original: BabylonMsg) -> Self {
        CosmosMsg::Custom(original)
    }
}
