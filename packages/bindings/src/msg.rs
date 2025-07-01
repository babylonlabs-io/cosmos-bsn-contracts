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
    /// Reports a BTC-finalised header
    /// can be used for many use cases, notably unbonding mature validators/delegations till this header
    FinalizedHeader {
        height: i64,
        time: i64, // NOTE: UNIX timestamp is in i64
    },
    /// Mints the requested block rewards for the finality providers.
    /// It can only be sent from the finality contract.
    /// The rewards are minted to the staking contract address, so that they
    /// can be distributed across the active finality provider set
    MintRewards { amount: Coin, recipient: String },
    /// Message that the Babylon contract sends to Babylon
    /// to notify it of consumer chain slashing.
    EquivocationEvidence {
        /// Address submitting the evidence
        signer: String,
        /// BTC PK of the finality provider that casts this vote
        fp_btc_pk: Vec<u8>,
        /// Height of the conflicting blocks
        block_height: u64,
        /// Public randomness the finality provider has committed to.
        /// Deserializes to `SchnorrPubRand`
        pub_rand: Vec<u8>,
        /// AppHash of the canonical block
        canonical_app_hash: Vec<u8>,
        /// AppHash of the fork block
        fork_app_hash: Vec<u8>,
        /// Finality signature to the canonical block,
        /// where finality signature is an EOTS signature, i.e.,
        /// the `s` in a Schnorr signature `(r, s)`.
        /// `r` is the public randomness already committed by the finality provider.
        /// Deserializes to `SchnorrEOTSSig`
        canonical_finality_sig: Vec<u8>,
        /// Finality signature to the fork block,
        /// where finality signature is an EOTS signature.
        /// Deserializes to `SchnorrEOTSSig`
        fork_finality_sig: Vec<u8>,
    },
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
