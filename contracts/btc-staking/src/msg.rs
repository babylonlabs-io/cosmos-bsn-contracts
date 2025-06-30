use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{coin, Coin};
#[cfg(not(target_arch = "wasm32"))]
use {
    crate::state::config::Config, babylon_apis::btc_staking_api::ActiveBtcDelegation,
    cw_controllers::AdminResponse,
};

use babylon_apis::btc_staking_api::FinalityProvider;

use crate::state::config::Params;
use crate::state::staking::BtcDelegation;

#[cw_serde]
#[derive(Default)]
pub struct InstantiateMsg {
    pub params: Option<Params>,
    pub admin: Option<String>,
}

pub type ExecuteMsg = babylon_apis::btc_staking_api::ExecuteMsg;

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    /// Returns the current configuration of the btc-staking contract.
    #[returns(Config)]
    Config {},
    /// Returns the current Consumer-specific parameters of the btc-staking contract.
    #[returns(Params)]
    Params {},
    /// Returns the current admin of the contract.
    #[returns(AdminResponse)]
    Admin {},
    /// Returns the finality provider by its BTC public key, in hex format
    #[returns(FinalityProvider)]
    FinalityProvider { btc_pk_hex: String },
    /// Returns the list of registered finality providers
    #[returns(FinalityProvidersResponse)]
    FinalityProviders {
        /// BTC public key of the FP to start after, or `None` to start from the beginning
        start_after: Option<String>,
        limit: Option<u32>,
    },
    /// Returns delegation information by its staking tx hash, in hex format.
    #[returns(ActiveBtcDelegation)]
    Delegation { staking_tx_hash_hex: String },
    /// Return the list of delegations
    #[returns(BtcDelegationsResponse)]
    Delegations {
        /// Staking tx hash (in hex format) of the delegation to start after,
        /// or `None` to start from the beginning.
        start_after: Option<String>,
        /// Maximum number of delegations to return.
        limit: Option<u32>,
        /// An optional filter to return only active delegations
        active: Option<bool>,
    },
    /// Returns the list of staking tx hashes (in hex format) corresponding to
    /// delegations, for a given finality provider.
    ///
    /// The hashes are returned in hex format
    //TODO?: Support pagination
    #[returns(DelegationsByFPResponse)]
    DelegationsByFP {
        /// BTC public key of the finality provider, in hex format.
        btc_pk_hex: String,
    },
    /// Returns the finality provider information by its BTC public key, in hex format.
    /// The information includes the aggregated power of the finality provider.
    #[returns(FinalityProviderInfo)]
    FinalityProviderInfo {
        btc_pk_hex: String,
        /// Optional block height at which the power is being aggregated.
        /// If `height` is not provided, the latest aggregated power is returned
        height: Option<u64>,
    },
    /// Returns the list of finality provider infos sorted by their aggregated power, in descending order.
    #[returns(FinalityProvidersByPowerResponse)]
    FinalityProvidersByPower {
        /// BTC public key of the FP to start after, or `None` to start from the top
        start_after: Option<FinalityProviderInfo>,
        limit: Option<u32>,
    },
    /// Returns the pending rewards for a staker on a finality provider.
    /// The staker address must be its Babylon delegator address.
    /// The rewards are returned in the form of a Coin.
    #[returns(PendingRewardsResponse)]
    PendingRewards {
        staker_addr: String,
        fp_pubkey_hex: String,
    },
    /// Returns the pending rewards for a staker on all finality providers.
    /// The staker address must be its Babylon delegator address.
    #[returns(AllPendingRewardsResponse)]
    AllPendingRewards {
        staker_addr: String,
        start_after: Option<PendingRewards>,
        limit: Option<u32>,
    },
    /// Returns the height at which the contract gets its first delegation, if any.
    #[returns(ActivatedHeightResponse)]
    ActivatedHeight {},
}

#[cw_serde]
pub struct FinalityProvidersResponse {
    pub fps: Vec<FinalityProvider>,
}

#[cw_serde]
pub struct BtcDelegationsResponse {
    pub delegations: Vec<BtcDelegation>,
}

#[cw_serde]
pub struct DelegationsByFPResponse {
    pub hashes: Vec<String>,
}

#[cw_serde]
pub struct FinalityProvidersByPowerResponse {
    pub fps: Vec<FinalityProviderInfo>,
}

#[cw_serde]
pub struct FinalityProviderInfo {
    /// Bitcoin secp256k1 PK of this finality provider.
    /// The PK follows encoding in BIP-340 spec in hex format
    pub btc_pk_hex: String,
    /// Aggregated power of this finality provider.
    /// The power is calculated based on the amount of BTC delegated to this finality provider
    pub power: u64,
}

#[cw_serde]
pub struct ActivatedHeightResponse {
    pub height: u64,
}

/// Pending rewards on one FP
#[cw_serde]
pub struct PendingRewardsResponse {
    pub rewards: Coin,
}

/// Pending rewards on all FPs
#[cw_serde]
pub struct AllPendingRewardsResponse {
    pub rewards: Vec<PendingRewards>,
}

#[cw_serde]
pub struct PendingRewards {
    pub staking_tx_hash: Vec<u8>,
    pub fp_pubkey_hex: String,
    pub rewards: Coin,
}

impl PendingRewards {
    pub fn new(
        staking_tx_hash: &[u8],
        fp_pubkey_hex: impl Into<String>,
        amount: u128,
        denom: impl Into<String>,
    ) -> Self {
        Self {
            fp_pubkey_hex: fp_pubkey_hex.into(),
            staking_tx_hash: staking_tx_hash.into(),
            rewards: coin(amount, denom),
        }
    }
}
