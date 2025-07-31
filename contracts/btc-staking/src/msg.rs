use cosmwasm_schema::{cw_serde, QueryResponses};
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
    /// Returns the list of finality provider infos sorted by their total active sats, in descending order.
    #[returns(FinalityProvidersByTotalActiveSatsResponse)]
    FinalityProvidersByTotalActiveSats {
        /// BTC public key of the FP to start after, or `None` to start from the top
        start_after: Option<FinalityProviderInfo>,
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
pub struct FinalityProvidersByTotalActiveSatsResponse {
    pub fps: Vec<FinalityProviderInfo>,
}

#[cw_serde]
pub struct FinalityProviderInfo {
    /// Bitcoin secp256k1 PK of this finality provider.
    /// The PK follows encoding in BIP-340 spec in hex format
    pub btc_pk_hex: String,
    /// Total active sats delegated to this finality provider
    pub total_active_sats: u64,
    /// Whether this finality provider is slashed
    pub slashed: bool,
}

#[cw_serde]
pub struct ActivatedHeightResponse {
    pub height: u64,
}
