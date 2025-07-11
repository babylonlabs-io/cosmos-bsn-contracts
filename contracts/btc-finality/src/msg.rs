use cosmwasm_schema::{cw_serde, QueryResponses};
#[cfg(not(target_arch = "wasm32"))]
use {
    crate::state::config::Config, babylon_apis::finality_api::PubRandCommit,
    cw_controllers::AdminResponse,
};

use crate::state::config::Params;
use babylon_apis::finality_api::{Evidence, IndexedBlock};
use btc_staking::msg::FinalityProviderInfo;

#[cw_serde]
#[derive(Default)]
pub struct InstantiateMsg {
    pub params: Option<Params>,
    pub admin: Option<String>,
}

pub type ExecuteMsg = babylon_apis::finality_api::ExecuteMsg;

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    /// Returns the current configuration of the btc-finality contract.
    #[returns(Config)]
    Config {},
    /// Returns the current Consumer-specific parameters of the btc-finality contract.
    #[returns(Params)]
    Params {},
    /// Returns the current admin of the contract.
    #[returns(AdminResponse)]
    Admin {},
    /// Returns the signature of the finality provider for a given block height.
    #[returns(FinalitySignatureResponse)]
    FinalitySignature { btc_pk_hex: String, height: u64 },
    /// Returns the public random commitments for a given FP.
    #[returns(Vec<PubRandCommit>)]
    PubRandCommit {
        /// BTC public key of the finality provider, in hex format.
        btc_pk_hex: String,
        /// Height of to start after (before, if `reverse` is `true`),
        /// or `None` to start from the beginning (end, if `reverse` is `true`).
        start_after: Option<u64>,
        /// Maximum number of commitments to return.
        limit: Option<u32>,
        /// An optional flag to return the commitments in reverse order
        reverse: Option<bool>,
    },
    /// Returns the first public random commitment (if any) for a given FP.
    ///
    /// It's a convenience shortcut of `PubRandCommit` with a `limit` of 1, and `reverse` set to
    /// false.
    #[returns(Option<PubRandCommit>)]
    FirstPubRandCommit {
        /// BTC public key of the finality provider, in hex format.
        btc_pk_hex: String,
    },
    /// `LastPubRandCommit` returns the last public random commitment (if any) for a given FP.
    ///
    /// It's a convenience shortcut of `PubRandCommit` with a `limit` of 1, and `reverse` set to
    /// true.
    #[returns(Option<PubRandCommit>)]
    LastPubRandCommit {
        /// BTC public key of the finality provider, in hex format.
        btc_pk_hex: String,
    },
    /// Returns the indexed block information at height.
    #[returns(IndexedBlock)]
    Block { height: u64 },
    /// Return the list of indexed blocks.
    #[returns(BlocksResponse)]
    Blocks {
        /// Height of the block to start after (before, if `reverse` is `true`),
        /// or `None` to start from the beginning (end, if `reverse` is `true`).
        start_after: Option<u64>,
        /// Maximum number of blocks to return.
        limit: Option<u32>,
        /// An optional filter to return only finalised blocks.
        finalised: Option<bool>,
        /// An optional flag to return the blocks in reverse order
        reverse: Option<bool>,
    },
    /// Returns the evidence for a given FP and block height.
    #[returns(EvidenceResponse)]
    Evidence { btc_pk_hex: String, height: u64 },

    /// Returns the list of jailed finality providers
    #[returns(JailedFinalityProvidersResponse)]
    JailedFinalityProviders {
        start_after: Option<String>,
        limit: Option<u32>,
    },
    /// Returns the set of active finality providers at a given height
    #[returns(ActiveFinalityProvidersResponse)]
    ActiveFinalityProviders { height: u64 },
}

#[cw_serde]
pub struct FinalitySignatureResponse {
    pub signature: Vec<u8>,
}

#[cw_serde]
pub struct BlocksResponse {
    pub blocks: Vec<IndexedBlock>,
}

#[cw_serde]
pub struct EvidenceResponse {
    pub evidence: Option<Evidence>,
}

#[cw_serde]
pub struct JailedFinalityProvidersResponse {
    pub jailed_finality_providers: Vec<JailedFinalityProvider>,
}

#[cw_serde]
pub struct JailedFinalityProvider {
    pub btc_pk_hex: String,
    /// Here zero means 'forever'
    pub jailed_until: u64,
}

#[cw_serde]
pub struct ActiveFinalityProvidersResponse {
    pub active_finality_providers: Vec<FinalityProviderInfo>,
}
