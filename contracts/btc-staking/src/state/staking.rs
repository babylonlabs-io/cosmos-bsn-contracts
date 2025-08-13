use crate::error::ContractError;
use crate::state::fp_index::FinalityProviderIndexes;
use babylon_apis::btc_staking_api::{BTCDelegationStatus, FinalityProvider, HASH_SIZE};
use babylon_apis::{btc_staking_api, Bytes};
use cosmwasm_schema::cw_serde;
use cw_storage_plus::{IndexedSnapshotMap, Map, MultiIndex, Strategy};
use k256::schnorr::SigningKey;

/// Finality providers by their BTC public key
pub(crate) const FPS: Map<&str, FinalityProvider> = Map::new("fps");

/// TODO: Replace with IndexedMap for better efficiency (#126 follow-up)
/// This current implementation stores all delegation hashes for a height in a single Vec,
/// which becomes inefficient as the number of delegations per height grows.
/// A better approach would be to use an IndexedMap with a MultiIndex on end_height,
/// allowing more efficient queries and updates without loading the entire vector.
///
/// Maps a BTC height to a list of staking transaction hashes that expire at that height
pub const BTC_DELEGATION_EXPIRY_INDEX: Map<u32, Vec<[u8; HASH_SIZE]>> =
    Map::new("btc_delegation_expiry_index");

/// Btc Delegations info, by staking tx hash
pub(crate) const BTC_DELEGATIONS: Map<&[u8; HASH_SIZE], BtcDelegation> =
    Map::new("btc_delegations");

/// Map of staking hashes by finality provider
// TODO: Remove and use the delegations() map instead (related to #123)
pub(crate) const FP_DELEGATIONS: Map<&str, Vec<Vec<u8>>> = Map::new("fp_delegations");

/// Reverse map of finality providers by staking hash
// TODO: Remove and use the delegations() reverse index instead (related to #123)
pub(crate) const DELEGATION_FPS: Map<&[u8; HASH_SIZE], Vec<String>> = Map::new("delegation_fps");

pub const FP_STATE_KEY: &str = "fp_state";
const FP_STATE_CHECKPOINTS: &str = "fp_state__checkpoints";
const FP_STATE_CHANGELOG: &str = "fp_state__changelog";
pub const FP_POWER_KEY: &str = "fp_state__power";

/// Indexed snapshot map for finality providers.
///
/// This allows querying the map finality providers, sorted by their (aggregated) power.
/// The power index is a `MultiIndex`, as there can be multiple FPs with the same power.
///
/// The indexes are not snapshotted; only the current power is indexed at any given time.
pub fn get_fp_state_map<'a>(
) -> IndexedSnapshotMap<&'a str, FinalityProviderState, FinalityProviderIndexes<'a>> {
    let indexes = FinalityProviderIndexes {
        power: MultiIndex::new(
            |_, fp_state| fp_state.total_active_sats,
            FP_STATE_KEY,
            FP_POWER_KEY,
        ),
    };
    IndexedSnapshotMap::new(
        FP_STATE_KEY,
        FP_STATE_CHECKPOINTS,
        FP_STATE_CHANGELOG,
        Strategy::EveryBlock,
        indexes,
    )
}

#[cw_serde]
#[derive(Default)]
pub struct FinalityProviderState {
    /// Total active sats delegated to this finality provider
    pub total_active_sats: u64,
    /// Whether this finality provider is slashed
    pub slashed: bool,
}

#[cw_serde]
pub struct BtcDelegation {
    /// Address to receive rewards from BTC delegation.
    pub staker_addr: String,
    /// Bitcoin secp256k1 PK of the BTC delegator.
    /// The PK follows encoding in BIP-340 spec in hex format
    pub btc_pk_hex: String,
    /// List of BIP-340 PKs of the finality providers that this BTC delegation delegates to.
    pub fp_btc_pk_list: Vec<String>,
    /// Start height of the BTC delegation.
    /// It is the start BTC height of the time-lock
    pub start_height: u32,
    /// End height of the BTC delegation.
    /// It is the end BTC height of the time-lock - w
    pub end_height: u32,
    /// Total BTC stakes in this delegation, quantified in satoshi.
    pub total_sat: u64,
    /// Staking tx in raw bytes.
    pub staking_tx: Bytes,
    /// Slashing tx in raw bytes.
    pub slashing_tx: Bytes,
    /// Signature on the slashing tx by the delegator (i.e. SK corresponding to btc_pk) as string hex.
    /// It will be a part of the witness for the staking tx output.
    pub delegator_slashing_sig: Bytes,
    /// List of adaptor signatures on the slashing tx by each covenant member.
    /// It will be a part of the witness for the staking tx output.
    pub covenant_sigs: Vec<CovenantAdaptorSignatures>,
    /// Index of the staking output in the staking tx
    pub staking_output_idx: u32,
    /// unbonding_time is used in unbonding output time-lock path and in slashing transactions
    /// change outputs
    pub unbonding_time: u32,
    /// Undelegation info of this delegation.
    pub undelegation_info: BtcUndelegationInfo,
    /// Params version used to validate the delegation.
    pub params_version: u32,
}

impl BtcDelegation {
    pub fn is_active(&self) -> bool {
        // TODO: Implement full delegation status checks (needs BTC height) (related to #7.2)
        // self.get_status(btc_height, w) == BTCDelegationStatus::ACTIVE
        !self.is_unbonded_early()
    }

    fn is_unbonded_early(&self) -> bool {
        self.undelegation_info.delegator_unbonding_info.is_some()
    }

    pub fn get_status(&self, btc_height: u32, w: u32) -> BTCDelegationStatus {
        // Manually unbonded, staking tx time-lock has not begun, is less than w BTC blocks left, or
        // has expired
        if self.is_unbonded_early()
            || btc_height < self.start_height
            || btc_height + w > self.end_height
        {
            BTCDelegationStatus::UNBONDED
        } else {
            // At this point, the BTC delegation has an active time-lock, and Babylon is not aware of
            // an unbonding tx with the delegator's signature
            BTCDelegationStatus::ACTIVE
        }
    }

    /// Checks whether the given signing key corresponds to any finality provider the staker has
    /// delegated to.
    pub fn matches_delegated_fp(&self, fp_sk_hex: &str) -> Result<bool, ContractError> {
        let fp_sk = SigningKey::from_bytes(&hex::decode(fp_sk_hex)?)?;

        // calculate the corresponding VerifyingKey
        let fp_pk = fp_sk.verifying_key();
        let fp_pk_hex = hex::encode(fp_pk.to_bytes());

        Ok(self.fp_btc_pk_list.contains(&fp_pk_hex))
    }
}

impl From<btc_staking_api::ActiveBtcDelegation> for BtcDelegation {
    fn from(active_delegation: btc_staking_api::ActiveBtcDelegation) -> Self {
        BtcDelegation {
            staker_addr: active_delegation.staker_addr,
            btc_pk_hex: active_delegation.btc_pk_hex,
            fp_btc_pk_list: active_delegation.fp_btc_pk_list,
            start_height: active_delegation.start_height,
            end_height: active_delegation.end_height,
            total_sat: active_delegation.total_sat,
            staking_tx: active_delegation.staking_tx.to_vec(),
            slashing_tx: active_delegation.slashing_tx.to_vec(),
            delegator_slashing_sig: active_delegation.delegator_slashing_sig.to_vec(),
            covenant_sigs: active_delegation
                .covenant_sigs
                .into_iter()
                .map(|sig| sig.into())
                .collect(),
            staking_output_idx: active_delegation.staking_output_idx,
            unbonding_time: active_delegation.unbonding_time,
            undelegation_info: active_delegation.undelegation_info.into(),
            params_version: active_delegation.params_version,
        }
    }
}

impl From<&btc_staking_api::ActiveBtcDelegation> for BtcDelegation {
    fn from(active_delegation: &btc_staking_api::ActiveBtcDelegation) -> Self {
        BtcDelegation::from(active_delegation.clone())
    }
}

#[cw_serde]
pub struct CovenantAdaptorSignatures {
    /// cov_pk is the public key of the covenant emulator, used as the public key of the adaptor signature
    pub cov_pk: Bytes,
    /// adaptor_sigs is a list of adaptor signatures, each encrypted by a restaked BTC finality provider's public key
    pub adaptor_sigs: Vec<Bytes>,
}

impl From<btc_staking_api::CovenantAdaptorSignatures> for CovenantAdaptorSignatures {
    fn from(cov_adaptor_sigs: btc_staking_api::CovenantAdaptorSignatures) -> Self {
        CovenantAdaptorSignatures {
            cov_pk: cov_adaptor_sigs.cov_pk.to_vec(),
            adaptor_sigs: cov_adaptor_sigs
                .adaptor_sigs
                .into_iter()
                .map(|sig| sig.to_vec())
                .collect(),
        }
    }
}

#[cw_serde]
pub struct BtcUndelegationInfo {
    /// Transaction which will transfer the funds from staking
    /// output to unbonding output. Unbonding output will usually have lower timelock
    /// than staking output.
    pub unbonding_tx: Bytes,
    /// Signature on the unbonding tx by the delegator (i.e. SK corresponding to btc_pk).
    /// It effectively proves that the delegator wants to unbond and thus
    /// Babylon will consider this BTC delegation unbonded. Delegator's BTC
    /// on Bitcoin will be unbonded after time-lock.
    pub delegator_unbonding_info: Option<DelegatorUnbondingInfo>,
    /// List of signatures on the unbonding tx by covenant members.
    pub covenant_unbonding_sig_list: Vec<SignatureInfo>,
    /// Unbonding slashing tx.
    pub slashing_tx: Bytes,
    /// Signature on the slashing tx by the delegator (i.e. SK corresponding to btc_pk).
    /// It will be a part of the witness for the unbonding tx output.
    pub delegator_slashing_sig: Bytes,
    /// List of adaptor signatures on the unbonding slashing tx by each covenant member.
    /// It will be a part of the witness for the staking tx output.
    pub covenant_slashing_sigs: Vec<CovenantAdaptorSignatures>,
}

#[cw_serde]
pub struct DelegatorUnbondingInfo {
    pub spend_stake_tx: Bytes,
}

impl From<btc_staking_api::BtcUndelegationInfo> for BtcUndelegationInfo {
    fn from(undelegation_info: btc_staking_api::BtcUndelegationInfo) -> Self {
        let delegator_unbonding_info =
            if let Some(delegator_unbonding_info) = undelegation_info.delegator_unbonding_info {
                Some(DelegatorUnbondingInfo {
                    spend_stake_tx: delegator_unbonding_info.spend_stake_tx.to_vec(),
                })
            } else {
                None
            };

        BtcUndelegationInfo {
            unbonding_tx: undelegation_info.unbonding_tx.to_vec(),
            delegator_unbonding_info,
            covenant_unbonding_sig_list: undelegation_info
                .covenant_unbonding_sig_list
                .into_iter()
                .map(|sig| sig.into())
                .collect(),
            slashing_tx: undelegation_info.slashing_tx.to_vec(),
            delegator_slashing_sig: undelegation_info.delegator_slashing_sig.to_vec(),
            covenant_slashing_sigs: undelegation_info
                .covenant_slashing_sigs
                .into_iter()
                .map(|sig| sig.into())
                .collect(),
        }
    }
}

#[cw_serde]
pub struct SignatureInfo {
    pub pk: Bytes,
    pub sig: Bytes,
}

impl From<btc_staking_api::SignatureInfo> for SignatureInfo {
    fn from(sig_info: btc_staking_api::SignatureInfo) -> Self {
        SignatureInfo {
            pk: sig_info.pk.to_vec(),
            sig: sig_info.sig.to_vec(),
        }
    }
}
