use std::str::FromStr;

/// BTC staking messages / API
/// The definitions here follow the same structure as the equivalent IBC protobuf message types,
/// defined in `packages/proto/src/gen/babylon.btcstaking.v1.rs`
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Binary, Decimal, Uint128};

/// Hash size in bytes
pub const HASH_SIZE: usize = 32;

#[cw_serde]
/// btc_staking execution handlers
pub enum ExecuteMsg {
    /// Change the admin
    UpdateAdmin { admin: Option<String> },
    /// Set the BTC light client addr and BTC finality addr.
    /// Only admin or the babylon contract can set this
    UpdateContractAddresses {
        btc_light_client: String,
        finality: String,
    },
    /// BTC Staking operations
    BtcStaking {
        new_fp: Vec<NewFinalityProvider>,
        active_del: Vec<ActiveBtcDelegation>,
        slashed_del: Vec<SlashedBtcDelegation>,
        unbonded_del: Vec<UnbondedBtcDelegation>,
    },
    /// Slash finality provider staking power.
    /// Used by the babylon-contract only.
    /// The Babylon contract will call this message to set the finality provider's staking power to
    /// zero when the finality provider is found to be malicious by the finality contract.
    Slash { fp_btc_pk_hex: String },
    /// Message sent by the finality contract, to distribute rewards to delegators.
    DistributeRewards {
        /// List of finality providers and their rewards.
        fp_distribution: Vec<RewardInfo>,
    },
    /// Message sent by anyone on behalf of the staker, to withdraw rewards from BTC staking via the given FP.
    WithdrawRewards {
        /// Both the address to claim and receive the rewards.
        /// It's a Babylon address. If rewards are to be sent to a Consumer address, the
        /// staker's equivalent address in that chain will be computed and used.
        staker_addr: String,
        fp_pubkey_hex: String,
    },
}

#[cw_serde]
pub struct RewardInfo {
    pub fp_pubkey_hex: String,
    pub reward: Uint128,
}

#[cw_serde]
pub struct NewFinalityProvider {
    /// Description terms for the finality provider.
    pub description: Option<FinalityProviderDescription>,
    /// Commission rate of the finality provider.
    pub commission: Decimal,
    /// Bech32 address identifier of the finality provider.
    pub addr: String,
    /// Bitcoin secp256k1 PK of this finality provider
    /// the PK follows encoding in BIP-340 spec in hex format
    pub btc_pk_hex: String,
    /// Proof of possession of the babylon_pk and btc_pk
    pub pop: Option<ProofOfPossessionBtc>,
    /// ID of the consumer that the finality provider is operating on.
    pub consumer_id: String,
}

impl TryFrom<&babylon_proto::babylon::btcstaking::v1::NewFinalityProvider> for NewFinalityProvider {
    type Error = String;

    fn try_from(
        fp: &babylon_proto::babylon::btcstaking::v1::NewFinalityProvider,
    ) -> Result<Self, Self::Error> {
        Ok(NewFinalityProvider {
            description: fp
                .description
                .as_ref()
                .map(|d| FinalityProviderDescription {
                    moniker: d.moniker.clone(),
                    identity: d.identity.clone(),
                    website: d.website.clone(),
                    security_contact: d.security_contact.clone(),
                    details: d.details.clone(),
                }),
            commission: Decimal::from_str(&fp.commission)
                .map_err(|e| format!("Failed to parse commission: {}", e))?,
            addr: fp.addr.clone(),
            btc_pk_hex: fp.btc_pk_hex.clone(),
            pop: fp.pop.as_ref().map(|pop| ProofOfPossessionBtc {
                btc_sig_type: pop.btc_sig_type,
                btc_sig: pop.btc_sig.to_vec().into(),
            }),
            consumer_id: fp.bsn_id.clone(),
        })
    }
}

#[cw_serde]
pub struct FinalityProvider {
    /// Description terms for the finality provider.
    pub description: Option<FinalityProviderDescription>,
    /// Commission rate of the finality provider.
    pub commission: Decimal,
    /// Bech32 address identifier of the finality provider.
    pub addr: String,
    /// Bitcoin secp256k1 PK of this finality provider
    /// the PK follows encoding in BIP-340 spec in hex format
    pub btc_pk_hex: String,
    /// Proof of possession of the babylon_pk and btc_pk.
    pub pop: Option<ProofOfPossessionBtc>,
    /// Height on which the finality provider is slashed.
    pub slashed_height: u64,
    /// BTC height on which the finality provider is slashed.
    pub slashed_btc_height: u32,
    /// ID of the consumer that the finality provider is operating on.
    pub consumer_id: String,
}

impl From<&NewFinalityProvider> for FinalityProvider {
    fn from(new_fp: &NewFinalityProvider) -> Self {
        FinalityProvider {
            description: new_fp.description.clone(),
            commission: new_fp.commission,
            addr: new_fp.addr.clone(),
            btc_pk_hex: new_fp.btc_pk_hex.clone(),
            pop: new_fp.pop.clone(),
            slashed_height: 0,
            slashed_btc_height: 0,
            consumer_id: new_fp.consumer_id.clone(),
        }
    }
}

#[cw_serde]
pub struct FinalityProviderDescription {
    /// Name of the finality provider.
    pub moniker: String,
    /// Identity of the finality provider.
    pub identity: String,
    /// Website of the finality provider.
    pub website: String,
    /// Security contact of the finality provider.
    pub security_contact: String,
    /// Details of the finality provider.
    pub details: String,
}

impl FinalityProviderDescription {
    /// Description field lengths
    pub const MAX_MONIKER_LENGTH: usize = 70;
    pub const MAX_IDENTITY_LENGTH: usize = 3000;
    pub const MAX_WEBSITE_LENGTH: usize = 140;
    pub const MAX_SECURITY_CONTACT_LENGTH: usize = 140;
    pub const MAX_DETAILS_LENGTH: usize = 280;
}

/// Indicates the type of btc_sig in a pop
#[cw_serde]
pub enum BTCSigType {
    /// BIP340 means the btc_sig will follow the BIP-340 encoding
    BIP340 = 0,
    /// BIP322 means the btc_sig will follow the BIP-322 encoding
    BIP322 = 1,
    /// ECDSA means the btc_sig will follow the ECDSA encoding
    /// ref: https://github.com/okx/js-wallet-sdk/blob/a57c2acbe6ce917c0aa4e951d96c4e562ad58444/packages/coin-bitcoin/src/BtcWallet.ts#L331
    ECDSA = 2,
}

impl TryFrom<i32> for BTCSigType {
    type Error = String;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(BTCSigType::BIP340),
            1 => Ok(BTCSigType::BIP322),
            2 => Ok(BTCSigType::ECDSA),
            _ => Err(format!("Invalid BTCSigType value: {}", value)),
        }
    }
}

/// Proof of possession that a Babylon secp256k1 secret key and a Bitcoin secp256k1 secret key are
/// held by the same person.
#[cw_serde]
pub struct ProofOfPossessionBtc {
    /// Type of `btc_sig` in the pop.
    pub btc_sig_type: i32,
    /// Signature generated via sign(sk_btc, babylon_sig).
    ///
    /// The signature follows encoding in either BIP-340 spec or BIP-322 spec.
    pub btc_sig: Binary,
}

/// Represents the status of a delegation.
/// The state transition path is PENDING -> ACTIVE -> UNBONDED with two possibilities:
///     1. The typical path when time-lock of staking transaction expires.
///     2. The path when staker requests an early undelegation through a BtcStaking
///     UnbondedBtcDelegation message.
#[cw_serde]
pub enum BTCDelegationStatus {
    /// A delegation waiting for covenant signatures to become active
    PENDING = 0,
    /// A delegation that has voting power
    ACTIVE = 1,
    /// A delegation that no longer has voting power:
    /// - Either reaching the end of staking transaction time-lock.
    /// - Or by receiving an unbonding tx with signatures from staker and covenant committee
    UNBONDED = 2,
    /// ANY is any of the status above
    ANY = 3,
}

/// Message sent when a BTC delegation newly receives covenant signatures and thus becomes active.
#[cw_serde]
pub struct ActiveBtcDelegation {
    /// Address to receive rewards from BTC delegation.
    pub staker_addr: String,
    /// Bitcoin secp256k1 PK of the BTC delegator.
    /// The PK follows encoding in BIP-340 spec in hex format
    pub btc_pk_hex: String,
    /// List of BIP-340 PKs of the finality providers that
    /// this BTC delegation delegates to
    pub fp_btc_pk_list: Vec<String>,
    /// Start BTC height of the BTC delegation.
    /// It is the start BTC height of the time-lock
    pub start_height: u32,
    /// End height of the BTC delegation.
    /// It is the end BTC height of the time-lock - w
    pub end_height: u32,
    /// Total BTC stakes in this delegation, quantified in satoshi
    pub total_sat: u64,
    /// Staking tx.
    pub staking_tx: Binary,
    /// Slashing tx.
    pub slashing_tx: Binary,
    /// Signature on the slashing tx by the delegator (i.e. SK corresponding to btc_pk) as string hex.
    /// It will be a part of the witness for the staking tx output.
    pub delegator_slashing_sig: Binary,
    /// List of adaptor signatures on the slashing tx by each covenant member.
    /// It will be a part of the witness for the staking tx output.
    pub covenant_sigs: Vec<CovenantAdaptorSignatures>,
    /// Index of the staking output in the staking tx
    pub staking_output_idx: u32,
    /// Used in unbonding output time-lock path and in slashing transactions change outputs
    pub unbonding_time: u32,
    /// Undelegation info of this delegation.
    pub undelegation_info: BtcUndelegationInfo,
    /// Params version used to validate the delegation
    pub params_version: u32,
}

impl TryFrom<&babylon_proto::babylon::btcstaking::v1::ActiveBtcDelegation> for ActiveBtcDelegation {
    type Error = String;

    fn try_from(
        d: &babylon_proto::babylon::btcstaking::v1::ActiveBtcDelegation,
    ) -> Result<Self, Self::Error> {
        let delegator_unbonding_info = if let Some(info) = d
            .undelegation_info
            .clone()
            .unwrap()
            .delegator_unbonding_info
        {
            Some(DelegatorUnbondingInfo {
                spend_stake_tx: Binary::new(info.spend_stake_tx.to_vec()),
            })
        } else {
            None
        };

        Ok(ActiveBtcDelegation {
            staker_addr: d.staker_addr.clone(),
            btc_pk_hex: d.btc_pk_hex.clone(),
            fp_btc_pk_list: d.fp_btc_pk_list.clone(),
            start_height: d.start_height,
            end_height: d.end_height,
            total_sat: d.total_sat,
            staking_tx: d.staking_tx.to_vec().into(),
            slashing_tx: d.slashing_tx.to_vec().into(),
            delegator_slashing_sig: d.delegator_slashing_sig.to_vec().into(),
            covenant_sigs: d
                .covenant_sigs
                .iter()
                .map(|s| CovenantAdaptorSignatures {
                    cov_pk: s.cov_pk.to_vec().into(),
                    adaptor_sigs: s.adaptor_sigs.iter().map(|a| a.to_vec().into()).collect(),
                })
                .collect(),
            staking_output_idx: d.staking_output_idx,
            unbonding_time: d.unbonding_time,
            undelegation_info: d
                .undelegation_info
                .as_ref()
                .map(|ui| BtcUndelegationInfo {
                    unbonding_tx: ui.unbonding_tx.to_vec().into(),
                    delegator_unbonding_info,
                    covenant_unbonding_sig_list: ui
                        .covenant_unbonding_sig_list
                        .iter()
                        .map(|s| SignatureInfo {
                            pk: s.pk.to_vec().into(),
                            sig: s.sig.to_vec().into(),
                        })
                        .collect(),
                    slashing_tx: ui.slashing_tx.to_vec().into(),
                    delegator_slashing_sig: ui.delegator_slashing_sig.to_vec().into(),
                    covenant_slashing_sigs: ui
                        .covenant_slashing_sigs
                        .iter()
                        .map(|s| CovenantAdaptorSignatures {
                            cov_pk: s.cov_pk.to_vec().into(),
                            adaptor_sigs: s
                                .adaptor_sigs
                                .iter()
                                .map(|a| a.to_vec().into())
                                .collect(),
                        })
                        .collect(),
                })
                .ok_or("undelegation info not set")?,
            params_version: d.params_version,
        })
    }
}

/// Represents a list adaptor signatures signed by the
/// covenant with different finality provider's public keys as encryption keys
#[cw_serde]
pub struct CovenantAdaptorSignatures {
    /// Public key of the covenant emulator, used as the public key of the adaptor signature
    pub cov_pk: Binary,
    /// List of adaptor signatures, each encrypted by a restaked BTC finality provider's public key
    pub adaptor_sigs: Vec<Binary>,
}

/// Provides all necessary info about the undelegation.
#[cw_serde]
pub struct BtcUndelegationInfo {
    /// Transaction which will transfer the funds from staking
    /// output to unbonding output. Unbonding output will usually have lower timelock
    /// than staking output.
    pub unbonding_tx: Binary,
    /// Unbonding slashing tx
    pub slashing_tx: Binary,
    /// Signature on the slashing tx
    /// by the delegator (i.e. SK corresponding to btc_pk).
    /// It will be a part of the witness for the unbonding tx output.
    pub delegator_slashing_sig: Binary,
    /// List of adaptor signatures on the
    /// unbonding slashing tx by each covenant member
    /// It will be a part of the witness for the staking tx output.
    pub covenant_slashing_sigs: Vec<CovenantAdaptorSignatures>,
    /// List of signatures on the unbonding tx
    /// by covenant members
    pub covenant_unbonding_sig_list: Vec<SignatureInfo>,
    /// Information about transaction which spent
    /// the staking output
    pub delegator_unbonding_info: Option<DelegatorUnbondingInfo>,
}

#[cw_serde]
pub struct DelegatorUnbondingInfo {
    pub spend_stake_tx: Binary,
}

/// A BIP-340 signature together with its signer's BIP-340 PK.
#[cw_serde]
pub struct SignatureInfo {
    pub pk: Binary,
    pub sig: Binary,
}

/// A packet sent from Babylon to the Consumer chain about a slashed BTC
/// delegation re-staked to >=1 of the Consumer chain's finality providers
#[cw_serde]
pub struct SlashedBtcDelegation {
    /// Staking tx hash of the BTC delegation. It uniquely identifies a BTC delegation
    pub staking_tx_hash: String,
    /// Extracted BTC SK of the finality provider on this Consumer chain.
    pub recovered_fp_btc_sk: String,
}

/// Sent from Babylon to the Consumer chain upon an early unbonded BTC
/// delegation.
#[cw_serde]
pub struct UnbondedBtcDelegation {
    /// Staking tx hash of the BTC delegation. It uniquely identifies a BTC delegation
    pub staking_tx_hash: String,
    /// Signature on the unbonding tx signed by the BTC delegator
    /// It proves that the BTC delegator wants to unbond
    pub unbonding_tx_sig: Binary,
}

#[cw_serde]
pub enum SudoMsg {
    /// The SDK should call SudoMsg::BeginBlock{} once per block (in BeginBlock).
    /// It allows the staking module to index the BTC height, and update the power
    /// distribution of Finality Providers.
    BeginBlock {
        hash_hex: String,
        app_hash_hex: String,
    },
}
