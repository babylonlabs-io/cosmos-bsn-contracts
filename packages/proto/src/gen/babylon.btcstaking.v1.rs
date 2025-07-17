// @generated
/// ProofOfPossessionBTC is the proof of possession that a Babylon
/// address and a Bitcoin secp256k1 secret key are held by the same
/// person
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProofOfPossessionBtc {
    /// btc_sig_type indicates the type of btc_sig in the pop
    #[prost(enumeration="BtcSigType", tag="1")]
    pub btc_sig_type: i32,
    /// btc_sig is the signature generated via sign(sk_btc, babylon_staker_address)
    /// the signature follows encoding in either BIP-340 spec or BIP-322 spec
    #[prost(bytes="bytes", tag="2")]
    pub btc_sig: ::prost::bytes::Bytes,
}
/// BTCSigType indicates the type of btc_sig in a pop
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, ::prost::Enumeration)]
#[repr(i32)]
pub enum BtcSigType {
    /// BIP340 means the btc_sig will follow the BIP-340 encoding
    Bip340 = 0,
    /// BIP322 means the btc_sig will follow the BIP-322 encoding
    Bip322 = 1,
    /// ECDSA means the btc_sig will follow the ECDSA encoding
    /// ref: <https://github.com/okx/js-wallet-sdk/blob/a57c2acbe6ce917c0aa4e951d96c4e562ad58444/packages/coin-bitcoin/src/BtcWallet.ts#L331>
    Ecdsa = 2,
}
impl BtcSigType {
    /// String value of the enum field names used in the ProtoBuf definition.
    ///
    /// The values are not transformed in any way and thus are considered stable
    /// (if the ProtoBuf definition does not change) and safe for programmatic use.
    pub fn as_str_name(&self) -> &'static str {
        match self {
            BtcSigType::Bip340 => "BIP340",
            BtcSigType::Bip322 => "BIP322",
            BtcSigType::Ecdsa => "ECDSA",
        }
    }
    /// Creates an enum from field names used in the ProtoBuf definition.
    pub fn from_str_name(value: &str) -> ::core::option::Option<Self> {
        match value {
            "BIP340" => Some(Self::Bip340),
            "BIP322" => Some(Self::Bip322),
            "ECDSA" => Some(Self::Ecdsa),
            _ => None,
        }
    }
}
/// FinalityProvider defines a finality provider
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct FinalityProvider {
    /// addr is the bech32 address identifier of the finality provider.
    #[prost(string, tag="1")]
    pub addr: ::prost::alloc::string::String,
    /// description defines the description terms for the finality provider.
    #[prost(message, optional, tag="2")]
    pub description: ::core::option::Option<cosmos_sdk_proto::cosmos::staking::v1beta1::Description>,
    /// commission defines the commission rate of the finality provider.
    #[prost(string, tag="3")]
    pub commission: ::prost::alloc::string::String,
    /// btc_pk is the Bitcoin secp256k1 PK of this finality provider
    /// the PK follows encoding in BIP-340 spec
    #[prost(bytes="bytes", tag="4")]
    pub btc_pk: ::prost::bytes::Bytes,
    /// pop is the proof of possession of the btc_pk, where the BTC
    /// private key signs the bech32 bbn addr of the finality provider.
    #[prost(message, optional, tag="5")]
    pub pop: ::core::option::Option<ProofOfPossessionBtc>,
    /// slashed_babylon_height indicates the Babylon height when
    /// the finality provider is slashed.
    /// if it's 0 then the finality provider is not slashed
    #[prost(uint64, tag="6")]
    pub slashed_babylon_height: u64,
    /// slashed_btc_height indicates the BTC height when
    /// the finality provider is slashed.
    /// if it's 0 then the finality provider is not slashed
    #[prost(uint32, tag="7")]
    pub slashed_btc_height: u32,
    /// jailed defines whether the finality provider is jailed
    #[prost(bool, tag="8")]
    pub jailed: bool,
    /// highest_voted_height is the highest height for which the
    /// finality provider has voted
    #[prost(uint32, tag="9")]
    pub highest_voted_height: u32,
    /// bsn_id is the ID of the BSN the finality provider is securing
    #[prost(string, tag="10")]
    pub bsn_id: ::prost::alloc::string::String,
    /// commission_info contains information details of the finality provider commission.
    #[prost(message, optional, tag="11")]
    pub commission_info: ::core::option::Option<CommissionInfo>,
}
/// CommissionInfo defines the information related to the commission of
/// a finality provider.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CommissionInfo {
    /// max_rate defines the maximum commission rate which validator can ever charge, as a fraction.
    #[prost(string, tag="1")]
    pub max_rate: ::prost::alloc::string::String,
    /// max_change_rate defines the maximum daily increase of the validator commission, as a fraction.
    #[prost(string, tag="2")]
    pub max_change_rate: ::prost::alloc::string::String,
    /// update_time is the last time the commission rate was changed.
    #[prost(message, optional, tag="3")]
    pub update_time: ::core::option::Option<::pbjson_types::Timestamp>,
}
/// BTCDelegation defines a BTC delegation
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcDelegation {
    /// staker_addr is the address to receive rewards from BTC delegation.
    #[prost(string, tag="1")]
    pub staker_addr: ::prost::alloc::string::String,
    /// btc_pk is the Bitcoin secp256k1 PK of this BTC delegation
    /// the PK follows encoding in BIP-340 spec
    #[prost(bytes="bytes", tag="2")]
    pub btc_pk: ::prost::bytes::Bytes,
    /// pop is the proof of possession of babylon_pk and btc_pk
    #[prost(message, optional, tag="3")]
    pub pop: ::core::option::Option<ProofOfPossessionBtc>,
    /// fp_btc_pk_list is the list of BIP-340 PKs of the finality providers that
    /// this BTC delegation delegates to
    /// If there are more than 1 PKs, then this means the delegation is multi-staked
    #[prost(bytes="bytes", repeated, tag="4")]
    pub fp_btc_pk_list: ::prost::alloc::vec::Vec<::prost::bytes::Bytes>,
    /// staking_time is the number of blocks for which the delegation is locked on
    /// BTC chain
    #[prost(uint32, tag="5")]
    pub staking_time: u32,
    /// start_height is the start BTC height of the BTC delegation
    /// it is the start BTC height of the timelock
    #[prost(uint32, tag="6")]
    pub start_height: u32,
    /// end_height is the end height of the BTC delegation
    /// it is calculated by end_height = start_height + staking_time
    #[prost(uint32, tag="7")]
    pub end_height: u32,
    /// total_sat is the total amount of BTC stakes in this delegation
    /// quantified in satoshi
    #[prost(uint64, tag="8")]
    pub total_sat: u64,
    /// staking_tx is the staking tx
    #[prost(bytes="bytes", tag="9")]
    pub staking_tx: ::prost::bytes::Bytes,
    /// staking_output_idx is the index of the staking output in the staking tx
    #[prost(uint32, tag="10")]
    pub staking_output_idx: u32,
    /// slashing_tx is the slashing tx
    /// It is partially signed by SK corresponding to btc_pk, but not signed by
    /// finality provider or covenant yet.
    #[prost(bytes="bytes", tag="11")]
    pub slashing_tx: ::prost::bytes::Bytes,
    /// delegator_sig is the signature on the slashing tx
    /// by the delegator (i.e., SK corresponding to btc_pk).
    /// It will be a part of the witness for the staking tx output.
    #[prost(bytes="bytes", tag="12")]
    pub delegator_sig: ::prost::bytes::Bytes,
    /// covenant_sigs is a list of adaptor signatures on the slashing tx
    /// by each covenant member
    /// It will be a part of the witness for the staking tx output.
    #[prost(message, repeated, tag="13")]
    pub covenant_sigs: ::prost::alloc::vec::Vec<CovenantAdaptorSignatures>,
    /// unbonding_time describes how long the funds will be locked either in
    /// unbonding output or slashing change output
    #[prost(uint32, tag="14")]
    pub unbonding_time: u32,
    /// btc_undelegation is the information about the early unbonding path of the
    /// BTC delegation
    #[prost(message, optional, tag="15")]
    pub btc_undelegation: ::core::option::Option<BtcUndelegation>,
    /// version of the params used to validate the delegation
    #[prost(uint32, tag="16")]
    pub params_version: u32,
    /// btc_tip_height is the height of the BTC light client tip at the time of
    /// the delegation creation
    #[prost(uint32, tag="17")]
    pub btc_tip_height: u32,
    /// stk_exp is contains the relevant information about the previous staking that
    /// originated this stake. If nil it is NOT a stake expansion.
    #[prost(message, optional, tag="18")]
    pub stk_exp: ::core::option::Option<StakeExpansion>,
}
/// StakeExpansion stores information necessary to construct the expanded BTC staking
/// transaction created from a previous BTC staking.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct StakeExpansion {
    /// previous_staking_tx_hash is the hash of the staking tx that was used as
    /// input to the stake expansion.
    #[prost(bytes="bytes", tag="1")]
    pub previous_staking_tx_hash: ::prost::bytes::Bytes,
    /// other_funding_tx_out is the other funding output (TxOut) which was used
    /// as input to construct the BTC delegation. The stake expansion has a set of
    /// 2 inputs, the first input is the previous staking transaction and the
    /// second input (this one) is to pay for fees and optionally to add more
    /// stake to the BTC delegation.
    #[prost(bytes="bytes", tag="2")]
    pub other_funding_tx_out: ::prost::bytes::Bytes,
    /// previous_stk_covenant_sigs is a list of signatures on the stake expansion
    /// transaction (i.e., the transaction spending the previous staking transaction
    /// {previous_staking_tx_hash}) by each covenant member.
    /// It must be provided to allow the previous staking tx to be spent as
    /// an transaction input of another BTC staking transaction.
    #[prost(message, repeated, tag="3")]
    pub previous_stk_covenant_sigs: ::prost::alloc::vec::Vec<SignatureInfo>,
}
/// DelegatorUnbondingInfo contains the information about transaction which spent
/// the staking output. It contains:
/// - spend_stake_tx: the transaction which spent the staking output
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct DelegatorUnbondingInfo {
    /// spend_stake_tx is the transaction which spent the staking output. It is
    /// filled only if spend_stake_tx is different than unbonding_tx registered
    /// on the Babylon chain.
    #[prost(bytes="bytes", tag="1")]
    pub spend_stake_tx: ::prost::bytes::Bytes,
}
/// BTCUndelegation contains the information about the early unbonding path of
/// the BTC delegation
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcUndelegation {
    /// unbonding_tx is the transaction which will transfer the funds from staking
    /// output to unbonding output. Unbonding output will usually have lower
    /// timelock than staking output.
    #[prost(bytes="bytes", tag="1")]
    pub unbonding_tx: ::prost::bytes::Bytes,
    /// slashing_tx is the slashing tx for unbonding transactions
    /// It is partially signed by SK corresponding to btc_pk, but not signed by
    /// finality provider or covenant yet.
    #[prost(bytes="bytes", tag="2")]
    pub slashing_tx: ::prost::bytes::Bytes,
    /// delegator_slashing_sig is the signature on the slashing tx
    /// by the delegator (i.e., SK corresponding to btc_pk).
    /// It will be a part of the witness for the unbonding tx output.
    #[prost(bytes="bytes", tag="3")]
    pub delegator_slashing_sig: ::prost::bytes::Bytes,
    /// covenant_slashing_sigs is a list of adaptor signatures on the slashing tx
    /// by each covenant member
    /// It will be a part of the witness for the staking tx output.
    #[prost(message, repeated, tag="4")]
    pub covenant_slashing_sigs: ::prost::alloc::vec::Vec<CovenantAdaptorSignatures>,
    /// covenant_unbonding_sig_list is the list of signatures on the unbonding tx
    /// by covenant members
    /// It must be provided after processing undelegate message by Babylon
    #[prost(message, repeated, tag="5")]
    pub covenant_unbonding_sig_list: ::prost::alloc::vec::Vec<SignatureInfo>,
    /// delegator_unbonding_info is the information about transaction which spent
    /// the staking output
    #[prost(message, optional, tag="6")]
    pub delegator_unbonding_info: ::core::option::Option<DelegatorUnbondingInfo>,
}
/// SignatureInfo is a BIP-340 signature together with its signer's BIP-340 PK
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SignatureInfo {
    #[prost(bytes="bytes", tag="1")]
    pub pk: ::prost::bytes::Bytes,
    #[prost(bytes="bytes", tag="2")]
    pub sig: ::prost::bytes::Bytes,
}
/// CovenantAdaptorSignatures is a list adaptor signatures signed by the
/// covenant with different finality provider's public keys as encryption keys
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CovenantAdaptorSignatures {
    /// cov_pk is the public key of the covenant emulator, used as the public key
    /// of the adaptor signature
    #[prost(bytes="bytes", tag="1")]
    pub cov_pk: ::prost::bytes::Bytes,
    /// adaptor_sigs is a list of adaptor signatures, each encrypted
    /// by the finality provider public keys involved in the multi-staking
    /// procedure
    #[prost(bytes="bytes", repeated, tag="2")]
    pub adaptor_sigs: ::prost::alloc::vec::Vec<::prost::bytes::Bytes>,
}
/// InclusionProof proves the existence of tx on BTC blockchain
/// including
/// - the position of the tx on BTC blockchain
/// - the Merkle proof that this tx is on the above position
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InclusionProof {
    /// key is the position (txIdx, blockHash) of this tx on BTC blockchain
    #[prost(message, optional, tag="1")]
    pub key: ::core::option::Option<super::super::btccheckpoint::v1::TransactionKey>,
    /// proof is the Merkle proof that this tx is included in the position in `key`
    #[prost(bytes="bytes", tag="2")]
    pub proof: ::prost::bytes::Bytes,
}
/// Params defines the parameters for the module.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Params {
    /// PARAMETERS COVERING STAKING
    /// covenant_pks is the list of public keys held by the covenant committee
    /// each PK follows encoding in BIP-340 spec on Bitcoin
    #[prost(bytes="bytes", repeated, tag="1")]
    pub covenant_pks: ::prost::alloc::vec::Vec<::prost::bytes::Bytes>,
    /// covenant_quorum is the minimum number of signatures needed for the covenant
    /// multisignature
    #[prost(uint32, tag="2")]
    pub covenant_quorum: u32,
    /// min_staking_value_sat is the minimum of satoshis locked in staking output
    #[prost(int64, tag="3")]
    pub min_staking_value_sat: i64,
    /// max_staking_value_sat is the maximum of satoshis locked in staking output
    #[prost(int64, tag="4")]
    pub max_staking_value_sat: i64,
    /// min_staking_time is the minimum lock time specified in staking output
    /// script
    #[prost(uint32, tag="5")]
    pub min_staking_time_blocks: u32,
    /// max_staking_time_blocks is the maximum lock time time specified in staking
    /// output script
    #[prost(uint32, tag="6")]
    pub max_staking_time_blocks: u32,
    /// PARAMETERS COVERING SLASHING
    /// slashing_pk_script is the pk_script expected in slashing output ie. the
    /// first output of slashing transaction
    #[prost(bytes="bytes", tag="7")]
    pub slashing_pk_script: ::prost::bytes::Bytes,
    /// min_slashing_tx_fee_sat is the minimum amount of tx fee (quantified
    /// in Satoshi) needed for the pre-signed slashing tx. It covers both:
    /// staking slashing transaction and unbonding slashing transaction
    #[prost(int64, tag="8")]
    pub min_slashing_tx_fee_sat: i64,
    /// slashing_rate determines the portion of the staked amount to be slashed,
    /// expressed as a decimal (e.g., 0.5 for 50%). Maximal precion is 2 decimal
    /// places
    #[prost(string, tag="9")]
    pub slashing_rate: ::prost::alloc::string::String,
    /// PARAMETERS COVERING UNBONDING
    /// unbonding_time is the exact unbonding time required from unbonding
    /// transaction it must be larger than `checkpoint_finalization_timeout` from
    /// `btccheckpoint` module
    #[prost(uint32, tag="10")]
    pub unbonding_time_blocks: u32,
    /// unbonding_fee exact fee required for unbonding transaction
    #[prost(int64, tag="11")]
    pub unbonding_fee_sat: i64,
    /// PARAMETERS COVERING FINALITY PROVIDERS
    /// min_commission_rate is the chain-wide minimum commission rate that a
    /// finality provider can charge their delegators expressed as a decimal (e.g.,
    /// 0.5 for 50%). Maximal precion is 2 decimal places
    #[prost(string, tag="12")]
    pub min_commission_rate: ::prost::alloc::string::String,
    /// base gas fee for delegation creation
    #[prost(uint64, tag="13")]
    pub delegation_creation_base_gas_fee: u64,
    /// allow_list_expiration_height is the height at which the allow list expires
    /// i.e all staking transactions are allowed to enter Babylon chain afterwards
    /// setting it to 0 means allow list is disabled
    #[prost(uint64, tag="14")]
    pub allow_list_expiration_height: u64,
    /// btc_activation_height is the btc height from which parameters are activated
    /// (inclusive)
    #[prost(uint32, tag="15")]
    pub btc_activation_height: u32,
    /// max_finality_providers is the maximum number of finality providers that can
    /// be used in staking script
    #[prost(uint32, tag="16")]
    pub max_finality_providers: u32,
}
/// BTCStakingIBCPacket is an IBC packet sent from Babylon to a consumer
/// It carries a set of events related to BTC staking for a given consumer
/// It will be constructed and sent upon `EndBlock` of ZoneConcierge
/// (if there are any BTC staking events for a consumer)
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcStakingIbcPacket {
    #[prost(message, repeated, tag="1")]
    pub new_fp: ::prost::alloc::vec::Vec<NewFinalityProvider>,
    #[prost(message, repeated, tag="2")]
    pub active_del: ::prost::alloc::vec::Vec<ActiveBtcDelegation>,
    #[prost(message, repeated, tag="3")]
    pub slashed_del: ::prost::alloc::vec::Vec<SlashedBtcDelegation>,
    #[prost(message, repeated, tag="4")]
    pub unbonded_del: ::prost::alloc::vec::Vec<UnbondedBtcDelegation>,
}
/// NewFinalityProvider is an IBC packet sent from Babylon to consumer
/// upon a newly registered finality provider on this consumer
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NewFinalityProvider {
    /// description defines the description terms for the finality provider.
    #[prost(message, optional, tag="1")]
    pub description: ::core::option::Option<cosmos_sdk_proto::cosmos::staking::v1beta1::Description>,
    /// commission defines the commission rate of the finality provider.
    /// It forms as a string converted from "cosmossdk.io/math.LegacyDec"
    #[prost(string, tag="2")]
    pub commission: ::prost::alloc::string::String,
    /// addr is the bech32 address identifier of the finality provider.
    #[prost(string, tag="3")]
    pub addr: ::prost::alloc::string::String,
    /// btc_pk_hex is the Bitcoin secp256k1 PK of this finality provider
    /// the PK follows encoding in BIP-340 spec in hex format
    #[prost(string, tag="4")]
    pub btc_pk_hex: ::prost::alloc::string::String,
    /// pop is the proof of possession of babylon_pk and btc_pk
    #[prost(message, optional, tag="5")]
    pub pop: ::core::option::Option<ProofOfPossessionBtc>,
    /// bsn_id is the ID of the BSN the finality provider is operating on.
    /// If it's missing / empty, it's assumed the finality provider is operating in Babylon.
    #[prost(string, tag="8")]
    pub bsn_id: ::prost::alloc::string::String,
}
/// ActiveBTCDelegation is an IBC packet sent from Babylon to consumer
/// upon a BTC delegation newly receives covenant signatures and thus becomes active
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ActiveBtcDelegation {
    /// staker_addr is the address to receive rewards from BTC delegation.
    #[prost(string, tag="1")]
    pub staker_addr: ::prost::alloc::string::String,
    /// btc_pk_hex is the Bitcoin secp256k1 PK of this BTC delegation
    /// the PK follows encoding in BIP-340 spec in hex format
    #[prost(string, tag="2")]
    pub btc_pk_hex: ::prost::alloc::string::String,
    /// fp_btc_pk_list is the list of BIP-340 PKs of the finality providers that
    /// this BTC delegation delegates to
    #[prost(string, repeated, tag="3")]
    pub fp_btc_pk_list: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
    /// start_height is the start BTC height of the BTC delegation
    /// it is the start BTC height of the timelock
    #[prost(uint32, tag="4")]
    pub start_height: u32,
    /// end_height is the end height of the BTC delegation
    /// it is the end BTC height of the timelock - w
    #[prost(uint32, tag="5")]
    pub end_height: u32,
    /// total_sat is the total amount of BTC stakes in this delegation
    /// quantified in satoshi
    #[prost(uint64, tag="6")]
    pub total_sat: u64,
    /// staking_tx is the staking tx
    #[prost(bytes="bytes", tag="7")]
    pub staking_tx: ::prost::bytes::Bytes,
    /// slashing_tx is the slashing tx
    #[prost(bytes="bytes", tag="8")]
    pub slashing_tx: ::prost::bytes::Bytes,
    /// delegator_slashing_sig is the signature on the slashing tx
    /// by the delegator (i.e., SK corresponding to btc_pk) as string hex.
    /// It will be a part of the witness for the staking tx output.
    #[prost(bytes="bytes", tag="9")]
    pub delegator_slashing_sig: ::prost::bytes::Bytes,
    /// covenant_sigs is a list of adaptor signatures on the slashing tx
    /// by each covenant member
    /// It will be a part of the witness for the staking tx output.
    #[prost(message, repeated, tag="10")]
    pub covenant_sigs: ::prost::alloc::vec::Vec<CovenantAdaptorSignatures>,
    /// staking_output_idx is the index of the staking output in the staking tx
    #[prost(uint32, tag="11")]
    pub staking_output_idx: u32,
    /// unbonding_time used in unbonding output timelock path and in slashing transactions
    /// change outputs
    #[prost(uint32, tag="12")]
    pub unbonding_time: u32,
    /// undelegation_info is the undelegation info of this delegation.
    #[prost(message, optional, tag="13")]
    pub undelegation_info: ::core::option::Option<BtcUndelegationInfo>,
    /// params version used to validate delegation
    #[prost(uint32, tag="14")]
    pub params_version: u32,
}
/// BTCUndelegationInfo provides all necessary info about the undeleagation
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcUndelegationInfo {
    /// unbonding_tx is the transaction which will transfer the funds from staking
    /// output to unbonding output. Unbonding output will usually have lower timelock
    /// than staking output.
    #[prost(bytes="bytes", tag="1")]
    pub unbonding_tx: ::prost::bytes::Bytes,
    /// slashing_tx is the slashing tx for unbonding transactions
    /// It is partially signed by SK corresponding to btc_pk, but not signed by
    /// finality provider or covenant yet.
    #[prost(bytes="bytes", tag="2")]
    pub slashing_tx: ::prost::bytes::Bytes,
    /// delegator_slashing_sig is the signature on the slashing tx
    /// by the delegator (i.e., SK corresponding to btc_pk).
    /// It will be a part of the witness for the unbonding tx output.
    #[prost(bytes="bytes", tag="3")]
    pub delegator_slashing_sig: ::prost::bytes::Bytes,
    /// covenant_slashing_sigs is a list of adaptor signatures on the slashing tx
    /// by each covenant member
    /// It will be a part of the witness for the staking tx output.
    #[prost(message, repeated, tag="4")]
    pub covenant_slashing_sigs: ::prost::alloc::vec::Vec<CovenantAdaptorSignatures>,
    /// covenant_unbonding_sig_list is the list of signatures on the unbonding tx
    /// by covenant members
    /// It must be provided after processing undelegate message by Babylon
    #[prost(message, repeated, tag="5")]
    pub covenant_unbonding_sig_list: ::prost::alloc::vec::Vec<SignatureInfo>,
    /// delegator_unbonding_info is the information about transaction which spent
    /// the staking output
    #[prost(message, optional, tag="6")]
    pub delegator_unbonding_info: ::core::option::Option<DelegatorUnbondingInfo>,
}
/// SlashedBTCDelegation is an IBC packet sent from Babylon Genesis to consumer
/// about a slashed BTC delegation multi-staked to a finality provider
/// securing the consumer.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SlashedBtcDelegation {
    /// staking tx hash of the BTC delegation. It uniquely identifies a BTC delegation
    #[prost(string, tag="1")]
    pub staking_tx_hash: ::prost::alloc::string::String,
    /// recovered_fp_btc_sk is the extracted BTC SK of the finality provider on
    /// this consumer
    /// this allows the consumer to verify the BTC delegation is indeed slashed
    #[prost(string, tag="2")]
    pub recovered_fp_btc_sk: ::prost::alloc::string::String,
}
/// UnbondedBTCDelegation is an IBC packet sent from Babylon to consumer
/// upon an early unbonded BTC delegation
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UnbondedBtcDelegation {
    /// staking tx hash of the BTC delegation. It uniquely identifies a BTC delegation
    #[prost(string, tag="1")]
    pub staking_tx_hash: ::prost::alloc::string::String,
    /// unbonding_tx_sig is the signature on the unbonding tx signed by the BTC delegator
    /// It proves that the BTC delegator wants to unbond
    #[prost(bytes="bytes", tag="2")]
    pub unbonding_tx_sig: ::prost::bytes::Bytes,
    /// stake_spending_tx is the stake spending tx
    #[prost(bytes="bytes", tag="3")]
    pub stake_spending_tx: ::prost::bytes::Bytes,
    /// proof is the inclusion proof for the stake spending tx
    #[prost(message, optional, tag="4")]
    pub proof: ::core::option::Option<InclusionProof>,
}
// @@protoc_insertion_point(module)
