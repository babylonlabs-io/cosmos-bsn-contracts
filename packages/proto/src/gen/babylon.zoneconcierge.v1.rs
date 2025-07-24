// @generated
/// IndexedHeader is the metadata of a BSN header
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct IndexedHeader {
    /// consumer_id is the unique ID of the consumer
    #[prost(string, tag="1")]
    pub consumer_id: ::prost::alloc::string::String,
    /// hash is the hash of this header
    #[prost(bytes="bytes", tag="2")]
    pub hash: ::prost::bytes::Bytes,
    /// height is the height of this header on the BSN's ledger.
    /// (hash, height) jointly provide the position of the header on the BSN ledger
    #[prost(uint64, tag="3")]
    pub height: u64,
    /// time is the timestamp of this header on the BSN's ledger.
    /// It is needed for a BSN to unbond all mature validators/delegations before
    /// this timestamp, when this header is BTC-finalised
    #[prost(message, optional, tag="4")]
    pub time: ::core::option::Option<::pbjson_types::Timestamp>,
    /// babylon_header_hash is the hash of the babylon block that includes this BSN
    /// header
    #[prost(bytes="bytes", tag="5")]
    pub babylon_header_hash: ::prost::bytes::Bytes,
    /// babylon_header_height is the height of the babylon block that includes this
    /// BSN header
    #[prost(uint64, tag="6")]
    pub babylon_header_height: u64,
    /// epoch is the epoch number of this header on Babylon ledger
    #[prost(uint64, tag="7")]
    pub babylon_epoch: u64,
    /// babylon_tx_hash is the hash of the tx that includes this header
    /// (babylon_block_height, babylon_tx_hash) jointly provides the position of
    /// the header on Babylon ledger
    #[prost(bytes="bytes", tag="8")]
    pub babylon_tx_hash: ::prost::bytes::Bytes,
}
/// ProofEpochSealed is the proof that an epoch is sealed by the sealer header,
/// i.e., the 2nd header of the next epoch With the access of metadata
/// - Metadata of this epoch, which includes the sealer header
/// - Raw checkpoint of this epoch
/// The verifier can perform the following verification rules:
/// - The raw checkpoint's `app_hash` is same as in the sealer header
/// - More than 2/3 (in voting power) validators in the validator set of this
/// epoch have signed `app_hash` of the sealer header
/// - The epoch metadata is committed to the `app_hash` of the sealer header
/// - The validator set is committed to the `app_hash` of the sealer header
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProofEpochSealed {
    /// validator_set is the validator set of the sealed epoch
    /// This validator set has generated a BLS multisig on `app_hash` of
    /// the sealer header
    #[prost(message, repeated, tag="1")]
    pub validator_set: ::prost::alloc::vec::Vec<super::super::checkpointing::v1::ValidatorWithBlsKey>,
    /// proof_epoch_info is the Merkle proof that the epoch's metadata is committed
    /// to `app_hash` of the sealer header
    #[prost(message, optional, tag="2")]
    pub proof_epoch_info: ::core::option::Option<tendermint_proto::crypto::ProofOps>,
    /// proof_epoch_info is the Merkle proof that the epoch's validator set is
    /// committed to `app_hash` of the sealer header
    #[prost(message, optional, tag="3")]
    pub proof_epoch_val_set: ::core::option::Option<tendermint_proto::crypto::ProofOps>,
}
/// ProofFinalizedHeader is a set of proofs that attest a header is
/// BTC-finalised
///
///
/// The following fields include proofs that attest the header is
/// BTC-finalised
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ProofFinalizedHeader {
    /// proof_epoch_sealed is the proof that the epoch is sealed
    #[prost(message, optional, tag="1")]
    pub proof_epoch_sealed: ::core::option::Option<ProofEpochSealed>,
    /// proof_epoch_submitted is the proof that the epoch's checkpoint is included
    /// in BTC ledger It is the two TransactionInfo in the best (i.e., earliest)
    /// checkpoint submission
    #[prost(message, repeated, tag="2")]
    pub proof_epoch_submitted: ::prost::alloc::vec::Vec<super::super::btccheckpoint::v1::TransactionInfo>,
    /// proof_consumer_header_in_epoch is the proof that the consumer header is included in the epoch
    #[prost(message, optional, tag="3")]
    pub proof_consumer_header_in_epoch: ::core::option::Option<tendermint_proto::crypto::ProofOps>,
}
/// OutboundPacket represents packets sent from Babylon to other chains
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct OutboundPacket {
    /// packet is the actual message carried in the IBC packet
    #[prost(oneof="outbound_packet::Packet", tags="1, 2, 3")]
    pub packet: ::core::option::Option<outbound_packet::Packet>,
}
/// Nested message and enum types in `OutboundPacket`.
pub mod outbound_packet {
    /// packet is the actual message carried in the IBC packet
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Packet {
        #[prost(message, tag="1")]
        BtcTimestamp(super::BtcTimestamp),
        #[prost(message, tag="2")]
        BtcStaking(super::super::super::btcstaking::v1::BtcStakingIbcPacket),
        #[prost(message, tag="3")]
        BtcHeaders(super::BtcHeaders),
    }
}
/// InboundPacket represents packets received by Babylon from other chains
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct InboundPacket {
    /// packet is the actual message carried in the IBC packet
    #[prost(oneof="inbound_packet::Packet", tags="1, 2")]
    pub packet: ::core::option::Option<inbound_packet::Packet>,
}
/// Nested message and enum types in `InboundPacket`.
pub mod inbound_packet {
    /// packet is the actual message carried in the IBC packet
    #[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Packet {
        #[prost(message, tag="1")]
        BsnSlashing(super::BsnSlashingIbcPacket),
        #[prost(message, tag="2")]
        BsnBaseBtcHeader(super::BsnBaseBtcHeaderIbcPacket),
    }
}
/// BTCHeaders contains BTC headers that have been verified and inserted into Babylon's BTC light client
/// These headers are forwarded to BSNs to keep their light clients in sync with Babylon
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcHeaders {
    #[prost(message, repeated, tag="1")]
    pub headers: ::prost::alloc::vec::Vec<super::super::btclightclient::v1::BtcHeaderInfo>,
}
/// BTCTimestamp is a BTC timestamp that carries information of a BTC-finalised epoch.
/// It includes a number of BTC headers, a raw checkpoint, an epoch metadata, and
/// a BSN header if there exists BSN headers checkpointed to this epoch.
/// Upon a newly finalised epoch in Babylon, Babylon will send a BTC timestamp to each
/// BSN via IBC.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BtcTimestamp {
    /// header is the last BSN header in the finalized Babylon epoch
    #[prost(message, optional, tag="1")]
    pub header: ::core::option::Option<IndexedHeader>,
    //
    // Data for BTC light client

    /// btc_headers is BTC headers between
    /// - the block AFTER the common ancestor of BTC tip at epoch `lastFinalizedEpoch-1` and BTC tip at epoch `lastFinalizedEpoch`
    /// - BTC tip at epoch `lastFinalizedEpoch`
    /// where `lastFinalizedEpoch` is the last finalised epoch in Babylon
    #[prost(message, optional, tag="2")]
    pub btc_headers: ::core::option::Option<BtcHeaders>,
    //
    // Data for Babylon epoch chain

    /// epoch_info is the metadata of the sealed epoch
    #[prost(message, optional, tag="3")]
    pub epoch_info: ::core::option::Option<super::super::epoching::v1::Epoch>,
    /// raw_checkpoint is the raw checkpoint that seals this epoch
    #[prost(message, optional, tag="4")]
    pub raw_checkpoint: ::core::option::Option<super::super::checkpointing::v1::RawCheckpoint>,
    /// btc_submission_key is position of two BTC txs that include the raw checkpoint of this epoch
    #[prost(message, optional, tag="5")]
    pub btc_submission_key: ::core::option::Option<super::super::btccheckpoint::v1::SubmissionKey>,
    ///
    /// Proofs that the header is finalized
    #[prost(message, optional, tag="6")]
    pub proof: ::core::option::Option<ProofFinalizedHeader>,
}
/// BSNSlashingIBCPacket defines the slashing information that a BSN sends to Babylon's ZoneConcierge upon a
/// BSN slashing event.
/// It includes the FP public key, the BSN block height at the slashing event, and the double sign evidence.
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BsnSlashingIbcPacket {
    /// / evidence is the FP slashing evidence that the BSN sends to Babylon
    #[prost(message, optional, tag="1")]
    pub evidence: ::core::option::Option<super::super::finality::v1::Evidence>,
}
/// BSNBaseBTCHeaderIBCPacket defines the base BTC header information that a BSN sends to Babylon's ZoneConcierge
/// to inform Babylon about which BTC header the BSN considers as its starting point for BTC light client synchronization
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct BsnBaseBtcHeaderIbcPacket {
    /// base_btc_header is the BTC header that the BSN uses as the base for its BTC light client
    #[prost(message, optional, tag="1")]
    pub base_btc_header: ::core::option::Option<super::super::btclightclient::v1::BtcHeaderInfo>,
}
// @@protoc_insertion_point(module)
