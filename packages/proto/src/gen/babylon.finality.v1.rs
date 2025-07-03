// @generated
/// PubRandCommit is a commitment to a series of public randomness
/// currently, the commitment is a root of a Merkle tree that includes
/// a series of public randomness
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct PubRandCommit {
    /// start_height is the height of the first commitment
    #[prost(uint64, tag="1")]
    pub start_height: u64,
    /// num_pub_rand is the number of committed public randomness
    #[prost(uint64, tag="2")]
    pub num_pub_rand: u64,
    /// commitment is the value of the commitment
    /// currently, it is the root of the merkle tree constructed by the public randomness
    #[prost(bytes="bytes", tag="3")]
    pub commitment: ::prost::bytes::Bytes,
    /// epoch_num defines the epoch number that the commit falls into
    #[prost(uint64, tag="4")]
    pub epoch_num: u64,
}
/// Evidence is the evidence that a finality provider has signed finality
/// signatures with correct public randomness on two conflicting Babylon headers
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct Evidence {
    /// fp_btc_pk is the BTC PK of the finality provider that casts this vote
    #[prost(bytes="bytes", tag="1")]
    pub fp_btc_pk: ::prost::bytes::Bytes,
    /// block_height is the height of the conflicting blocks
    #[prost(uint64, tag="2")]
    pub block_height: u64,
    /// pub_rand is the public randomness the finality provider has committed to
    #[prost(bytes="bytes", tag="3")]
    pub pub_rand: ::prost::bytes::Bytes,
    /// canonical_app_hash is the AppHash of the canonical block
    #[prost(bytes="bytes", tag="4")]
    pub canonical_app_hash: ::prost::bytes::Bytes,
    /// fork_app_hash is the AppHash of the fork block
    #[prost(bytes="bytes", tag="5")]
    pub fork_app_hash: ::prost::bytes::Bytes,
    /// canonical_finality_sig is the finality signature to the canonical block
    /// where finality signature is an EOTS signature, i.e.,
    /// the `s` in a Schnorr signature `(r, s)`
    /// `r` is the public randomness that is already committed by the finality provider
    #[prost(bytes="bytes", tag="6")]
    pub canonical_finality_sig: ::prost::bytes::Bytes,
    /// fork_finality_sig is the finality signature to the fork block
    /// where finality signature is an EOTS signature
    #[prost(bytes="bytes", tag="7")]
    pub fork_finality_sig: ::prost::bytes::Bytes,
}
/// MsgCommitPubRandList defines a message for committing a list of public randomness for EOTS
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgCommitPubRandList {
    #[prost(string, tag="1")]
    pub signer: ::prost::alloc::string::String,
    /// fp_btc_pk is the BTC PK of the finality provider that commits the public randomness
    #[prost(bytes="bytes", tag="2")]
    pub fp_btc_pk: ::prost::bytes::Bytes,
    /// start_height is the start block height of the list of public randomness
    #[prost(uint64, tag="3")]
    pub start_height: u64,
    /// num_pub_rand is the number of public randomness committed
    #[prost(uint64, tag="4")]
    pub num_pub_rand: u64,
    /// commitment is the commitment of these public randomness
    /// currently it's the root of the Merkle tree that includes these public randomness
    #[prost(bytes="bytes", tag="5")]
    pub commitment: ::prost::bytes::Bytes,
    /// sig is the signature on (start_height || num_pub_rand || commitment) signed by
    /// SK corresponding to fp_btc_pk. This prevents others to commit public
    /// randomness on behalf of fp_btc_pk
    /// TODO: another option is to restrict signer to correspond to fp_btc_pk. This restricts
    /// the tx submitter to be the holder of fp_btc_pk. Decide this later
    #[prost(bytes="bytes", tag="6")]
    pub sig: ::prost::bytes::Bytes,
}
/// MsgAddFinalitySig defines a message for adding a finality vote
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct MsgAddFinalitySig {
    #[prost(string, tag="1")]
    pub signer: ::prost::alloc::string::String,
    /// fp_btc_pk is the BTC PK of the finality provider that casts this vote
    #[prost(bytes="bytes", tag="2")]
    pub fp_btc_pk: ::prost::bytes::Bytes,
    /// block_height is the height of the voted block
    #[prost(uint64, tag="3")]
    pub block_height: u64,
    /// pub_rand is the public randomness committed at this height
    #[prost(bytes="bytes", tag="4")]
    pub pub_rand: ::prost::bytes::Bytes,
    /// proof is the proof that the given public randomness is committed under the commitment
    #[prost(message, optional, tag="5")]
    pub proof: ::core::option::Option<tendermint_proto::crypto::Proof>,
    /// block_app_hash is the AppHash of the voted block
    #[prost(bytes="bytes", tag="6")]
    pub block_app_hash: ::prost::bytes::Bytes,
    /// finality_sig is the finality signature to this block
    /// where finality signature is an EOTS signature, i.e.,
    /// the `s` in a Schnorr signature `(r, s)`
    /// `r` is the public randomness that is already committed by the finality provider
    #[prost(bytes="bytes", tag="7")]
    pub finality_sig: ::prost::bytes::Bytes,
}
// @@protoc_insertion_point(module)
