/// Finality messages / API
/// The definitions here roughly follow the same structure as the equivalent IBC protobuf pub struct types,
/// defined in `packages/proto/src/gen/babylon.finality.v1.rs`
use cosmwasm_schema::cw_serde;
use cosmwasm_std::Binary;

use babylon_merkle::Proof;

use crate::Bytes;

#[cw_serde]
#[derive(Default)]
pub struct InstantiateMsg {
    pub admin: Option<String>,
    pub max_active_finality_providers: Option<u32>,
    pub min_pub_rand: Option<u64>,
    pub reward_interval: Option<u64>,
    pub missed_blocks_window: Option<u64>,
    pub jail_duration: Option<u64>,
    pub finality_activation_height: Option<u64>,
}

#[cw_serde]
/// babylon_finality execution handlers
pub enum ExecuteMsg {
    /// Change the admin
    UpdateAdmin { admin: Option<String> },
    /// Set the BTC staking addr.
    /// Only admin or the babylon contract can set this
    UpdateStaking { staking: String },
    /// Committing a sequence of public randomness for EOTS
    CommitPublicRandomness {
        /// BTC PK of the finality provider that commits the public randomness
        fp_pubkey_hex: String,
        /// Start block height of the list of public randomness
        start_height: u64,
        /// Amount of public randomness committed
        num_pub_rand: u64,
        /// Commitment of these public randomness values.
        /// Currently, it's the root of the Merkle tree that includes the public randomness
        commitment: Binary,
        /// Signature on (start_height || num_pub_rand || commitment) signed by
        /// the SK corresponding to `fp_pubkey_hex`.
        /// This prevents others committing public randomness on behalf of `fp_pubkey_hex`
        signature: Binary,
    },
    /// Submit Finality Signature.
    ///
    /// This is a message that can be called by a finality provider to submit their finality
    /// signature to the Consumer chain.
    /// The signature is verified by the Consumer chain using the finality provider's public key
    ///
    /// This message is equivalent to the `MsgAddFinalitySig` message in the Babylon finality protobuf
    /// defs.
    SubmitFinalitySignature {
        fp_pubkey_hex: String,
        height: u64,
        pub_rand: Binary,
        proof: Proof,
        // FIXME: Rename to block_app_hash for consistency / clarity
        block_hash: Binary,
        signature: Binary,
    },
    /// Unjails finality provider.
    /// Admin can unjail anyone anytime, others can unjail only themselves, and only if the jail
    /// period passed.
    Unjail {
        /// FP to unjail
        fp_pubkey_hex: String,
    },
}

/// Represents the necessary metadata and finalization status of a block.
#[cw_serde]
pub struct IndexedBlock {
    /// Height of the block.
    pub height: u64,
    /// AppHash of the block.
    pub app_hash: Bytes,
    /// Whether the IndexedBlock is finalised by 2/3 of the finality providers or not.
    pub finalized: bool,
}

/// Represents a commitment to a series of public randomness.
/// Currently, the commitment is a root of a Merkle tree that includes a series of public randomness
/// values
#[cw_serde]
pub struct PubRandCommit {
    /// Height of the first commitment.
    pub start_height: u64,
    /// Number of committed public randomness.
    pub num_pub_rand: u64,
    /// Height that the commit was submitted.
    pub height: u64,
    /// Value of the commitment.
    /// Currently, it's the root of the Merkle tree constructed by the public randomness
    pub commitment: Bytes,
}

impl PubRandCommit {
    /// Checks if the given height is within the range of the commitment
    pub fn in_range(&self, height: u64) -> bool {
        self.start_height <= height && height <= self.end_height()
    }

    /// Returns the height of the last commitment
    pub fn end_height(&self) -> u64 {
        self.start_height + self.num_pub_rand - 1
    }
}

/// Evidence is the evidence that a finality provider has signed finality
/// signatures with correct public randomness on two conflicting Babylon headers
#[cw_serde]
pub struct Evidence {
    /// BTC PK of the finality provider that casts this vote
    pub fp_btc_pk: Bytes,
    /// Height of the conflicting blocks
    pub block_height: u64,
    /// Public randomness the finality provider has committed to.
    /// Deserializes to `SchnorrPubRand`
    pub pub_rand: Bytes,
    /// AppHash of the canonical block
    pub canonical_app_hash: Bytes,
    /// AppHash of the fork block
    pub fork_app_hash: Bytes,
    /// Finality signature to the canonical block,
    /// where finality signature is an EOTS signature, i.e.,
    /// the `s` in a Schnorr signature `(r, s)`.
    /// `r` is the public randomness already committed by the finality provider.
    /// Deserializes to `SchnorrEOTSSig`
    pub canonical_finality_sig: Bytes,
    /// Finality signature to the fork block,
    /// where finality signature is an EOTS signature.
    /// Deserializes to `SchnorrEOTSSig`
    pub fork_finality_sig: Bytes,
    /// Context in which the finality signatures were used.
    /// It must be hex encoded 32 bytes, of the sha256 hash of the context string
    pub signing_context: String,
}

#[cw_serde]
pub enum SudoMsg {
    /// The SDK should call SudoMsg::BeginBlock{} once per block (in BeginBlock).
    /// It allows the staking module to index the BTC height, and update the power
    /// distribution of the active Finality Providers.
    BeginBlock {
        hash_hex: String,
        app_hash_hex: String,
    },
    /// The SDK should call SudoMsg::EndBlock{} once per block (in EndBlock).
    /// It allows the finality module to index blocks and tally the finality provider votes
    EndBlock {
        hash_hex: String,
        app_hash_hex: String,
    },
}
