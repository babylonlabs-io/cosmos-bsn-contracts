use crate::error::{ContractError, FinalitySigError, PubRandCommitError};
use babylon_apis::finality_api::PubRandCommit;
use babylon_apis::finality_api::{Evidence, IndexedBlock};
use babylon_merkle::Proof;
use cosmwasm_schema::{cw_serde, QueryResponses};
use k256::schnorr::{signature::Verifier, Signature, VerifyingKey};
use k256::sha2::{Digest, Sha256};
use std::collections::HashMap;
#[cfg(not(target_arch = "wasm32"))]
use {crate::state::config::Config, cw_controllers::AdminResponse};

pub const COMMITMENT_LENGTH_BYTES: usize = 32;

/// BIP340 public key length in bytes.
pub const BIP340_PUB_KEY_LEN: usize = 32;
/// BIP340 signature length in bytes.
pub const BIP340_SIGNATURE_LEN: usize = 64;
/// Schnorr public randomness length in bytes
pub const SCHNORR_PUB_RAND_LEN: usize = 32;
/// Schnorr EOTS signature length in bytes.
pub const SCHNORR_EOTS_SIG_LEN: usize = 32;
/// Tendermint hash size (SHA256) in bytes.
pub const TMHASH_SIZE: usize = 32;

pub type InstantiateMsg = babylon_apis::finality_api::InstantiateMsg;
pub type ExecuteMsg = babylon_apis::finality_api::ExecuteMsg;

// https://github.com/babylonlabs-io/babylon/blob/49972e2d3e35caf0a685c37e1f745c47b75bfc69/x/finality/types/tx.pb.go#L36
#[derive(Debug)]
pub struct MsgCommitPubRand {
    pub fp_btc_pk_hex: String,
    pub start_height: u64,
    pub num_pub_rand: u64,
    pub commitment: Vec<u8>,
    pub sig: Vec<u8>,
}

impl MsgCommitPubRand {
    // https://github.com/babylonlabs-io/babylon/blob/49972e2d3e35caf0a685c37e1f745c47b75bfc69/x/finality/types/msg.go#L161
    pub(crate) fn validate_basic(&self) -> Result<(), PubRandCommitError> {
        if self.fp_btc_pk_hex.is_empty() {
            return Err(PubRandCommitError::EmptyFpBtcPubKey);
        }

        // Checks if the commitment is exactly 32 bytes
        if self.commitment.len() != COMMITMENT_LENGTH_BYTES {
            return Err(PubRandCommitError::BadCommitmentLength(
                self.commitment.len(),
            ));
        }

        // To avoid public randomness reset,
        // check for overflow when doing (StartHeight + NumPubRand)
        if self.start_height.checked_add(self.num_pub_rand).is_none() {
            return Err(PubRandCommitError::OverflowInBlockHeight(
                self.start_height,
                self.num_pub_rand,
            ));
        }

        if self.sig.is_empty() {
            return Err(PubRandCommitError::EmptySignature);
        }

        Ok(())
    }

    pub fn verify_sig(&self, signing_context: String) -> Result<(), PubRandCommitError> {
        // get BTC public key for verification
        let btc_pk_raw = hex::decode(&self.fp_btc_pk_hex)?;
        let btc_pk = VerifyingKey::from_bytes(&btc_pk_raw)?;

        let schnorr_sig = Signature::try_from(self.sig.as_slice())?;

        let signed_msg = commit_pub_rand_signed_message(
            signing_context,
            self.start_height,
            self.num_pub_rand,
            &self.commitment,
        );

        // Verify the signature
        btc_pk.verify(&signed_msg, &schnorr_sig)?;

        Ok(())
    }
}

pub(crate) fn commit_pub_rand_signed_message(
    signing_context: String,
    start_height: u64,
    num_pub_rand: u64,
    commitment: &[u8],
) -> Vec<u8> {
    let mut msg: Vec<u8> = vec![];
    msg.extend(signing_context.into_bytes());
    msg.extend(start_height.to_be_bytes());
    msg.extend(num_pub_rand.to_be_bytes());
    msg.extend_from_slice(commitment);
    msg
}

// https://github.com/babylonlabs-io/babylon/blob/49972e2d3e35caf0a685c37e1f745c47b75bfc69/x/finality/types/tx.pb.go#L154
pub struct MsgAddFinalitySig {
    pub fp_btc_pk_hex: String,
    pub height: u64,
    pub pub_rand: Vec<u8>,
    pub proof: Proof,
    pub block_app_hash: Vec<u8>,
    pub signature: Vec<u8>,
}

impl MsgAddFinalitySig {
    // https://github.com/babylonlabs-io/babylon/blob/49972e2d3e35caf0a685c37e1f745c47b75bfc69/x/finality/types/msg.go#L40
    pub(crate) fn validate_basic(&self) -> Result<(), FinalitySigError> {
        // Validate FP BTC PubKey
        if self.fp_btc_pk_hex.is_empty() {
            return Err(FinalitySigError::EmptyFpBtcPk);
        }

        // Validate FP BTC PubKey length
        let fp_btc_pk = hex::decode(&self.fp_btc_pk_hex)?;
        if fp_btc_pk.len() != BIP340_PUB_KEY_LEN {
            return Err(FinalitySigError::InvalidFpBtcPkLength {
                actual: fp_btc_pk.len(),
                expected: BIP340_PUB_KEY_LEN,
            });
        }

        // Validate Public Randomness length
        if self.pub_rand.len() != SCHNORR_PUB_RAND_LEN {
            return Err(FinalitySigError::InvalidPubRandLength {
                actual: self.pub_rand.len(),
                expected: SCHNORR_PUB_RAND_LEN,
            });
        }

        // `self.proof` is not an Option, thus it must not be empty.

        // Validate finality signature length
        if self.signature.len() != SCHNORR_EOTS_SIG_LEN {
            return Err(FinalitySigError::InvalidFinalitySigLength {
                actual: self.signature.len(),
                expected: SCHNORR_EOTS_SIG_LEN,
            });
        }

        // Validate block app hash length
        if self.block_app_hash.len() != TMHASH_SIZE {
            return Err(FinalitySigError::InvalidBlockAppHashLength {
                actual: self.block_app_hash.len(),
                expected: TMHASH_SIZE,
            });
        }

        Ok(())
    }

    /// Verifies the finality signature message w.r.t. the public randomness commitment:
    /// - Public randomness inclusion proof.
    pub(crate) fn verify_finality_signature(
        &self,
        pr_commit: &PubRandCommit,
        signing_context: &str,
    ) -> Result<(), ContractError> {
        let proof_height = pr_commit.start_height + self.proof.index;
        if self.height != proof_height {
            return Err(ContractError::InvalidFinalitySigHeight(
                proof_height,
                self.height,
            ));
        }
        // Verify the total amount of randomness is the same as in the commitment
        if self.proof.total != pr_commit.num_pub_rand {
            return Err(ContractError::InvalidFinalitySigAmount(
                self.proof.total,
                pr_commit.num_pub_rand,
            ));
        }
        // Verify the proof of inclusion for this public randomness
        self.proof.validate_basic()?;
        self.proof.verify(&pr_commit.commitment, &self.pub_rand)?;

        // Public randomness is good, verify finality signature
        let pubkey = eots::PublicKey::from_hex(&self.fp_btc_pk_hex)?;

        // The EOTS signature on a block will be (signing_context || block_height || block_app_hash)
        let msg = crate::finality::msg_to_sign_for_vote(
            signing_context,
            self.height,
            &self.block_app_hash,
        );

        let msg_hash = Sha256::digest(msg);

        if !pubkey.verify_hash(&self.pub_rand, msg_hash.into(), &self.signature)? {
            return Err(ContractError::FailedToVerifyEots);
        }

        Ok(())
    }
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    /// Returns the current configuration of the btc-finality contract.
    #[returns(Config)]
    Config {},
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
    /// Returns the voting power of a given finality provider at a given height
    #[returns(FinalityProviderPowerResponse)]
    FinalityProviderPower { btc_pk_hex: String, height: u64 },
    /// Returns the activated height of the BTC staking protocol
    #[returns(u64)]
    ActivatedHeight {},
    /// Returns the finality providers who have signed the block at given height.
    #[returns(VotesResponse)]
    Votes { height: u64 },
    /// Returns the signing info of a finality provider if any.
    #[returns(Option<SigningInfoResponse>)]
    SigningInfo { btc_pk_hex: String },
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
    pub active_finality_providers: HashMap<String, u64>,
}

#[cw_serde]
pub struct FinalityProviderPowerResponse {
    pub power: u64,
}

#[cw_serde]
pub struct VotesResponse {
    pub btc_pks: Vec<String>,
}

#[cw_serde]
pub struct SigningInfoResponse {
    pub fp_btc_pk_hex: String,
    pub start_height: u64,
    pub last_signed_height: u64,
    pub jailed_until: Option<u64>,
}
