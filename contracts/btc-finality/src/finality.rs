use crate::contract::encode_smart_query;
use crate::error::ContractError;
use crate::state::config::{ADMIN, CONFIG};
use crate::state::finality::{
    collect_accumulated_voting_weights, get_fp_power, get_last_signed_height,
    get_power_table_at_height, ACCUMULATED_VOTING_WEIGHTS, BLOCKS, EVIDENCES, FP_BLOCK_SIGNER,
    FP_POWER_TABLE, FP_START_HEIGHT, JAIL, NEXT_HEIGHT, SIGNATURES,
};
use crate::state::public_randomness::{
    get_last_finalized_height, get_last_pub_rand_commit,
    get_timestamped_pub_rand_commit_for_height, has_timestamped_pub_rand_commit_for_height,
    PUB_RAND_COMMITS, PUB_RAND_VALUES,
};
use babylon_apis::btc_staking_api::FinalityProvider;
use babylon_apis::finality_api::{Evidence, IndexedBlock, PubRandCommit};
use babylon_apis::to_canonical_addr;
use babylon_contract::msg::contract::{ExecuteMsg::RewardsDistribution, RewardInfo};
use babylon_contract::ExecuteMsg;
use babylon_merkle::Proof;
use btc_staking::msg::{FinalityProviderInfo, FinalityProvidersByTotalActiveSatsResponse};
use cosmwasm_std::Order::Ascending;
use cosmwasm_std::{
    to_json_binary, Addr, DepsMut, Env, Event, MessageInfo, QuerierWrapper, Response, StdResult,
    Storage, Uint128, WasmMsg,
};
use k256::schnorr::{signature::Verifier, Signature, VerifyingKey};
use k256::sha2::{Digest, Sha256};
use std::cmp::max;
use std::collections::{HashMap, HashSet};

// The maximum number of blocks into the future
// that a public randomness commitment start height can target. This limit prevents abuse by capping
// the size of the commitments index, protecting against potential memory exhaustion
// or performance degradation caused by excessive future commitments.
const MAX_PUB_RAND_COMMIT_OFFSET: u64 = 160_000;

const COMMITMENT_LENGTH_BYTES: usize = 32;

// BIP340 public key length
const BIP340_PUB_KEY_LEN: usize = 32;
// Schnorr public randomness length
const SCHNORR_PUB_RAND_LEN: usize = 32;
// Schnorr EOTS signature length
const SCHNORR_EOTS_SIG_LEN: usize = 32;
// Tendermint hash size (SHA256)
const TMHASH_SIZE: usize = 32;

const QUERY_LIMIT: Option<u32> = Some(30);

pub const JAIL_FOREVER: u64 = 0;

#[derive(thiserror::Error, Debug, PartialEq)]
pub enum PubRandCommitError {
    #[error("Empty FP BTC PubKey")]
    EmptyFpBtcPubKey,
    #[error("Commitment must be {COMMITMENT_LENGTH_BYTES} bytes, got {0}")]
    BadCommitmentLength(usize),
    #[error("public rand commit start block height: {0} is equal or higher than start_height + num_pub_rand ({1})")]
    OverflowInBlockHeight(u64, u64),
    #[error("Empty signature")]
    EmptySignature,
    #[error("Ecdsa error: {0}")]
    Ecdsa(String),
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
}

impl From<k256::ecdsa::Error> for PubRandCommitError {
    fn from(e: k256::ecdsa::Error) -> Self {
        Self::Ecdsa(e.to_string())
    }
}

// https://github.com/babylonlabs-io/babylon/blob/49972e2d3e35caf0a685c37e1f745c47b75bfc69/x/finality/types/tx.pb.go#L36
pub struct MsgCommitPubRand {
    pub fp_btc_pk_hex: String,
    pub start_height: u64,
    pub num_pub_rand: u64,
    pub commitment: Vec<u8>,
    pub sig: Vec<u8>,
}

impl MsgCommitPubRand {
    // https://github.com/babylonlabs-io/babylon/blob/49972e2d3e35caf0a685c37e1f745c47b75bfc69/x/finality/types/msg.go#L161
    fn validate_basic(&self) -> Result<(), PubRandCommitError> {
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
        if self.start_height >= (self.start_height + self.num_pub_rand) {
            return Err(PubRandCommitError::OverflowInBlockHeight(
                self.start_height,
                self.start_height + self.num_pub_rand,
            ));
        }

        if self.sig.is_empty() {
            return Err(PubRandCommitError::EmptySignature);
        }

        Ok(())
    }

    fn verify_sig(&self, signing_context: String) -> Result<(), PubRandCommitError> {
        let Self {
            fp_btc_pk_hex,
            start_height,
            num_pub_rand,
            commitment,
            sig: signature,
        } = self;

        // get BTC public key for verification
        let btc_pk_raw = hex::decode(fp_btc_pk_hex)?;
        let btc_pk = VerifyingKey::from_bytes(&btc_pk_raw)?;

        let schnorr_sig = Signature::try_from(signature.as_slice())?;

        // get signed message
        let mut msg: Vec<u8> = vec![];
        msg.extend(signing_context.into_bytes());
        msg.extend(start_height.to_be_bytes());
        msg.extend(num_pub_rand.to_be_bytes());
        msg.extend_from_slice(commitment);

        // Verify the signature
        btc_pk.verify(&msg, &schnorr_sig)?;

        Ok(())
    }
}

pub fn handle_public_randomness_commit(
    deps: DepsMut,
    env: &Env,
    pub_rand_commit: MsgCommitPubRand,
) -> Result<Response, ContractError> {
    pub_rand_commit.validate_basic()?;

    let cfg = CONFIG.load(deps.storage)?;

    // Check the commit start height is not too far into the future
    if pub_rand_commit.start_height >= env.block.height + MAX_PUB_RAND_COMMIT_OFFSET {
        return Err(ContractError::FuturePubRandStartHeight {
            start_height: pub_rand_commit.start_height,
            current_height: env.block.height,
            max_offset: MAX_PUB_RAND_COMMIT_OFFSET,
        });
    }

    // Ensure the request contains enough amounts of public randomness
    let min_pub_rand = cfg.min_pub_rand;
    if pub_rand_commit.num_pub_rand < min_pub_rand {
        return Err(ContractError::TooFewPubRand(
            min_pub_rand,
            pub_rand_commit.num_pub_rand,
        ));
    }
    // TODO: ensure log_2(num_pub_rand) is an integer?

    // Ensure the finality provider is registered
    // TODO: Use a raw query for performance and cost (#41)
    let _fp: FinalityProvider = deps
        .querier
        .query_wasm_smart(
            cfg.staking,
            &btc_staking::msg::QueryMsg::FinalityProvider {
                btc_pk_hex: pub_rand_commit.fp_btc_pk_hex.clone(),
            },
        )
        .map_err(|_| {
            ContractError::FinalityProviderNotFound(pub_rand_commit.fp_btc_pk_hex.clone())
        })?;

    let signing_context = babylon_apis::signing_context::fp_rand_commit_context_v0(
        &env.block.chain_id,
        env.contract.address.as_str(),
    );

    // Verify signature over the list
    pub_rand_commit.verify_sig(signing_context)?;

    // Get last public randomness commitment
    // TODO: allow committing public randomness earlier than existing ones?
    let last_pr_commit = get_last_pub_rand_commit(deps.storage, &pub_rand_commit.fp_btc_pk_hex)
        .ok() // Turn error into None
        .flatten();

    // Check for overlapping heights if there is a last commit
    if let Some(last_pr_commit) = last_pr_commit {
        if pub_rand_commit.start_height <= last_pr_commit.end_height() {
            return Err(ContractError::InvalidPubRandHeight(
                pub_rand_commit.start_height,
                last_pr_commit.end_height(),
            ));
        }
    }

    // All good, store the given public randomness commitment
    let MsgCommitPubRand {
        fp_btc_pk_hex,
        start_height,
        num_pub_rand,
        commitment,
        ..
    } = pub_rand_commit;

    let pr_commit = PubRandCommit {
        start_height,
        num_pub_rand,
        height: env.block.height,
        commitment,
    };

    PUB_RAND_COMMITS.save(deps.storage, (&fp_btc_pk_hex, start_height), &pr_commit)?;

    // TODO: Add events (#124)
    Ok(Response::new())
}

/// Returns the message for an EOTS signature
/// The EOTS signature on a block will be (context || blockHeight || blockHash)
fn msg_to_sign_for_vote(context: &str, block_height: u64, block_hash: &[u8]) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(context.as_bytes());
    msg.extend_from_slice(&block_height.to_be_bytes());
    msg.extend_from_slice(block_hash);
    msg
}

/// Finality signature error types.
#[derive(thiserror::Error, Debug, PartialEq)]
pub enum FinalitySigError {
    #[error("empty Finality Provider BTC PubKey")]
    EmptyFpBtcPk,
    #[error("invalid finality provider BTC public key length: got {actual}, want {expected}")]
    InvalidFpBtcPkLength { actual: usize, expected: usize },
    #[error("invalid public randomness length: got {actual}, want {expected}")]
    InvalidPubRandLength { actual: usize, expected: usize },
    #[error("empty inclusion proof")]
    EmptyProof,
    #[error("invalid finality signature length: got {actual}, want {expected}")]
    InvalidFinalitySigLength { actual: usize, expected: usize },
    #[error("invalid block app hash length: got {actual}, want {expected}")]
    InvalidBlockAppHashLength { actual: usize, expected: usize },
    #[error("duplicated finality vote")]
    DuplicatedFinalitySig,
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
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
    fn validate_basic(&self) -> Result<(), FinalitySigError> {
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
    fn verify_finality_signature(
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
        let msg = msg_to_sign_for_vote(signing_context, self.height, &self.block_app_hash);

        let msg_hash = Sha256::digest(msg);

        if !pubkey.verify_hash(&self.pub_rand, msg_hash.into(), &self.signature)? {
            return Err(ContractError::FailedToVerifyEots);
        }

        Ok(())
    }
}

pub fn handle_finality_signature(
    mut deps: DepsMut,
    env: Env,
    add_finality_sig: MsgAddFinalitySig,
) -> Result<Response, ContractError> {
    add_finality_sig.validate_basic()?;

    // Ensure the finality provider exists
    let staking_addr = CONFIG.load(deps.storage)?.staking;
    let fp: FinalityProvider = deps.querier.query_wasm_smart(
        staking_addr.clone(),
        &btc_staking::msg::QueryMsg::FinalityProvider {
            btc_pk_hex: add_finality_sig.fp_btc_pk_hex.clone(),
        },
    )?;

    // Ensure the finality provider is not slashed at this time point
    // NOTE: It's possible that the finality provider equivocates for height h, and the signature is
    // processed at height h' > h. In this case:
    // - We should reject any new signature from this finality provider, since it's known to be adversarial.
    // - We should set its voting power since height h'+1 to be zero, for the same reason.
    // - We should NOT set its voting power between [h, h'] to be zero, since
    //   - Babylon BTC staking ensures safety upon 2f+1 votes, *even if* f of them are adversarial.
    //     This is because as long as a block gets 2f+1 votes, any other block with 2f+1 votes has a
    //     f+1 quorum intersection with this block, contradicting the assumption and leading to
    //     the safety proof.
    //     This ensures slashable safety together with EOTS, thus does not undermine Babylon's security guarantee.
    //   - Due to this reason, when tallying a block, Babylon finalises this block upon 2f+1 votes. If we
    //     modify voting power table in the history, some finality decisions might be contradicting to the
    //     signature set and voting power table.
    //   - To fix the above issue, Babylon has to allow finalised and not-finalised blocks. However,
    //     this means Babylon will lose safety under an adaptive adversary corrupting even 1
    //     finality provider. It can simply corrupt a new finality provider and equivocate a
    //     historical block over and over again, making a previous block not finalisable forever
    if fp.is_slashed() {
        return Err(ContractError::FinalityProviderAlreadySlashed(
            add_finality_sig.fp_btc_pk_hex,
        ));
    }

    let fp_btc_pk_hex = &add_finality_sig.fp_btc_pk_hex;
    let height = add_finality_sig.height;

    // Get the finality provider's voting power at this height (also ensures they have power)
    let voting_power = get_fp_power(deps.storage, height, fp_btc_pk_hex)?;
    if voting_power == 0 {
        return Err(ContractError::NoVotingPower(
            fp_btc_pk_hex.to_string(),
            height,
        ));
    }

    // Ensure the height is proper
    if env.block.height < height {
        return Err(ContractError::HeightTooHigh);
    }

    // Ensure the finality provider has not cast the same vote yet
    let existing_sig = SIGNATURES.may_load(deps.storage, (height, fp_btc_pk_hex))?;
    match existing_sig {
        Some(existing_sig) if existing_sig == add_finality_sig.signature => {
            deps.api.debug(&format!("CONTRACT: handle_finality_signature: Received duplicated finality vote. Height: {height}, Finality Provider: {fp_btc_pk_hex}"));
            // Exactly the same vote already exists, return success to the provider
            // While there is no tx refunding in the contract, an error is still returned for consistency.
            // https://github.com/babylonlabs-io/babylon/blob/80d89b10add5d914f2a7353b725b803b17fb7cc5/x/finality/keeper/msg_server.go#L131
            return Err(FinalitySigError::DuplicatedFinalitySig.into());
        }
        _ => {}
    }

    // Find the timestamped public randomness commitment for this height from this finality provider
    let pr_commit =
        get_timestamped_pub_rand_commit_for_height(&deps.as_ref(), fp_btc_pk_hex, height)?;

    let signing_context = babylon_apis::signing_context::fp_fin_vote_context_v0(
        &env.block.chain_id,
        env.contract.address.as_str(),
    );

    add_finality_sig.verify_finality_signature(&pr_commit, &signing_context)?;

    let MsgAddFinalitySig {
        fp_btc_pk_hex,
        height,
        pub_rand,
        proof: _,
        block_app_hash,
        signature,
    } = add_finality_sig;

    // The public randomness value is good, save it.
    PUB_RAND_VALUES.save(deps.storage, (&fp_btc_pk_hex, height), &pub_rand)?;

    // Verify whether the voted block is a fork or not
    let indexed_block = BLOCKS
        .load(deps.storage, height)
        .map_err(|err| ContractError::BlockNotFound(height, err.to_string()))?;

    let mut res = Response::new();
    if indexed_block.app_hash != block_app_hash {
        // The finality provider votes for a fork!

        // Construct evidence
        let mut evidence = Evidence {
            fp_btc_pk: hex::decode(&fp_btc_pk_hex)?,
            block_height: height,
            pub_rand,
            canonical_app_hash: indexed_block.app_hash,
            canonical_finality_sig: vec![],
            fork_app_hash: block_app_hash,
            fork_finality_sig: signature,
            signing_context,
        };

        // If this finality provider has also signed the canonical block, slash it
        let canonical_sig = SIGNATURES.may_load(deps.storage, (height, &fp_btc_pk_hex))?;
        if let Some(canonical_sig) = canonical_sig {
            // Set canonical sig
            evidence.canonical_finality_sig = canonical_sig;
            // Slash this finality provider, including setting its voting power to zero, extracting
            // its BTC SK, and emitting an event
            let (msg, ev) = slash_finality_provider(&mut deps, &fp_btc_pk_hex, &evidence)?;
            res = res.add_message(msg);
            res = res.add_event(ev);
        }
        // TODO?: Also slash if this finality provider has signed another fork before

        // Save evidence
        EVIDENCES.save(deps.storage, (&fp_btc_pk_hex, height), &evidence)?;

        // NOTE: We should NOT return error here, otherwise the state change triggered in this tx
        // (including the evidence) will be rolled back
        return Ok(res);
    }

    // This signature is good, save the vote to the store
    SIGNATURES.save(deps.storage, (height, &fp_btc_pk_hex), &signature)?;

    // Store the block height this finality provider has signed
    FP_BLOCK_SIGNER.save(deps.storage, &fp_btc_pk_hex, &height)?;

    // If this finality provider has signed the canonical block before, slash it via extracting its
    // secret key, and emit an event
    if let Some(mut evidence) = EVIDENCES.may_load(deps.storage, (&fp_btc_pk_hex, height))? {
        // The finality provider has voted for a fork before!
        // This evidence is at the same height as this signature, slash this finality provider

        // Set canonical sig to this evidence
        evidence.canonical_finality_sig = signature.to_vec();
        EVIDENCES.save(deps.storage, (&fp_btc_pk_hex, height), &evidence)?;

        // Slash this finality provider, including setting its voting power to zero, extracting its
        // BTC SK, and emitting an event
        let (msg, ev) = slash_finality_provider(&mut deps, &fp_btc_pk_hex, &evidence)?;
        res = res.add_message(msg);
        res = res.add_event(ev);
        return Ok(res);
    }

    // Accumulate voting weight for this FP for reward distribution
    ACCUMULATED_VOTING_WEIGHTS.update(deps.storage, &fp_btc_pk_hex, |existing| {
        Ok::<u128, ContractError>(existing.unwrap_or(0) + (voting_power as u128))
    })?;

    Ok(res)
}

pub fn handle_unjail(
    deps: DepsMut,
    env: &Env,
    info: &MessageInfo,
    fp_btc_pk_hex: &str,
) -> Result<Response, ContractError> {
    // Admin can unjail almost anyone
    let is_admin = ADMIN.is_admin(deps.as_ref(), &info.sender)?;

    // Others can unjail only themselves
    // First, ensure the finality provider is jailed
    let jail_until = JAIL.load(deps.storage, fp_btc_pk_hex)?;

    // Ensure the jail is not forever
    if jail_until == JAIL_FOREVER {
        return Err(ContractError::JailedForever {});
    }

    // Ensure the jail period has passed (except for admin)
    if !is_admin && env.block.time.seconds() < jail_until {
        return Err(ContractError::JailPeriodNotPassed(
            fp_btc_pk_hex.to_string(),
        ));
    }

    // Get the finality provider info to check if the sender is the finality provider's
    // operator address in the BSN
    let staking_addr = CONFIG.load(deps.storage)?.staking;
    let fp: FinalityProvider = deps
        .querier
        .query_wasm_smart(
            staking_addr.clone(),
            &btc_staking::msg::QueryMsg::FinalityProvider {
                btc_pk_hex: fp_btc_pk_hex.to_string(),
            },
        )
        .map_err(|_| ContractError::FinalityProviderNotFound(fp_btc_pk_hex.to_string()))?;

    // Compute canonical sender and FP operator addresses
    let sender_canonical_addr = deps.api.addr_canonicalize(info.sender.as_ref())?;
    let fp_canonical_addr = to_canonical_addr(&fp.addr, "bbn")?;
    if !is_admin && sender_canonical_addr != fp_canonical_addr {
        return Err(ContractError::Unauthorized {});
    }

    // Unjail the finality provider
    JAIL.remove(deps.storage, fp_btc_pk_hex);
    // Remove the start height, so that it can be reset
    FP_START_HEIGHT.remove(deps.storage, fp_btc_pk_hex);
    // Remove the last block signing height, so that it can be reset
    FP_BLOCK_SIGNER.remove(deps.storage, fp_btc_pk_hex);

    Ok(Response::new()
        .add_attribute("action", "unjail")
        .add_attribute("fp", fp_btc_pk_hex))
}

/// `slash_finality_provider` slashes a finality provider with the given evidence including setting
/// its voting power to zero, extracting its BTC SK, and emitting an event
fn slash_finality_provider(
    deps: &mut DepsMut,
    fp_btc_pk_hex: &str,
    evidence: &Evidence,
) -> Result<(WasmMsg, Event), ContractError> {
    let pk = eots::PublicKey::from_hex(fp_btc_pk_hex)?;

    let canonical_msg_to_sign = msg_to_sign_for_vote(
        &evidence.signing_context,
        evidence.block_height,
        &evidence.canonical_app_hash,
    );
    let canonical_msg_to_sign_hash = Sha256::digest(&canonical_msg_to_sign);

    let fork_msg_to_sign = msg_to_sign_for_vote(
        &evidence.signing_context,
        evidence.block_height,
        &evidence.fork_app_hash,
    );
    let fork_msg_to_sign_hash = Sha256::digest(&fork_msg_to_sign);

    let btc_sk = pk
        .extract_from_hashes(
            &evidence.pub_rand,
            canonical_msg_to_sign_hash.into(),
            &evidence.canonical_finality_sig,
            fork_msg_to_sign_hash.into(),
            &evidence.fork_finality_sig,
        )
        .map_err(|err| ContractError::SecretKeyExtractionError(err.to_string()))?;

    // Emit slashing event.
    // Raises slashing event to babylon over IBC.
    // Send to babylon-contract for forwarding
    let msg = ExecuteMsg::Slashing {
        evidence: evidence.clone(),
    };

    let babylon_addr = CONFIG.load(deps.storage)?.babylon;

    let wasm_msg = WasmMsg::Execute {
        contract_addr: babylon_addr.to_string(),
        msg: to_json_binary(&msg)?,
        funds: vec![],
    };

    let ev = Event::new("slashed_finality_provider")
        .add_attribute("module", "finality")
        .add_attribute("finality_provider", fp_btc_pk_hex)
        .add_attribute("block_height", evidence.block_height.to_string())
        .add_attribute(
            "canonical_app_hash",
            hex::encode(&evidence.canonical_app_hash),
        )
        .add_attribute(
            "canonical_finality_sig",
            hex::encode(&evidence.canonical_finality_sig),
        )
        .add_attribute("fork_app_hash", hex::encode(&evidence.fork_app_hash))
        .add_attribute(
            "fork_finality_sig",
            hex::encode(&evidence.fork_finality_sig),
        )
        .add_attribute("secret_key", hex::encode(btc_sk.to_bytes()));
    Ok((wasm_msg, ev))
}

pub fn index_block(
    deps: &mut DepsMut,
    height: u64,
    app_hash: &[u8],
) -> Result<Event, ContractError> {
    let indexed_block = IndexedBlock {
        height,
        app_hash: app_hash.into(),
        finalized: false,
    };
    BLOCKS.save(deps.storage, height, &indexed_block)?;

    // Register the indexed block height
    let ev = Event::new("index_block")
        .add_attribute("module", "finality")
        .add_attribute("last_height", height.to_string());
    Ok(ev)
}

/// Tries to finalise all blocks that are non-finalised AND have a non-nil
/// finality provider set, from the earliest to the latest.
///
/// This function is invoked upon each `EndBlock`, after the BTC staking protocol is activated.
/// It ensures that at height `h`, the ancestor chain `[activated_height, h-1]` contains either
/// - finalised blocks (i.e., blocks with a finality provider set AND QC of this finality provider set),
/// - non-finalisable blocks (i.e. blocks with no active finality providers),
///   but no blocks that have a finality provider set and do not receive a QC
///
/// It must be invoked only after the BTC staking protocol is activated.
pub fn tally_blocks(
    deps: &mut DepsMut,
    env: &Env,
    activated_height: u64,
) -> Result<Vec<Event>, ContractError> {
    // Start finalising blocks since max(activated_height, next_height)
    let next_height = NEXT_HEIGHT.may_load(deps.storage)?.unwrap_or(0);
    let start_height = max(activated_height, next_height);

    // Find all blocks that are non-finalised AND have a finality provider set since
    // max(activated_height, last_finalized_height + 1)
    // There are 4 different scenarios:
    // - Has finality providers, non-finalised: Tally and try to finalise.
    // - Does not have finality providers, non-finalised: Non-finalisable, continue.
    // - Has finality providers, finalised: Impossible, panic.
    // - Does not have finality providers, finalised: Impossible, panic.
    // After this for loop, the blocks since the earliest activated height are either finalised or
    // non-finalisable
    let mut events = vec![];
    for h in start_height..=env.block.height {
        let mut indexed_block = BLOCKS.load(deps.storage, h)?;
        // Get the finality provider set of this block
        let fp_power_table = get_power_table_at_height(deps.storage, h)?;
        let has_fp = !fp_power_table.is_empty();

        match (has_fp, indexed_block.finalized) {
            (true, false) => {
                // Has finality providers, non-finalised: tally and try to finalise the block
                let voter_btc_pks = SIGNATURES
                    .prefix(indexed_block.height)
                    .keys(deps.storage, None, None, Ascending)
                    .collect::<StdResult<Vec<_>>>()?;
                if tally(&fp_power_table, &voter_btc_pks) {
                    // If this block gets >2/3 votes, finalise it
                    let ev = finalize_block(deps.storage, &mut indexed_block, &voter_btc_pks)?;
                    events.push(ev);
                } else {
                    // If not, then this block and all subsequent blocks should not be finalised.
                    // Thus, we need to break here
                    break;
                }
            }
            (false, false) => {
                // Does not have finality providers, non-finalised: not finalisable,
                // Increment the next height to finalise and continue
                NEXT_HEIGHT.save(deps.storage, &(indexed_block.height + 1))?;
                continue;
            }
            (true, true) => {
                // Has finality providers and the block is finalised.
                // This can only be a programming error
                return Err(ContractError::FinalisedBlockWithFinalityProviderSet(
                    indexed_block.height,
                ));
            }
            (false, true) => {
                // Does not have finality providers, finalised: impossible to happen
                return Err(ContractError::FinalisedBlockWithoutFinalityProviderSet(
                    indexed_block.height,
                ));
            }
        }
    }

    Ok(events)
}

/// Checks whether a block with the given finality provider set and votes reaches a quorum or not.
fn tally(fp_power_table: &HashMap<String, u64>, voters: &[String]) -> bool {
    let voters: HashSet<_> = voters.iter().collect();
    let mut total_power = 0;
    let mut voted_power = 0;
    for (fp_btc_pk_hex, power) in fp_power_table {
        total_power += power;
        if voters.contains(fp_btc_pk_hex) {
            voted_power += power;
        }
    }
    voted_power * 3 > total_power * 2
}

/// Sets a block to be finalised.
fn finalize_block(
    store: &mut dyn Storage,
    block: &mut IndexedBlock,
    _voters: &[String],
) -> Result<Event, ContractError> {
    // Set block to be finalised
    block.finalized = true;
    BLOCKS.save(store, block.height, block)?;

    // Set the next height to finalise as height+1
    NEXT_HEIGHT.save(store, &(block.height + 1))?;

    // Record the last finalized height metric
    let ev = Event::new("finalize_block")
        .add_attribute("module", "finality")
        .add_attribute("finalized_height", block.height.to_string());
    Ok(ev)
}

/// Sorts all finality providers, counts the total voting power of top finality providers, and records them
/// in the contract state.
pub fn compute_active_finality_providers(
    deps: &mut DepsMut,
    env: &Env,
    max_active_fps: usize,
) -> Result<(), ContractError> {
    let cfg = CONFIG.load(deps.storage)?;
    // Get last finalized height (for timestamped public randomness checks)
    let last_finalized_height = get_last_finalized_height(&deps.as_ref())?;

    // Get all finality providers from the staking contract, filtered
    let mut batch = query_fps_by_total_active_sats(&cfg.staking, &deps.querier, None, QUERY_LIMIT)?;

    let mut fp_power_table = HashMap::new();
    let mut total_power: u64 = 0;
    while !batch.is_empty() && fp_power_table.len() < max_active_fps {
        let last = batch.last().cloned();

        let (filtered, running_total): (Vec<_>, Vec<_>) = batch
            .into_iter()
            .filter(|fp| {
                // Filter out FPs with no active sats
                if fp.total_active_sats == 0 {
                    return false;
                }
                // Filter out slashed FPs
                if fp.slashed {
                    return false;
                }
                // Filter out FPs that are jailed.
                // Error (shouldn't happen) is being mapped to "jailed forever"
                if JAIL
                    .may_load(deps.storage, &fp.btc_pk_hex)
                    .unwrap_or(Some(JAIL_FOREVER))
                    .is_some()
                {
                    return false;
                }
                // Filter out FPs that don't have timestamped public randomness
                if !has_timestamped_pub_rand_commit_for_height(
                    &deps.as_ref(),
                    &fp.btc_pk_hex,
                    env.block.height,
                    Some(last_finalized_height),
                ) {
                    return false;
                }

                true
            })
            .scan(total_power, |acc, fp| {
                *acc += fp.total_active_sats;
                Some((fp, *acc))
            })
            .unzip();

        // Add the filtered finality providers to the power table
        for fp in filtered {
            fp_power_table.insert(fp.btc_pk_hex, fp.total_active_sats);
        }
        // Update the total power
        total_power = running_total.last().copied().unwrap_or_default();

        // and get the next page
        batch = query_fps_by_total_active_sats(&cfg.staking, &deps.querier, last, QUERY_LIMIT)?;
    }

    // Online FPs verification
    // Store starting heights of fps entering the active set
    let old_power_table = get_power_table_at_height(deps.storage, env.block.height - 1)?;
    let old_fps = old_power_table.keys().collect();
    let cur_fps: HashSet<_> = fp_power_table.keys().collect();
    let new_fps = cur_fps.difference(&old_fps);
    for fp in new_fps {
        // Active since the next block. Only save if not already set
        FP_START_HEIGHT.update(deps.storage, fp, |h| match h {
            Some(h) => Ok::<_, ContractError>(h),
            None => Ok(env.block.height + 1),
        })?;
    }

    // Check for inactive finality providers, and jail them
    fp_power_table.iter().try_for_each(|(fp_btc_pk_hex, _)| {
        let last_sign_height = get_last_signed_height(deps.storage, fp_btc_pk_hex)?;
        match last_sign_height {
            Some(h) if h > env.block.height.saturating_sub(cfg.missed_blocks_window) => {
                Ok::<_, ContractError>(())
            }
            _ => {
                // FP is inactive for at least missed_blocks_window, jail! (if not already jailed)
                JAIL.update(deps.storage, fp_btc_pk_hex, |jailed| match jailed {
                    Some(jail_time) => Ok::<_, ContractError>(jail_time),
                    None => Ok(env.block.time.seconds() + cfg.jail_duration),
                })?;
                Ok(())
            }
        }
    })?;

    // Save the new set of active finality providers
    for (fp_btc_pk_hex, power) in fp_power_table {
        FP_POWER_TABLE.save(
            deps.storage,
            (env.block.height, fp_btc_pk_hex.as_str()),
            &power,
        )?;
    }

    Ok(())
}

/// Queries the BTC staking contract for finality providers ordered by total active sats.
pub fn query_fps_by_total_active_sats(
    staking_addr: &Addr,
    querier: &QuerierWrapper,
    start_after: Option<FinalityProviderInfo>,
    limit: Option<u32>,
) -> StdResult<Vec<FinalityProviderInfo>> {
    let query = encode_smart_query(
        staking_addr,
        &btc_staking::msg::QueryMsg::FinalityProvidersByTotalActiveSats { start_after, limit },
    )?;
    let res: FinalityProvidersByTotalActiveSatsResponse = querier.query(&query)?;
    Ok(res.fps)
}

/// Calculates and returns reward distribution directly without storing in REWARDS.
/// Returns only the reward info vector - caller constructs WasmMsg as needed.
pub fn handle_rewards_distribution(
    deps: &mut DepsMut,
    env: &Env,
) -> Result<Response, ContractError> {
    let cfg = CONFIG.load(deps.storage)?;

    // Get current balance of the finality contract (total rewards to distribute)
    let current_balance = deps
        .querier
        .query_balance(env.contract.address.clone(), cfg.denom.clone())?
        .amount;

    if current_balance.is_zero() {
        // No rewards to distribute, return empty response
        return Ok(Response::new());
    }

    // Collect all accumulated voting weights and calculate total in one pass
    let (fp_entries, total_accumulated_weight) = collect_accumulated_voting_weights(deps.storage)?;

    if fp_entries.is_empty() || total_accumulated_weight.is_zero() {
        // No accumulated voting weights, clear them and return empty response
        ACCUMULATED_VOTING_WEIGHTS.clear(deps.storage);
        return Ok(Response::new());
    }

    // Calculate rewards proportionally and build reward info directly
    let mut fp_rewards = Vec::new();
    let mut total_rewards = 0u128;

    for (fp_btc_pk_hex, accumulated_weight) in fp_entries {
        // Use Uint128 arithmetic for safe multiplication and division with floor division
        let numerator = current_balance.checked_mul(accumulated_weight)?;
        let reward = numerator.div_floor((total_accumulated_weight, Uint128::one()));

        if !reward.is_zero() {
            fp_rewards.push(RewardInfo {
                fp_pubkey_hex: fp_btc_pk_hex,
                reward,
            });
            total_rewards += reward.u128();
        }
    }

    // Clear all accumulated voting weights for the next reward interval
    ACCUMULATED_VOTING_WEIGHTS.clear(deps.storage);

    // If there are rewards to distribute, create and add the message
    let mut res = Response::new();
    if !fp_rewards.is_empty() {
        let msg = RewardsDistribution {
            fp_distribution: fp_rewards,
        };
        let wasm_msg = WasmMsg::Execute {
            contract_addr: cfg.babylon.to_string(),
            msg: cosmwasm_std::to_json_binary(&msg)?,
            funds: cosmwasm_std::coins(total_rewards, cfg.denom.as_str()),
        };
        res = res.add_message(wasm_msg);
    }

    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    // Helper function to generate random bytes
    fn gen_random_bytes(rng: &mut StdRng, len: usize) -> Vec<u8> {
        (0..len).map(|_| rng.gen()).collect()
    }

    // https://github.com/babylonlabs-io/babylon/blob/49972e2d3e35caf0a685c37e1f745c47b75bfc69/x/finality/types/msg_test.go#L167
    #[test]
    fn test_msg_add_finality_sig_validate_basic() {
        let mut rng = StdRng::seed_from_u64(1);

        struct TestCase {
            name: &'static str,
            msg_modifier: fn(&mut MsgAddFinalitySig),
            expected: Result<(), FinalitySigError>,
        }

        let test_cases = vec![
            TestCase {
                name: "valid message",
                // No modification needed for valid message
                msg_modifier: |_| {},
                expected: Ok(()),
            },
            TestCase {
                name: "empty FP BTC PubKey",
                msg_modifier: |msg| msg.fp_btc_pk_hex.clear(),
                expected: Err(FinalitySigError::EmptyFpBtcPk),
            },
            TestCase {
                name: "invalid FP BTC PubKey length",
                msg_modifier: |msg| {
                    msg.fp_btc_pk_hex = hex::encode(vec![0u8; 16]); // Too short
                },
                expected: Err(FinalitySigError::InvalidFpBtcPkLength {
                    actual: 16,
                    expected: 32,
                }),
            },
            TestCase {
                name: "empty Public Randomness",
                msg_modifier: |msg| msg.pub_rand.clear(),
                expected: Err(FinalitySigError::InvalidPubRandLength {
                    actual: 0,
                    expected: 32,
                }),
            },
            TestCase {
                name: "invalid Public Randomness length",
                msg_modifier: |msg| {
                    msg.pub_rand = vec![0u8; 16]; // Too short
                },
                expected: Err(FinalitySigError::InvalidPubRandLength {
                    actual: 16,
                    expected: 32,
                }),
            },
            TestCase {
                name: "empty finality signature",
                msg_modifier: |msg| msg.signature.clear(),
                expected: Err(FinalitySigError::InvalidFinalitySigLength {
                    actual: 0,
                    expected: 32,
                }),
            },
            TestCase {
                name: "invalid finality signature length",
                msg_modifier: |msg| {
                    msg.signature = vec![0u8; 16]; // Too short
                },
                expected: Err(FinalitySigError::InvalidFinalitySigLength {
                    actual: 16,
                    expected: 32,
                }),
            },
            TestCase {
                name: "invalid block app hash length",
                msg_modifier: |msg| {
                    msg.block_app_hash = vec![0u8; 16]; // Too short
                },
                expected: Err(FinalitySigError::InvalidBlockAppHashLength {
                    actual: 16,
                    expected: 32,
                }),
            },
        ];

        for TestCase {
            name,
            msg_modifier,
            expected,
        } in test_cases
        {
            // Create a valid message
            let mut msg = MsgAddFinalitySig {
                fp_btc_pk_hex: hex::encode(gen_random_bytes(&mut rng, BIP340_PUB_KEY_LEN)),
                height: rng.gen_range(1..1000),
                pub_rand: gen_random_bytes(&mut rng, SCHNORR_PUB_RAND_LEN),
                proof: Proof {
                    total: 0,
                    index: 0,
                    leaf_hash: Default::default(),
                    aunts: Default::default(),
                },
                block_app_hash: gen_random_bytes(&mut rng, TMHASH_SIZE),
                signature: gen_random_bytes(&mut rng, SCHNORR_EOTS_SIG_LEN),
            };

            // Apply the test case modifier
            msg_modifier(&mut msg);

            assert_eq!(msg.validate_basic(), expected, "Test case failed: {}", name);
        }
    }
}
