use crate::error::{ContractError, FinalitySigError};
use crate::msg::{MsgAddFinalitySig, MsgCommitPubRand};
use crate::state::config::{ADMIN, CONFIG};
use crate::state::finality::{
    collect_accumulated_voting_weights, get_fp_power, is_fp_jailed, ACCUMULATED_VOTING_WEIGHTS,
    BLOCKS, EVIDENCES, FP_BLOCK_SIGNER, FP_START_HEIGHT, JAIL, SIGNATURES,
};
use crate::state::public_randomness::{
    get_last_pub_rand_commit, get_timestamped_pub_rand_commit_for_height, PUB_RAND_COMMITS,
    PUB_RAND_VALUES,
};
use babylon_apis::btc_staking_api::FinalityProvider;
use babylon_apis::finality_api::{Evidence, IndexedBlock, PubRandCommit};
use babylon_apis::to_canonical_addr;
use babylon_contract::msg::contract::{ExecuteMsg, RewardInfo};
use cosmwasm_logging::debug;
use cosmwasm_std::{
    coins, to_json_binary, DepsMut, Env, Event, MessageInfo, Response, Uint128, WasmMsg,
};

// The maximum number of blocks into the future
// that a public randomness commitment start height can target. This limit prevents abuse by capping
// the size of the commitments index, protecting against potential memory exhaustion
// or performance degradation caused by excessive future commitments.
const MAX_PUB_RAND_COMMIT_OFFSET: u64 = 160_000;

/// Validates that the given height is not lower than the finality activation height.
/// Returns error if the height received is lower than the finality activation block height.
fn validate_finality_activation(height: u64, activation_height: u64) -> Result<(), ContractError> {
    if height < activation_height {
        return Err(ContractError::FinalityNotActivated {
            height,
            activation_height,
        });
    }

    Ok(())
}

pub fn handle_public_randomness_commit(
    deps: DepsMut,
    env: &Env,
    pub_rand_commit: MsgCommitPubRand,
) -> Result<Response, ContractError> {
    pub_rand_commit.validate_basic()?;

    let cfg = CONFIG.load(deps.storage)?;

    validate_finality_activation(pub_rand_commit.start_height, cfg.finality_activation_height)?;

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
pub(crate) fn msg_to_sign_for_vote(context: &str, block_height: u64, block_hash: &[u8]) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(context.as_bytes());
    msg.extend_from_slice(&block_height.to_be_bytes());
    msg.extend_from_slice(block_hash);
    msg
}

pub fn handle_finality_signature(
    mut deps: DepsMut,
    env: Env,
    add_finality_sig: MsgAddFinalitySig,
) -> Result<Response, ContractError> {
    add_finality_sig.validate_basic()?;

    let cfg = CONFIG.load(deps.storage)?;

    validate_finality_activation(add_finality_sig.height, cfg.finality_activation_height)?;

    // Ensure the finality provider exists
    let staking_addr = cfg.staking;
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
    // NOTE: Returning slashed error explicitly is necessary for FPs to update their states
    if fp.is_slashed() {
        return Err(ContractError::FinalityProviderAlreadySlashed(
            add_finality_sig.fp_btc_pk_hex,
        ));
    }

    // Ensure the finality provider is not jailed
    // NOTE: Returning jailed error explicitly is necessary for FPs to update their states
    if is_fp_jailed(deps.storage, &add_finality_sig.fp_btc_pk_hex) {
        return Err(ContractError::FinalityProviderAlreadyJailed(
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
            debug!("handle_finality_signature: Received duplicated finality vote. Height: {height}, Finality Provider: {fp_btc_pk_hex}");
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
        // following https://github.com/babylonlabs-io/babylon/blob/4aa85a8d9bf85771d448cd3026e99962fe0dab8e/x/finality/keeper/msg_server.go#L150-L192

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
    // following https://github.com/babylonlabs-io/babylon/blob/4aa85a8d9bf85771d448cd3026e99962fe0dab8e/x/finality/keeper/msg_server.go#L204-L236
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
/// its voting power to zero and emitting an event
/// following https://github.com/babylonlabs-io/babylon/blob/4aa85a8d9bf85771d448cd3026e99962fe0dab8e/x/finality/keeper/msg_server.go#L384-L412 without the logic for propagating the slashing event to other BSNs
fn slash_finality_provider(
    deps: &mut DepsMut,
    fp_btc_pk_hex: &str,
    evidence: &Evidence,
) -> Result<(WasmMsg, Event), ContractError> {
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
        );

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

/// Handles finality provider reward distribution based on accumulated voting weights.
///
/// This function is called periodically (based on `reward_interval` configuration) to distribute
/// rewards to finality providers proportionally based on their accumulated voting power since the
/// last distribution. The function calculates rewards from the contract's current balance and
/// creates a message to send rewards to the Babylon contract for distribution.
pub fn handle_rewards_distribution(
    deps: &mut DepsMut,
    env: &Env,
) -> Result<Option<WasmMsg>, ContractError> {
    let cfg = CONFIG.load(deps.storage)?;

    // Get current balance of the finality contract (total rewards to distribute)
    let current_balance = deps
        .querier
        .query_balance(env.contract.address.clone(), cfg.denom.clone())?
        .amount;

    if current_balance.is_zero() {
        // No rewards to distribute, return None
        return Ok(None);
    }

    // Collect all accumulated voting weights and calculate total in one pass
    let (fp_entries, total_accumulated_weight) = collect_accumulated_voting_weights(deps.storage)?;

    if fp_entries.is_empty() || total_accumulated_weight.is_zero() {
        // No accumulated voting weights, clear them and return None
        ACCUMULATED_VOTING_WEIGHTS.clear(deps.storage);
        return Ok(None);
    }

    // Calculate rewards proportionally and build reward info directly
    let mut fp_rewards = Vec::new();
    let mut total_rewards = Uint128::zero();

    for (fp_btc_pk_hex, accumulated_weight) in fp_entries {
        // Use Uint128 arithmetic for safe multiplication and division with floor division
        let numerator = current_balance.checked_mul(accumulated_weight)?;
        let reward = numerator.div_floor((total_accumulated_weight, Uint128::one()));

        if !reward.is_zero() {
            fp_rewards.push(RewardInfo {
                fp_pubkey_hex: fp_btc_pk_hex,
                reward,
            });
            total_rewards = total_rewards.checked_add(reward)?;
        }
    }

    // Clear all accumulated voting weights for the next reward interval
    ACCUMULATED_VOTING_WEIGHTS.clear(deps.storage);

    // If there are rewards to distribute, create and return the message
    if fp_rewards.is_empty() {
        return Ok(None);
    }

    let msg = ExecuteMsg::RewardsDistribution {
        fp_distribution: fp_rewards,
    };
    let wasm_msg = WasmMsg::Execute {
        contract_addr: cfg.babylon.to_string(),
        msg: to_json_binary(&msg)?,
        funds: coins(total_rewards.u128(), cfg.denom.as_str()),
    };

    Ok(Some(wasm_msg))
}
