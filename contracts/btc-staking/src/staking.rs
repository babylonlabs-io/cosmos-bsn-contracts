use bitcoin::absolute::LockTime;
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::{Transaction, Txid};
use cosmwasm_std::{
    coin, BankMsg, CanonicalAddr, CosmosMsg, DepsMut, Env, Event, IbcMsg, MessageInfo, Order,
    Response, StdResult, Storage, Uint128, Uint256,
};
use cw_storage_plus::Bound;
use hex::ToHex;

use crate::error::ContractError;
use crate::state::config::{Config, ADMIN, CONFIG, PARAMS};
use crate::state::delegations::{delegations, DelegationDistribution};
use crate::state::staking::{
    fps, BtcDelegation, DelegatorUnbondingInfo, FinalityProviderState, ACTIVATED_HEIGHT,
    BTC_DELEGATIONS, BTC_DELEGATION_EXPIRY_INDEX, DELEGATION_FPS, FPS, FP_DELEGATIONS,
};
use crate::validation::{
    verify_active_delegation, verify_new_fp, verify_slashed_delegation, verify_undelegation,
};
use babylon_apis::btc_staking_api::{
    ActiveBtcDelegation, FinalityProvider, NewFinalityProvider, RewardInfo, SlashedBtcDelegation,
    UnbondedBtcDelegation, HASH_SIZE,
};
use babylon_apis::{to_canonical_addr, Validate};
use babylon_bindings::BabylonMsg;
use babylon_contract::ibc::packet_timeout;
use babylon_contract::msg::ibc::TransferInfoResponse;
use btc_light_client::msg::btc_header::BtcHeaderResponse;
use cw_utils::{must_pay, nonpayable};
use std::str::FromStr;

pub const DISTRIBUTION_POINTS_SCALE: Uint256 = Uint256::from_u128(1_000_000_000);

/// handle_btc_staking handles the BTC staking operations
pub fn handle_btc_staking(
    deps: DepsMut,
    env: Env,
    info: &MessageInfo,
    new_fps: &[NewFinalityProvider],
    active_delegations: &[ActiveBtcDelegation],
    slashed_delegations: &[SlashedBtcDelegation],
    unbonded_delegations: &[UnbondedBtcDelegation],
) -> Result<Response<BabylonMsg>, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    if info.sender != config.babylon && !ADMIN.is_admin(deps.as_ref(), &info.sender)? {
        return Err(ContractError::Unauthorized);
    }

    let mut res = Response::new();

    for fp in new_fps {
        handle_new_fp(deps.storage, fp, env.block.height)?;
        // TODO: Add event (#124)
    }

    // Process active delegations
    for del in active_delegations {
        handle_active_delegation(deps.storage, env.block.height, del)?;
        // TODO: Add event (#124)
    }

    // Process slashed delegations
    for del in slashed_delegations {
        let ev = handle_slashed_delegation(deps.storage, env.block.height, del)?;
        res = res.add_event(ev);
    }

    // Process undelegations
    for undel in unbonded_delegations {
        let ev = handle_undelegation(deps.storage, env.block.height, undel)?;
        res = res.add_event(ev);
    }

    Ok(res)
}

/// handle_bew_fp handles registering a new finality provider
pub fn handle_new_fp(
    storage: &mut dyn Storage,
    new_fp: &NewFinalityProvider,
    height: u64,
) -> Result<(), ContractError> {
    // Avoid overwriting existing finality providers
    if FPS.has(storage, &new_fp.btc_pk_hex) {
        return Err(ContractError::FinalityProviderAlreadyExists(
            new_fp.btc_pk_hex.clone(),
        ));
    }
    // basic validations on the finality provider data
    new_fp.validate()?;

    // verify the finality provider registration request (full or lite)
    verify_new_fp(new_fp)?;

    // get DB object
    let fp = FinalityProvider::from(new_fp);

    // save to DB
    FPS.save(storage, &fp.btc_pk_hex, &fp)?;
    // Set its voting power to zero
    let fp_state = FinalityProviderState::default();
    fps().save(storage, &fp.btc_pk_hex, &fp_state, height)?;

    Ok(())
}

pub fn handle_active_delegation(
    storage: &mut dyn Storage,
    height: u64,
    active_delegation: &ActiveBtcDelegation,
) -> Result<(), ContractError> {
    // TODO: Get params / improve active delegation validation (related to #7.2)
    // btc_confirmation_depth
    // checkpoint_finalization_timeout
    // minimum_unbonding_time

    let params = PARAMS.load(storage)?;

    // Basic stateless checks
    active_delegation.validate()?;

    // TODO: Ensure all finality providers
    // - Are not slashed. (done)
    // - They have timestamped public randomness (#130)

    // Parse staking tx
    let staking_tx: Transaction = deserialize(&active_delegation.staking_tx)
        .map_err(|_| ContractError::InvalidBtcTx(active_delegation.staking_tx.encode_hex()))?;
    // Check staking time is at most uint16
    match staking_tx.lock_time {
        LockTime::Blocks(b) if b.to_consensus_u32() > u16::MAX as u32 => {
            return Err(ContractError::ErrInvalidLockTime(
                b.to_consensus_u32(),
                u16::MAX as u32,
            ));
        }
        LockTime::Blocks(_) => {}
        LockTime::Seconds(_) => {
            return Err(ContractError::ErrInvalidLockType);
        }
    }
    // Get staking tx hash
    let staking_tx_hash = staking_tx.compute_txid();

    // Check staking tx is not duplicated
    if BTC_DELEGATIONS.has(storage, staking_tx_hash.as_ref()) {
        return Err(ContractError::DelegationAlreadyExists(
            staking_tx_hash.to_string(),
        ));
    }

    // verify the active delegation (full or lite)
    verify_active_delegation(&params, active_delegation, &staking_tx)?;

    // All good, construct BTCDelegation and insert BTC delegation
    // NOTE: the BTC delegation does not have voting power yet.
    // It will have voting power only when
    // 1) Its corresponding staking tx is k-deep.
    // 2) It receives a covenant signature.

    // Get canonical address
    let canonical_addr = to_canonical_addr(&active_delegation.staker_addr, "bbn")?;

    // Update delegations by registered finality provider
    let fps = fps();
    let mut registered_fp = false;
    for fp_btc_pk_hex in &active_delegation.fp_btc_pk_list {
        // Skip if finality provider is not registered, as it can belong to another Consumer,
        // or Babylon
        if !FPS.has(storage, fp_btc_pk_hex) {
            continue;
        }

        // Skip slashed FPs
        let fp = FPS.load(storage, fp_btc_pk_hex)?;
        if fp.slashed_height > 0 {
            continue;
        }

        // Update staking tx hash by finality provider map
        let mut fp_delegations = FP_DELEGATIONS
            .may_load(storage, fp_btc_pk_hex)?
            .unwrap_or(vec![]);
        fp_delegations.push(staking_tx_hash.as_byte_array().to_vec());
        FP_DELEGATIONS.save(storage, fp_btc_pk_hex, &fp_delegations)?;

        // Update finality provider by staking tx hash reverse map
        let mut delegation_fps = DELEGATION_FPS
            .may_load(storage, staking_tx_hash.as_ref())?
            .unwrap_or(vec![]);
        delegation_fps.push(fp_btc_pk_hex.clone());
        DELEGATION_FPS.save(storage, staking_tx_hash.as_ref(), &delegation_fps)?;

        // Load FP state
        let mut fp_state = fps.load(storage, fp_btc_pk_hex)?;
        // Update aggregated voting power by FP
        fp_state.power = fp_state.power.saturating_add(active_delegation.total_sat);

        // Create delegation distribution info. Fail if it already exists
        delegations().create_distribution(
            storage,
            staking_tx_hash,
            fp_btc_pk_hex,
            &canonical_addr,
            active_delegation.total_sat,
        )?;

        // Save FP state
        fps.save(storage, fp_btc_pk_hex, &fp_state, height)?;

        registered_fp = true;
    }

    if !registered_fp {
        return Err(ContractError::FinalityProviderNotRegistered);
    }
    // Add this BTC delegation
    let delegation = BtcDelegation::from(active_delegation);
    BTC_DELEGATIONS.save(storage, staking_tx_hash.as_ref(), &delegation)?;

    // Store activated height, if first delegation
    if ACTIVATED_HEIGHT.may_load(storage)?.is_none() {
        ACTIVATED_HEIGHT.save(storage, &(height + 1))?; // Active from the next block onwards
    }

    // Index the delegation by its end height
    BTC_DELEGATION_EXPIRY_INDEX.update(
        storage,
        delegation.end_height,
        |existing| -> Result<_, ContractError> {
            let mut dels = existing.unwrap_or_default();
            let hash_bytes: [u8; HASH_SIZE] = *staking_tx_hash.as_ref();
            dels.push(hash_bytes);
            Ok(dels)
        },
    )?;

    // TODO: Emit corresponding events (#124)

    Ok(())
}

/// handle_undelegation handles undelegation from an active delegation
fn handle_undelegation(
    storage: &mut dyn Storage,
    height: u64,
    undelegation: &UnbondedBtcDelegation,
) -> Result<Event, ContractError> {
    // Basic stateless checks
    undelegation.validate()?;

    let staking_tx_hash = Txid::from_str(&undelegation.staking_tx_hash)?;
    let mut btc_del = BTC_DELEGATIONS.load(storage, staking_tx_hash.as_ref())?;

    // Ensure the BTC delegation is active
    if !btc_del.is_active() {
        return Err(ContractError::DelegationIsNotActive(
            staking_tx_hash.to_string(),
        ));
    }

    // verify the early unbonded delegation (full or lite)
    let params = PARAMS.load(storage)?;
    verify_undelegation(&params, &btc_del, &undelegation.unbonding_tx_sig)?;

    // Add the signature to the BTC delegation's undelegation and set back
    btc_undelegate(storage, &staking_tx_hash, &mut btc_del)?;

    // Discount the voting power from the affected finality providers
    discount_delegation_power(storage, height, staking_tx_hash.as_ref(), &btc_del)?;
    // Record event that the BTC delegation becomes unbonded
    let unbonding_event = Event::new("btc_undelegation")
        .add_attribute("staking_tx_hash", staking_tx_hash.to_string())
        .add_attribute("height", height.to_string());

    Ok(unbonding_event)
}

/// handle_slashed_delegation handles undelegation due to slashing from an active delegation
///
fn handle_slashed_delegation(
    storage: &mut dyn Storage,
    height: u64,
    delegation: &SlashedBtcDelegation,
) -> Result<Event, ContractError> {
    // Basic stateless checks
    delegation.validate()?;

    let staking_tx_hash = Txid::from_str(&delegation.staking_tx_hash)?;
    let mut btc_del = BTC_DELEGATIONS.load(storage, staking_tx_hash.as_ref())?;

    // Ensure the BTC delegation is active
    if !btc_del.is_active() {
        return Err(ContractError::DelegationIsNotActive(
            staking_tx_hash.to_string(),
        ));
    }

    // verify the slashed delegation (full or lite)
    let recovered_fp_sk_hex = delegation.recovered_fp_btc_sk.clone();
    verify_slashed_delegation(&btc_del, &recovered_fp_sk_hex)?;

    // Discount the voting power from the affected finality providers
    let affected_fps = DELEGATION_FPS.load(storage, staking_tx_hash.as_ref())?;
    let fps = fps();
    for fp_pubkey_hex in affected_fps {
        let mut fp_state = fps.load(storage, &fp_pubkey_hex)?;
        fp_state.power = fp_state.power.saturating_sub(btc_del.total_sat);

        // Distribution alignment
        delegations().reduce_distribution(
            storage,
            staking_tx_hash,
            &fp_pubkey_hex,
            btc_del.total_sat,
        )?;

        // Save FP state
        fps.save(storage, &fp_pubkey_hex, &fp_state, height)?;
    }

    // Mark the delegation as slashed
    btc_del.slashed = true;
    BTC_DELEGATIONS.save(storage, staking_tx_hash.as_ref(), &btc_del)?;

    // Record event that the BTC delegation becomes unbonded due to slashing at this height
    let slashing_event = Event::new("btc_undelegation_slashed")
        .add_attribute("staking_tx_hash", staking_tx_hash.to_string())
        .add_attribute("height", height.to_string());

    Ok(slashing_event)
}

/// handle_slash_fp handles FP slashing at the staking level
pub fn handle_slash_fp(
    deps: DepsMut,
    env: Env,
    info: &MessageInfo,
    fp_btc_pk_hex: &str,
) -> Result<Response<BabylonMsg>, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    if info.sender != config.babylon && !ADMIN.is_admin(deps.as_ref(), &info.sender)? {
        return Err(ContractError::Unauthorized);
    }
    slash_finality_provider(deps, env, fp_btc_pk_hex)
}

pub fn process_expired_btc_delegations(
    deps: DepsMut,
    env: Env,
) -> Result<Response<BabylonMsg>, ContractError> {
    // Get the current BTC tip height
    let tip_height = match get_btc_tip_height(&deps) {
        Ok(height) => height,
        Err(e) => {
            // TODO: Currently if no BTC headers exist, the tip will be empty and query fails.
            // However, when we insert BSN base BTC header during instantiate, that will ensure
            // the tip can never be empty as the tip will be at most the base header.
            // We should propagate this error instead of silently returning.
            // See https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/114
            deps.api
                .debug(&format!("Failed to get BTC tip height: {}", e));
            return Ok(Response::new()
                .add_attribute("action", "process_expired_delegations")
                .add_attribute("result", "skipped")
                .add_attribute("reason", "no_btc_tip"));
        }
    };

    // Get all heights that have expired delegations (heights <= current tip height)
    // Use a bounded range query to efficiently load only the heights we need
    let heights: Vec<u32> = BTC_DELEGATION_EXPIRY_INDEX
        .keys(
            deps.storage,
            None,                               // min bound (start from lowest height)
            Some(Bound::inclusive(tip_height)), // max bound (up to current tip height)
            Order::Ascending,
        )
        .collect::<StdResult<Vec<_>>>()?;

    // If no expired delegations are found, return early
    if heights.is_empty() {
        return Ok(Response::new()
            .add_attribute("action", "process_expired_delegations")
            .add_attribute("result", "no_action")
            .add_attribute("reason", "no_expired_delegations"));
    }

    // Process all expired heights (all heights less than or equal to current tip)
    for btc_height in heights {
        if let Some(expired_dels) =
            BTC_DELEGATION_EXPIRY_INDEX.may_load(deps.storage, btc_height)?
        {
            for staking_tx_hash in expired_dels {
                let btc_del = BTC_DELEGATIONS.load(deps.storage, &staking_tx_hash)?;

                // Only process active delegations
                if btc_del.is_active() {
                    // Update delegation power
                    discount_delegation_power(
                        deps.storage,
                        env.block.height,
                        &staking_tx_hash,
                        &btc_del,
                    )?;
                }
            }

            // Remove the processed height from the index to avoid reprocessing
            BTC_DELEGATION_EXPIRY_INDEX.remove(deps.storage, btc_height);
        }
    }

    Ok(Response::new()
        .add_attribute("action", "process_expired_delegations")
        .add_attribute("result", "success"))
}

fn discount_delegation_power(
    storage: &mut dyn Storage,
    height: u64,
    staking_tx_hash: &[u8; HASH_SIZE],
    btc_del: &BtcDelegation,
) -> Result<(), ContractError> {
    let affected_fps = DELEGATION_FPS.load(storage, staking_tx_hash)?;
    let fps = fps();

    for fp_pubkey_hex in affected_fps {
        // Load FP state
        let mut fp_state = fps
            .load(storage, &fp_pubkey_hex)
            .map_err(|_| ContractError::FinalityProviderNotFound(fp_pubkey_hex.clone()))?;

        // Update aggregated voting power by FP
        fp_state.power = fp_state.power.saturating_sub(btc_del.total_sat);

        // Load delegation
        let mut delegation = delegations()
            .delegation
            .load(storage, (staking_tx_hash, &fp_pubkey_hex))?;

        // Subtract amount, saturating if slashed
        delegation.stake = delegation.stake.saturating_sub(btc_del.total_sat);

        // Save delegation
        delegations()
            .delegation
            .save(storage, (staking_tx_hash, &fp_pubkey_hex), &delegation)?;

        // Save / update FP state
        fps.save(storage, &fp_pubkey_hex, &fp_state, height)?;
    }

    Ok(())
}

pub fn handle_distribute_rewards(
    mut deps: DepsMut,
    env: &Env,
    info: &MessageInfo,
    rewards: &[RewardInfo],
) -> Result<Vec<Event>, ContractError> {
    let config = CONFIG.load(deps.storage)?;

    // Check that the sender is the finality contract (AML)
    if info.sender != config.finality {
        return Err(ContractError::Unauthorized);
    }

    // Error if no proper funds to distribute
    let amount = must_pay(info, &config.denom)?;

    // Check that the total rewards match sent funds
    let total_amount: Uint128 = rewards.iter().map(|r| r.reward).sum();
    if total_amount != amount {
        return Err(ContractError::InvalidRewardsAmount(amount, total_amount));
    }

    rewards
        .iter()
        .map(|reward_info| {
            distribute_rewards(
                &mut deps,
                &reward_info.fp_pubkey_hex,
                reward_info.reward,
                env.block.height,
            )
        })
        .collect()
}

fn distribute_rewards(
    deps: &mut DepsMut,
    fp: &str,
    amount: Uint128,
    height: u64,
) -> Result<Event, ContractError> {
    // Load fp distribution info
    let mut fp_distribution = fps().load(deps.storage, fp)?;

    let total_stake = Uint256::from(fp_distribution.power);
    let points_distributed =
        Uint256::from(amount) * DISTRIBUTION_POINTS_SCALE + fp_distribution.points_leftover;
    let points_per_stake = points_distributed / total_stake;

    fp_distribution.points_leftover = points_distributed - points_per_stake * total_stake;
    fp_distribution.points_per_stake += points_per_stake;

    fps().save(deps.storage, fp, &fp_distribution, height)?;

    let event = Event::new("distribute_rewards")
        .add_attribute("fp", fp)
        .add_attribute("amount", amount.to_string());
    Ok(event)
}

/// Withdraw rewards from BTC staking via given FP.
///
/// `staker_addr` is the Babylon address to receive the rewards.
/// `fp_pubkey_hex` is the public key of the FP to withdraw rewards from.
pub fn handle_withdraw_rewards(
    mut deps: DepsMut,
    env: &Env,
    info: &MessageInfo,
    fp_pubkey_hex: &str,
    staker_addr: String,
) -> Result<Response<BabylonMsg>, ContractError> {
    nonpayable(info)?;
    let staker_canonical_addr = to_canonical_addr(&staker_addr, "bbn")?;

    let cfg = CONFIG.load(deps.storage)?;

    // Iterate over map of delegations per (canonical) sender
    let stakes = delegations()
        .delegation
        .idx
        .staker
        .prefix((staker_canonical_addr.to_vec(), fp_pubkey_hex.into()))
        .range(deps.storage, None, None, Order::Ascending)
        .collect::<StdResult<Vec<_>>>()?;

    let mut amount = Uint128::zero();
    for ((staking_tx_hash, _), mut delegation) in stakes {
        let delegation_reward =
            withdraw_delegation_reward(deps.branch(), &mut delegation, fp_pubkey_hex)?;
        if !delegation_reward.is_zero() {
            delegations().delegation.save(
                deps.storage,
                (&staking_tx_hash, fp_pubkey_hex),
                &delegation,
            )?;
            amount += delegation_reward;
        }
    }

    if amount.is_zero() {
        return Err(ContractError::NoRewards);
    }

    let (recipient, wasm_msg) = send_rewards_msg(
        &deps,
        env,
        &staker_addr,
        &staker_canonical_addr,
        cfg,
        amount,
    )?;
    let resp = Response::new()
        .add_message(wasm_msg)
        .add_attribute("action", "withdraw_rewards")
        .add_attribute("staker", staker_addr)
        .add_attribute("fp", fp_pubkey_hex)
        .add_attribute("recipient", recipient)
        .add_attribute("amount", amount.to_string());
    Ok(resp)
}

/// `send_rewards_msg` sends the rewards to either the staker address on the Consumer or on Babylon,
/// depending on the ICS-20 transfer info queried from the Babylon contract.
fn send_rewards_msg(
    deps: &DepsMut,
    env: &Env,
    staker_addr: &str,
    staker_canonical_addr: &CanonicalAddr,
    cfg: Config,
    amount: Uint128,
) -> Result<(String, CosmosMsg<BabylonMsg>), ContractError> {
    // Query the babylon contract for transfer info
    // TODO: Turn into a parameter set during instantiation to avoid query (related to #41)
    let transfer_info: TransferInfoResponse = deps.querier.query_wasm_smart(
        cfg.babylon.to_string(),
        &babylon_contract::msg::contract::QueryMsg::TransferInfo {},
    )?;

    // Create the corresponding bank or transfer packet
    let (recipient, cosmos_msg) = match transfer_info {
        None => {
            // Consumer withdrawal.
            // Send rewards to the staker address on the Consumer
            let recipient = deps.api.addr_humanize(staker_canonical_addr)?.to_string();
            let bank_msg = BankMsg::Send {
                to_address: recipient.clone(),
                amount: vec![coin(amount.u128(), cfg.denom)],
            };
            (recipient, CosmosMsg::Bank(bank_msg))
        }
        Some(ics20_channel_id) => {
            // Babylon withdrawal.
            // Send rewards to the staker address on Babylon (ICS-020 transfer)
            let ibc_msg = IbcMsg::Transfer {
                channel_id: ics20_channel_id,
                to_address: staker_addr.to_string(),
                amount: coin(amount.u128(), cfg.denom),
                timeout: packet_timeout(env),
                memo: None,
            };

            (staker_addr.to_string(), CosmosMsg::Ibc(ibc_msg))
        }
    };
    Ok((recipient, cosmos_msg))
}

pub fn withdraw_delegation_reward(
    deps: DepsMut,
    delegation: &mut DelegationDistribution,
    fp_pubkey_hex: &str,
) -> Result<Uint128, ContractError> {
    // Load FP state
    let fp_state = fps()
        .load(deps.storage, fp_pubkey_hex)
        .map_err(|_| ContractError::FinalityProviderNotFound(fp_pubkey_hex.to_string()))?;

    let amount = calculate_reward(delegation, &fp_state)?;

    // Update withdrawn_funds to hold this transfer
    delegation.withdrawn_funds += amount;
    Ok(amount)
}

/// Calculates reward for the delegation and the corresponding FP distribution.
pub(crate) fn calculate_reward(
    delegation: &DelegationDistribution,
    fp_state: &FinalityProviderState,
) -> Result<Uint128, ContractError> {
    let points = fp_state.points_per_stake * Uint256::from(delegation.stake);

    let total = Uint128::try_from(points / DISTRIBUTION_POINTS_SCALE)?;

    Ok(total - delegation.withdrawn_funds)
}

/// btc_undelegate adds the signature of the unbonding tx signed by the staker to the given BTC
/// delegation
fn btc_undelegate(
    storage: &mut dyn Storage,
    staking_tx_hash: &Txid,
    btc_del: &mut BtcDelegation,
) -> Result<(), ContractError> {
    btc_del.undelegation_info.delegator_unbonding_info = Some(DelegatorUnbondingInfo {
        spend_stake_tx: vec![0x00; 32], // TODO: avoid handling spend stake tx for now
    });

    // Set BTC delegation back to KV store
    BTC_DELEGATIONS.save(storage, staking_tx_hash.as_ref(), btc_del)?;

    // TODO: Record event that the BTC delegation becomes unbonded at this height (#124)
    Ok(())
}

/// `slash_finality_provider` slashes a finality provider with the given PK.
/// A slashed finality provider will not have voting power
pub(crate) fn slash_finality_provider(
    deps: DepsMut,
    env: Env,
    fp_btc_pk_hex: &str,
) -> Result<Response<BabylonMsg>, ContractError> {
    // Ensure finality provider exists
    let mut fp = FPS.load(deps.storage, fp_btc_pk_hex)?;

    // Check if the finality provider is already slashed
    if fp.slashed_height > 0 {
        return Err(ContractError::FinalityProviderAlreadySlashed(
            fp_btc_pk_hex.to_string(),
        ));
    }
    // Set the finality provider as slashed
    fp.slashed_height = env.block.height;

    // Set BTC slashing height (if available from the babylon contract)
    // FIXME: Turn this into a hard error (related to #7.2)
    // return fmt.Errorf("failed to get current BTC tip")
    let btc_height = get_btc_tip_height(&deps).unwrap_or_default();
    fp.slashed_btc_height = btc_height;

    // Record slashed event. The next `BeginBlock` will consume this event for updating the active
    // FP set.
    // We simply set the FP voting power to zero from the next *processing* height (See NOTE in
    // `handle_finality_signature`)
    fps().update(deps.storage, fp_btc_pk_hex, env.block.height + 1, |fp| {
        let mut fp = fp.unwrap_or_default();
        fp.power = 0;
        Ok::<_, ContractError>(fp)
    })?;

    // Save the finality provider back
    FPS.save(deps.storage, fp_btc_pk_hex, &fp)?;

    // TODO: Add events (#124)
    Ok(Response::new())
}

/// get_btc_tip_height queries the BTC light client for the latest BTC tip height
fn get_btc_tip_height(deps: &DepsMut) -> Result<u32, ContractError> {
    // Get the BTC light client address from config
    let btc_light_client_addr = CONFIG.load(deps.storage)?.btc_light_client;

    // Query the BTC light client for the tip header
    let query_msg = btc_light_client::msg::contract::QueryMsg::BtcTipHeader {};
    // TODO: use a raw query for performance / efficiency
    let tip: BtcHeaderResponse = deps
        .querier
        .query_wasm_smart(btc_light_client_addr, &query_msg)?;

    Ok(tip.height)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};

    use test_utils::{
        create_new_finality_provider, create_new_fp_sk, get_active_btc_delegation,
        get_btc_del_unbonding_sig, get_derived_btc_delegation,
    };

    use crate::contract::tests::{CREATOR, INIT_ADMIN};
    use crate::contract::{execute, instantiate};
    use crate::msg::{ExecuteMsg, InstantiateMsg};
    use crate::queries;
    use crate::state::staking::BtcUndelegationInfo;
    use crate::test_utils::staking_params;

    // Compute staking tx hash of a delegation
    pub(crate) fn staking_tx_hash(del: &BtcDelegation) -> Txid {
        let staking_tx: Transaction = deserialize(&del.staking_tx).unwrap();
        staking_tx.txid()
    }

    #[test]
    fn test_add_fp_unauthorized() {
        let mut deps = mock_dependencies();
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);
        let init_admin = deps.api.addr_make(INIT_ADMIN);

        instantiate(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            InstantiateMsg {
                params: None,
                admin: Some(init_admin.to_string()), // Admin provided
            },
        )
        .unwrap();

        let new_fp = create_new_finality_provider(1);

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![new_fp.clone()],
            active_del: vec![],
            slashed_del: vec![],
            unbonded_del: vec![],
        };

        // Only the Creator or Admin can call this
        let other_info = message_info(&deps.api.addr_make("other"), &[]);
        let err = execute(deps.as_mut(), mock_env(), other_info, msg.clone()).unwrap_err();
        assert_eq!(err, ContractError::Unauthorized);
    }

    #[test]
    fn test_add_fp_admin() {
        let mut deps = mock_dependencies();
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);
        let init_admin = deps.api.addr_make(INIT_ADMIN);

        instantiate(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            InstantiateMsg {
                params: None,
                admin: Some(init_admin.to_string()), // Admin provided
            },
        )
        .unwrap();

        let admin_info = message_info(&init_admin, &[]); // Mock info for the admin
        let new_fp = create_new_finality_provider(1);

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![new_fp.clone()],
            active_del: vec![],
            slashed_del: vec![],
            unbonded_del: vec![],
        };

        // Use admin_info to execute the message
        let res = execute(deps.as_mut(), mock_env(), admin_info.clone(), msg.clone()).unwrap();
        assert_eq!(0, res.messages.len());

        // Check the finality provider has been stored
        let query_res =
            queries::finality_provider(deps.as_ref(), new_fp.btc_pk_hex.clone()).unwrap();
        // get DB object
        let fp = FinalityProvider::from(&new_fp);
        assert_eq!(query_res, fp);

        // Trying to add the same fp again fails
        let err = execute(deps.as_mut(), mock_env(), admin_info, msg).unwrap_err();
        assert_eq!(
            err,
            ContractError::FinalityProviderAlreadyExists(new_fp.btc_pk_hex.clone())
        );
    }

    #[test]
    fn active_delegation_happy_path() {
        let mut deps = mock_dependencies();
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        let params = staking_params();
        instantiate(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            InstantiateMsg {
                params: Some(params),
                admin: None,
            },
        )
        .unwrap();

        // Build valid active delegation
        let active_delegation = get_active_btc_delegation();

        // Register one FP first
        let mut new_fp = create_new_finality_provider(1);
        new_fp
            .btc_pk_hex
            .clone_from(&active_delegation.fp_btc_pk_list[0]);

        // Check that the finality provider has no power yet
        let res = queries::finality_provider_info(deps.as_ref(), new_fp.btc_pk_hex.clone(), None);
        assert!(matches!(
            res,
            Err(ContractError::FinalityProviderNotFound(pk)) if pk == new_fp.btc_pk_hex
        ));

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![new_fp.clone()],
            active_del: vec![],
            slashed_del: vec![],
            unbonded_del: vec![],
        };

        execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Now add the active delegation
        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![],
            active_del: vec![active_delegation.clone()],
            slashed_del: vec![],
            unbonded_del: vec![],
        };

        let res = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();
        assert_eq!(0, res.messages.len());

        // Check the active delegation is being stored
        let delegation = BtcDelegation::from(&active_delegation);
        let staking_tx_hash_hex = staking_tx_hash(&delegation).to_string();
        let query_res = queries::delegation(deps.as_ref(), staking_tx_hash_hex).unwrap();
        assert_eq!(query_res, delegation);

        // Check that the finality provider power has been updated
        let fp = queries::finality_provider_info(deps.as_ref(), new_fp.btc_pk_hex.clone(), None)
            .unwrap();
        assert_eq!(fp.power, active_delegation.total_sat);
    }

    #[test]
    fn undelegation_works() {
        let mut deps = mock_dependencies();
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        let params = staking_params();
        instantiate(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            InstantiateMsg {
                params: Some(params),
                admin: None,
            },
        )
        .unwrap();

        // Register one FP first
        let new_fp = create_new_finality_provider(1);

        // Build valid active delegation
        let active_delegation = get_derived_btc_delegation(1, &[1]);

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![new_fp.clone()],
            active_del: vec![active_delegation.clone()],
            slashed_del: vec![],
            unbonded_del: vec![],
        };

        let res = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();
        assert_eq!(0, res.messages.len());

        // Check the delegation is active (it has no unbonding or slashing tx signature)
        let active_delegation_undelegation = active_delegation.undelegation_info.clone();
        // Compute the staking tx hash
        let delegation = BtcDelegation::from(&active_delegation);
        let staking_tx_hash_hex = staking_tx_hash(&delegation).to_string();

        let btc_del = queries::delegation(deps.as_ref(), staking_tx_hash_hex.clone()).unwrap();
        let btc_undelegation = btc_del.undelegation_info;
        assert_eq!(
            btc_undelegation,
            BtcUndelegationInfo {
                unbonding_tx: active_delegation_undelegation.unbonding_tx.to_vec(),
                slashing_tx: active_delegation_undelegation.slashing_tx.to_vec(),
                delegator_unbonding_info: None,
                delegator_slashing_sig: active_delegation_undelegation
                    .delegator_slashing_sig
                    .to_vec(),
                covenant_unbonding_sig_list: vec![],
                covenant_slashing_sigs: vec![],
            }
        );

        let unbonding_sig = get_btc_del_unbonding_sig(1, &[1]);

        // Now send the undelegation message
        let undelegation = UnbondedBtcDelegation {
            staking_tx_hash: staking_tx_hash_hex.clone(),
            unbonding_tx_sig: unbonding_sig.to_bytes().into(),
        };

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![],
            active_del: vec![],
            slashed_del: vec![],
            unbonded_del: vec![undelegation.clone()],
        };

        let res = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();
        assert_eq!(0, res.messages.len());

        // Check the delegation is not active any more (updated with the unbonding tx signature)
        let active_delegation_undelegation = active_delegation.undelegation_info;
        let btc_del = queries::delegation(deps.as_ref(), staking_tx_hash_hex).unwrap();
        let btc_undelegation = btc_del.undelegation_info;
        assert_eq!(
            btc_undelegation,
            BtcUndelegationInfo {
                unbonding_tx: active_delegation_undelegation.unbonding_tx.into(),
                slashing_tx: active_delegation_undelegation.slashing_tx.into(),
                delegator_unbonding_info: Some(DelegatorUnbondingInfo {
                    spend_stake_tx: vec![0x00; 32], // TODO: avoid handling spend stake tx for now
                }),
                delegator_slashing_sig: active_delegation_undelegation
                    .delegator_slashing_sig
                    .into(),
                covenant_unbonding_sig_list: vec![],
                covenant_slashing_sigs: vec![],
            }
        );

        // Check the finality provider power has been updated
        let fp = queries::finality_provider_info(deps.as_ref(), new_fp.btc_pk_hex.clone(), None)
            .unwrap();
        assert_eq!(fp.power, 0);
    }

    #[test]
    fn slashed_delegation_works() {
        let mut deps = mock_dependencies();
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        let params = staking_params();
        instantiate(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            InstantiateMsg {
                params: Some(params),
                admin: None,
            },
        )
        .unwrap();

        // Register one FP first
        let new_fp = create_new_finality_provider(1);

        // Build valid active delegation
        let active_delegation = get_derived_btc_delegation(1, &[1]);

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![new_fp.clone()],
            active_del: vec![active_delegation.clone()],
            slashed_del: vec![],
            unbonded_del: vec![],
        };

        let res = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();
        assert_eq!(0, res.messages.len());

        // Check the delegation is active (it has no unbonding sig or is slashed)
        // Compute the staking tx hash
        let delegation = BtcDelegation::from(&active_delegation);
        let staking_tx_hash_hex = staking_tx_hash(&delegation).to_string();
        // Query the delegation
        let btc_del = queries::delegation(deps.as_ref(), staking_tx_hash_hex.clone()).unwrap();
        assert!(btc_del.undelegation_info.delegator_unbonding_info.is_none());
        assert!(!btc_del.slashed);

        // Check the finality provider has power
        let fp = queries::finality_provider_info(deps.as_ref(), new_fp.btc_pk_hex.clone(), None)
            .unwrap();
        assert_eq!(fp.power, btc_del.total_sat);

        // Now send the slashed delegation message
        let fp_sk = create_new_fp_sk(1);
        let fp_sk_hex = hex::encode(fp_sk.to_bytes());
        let slashed = SlashedBtcDelegation {
            staking_tx_hash: staking_tx_hash_hex.clone(),
            recovered_fp_btc_sk: fp_sk_hex,
        };

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![],
            active_del: vec![],
            unbonded_del: vec![],
            slashed_del: vec![slashed.clone()],
        };

        let res = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();
        assert_eq!(0, res.messages.len());
        // Check events
        assert_eq!(res.events.len(), 1);
        assert_eq!(res.events[0].ty.as_str(), "btc_undelegation_slashed");
        assert_eq!(res.events[0].attributes.len(), 2);
        assert_eq!(res.events[0].attributes[0].key.as_str(), "staking_tx_hash");
        assert_eq!(
            res.events[0].attributes[0].value.as_str(),
            staking_tx_hash_hex
        );
        assert_eq!(res.events[0].attributes[1].key.as_str(), "height");

        // Check the delegation is not active any more (slashed)
        let btc_del = queries::delegation(deps.as_ref(), staking_tx_hash_hex).unwrap();
        assert!(btc_del.slashed);
        // Check the unbonding sig is still empty
        assert!(btc_del.undelegation_info.delegator_unbonding_info.is_none());

        // Check the finality provider power has been zeroed (it has only this delegation that was
        // slashed)
        let fp = queries::finality_provider_info(deps.as_ref(), new_fp.btc_pk_hex.clone(), None)
            .unwrap();
        assert_eq!(fp.power, 0);
    }
}
