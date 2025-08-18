use crate::error::ContractError;
use crate::state::config::{ADMIN, CONFIG};
use crate::state::delegations::delegations;
use crate::state::staking::{
    get_fp_state_map, BtcDelegation, DelegatorUnbondingInfo, FinalityProviderState,
    BTC_DELEGATIONS, BTC_DELEGATION_EXPIRY_INDEX, DELEGATION_FPS, FPS, FP_DELEGATIONS,
};
use crate::validation::{verify_active_delegation, verify_new_fp, verify_undelegation};
use babylon_apis::btc_staking_api::{
    ActiveBtcDelegation, FinalityProvider, NewFinalityProvider, UnbondedBtcDelegation, HASH_SIZE,
};
use babylon_apis::{to_canonical_addr, Validate};
use bitcoin::absolute::LockTime;
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::{Transaction, Txid};
use btc_light_client::msg::btc_header::BtcHeaderResponse;
use cosmwasm_std::{Deps, DepsMut, Env, Event, MessageInfo, Order, Response, StdResult, Storage};
use cw_storage_plus::Bound;
use std::str::FromStr;

/// Handles the BTC staking operations.
pub fn handle_btc_staking(
    deps: DepsMut,
    env: Env,
    info: &MessageInfo,
    new_fps: &[NewFinalityProvider],
    active_delegations: &[ActiveBtcDelegation],
    unbonded_delegations: &[UnbondedBtcDelegation],
) -> Result<Response, ContractError> {
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

    // Process undelegations
    for undel in unbonded_delegations {
        let ev = handle_undelegation(deps.storage, env.block.height, undel)?;
        res = res.add_event(ev);
    }

    Ok(res)
}

/// Handles registering a new finality provider.
fn handle_new_fp(
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

    // verify the finality provider registration request
    verify_new_fp(new_fp)?;

    // get DB object
    let fp = FinalityProvider::from(new_fp);

    // save to DB
    FPS.save(storage, &fp.btc_pk_hex, &fp)?;
    // Set its voting power to zero
    let fp_state = FinalityProviderState::default();
    get_fp_state_map().save(storage, &fp.btc_pk_hex, &fp_state, height)?;

    Ok(())
}

fn handle_active_delegation(
    storage: &mut dyn Storage,
    height: u64,
    active_delegation: &ActiveBtcDelegation,
) -> Result<(), ContractError> {
    let cfg = CONFIG.load(storage)?;

    // Basic stateless checks
    active_delegation.validate()?;

    // TODO: Ensure all finality providers
    // - Are not slashed. (done)
    // - They have timestamped public randomness (#130)

    // Parse staking tx
    let staking_tx: Transaction = deserialize(&active_delegation.staking_tx)?;
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

    // verify the active delegation
    verify_active_delegation(&cfg, active_delegation, &staking_tx)?;

    // All good, construct BTCDelegation and insert BTC delegation
    // NOTE: the BTC delegation does not have voting power yet.
    // It will have voting power only when
    // 1) Its corresponding staking tx is k-deep.
    // 2) It receives a covenant signature.

    // Get canonical address
    let canonical_addr = to_canonical_addr(&active_delegation.staker_addr, "bbn")?;

    // Update delegations by registered finality provider
    let fp_state_map = get_fp_state_map();
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
        let mut fp_state = fp_state_map.load(storage, fp_btc_pk_hex)?;
        // Update total active sats by FP
        fp_state.total_active_sats = fp_state
            .total_active_sats
            .saturating_add(active_delegation.total_sat);

        // Create delegation distribution info. Fail if it already exists
        delegations().create_distribution(
            storage,
            staking_tx_hash,
            fp_btc_pk_hex,
            &canonical_addr,
            active_delegation.total_sat,
        )?;

        // Save FP state
        fp_state_map.save(storage, fp_btc_pk_hex, &fp_state, height)?;

        registered_fp = true;
    }

    if !registered_fp {
        return Err(ContractError::FinalityProviderNotRegistered);
    }
    // Add this BTC delegation
    let delegation = BtcDelegation::from(active_delegation);
    BTC_DELEGATIONS.save(storage, staking_tx_hash.as_ref(), &delegation)?;

    // Index the delegation by its actual expiry height (end_height - unbonding_time)
    // This matches Babylon's logic where delegations expire at endHeight - unbondingTime
    let actual_expiry_height = delegation
        .end_height
        .saturating_sub(delegation.unbonding_time);
    BTC_DELEGATION_EXPIRY_INDEX.update(
        storage,
        actual_expiry_height,
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

/// Handles undelegation from an active delegation.
fn handle_undelegation(
    storage: &mut dyn Storage,
    height: u64,
    undelegation: &UnbondedBtcDelegation,
) -> Result<Event, ContractError> {
    // Basic stateless checks
    undelegation.validate()?;

    let cfg = CONFIG.load(storage)?;

    let staking_tx_hash = Txid::from_str(&undelegation.staking_tx_hash)?;
    let mut btc_del = BTC_DELEGATIONS.load(storage, staking_tx_hash.as_ref())?;

    // For undelegation, we only need to check that it's not already unbonded early
    // We don't need BTC height because undelegation is about adding early unbonding info
    if btc_del.is_unbonded_early() {
        return Err(ContractError::DelegationIsNotActive(
            staking_tx_hash.to_string(),
        ));
    }

    // verify the early unbonded delegation
    verify_undelegation(&cfg, &btc_del)?;

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

/// Handles FP slashing at the staking level.
pub fn handle_slash_fp(
    deps: DepsMut,
    env: Env,
    info: &MessageInfo,
    fp_btc_pk_hex: &str,
) -> Result<Response, ContractError> {
    let config = CONFIG.load(deps.storage)?;
    if info.sender != config.babylon && !ADMIN.is_admin(deps.as_ref(), &info.sender)? {
        return Err(ContractError::Unauthorized);
    }
    slash_finality_provider(deps, env, fp_btc_pk_hex)
}

pub fn process_expired_btc_delegations(deps: DepsMut, env: Env) -> Result<Response, ContractError> {
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
                .debug(&format!("Failed to get BTC tip height: {e}"));
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

                // Only process active delegations (check with current BTC height)
                if btc_del.is_active(tip_height) {
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
    let fp_state_map = get_fp_state_map();

    for fp_pubkey_hex in affected_fps {
        // Load FP state
        let mut fp_state = fp_state_map
            .load(storage, &fp_pubkey_hex)
            .map_err(|_| ContractError::FinalityProviderNotFound(fp_pubkey_hex.clone()))?;

        // Update total active sats by FP
        fp_state.total_active_sats = fp_state.total_active_sats.saturating_sub(btc_del.total_sat);

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
        fp_state_map.save(storage, &fp_pubkey_hex, &fp_state, height)?;
    }

    Ok(())
}

/// Adds the signature of the unbonding tx signed by the staker to the given BTC delegation.
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

/// Slashes a finality provider with the given PK.
/// A slashed finality provider will not have voting power
/// following https://github.com/babylonlabs-io/babylon/blob/4aa85a8d9bf85771d448cd3026e99962fe0dab8e/x/btcstaking/keeper/finality_providers.go#L133-L172
fn slash_finality_provider(
    deps: DepsMut,
    env: Env,
    fp_btc_pk_hex: &str,
) -> Result<Response, ContractError> {
    // Ensure finality provider exists
    let mut fp = FPS
        .load(deps.storage, fp_btc_pk_hex)
        .map_err(|_| ContractError::FinalityProviderNotFound(fp_btc_pk_hex.to_string()))?;

    // Ensure the finality provider is not already slashed
    if fp.is_slashed() {
        return Err(ContractError::FinalityProviderAlreadySlashed(
            fp_btc_pk_hex.to_string(),
        ));
    }
    // Set the finality provider as slashed
    fp.slashed_height = env.block.height;
    fp.slashed_btc_height = get_btc_tip_height(&deps).unwrap_or_default();

    // Record slashed event. The next `BeginBlock` will consume this event for updating the active
    // FP set. We simply set the FP total active sats to zero from the next *processing* height
    // (See NOTE in `handle_finality_signature`)
    get_fp_state_map().update(deps.storage, fp_btc_pk_hex, env.block.height + 1, |fp| {
        let mut fp = fp.unwrap_or_default();
        fp.slashed = true;
        Ok::<_, ContractError>(fp)
    })?;

    // Save the finality provider back
    FPS.save(deps.storage, fp_btc_pk_hex, &fp)?;

    Ok(Response::new())
}

/// Queries the BTC light client for the latest BTC tip height.
fn get_btc_tip_height(deps: &DepsMut) -> Result<u32, ContractError> {
    // Get the BTC light client address from config
    let config = CONFIG.load(deps.storage)?;

    // Query the BTC light client for the tip header
    let query_msg = btc_light_client::msg::contract::QueryMsg::BtcTipHeader {};
    // TODO: use a raw query for performance / efficiency
    let tip: BtcHeaderResponse = deps
        .querier
        .query_wasm_smart(&config.btc_light_client, &query_msg)?;

    Ok(tip.height)
}

/// Queries the BTC light client for the latest BTC tip height (for query contexts).
pub(crate) fn get_btc_tip_height_for_queries(deps: Deps) -> Result<u32, ContractError> {
    // Get the BTC light client address from config
    let config = CONFIG.load(deps.storage)?;

    // Query the BTC light client for the tip header
    let query_msg = btc_light_client::msg::contract::QueryMsg::BtcTipHeader {};
    // TODO: use a raw query for performance / efficiency
    let tip: BtcHeaderResponse = deps
        .querier
        .query_wasm_smart(&config.btc_light_client, &query_msg)?;

    Ok(tip.height)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::contract::tests::{CREATOR, INIT_ADMIN};
    use crate::contract::{execute, instantiate};
    use crate::msg::{ExecuteMsg, InstantiateMsg};
    use crate::queries;
    use crate::state::staking::BtcUndelegationInfo;
    use babylon_test_utils::{
        create_new_finality_provider, get_active_btc_delegation, get_derived_btc_delegation,
    };
    use btc_light_client::msg::btc_header::BtcHeaderResponse;
    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};
    use cosmwasm_std::{
        from_json, to_json_binary, Addr, ContractResult, SystemError, SystemResult, WasmQuery,
    };

    // Compute staking tx hash of a delegation
    pub(crate) fn staking_tx_hash(del: &BtcDelegation) -> Txid {
        let staking_tx: Transaction = deserialize(&del.staking_tx).unwrap();
        staking_tx.compute_txid()
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
                admin: Some(init_admin.to_string()), // Admin provided
            },
        )
        .unwrap();

        let new_fp = create_new_finality_provider(1);

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![new_fp.clone()],
            active_del: vec![],
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
                admin: Some(init_admin.to_string()), // Admin provided
            },
        )
        .unwrap();

        let admin_info = message_info(&init_admin, &[]); // Mock info for the admin
        let new_fp = create_new_finality_provider(1);

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![new_fp.clone()],
            active_del: vec![],
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

        instantiate(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            InstantiateMsg::default(),
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
        let res = queries::finality_provider_info(
            deps.as_ref(),
            &mock_env(),
            new_fp.btc_pk_hex.clone(),
            None,
        );
        assert!(matches!(
            res,
            Err(ContractError::FinalityProviderNotFound(pk)) if pk == new_fp.btc_pk_hex
        ));

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![new_fp.clone()],
            active_del: vec![],
            unbonded_del: vec![],
        };

        execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Now add the active delegation
        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![],
            active_del: vec![active_delegation.clone()],
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
        let fp = queries::finality_provider_info(
            deps.as_ref(),
            &mock_env(),
            new_fp.btc_pk_hex.clone(),
            None,
        )
        .unwrap();
        assert_eq!(fp.total_active_sats, active_delegation.total_sat);
    }

    #[test]
    fn undelegation_works() {
        let mut deps = mock_dependencies();
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        instantiate(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            InstantiateMsg::default(),
        )
        .unwrap();

        // Register one FP first
        let new_fp = create_new_finality_provider(1);

        // Build valid active delegation
        let active_delegation = get_derived_btc_delegation(1, &[1]);

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![new_fp.clone()],
            active_del: vec![active_delegation.clone()],
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

        // Now send the undelegation message
        let undelegation = UnbondedBtcDelegation {
            staking_tx_hash: staking_tx_hash_hex.clone(),
        };

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![],
            active_del: vec![],
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
        let fp = queries::finality_provider_info(
            deps.as_ref(),
            &mock_env(),
            new_fp.btc_pk_hex.clone(),
            None,
        )
        .unwrap();
        assert_eq!(fp.total_active_sats, 0);
    }

    #[test]
    fn test_slash_finality_provider() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        // Mock the BTC light client query
        deps.querier.update_wasm(|query| match query {
            WasmQuery::Smart {
                contract_addr: _,
                msg,
            } => {
                let query_msg: btc_light_client::msg::contract::QueryMsg = from_json(msg).unwrap();
                match query_msg {
                    btc_light_client::msg::contract::QueryMsg::BtcTipHeader {} => {
                        let response = BtcHeaderResponse::default();
                        SystemResult::Ok(ContractResult::Ok(to_json_binary(&response).unwrap()))
                    }
                    _ => SystemResult::Err(SystemError::UnsupportedRequest {
                        kind: "unsupported query".to_string(),
                    }),
                }
            }
            _ => SystemResult::Err(SystemError::UnsupportedRequest {
                kind: "unsupported query".to_string(),
            }),
        });

        instantiate(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            InstantiateMsg::default(),
        )
        .unwrap();

        // Mock the btc light client address
        let mut config = CONFIG.load(&deps.storage).unwrap();
        config.btc_light_client = Addr::unchecked("BTC_LIGHT_CLIENT_CONTRACT_ADDR");
        CONFIG.save(&mut deps.storage, &config).unwrap();

        // Register one FP first
        let new_fp = create_new_finality_provider(1);

        // Build valid active delegation
        let active_delegation = get_derived_btc_delegation(1, &[1]);

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![new_fp.clone()],
            active_del: vec![active_delegation.clone()],
            unbonded_del: vec![],
        };

        execute(deps.as_mut(), env.clone(), info.clone(), msg).unwrap();

        // Check that the finality provider has power before slashing
        let fp = queries::finality_provider_info(
            deps.as_ref(),
            &mock_env(),
            new_fp.btc_pk_hex.clone(),
            None,
        )
        .unwrap();
        assert_eq!(fp.total_active_sats, active_delegation.total_sat);
        assert!(!fp.slashed);

        // Slash the finality provider
        slash_finality_provider(deps.as_mut(), env.clone(), &new_fp.btc_pk_hex).unwrap();

        // Check that the finality provider is now slashed
        let fp = queries::finality_provider_info(
            deps.as_ref(),
            &mock_env(),
            new_fp.btc_pk_hex.clone(),
            None,
        )
        .unwrap();
        assert!(fp.slashed);
        assert_eq!(fp.total_active_sats, active_delegation.total_sat);

        // Try to slash the same finality provider again - should fail
        let err =
            slash_finality_provider(deps.as_mut(), env.clone(), &new_fp.btc_pk_hex).unwrap_err();
        assert!(matches!(
            err,
            ContractError::FinalityProviderAlreadySlashed(pk) if pk == new_fp.btc_pk_hex
        ));

        // Try to slash a non-existent finality provider - should fail
        let err =
            slash_finality_provider(deps.as_mut(), env.clone(), "non_existent_fp").unwrap_err();
        assert!(matches!(err, ContractError::FinalityProviderNotFound(_)));
    }
}
