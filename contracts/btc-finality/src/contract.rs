use crate::error::ContractError;
use crate::finality::{
    compute_active_finality_providers, distribute_rewards_in_range, handle_finality_signature,
    handle_public_randomness_commit, handle_unjail,
};
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::config::{
    Config, ADMIN, CONFIG, DEFAULT_JAIL_DURATION, DEFAULT_MAX_ACTIVE_FINALITY_PROVIDERS,
    DEFAULT_MIN_PUB_RAND, DEFAULT_MISSED_BLOCKS_WINDOW, DEFAULT_REWARD_INTERVAL,
};
use crate::state::finality::{REWARDS, TOTAL_PENDING_REWARDS};
use crate::{finality, queries, state};
use babylon_apis::finality_api::SudoMsg;
use babylon_contract::msg::contract::RewardInfo;
use btc_staking::msg::ActivatedHeightResponse;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    attr, coin, coins, to_json_binary, Addr, CustomQuery, Deps, DepsMut, Empty, Env, MessageInfo,
    Order, QuerierWrapper, QueryRequest, QueryResponse, Reply, Response, StdResult, Uint128,
    WasmMsg, WasmQuery,
};
use cw2::set_contract_version;
use cw_utils::{maybe_addr, nonpayable};

pub const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
pub const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    mut deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    nonpayable(&info)?;
    let denom = deps.querier.query_bonded_denom()?;

    let config = Config {
        denom,
        babylon: info.sender,
        staking: Addr::unchecked("UNSET"), // To be set later, through `UpdateStaking`
        max_active_finality_providers: msg
            .max_active_finality_providers
            .unwrap_or(DEFAULT_MAX_ACTIVE_FINALITY_PROVIDERS),
        min_pub_rand: msg.min_pub_rand.unwrap_or(DEFAULT_MIN_PUB_RAND),
        reward_interval: msg.reward_interval.unwrap_or(DEFAULT_REWARD_INTERVAL),
        missed_blocks_window: msg
            .missed_blocks_window
            .unwrap_or(DEFAULT_MISSED_BLOCKS_WINDOW),
        jail_duration: msg.jail_duration.unwrap_or(DEFAULT_JAIL_DURATION),
    };
    CONFIG.save(deps.storage, &config)?;

    let api = deps.api;
    ADMIN.set(deps.branch(), maybe_addr(api, msg.admin.clone())?)?;

    // initialize storage, so no issue when reading for the first time
    TOTAL_PENDING_REWARDS.save(deps.storage, &Uint128::zero())?;

    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    Ok(Response::new().add_attribute("action", "instantiate"))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn reply(_deps: DepsMut, _env: Env, _reply: Reply) -> StdResult<Response> {
    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> Result<QueryResponse, ContractError> {
    match msg {
        QueryMsg::Config {} => Ok(to_json_binary(&CONFIG.load(deps.storage)?)?),
        QueryMsg::Admin {} => to_json_binary(&ADMIN.query_admin(deps)?).map_err(Into::into),
        QueryMsg::FinalitySignature { btc_pk_hex, height } => Ok(to_json_binary(
            &queries::finality_signature(deps, btc_pk_hex, height)?,
        )?),
        QueryMsg::PubRandCommit {
            btc_pk_hex,
            start_after,
            limit,
            reverse,
        } => Ok(to_json_binary(
            &state::public_randomness::get_pub_rand_commit(
                deps.storage,
                &btc_pk_hex,
                start_after,
                limit,
                reverse,
            )?,
        )?),
        QueryMsg::FirstPubRandCommit { btc_pk_hex } => Ok(to_json_binary(
            &state::public_randomness::get_first_pub_rand_commit(deps.storage, &btc_pk_hex)?,
        )?),
        QueryMsg::LastPubRandCommit { btc_pk_hex } => Ok(to_json_binary(
            &state::public_randomness::get_last_pub_rand_commit(deps.storage, &btc_pk_hex)?,
        )?),
        QueryMsg::Block { height } => Ok(to_json_binary(&queries::block(deps, height)?)?),
        QueryMsg::Blocks {
            start_after,
            limit,
            finalised,
            reverse,
        } => Ok(to_json_binary(&queries::blocks(
            deps,
            start_after,
            limit,
            finalised,
            reverse,
        )?)?),
        QueryMsg::Evidence { btc_pk_hex, height } => Ok(to_json_binary(&queries::evidence(
            deps, btc_pk_hex, height,
        )?)?),
        QueryMsg::JailedFinalityProviders { start_after, limit } => Ok(to_json_binary(
            &queries::jailed_finality_providers(deps, start_after, limit)?,
        )?),
        QueryMsg::ActiveFinalityProviders { height } => Ok(to_json_binary(
            &queries::active_finality_providers(deps, height)?,
        )?),
        QueryMsg::FinalityProviderPower { btc_pk_hex, height } => Ok(to_json_binary(
            &queries::finality_provider_power(deps, btc_pk_hex, height)?,
        )?),
        QueryMsg::Votes { height } => Ok(to_json_binary(&queries::votes(deps, height)?)?),
        QueryMsg::SigningInfo { btc_pk_hex } => {
            Ok(to_json_binary(&queries::signing_info(deps, btc_pk_hex)?)?)
        }
    }
}

/// This is a no-op just to test how this integrates with wasmd
#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(_deps: DepsMut, _env: Env, _msg: Empty) -> StdResult<Response> {
    Ok(Response::default())
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    let api = deps.api;
    match msg {
        ExecuteMsg::UpdateAdmin { admin } => ADMIN
            .execute_update_admin(deps, info, maybe_addr(api, admin)?)
            .map_err(Into::into),
        ExecuteMsg::UpdateStaking { staking } => handle_update_staking(deps, info, staking),
        ExecuteMsg::SubmitFinalitySignature {
            fp_pubkey_hex,
            height,
            pub_rand,
            proof,
            block_hash: block_app_hash,
            signature,
        } => handle_finality_signature(
            deps,
            env,
            crate::finality::MsgAddFinalitySig {
                fp_btc_pk_hex: fp_pubkey_hex,
                height,
                pub_rand: pub_rand.into(),
                proof,
                block_app_hash: block_app_hash.into(),
                signature: signature.into(),
            },
        ),
        ExecuteMsg::CommitPublicRandomness {
            fp_pubkey_hex,
            start_height,
            num_pub_rand,
            commitment,
            signature,
        } => handle_public_randomness_commit(
            deps,
            &env,
            crate::finality::MsgCommitPubRand {
                fp_btc_pk_hex: fp_pubkey_hex,
                start_height,
                num_pub_rand,
                commitment: commitment.into(),
                sig: signature.into(),
            },
        ),
        ExecuteMsg::Unjail { fp_pubkey_hex } => handle_unjail(deps, &env, &info, &fp_pubkey_hex),
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn sudo(mut deps: DepsMut, env: Env, msg: SudoMsg) -> Result<Response, ContractError> {
    match msg {
        SudoMsg::BeginBlock { .. } => handle_begin_block(&mut deps, env),
        SudoMsg::EndBlock {
            hash_hex,
            app_hash_hex,
        } => handle_end_block(&mut deps, env, &hash_hex, &app_hash_hex),
    }
}

fn handle_update_staking(
    deps: DepsMut,
    info: MessageInfo,
    staking_addr: String,
) -> Result<Response, ContractError> {
    let mut cfg = CONFIG.load(deps.storage)?;
    if info.sender != cfg.babylon && !ADMIN.is_admin(deps.as_ref(), &info.sender)? {
        return Err(ContractError::Unauthorized {});
    }
    cfg.staking = deps.api.addr_validate(&staking_addr)?;
    CONFIG.save(deps.storage, &cfg)?;

    let attributes = vec![
        attr("action", "update_btc_staking"),
        attr("staking", staking_addr),
        attr("sender", info.sender),
    ];
    Ok(Response::new().add_attributes(attributes))
}

fn handle_begin_block(deps: &mut DepsMut, env: Env) -> Result<Response, ContractError> {
    // Compute active finality provider set
    let max_active_fps = CONFIG.load(deps.storage)?.max_active_finality_providers as usize;
    compute_active_finality_providers(deps, &env, max_active_fps)?;

    // TODO: Add events (#124)
    Ok(Response::new())
}

fn handle_end_block(
    deps: &mut DepsMut,
    env: Env,
    _hash_hex: &str,
    app_hash_hex: &str,
) -> Result<Response, ContractError> {
    // If the BTC staking protocol is activated i.e. there exists a height where at least one
    // finality provider has voting power, start indexing and tallying blocks
    let cfg = CONFIG.load(deps.storage)?;
    let mut res = Response::new();
    let activated_height = get_activated_height(&cfg.staking, &deps.querier)?;
    if activated_height > 0 {
        // Index the current block
        let ev = finality::index_block(deps, env.block.height, &hex::decode(app_hash_hex)?)?;
        res = res.add_event(ev);
        // Tally all non-finalised blocks
        let events = finality::tally_blocks(deps, &env, activated_height)?;
        res = res.add_events(events);
    }

    // On a reward distribution boundary, send rewards for distribution to Babylon Genesis
    if env.block.height > 0 && env.block.height % cfg.reward_interval == 0 {
        distribute_rewards_in_range(deps, &env)?;

        // Then send the accumulated rewards to Babylon Genesis via IBC
        let rewards = TOTAL_PENDING_REWARDS.load(deps.storage)?;
        if rewards.u128() > 0 {
            let (fp_rewards, wasm_msg) = send_rewards_msg(deps, rewards.u128(), &cfg)?;
            res = res.add_message(wasm_msg);
            // Zero out individual rewards
            for reward in fp_rewards {
                REWARDS.remove(deps.storage, &reward.fp_pubkey_hex);
            }
            // Zero out total pending rewards
            TOTAL_PENDING_REWARDS.save(deps.storage, &Uint128::zero())?;
        }
    }
    Ok(res)
}

// Sends rewards to the babylon contract to send it via IBC to Babylon Genesis
fn send_rewards_msg(
    deps: &mut DepsMut,
    rewards: u128,
    cfg: &Config,
) -> Result<(Vec<RewardInfo>, WasmMsg), ContractError> {
    // Get the pending rewards distribution
    let fp_rewards = REWARDS
        .range(deps.storage, None, None, Order::Ascending)
        .filter(|item| {
            if let Ok((_, reward)) = item {
                reward.u128() > 0
            } else {
                true // don't filter errors
            }
        })
        .map(|item| {
            let (fp_pubkey_hex, reward) = item?;
            Ok(RewardInfo {
                fp_pubkey_hex,
                reward,
            })
        })
        .collect::<StdResult<Vec<_>>>()?;
    // The rewards are sent to the babylon contract for IBC distribution to Babylon Genesis
    let msg = babylon_contract::msg::contract::ExecuteMsg::RewardsDistribution {
        fp_distribution: fp_rewards.clone(),
    };
    let wasm_msg = WasmMsg::Execute {
        contract_addr: cfg.babylon.to_string(),
        msg: to_json_binary(&msg)?,
        funds: coins(rewards, cfg.denom.as_str()),
    };
    Ok((fp_rewards, wasm_msg))
}

pub fn get_activated_height(staking_addr: &Addr, querier: &QuerierWrapper) -> StdResult<u64> {
    // TODO: Use a raw query (#41)
    let query = encode_smart_query(
        staking_addr,
        &btc_staking::msg::QueryMsg::ActivatedHeight {},
    )?;
    let res: ActivatedHeightResponse = querier.query(&query)?;
    Ok(res.height)
}

pub(crate) fn encode_smart_query<Q: CustomQuery>(
    addr: &Addr,
    msg: &btc_staking::msg::QueryMsg,
) -> StdResult<QueryRequest<Q>> {
    Ok(WasmQuery::Smart {
        contract_addr: addr.to_string(),
        msg: to_json_binary(&msg)?,
    }
    .into())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    use cosmwasm_std::{
        coins, from_json,
        testing::{message_info, mock_dependencies, mock_env},
    };
    use cw_controllers::AdminResponse;
    pub(crate) const CREATOR: &str = "creator";
    pub(crate) const INIT_ADMIN: &str = "initial_admin";
    const NEW_ADMIN: &str = "new_admin";

    #[test]
    fn instantiate_without_admin() {
        let mut deps = mock_dependencies();

        // Create an InstantiateMsg with admin set to None
        let msg = InstantiateMsg::default();

        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        // Call the instantiate function
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        // Assert that no messages were sent
        assert_eq!(0, res.messages.len());

        // Query the admin to verify it was not set
        let res = ADMIN.query_admin(deps.as_ref()).unwrap();
        assert_eq!(None, res.admin);
    }

    #[test]
    fn instantiate_with_admin() {
        let mut deps = mock_dependencies();
        let init_admin = deps.api.addr_make(INIT_ADMIN);

        // Create an InstantiateMsg with admin set to Some(INIT_ADMIN.into())
        let msg = InstantiateMsg {
            admin: Some(init_admin.to_string()), // Admin provided
            ..Default::default()
        };

        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        // Call the instantiate function
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        // Assert that no messages were sent
        assert_eq!(0, res.messages.len());

        // Use assert_admin to verify that the admin was set correctly
        // This uses the assert_admin helper function provided by the Admin crate
        ADMIN.assert_admin(deps.as_ref(), &init_admin).unwrap();

        // ensure the admin is queryable as well
        let res = query(deps.as_ref(), mock_env(), QueryMsg::Admin {}).unwrap();
        let admin: AdminResponse = from_json(res).unwrap();
        assert_eq!(admin.admin.unwrap(), init_admin.as_str())
    }

    #[test]
    fn test_send_rewards_msg() {
        let mut deps = mock_dependencies();

        // Set up the contract with config
        let babylon_addr = deps.api.addr_make("babylon");
        let staking_addr = deps.api.addr_make("staking");
        let config = Config {
            denom: "TOKEN".to_string(),
            babylon: babylon_addr.clone(),
            staking: staking_addr.clone(),
            max_active_finality_providers: DEFAULT_MAX_ACTIVE_FINALITY_PROVIDERS,
            min_pub_rand: DEFAULT_MIN_PUB_RAND,
            reward_interval: DEFAULT_REWARD_INTERVAL,
            missed_blocks_window: DEFAULT_MISSED_BLOCKS_WINDOW,
            jail_duration: DEFAULT_JAIL_DURATION,
        };
        CONFIG.save(&mut deps.storage, &config).unwrap();

        // Add some rewards for FPs
        let fp1 = "fp1".to_string();
        let fp2 = "fp2".to_string();
        REWARDS
            .save(&mut deps.storage, &fp1, &Uint128::from(100u128))
            .unwrap();
        REWARDS
            .save(&mut deps.storage, &fp2, &Uint128::from(200u128))
            .unwrap();
        TOTAL_PENDING_REWARDS
            .save(&mut deps.storage, &Uint128::from(300u128))
            .unwrap();

        // Test send_rewards_msg
        let (fp_rewards, wasm_msg) = send_rewards_msg(&mut deps.as_mut(), 300, &config).unwrap();

        // Verify the rewards are correct
        assert_eq!(fp_rewards.len(), 2);
        assert_eq!(fp_rewards[0].fp_pubkey_hex, fp1);
        assert_eq!(fp_rewards[0].reward, Uint128::from(100u128));
        assert_eq!(fp_rewards[1].fp_pubkey_hex, fp2);
        assert_eq!(fp_rewards[1].reward, Uint128::from(200u128));

        // Verify the WasmMsg is correct
        match wasm_msg {
            WasmMsg::Execute {
                contract_addr,
                msg,
                funds,
            } => {
                assert_eq!(contract_addr, babylon_addr.to_string());
                assert_eq!(funds, coins(300, "TOKEN"));

                // Verify the message is a RewardsDistribution message
                let msg_data: babylon_contract::msg::contract::ExecuteMsg = from_json(msg).unwrap();
                match msg_data {
                    babylon_contract::msg::contract::ExecuteMsg::RewardsDistribution {
                        fp_distribution,
                    } => {
                        assert_eq!(fp_distribution.len(), 2);
                        assert_eq!(fp_distribution[0].fp_pubkey_hex, fp1);
                        assert_eq!(fp_distribution[0].reward, Uint128::from(100u128));
                        assert_eq!(fp_distribution[1].fp_pubkey_hex, fp2);
                        assert_eq!(fp_distribution[1].reward, Uint128::from(200u128));
                    }
                    _ => panic!("Expected RewardsDistribution message"),
                }
            }
            _ => panic!("Expected WasmMsg::Execute"),
        }
    }

    #[test]
    fn test_send_rewards_msg_with_no_rewards() {
        let mut deps = mock_dependencies();

        // Set up the contract with config
        let babylon_addr = deps.api.addr_make("babylon");
        let staking_addr = deps.api.addr_make("staking");
        let config = Config {
            denom: "TOKEN".to_string(),
            babylon: babylon_addr.clone(),
            staking: staking_addr.clone(),
            max_active_finality_providers: DEFAULT_MAX_ACTIVE_FINALITY_PROVIDERS,
            min_pub_rand: DEFAULT_MIN_PUB_RAND,
            reward_interval: DEFAULT_REWARD_INTERVAL,
            missed_blocks_window: DEFAULT_MISSED_BLOCKS_WINDOW,
            jail_duration: DEFAULT_JAIL_DURATION,
        };
        CONFIG.save(&mut deps.storage, &config).unwrap();

        // No rewards in storage
        TOTAL_PENDING_REWARDS
            .save(&mut deps.storage, &Uint128::zero())
            .unwrap();

        // Test send_rewards_msg with no rewards
        let (fp_rewards, wasm_msg) = send_rewards_msg(&mut deps.as_mut(), 0, &config).unwrap();

        // Verify no rewards are returned
        assert_eq!(fp_rewards.len(), 0);

        // Verify the WasmMsg is correct (should still be created but with 0 funds)
        match wasm_msg {
            WasmMsg::Execute {
                contract_addr,
                msg,
                funds,
            } => {
                assert_eq!(contract_addr, babylon_addr.to_string());
                assert_eq!(funds, coins(0, "TOKEN"));

                // Verify the message is a RewardsDistribution message with empty distribution
                let msg_data: babylon_contract::msg::contract::ExecuteMsg = from_json(msg).unwrap();
                match msg_data {
                    babylon_contract::msg::contract::ExecuteMsg::RewardsDistribution {
                        fp_distribution,
                    } => {
                        assert_eq!(fp_distribution.len(), 0);
                    }
                    _ => panic!("Expected RewardsDistribution message"),
                }
            }
            _ => panic!("Expected WasmMsg::Execute"),
        }
    }

    #[test]
    fn test_update_admin() {
        let mut deps = mock_dependencies();
        let init_admin = deps.api.addr_make(INIT_ADMIN);
        let new_admin = deps.api.addr_make(NEW_ADMIN);

        // Create an InstantiateMsg with admin set to Some(INIT_ADMIN.into())
        let msg = InstantiateMsg {
            admin: Some(init_admin.to_string()), // Admin provided
            ..Default::default()
        };

        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        // Call the instantiate function
        let res = instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Assert that no messages were sent
        assert_eq!(0, res.messages.len());

        // Use assert_admin to verify that the admin was set correctly
        ADMIN.assert_admin(deps.as_ref(), &init_admin).unwrap();

        // Update the admin to new_admin
        let update_admin_msg = ExecuteMsg::UpdateAdmin {
            admin: Some(new_admin.to_string()),
        };

        // Execute the UpdateAdmin message with non-admin info
        let non_admin_info = message_info(&deps.api.addr_make("non_admin"), &[]);
        let err = execute(
            deps.as_mut(),
            mock_env(),
            non_admin_info,
            update_admin_msg.clone(),
        )
        .unwrap_err();
        assert_eq!(
            err,
            ContractError::Admin(cw_controllers::AdminError::NotAdmin {})
        );

        // Execute the UpdateAdmin message with the initial admin info
        let admin_info = message_info(&init_admin, &[]);
        let res = execute(deps.as_mut(), mock_env(), admin_info, update_admin_msg).unwrap();

        // Assert that no messages were sent
        assert_eq!(0, res.messages.len());

        // Use assert_admin to verify that the admin was updated correctly
        ADMIN.assert_admin(deps.as_ref(), &new_admin).unwrap();
    }

    #[test]
    fn test_distribute_rewards_basic() {
        let mut deps = mock_dependencies();
        let mut env = mock_env();
        env.contract.address = deps.api.addr_make("finality_contract");

        // Setup minimal config
        CONFIG
            .save(
                &mut deps.storage,
                &Config {
                    denom: "TOKEN".to_string(),
                    babylon: deps.api.addr_make("babylon"),
                    staking: deps.api.addr_make("staking"),
                    max_active_finality_providers: 100,
                    min_pub_rand: 1,
                    reward_interval: 50,
                    missed_blocks_window: 250,
                    jail_duration: 86400,
                },
            )
            .unwrap();

        // Set contract balance
        deps.querier
            .bank
            .update_balance(env.contract.address.clone(), vec![coin(1000, "TOKEN")]);

        // Setup: Direct accumulated voting weights (simulating FPs having voted)
        use crate::state::finality::ACCUMULATED_VOTING_WEIGHTS;
        let fp1 = "fp1".to_string();
        let fp2 = "fp2".to_string();

        // FP1 accumulated 2000 voting weight, FP2 accumulated 1000 voting weight
        ACCUMULATED_VOTING_WEIGHTS
            .save(&mut deps.storage, &fp1, &2000u128)
            .unwrap();
        ACCUMULATED_VOTING_WEIGHTS
            .save(&mut deps.storage, &fp2, &1000u128)
            .unwrap();

        TOTAL_PENDING_REWARDS
            .save(&mut deps.storage, &Uint128::zero())
            .unwrap();

        // Test reward distribution
        use crate::finality::distribute_rewards_in_range;
        distribute_rewards_in_range(&mut deps.as_mut(), &env).unwrap(); // Height params are ignored now

        // FP1 gets 2/3 of rewards (2000/3000), FP2 gets 1/3 (1000/3000)
        let fp1_reward = REWARDS.load(&deps.storage, &fp1).unwrap();
        let fp2_reward = REWARDS.load(&deps.storage, &fp2).unwrap();

        assert_eq!(fp1_reward, Uint128::from(666u128)); // 1000 * 2000 / 3000 = 666
        assert_eq!(fp2_reward, Uint128::from(333u128)); // 1000 * 1000 / 3000 = 333

        // Accumulated weights should be cleared after distribution
        let fp1_accumulated = ACCUMULATED_VOTING_WEIGHTS
            .may_load(&deps.storage, &fp1)
            .unwrap();
        let fp2_accumulated = ACCUMULATED_VOTING_WEIGHTS
            .may_load(&deps.storage, &fp2)
            .unwrap();
        assert_eq!(fp1_accumulated, None);
        assert_eq!(fp2_accumulated, None);
    }

    #[test]
    fn test_distribute_rewards_edge_cases() {
        let mut deps = mock_dependencies();
        let mut env = mock_env();
        env.contract.address = deps.api.addr_make("finality_contract");

        CONFIG
            .save(
                &mut deps.storage,
                &Config {
                    denom: "TOKEN".to_string(),
                    babylon: deps.api.addr_make("babylon"),
                    staking: deps.api.addr_make("staking"),
                    max_active_finality_providers: 100,
                    min_pub_rand: 1,
                    reward_interval: 50,
                    missed_blocks_window: 250,
                    jail_duration: 86400,
                },
            )
            .unwrap();

        TOTAL_PENDING_REWARDS
            .save(&mut deps.storage, &Uint128::zero())
            .unwrap();

        use crate::finality::distribute_rewards_in_range;

        // Test 1: No balance - should not panic
        deps.querier
            .bank
            .update_balance(env.contract.address.clone(), vec![coin(0, "TOKEN")]);
        distribute_rewards_in_range(&mut deps.as_mut(), &env).unwrap();

        // Test 2: No accumulated weights - should not panic
        deps.querier
            .bank
            .update_balance(env.contract.address.clone(), vec![coin(1000, "TOKEN")]);
        distribute_rewards_in_range(&mut deps.as_mut(), &env).unwrap();

        // Should complete without errors
        let total_pending = TOTAL_PENDING_REWARDS.load(&deps.storage).unwrap();
        assert_eq!(total_pending, Uint128::zero());
    }
}
