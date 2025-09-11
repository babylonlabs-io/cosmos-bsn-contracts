use crate::error::ContractError;
use crate::finality::{
    handle_finality_signature, handle_public_randomness_commit, handle_rewards_distribution,
    handle_unjail,
};
use crate::liveness::handle_liveness;
use crate::migrations::migrate_config_v1_0_0_rc_0_to_v1_0_0_rc_1;
use crate::msg::{ExecuteMsg, InstantiateMsg, MigrateMsg, QueryMsg};
use crate::power_dist_change::compute_active_finality_providers;
use crate::state::config::{
    Config, ADMIN, CONFIG, DEFAULT_FINALITY_ACTIVATION_HEIGHT, DEFAULT_JAIL_DURATION,
    DEFAULT_MAX_ACTIVE_FINALITY_PROVIDERS, DEFAULT_MAX_PUB_RAND_COMMIT_OFFSET,
    DEFAULT_MIN_PUB_RAND, DEFAULT_MISSED_BLOCKS_WINDOW, DEFAULT_REWARD_INTERVAL,
};
use crate::state::finality::get_btc_staking_activated_height;
#[cfg(test)]
use crate::state::finality::ACCUMULATED_VOTING_WEIGHTS;
use crate::{finality, queries, state};
use babylon_apis::finality_api::SudoMsg;
use cosmwasm_std::{
    attr, to_json_binary, Addr, Deps, DepsMut, Env, MessageInfo, QueryResponse, Reply, Response,
    StdResult,
};
use cw2::set_contract_version;
use cw_utils::{maybe_addr, nonpayable};
use std::cmp::max;

pub const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
pub const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

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
        finality_activation_height: msg
            .finality_activation_height
            .unwrap_or(DEFAULT_FINALITY_ACTIVATION_HEIGHT),
        max_pub_rand_commit_offset: msg
            .max_pub_rand_commit_offset
            .unwrap_or(DEFAULT_MAX_PUB_RAND_COMMIT_OFFSET),
    };
    CONFIG.save(deps.storage, &config)?;

    let api = deps.api;
    ADMIN.set(deps.branch(), maybe_addr(api, msg.admin.clone())?)?;

    // initialize storage, so no issue when reading for the first time

    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    Ok(Response::new().add_attribute("action", "instantiate"))
}

pub fn reply(_deps: DepsMut, _env: Env, _reply: Reply) -> StdResult<Response> {
    Ok(Response::default())
}

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
        QueryMsg::FinalityProviderPowerBatch {
            btc_pk_hex,
            heights,
        } => Ok(to_json_binary(&queries::finality_provider_power_batch(
            deps, btc_pk_hex, heights,
        )?)?),
        QueryMsg::Votes { height } => Ok(to_json_binary(&queries::votes(deps, height)?)?),
        QueryMsg::SigningInfo { btc_pk_hex } => {
            Ok(to_json_binary(&queries::signing_info(deps, btc_pk_hex)?)?)
        }
        QueryMsg::ActivatedHeight {} => {
            let activated_height = get_btc_staking_activated_height(deps.storage);
            if let Some(height) = activated_height {
                Ok(to_json_binary(&height)?)
            } else {
                Err(ContractError::BTCStakingNotActivated)
            }
        }
        QueryMsg::LastFinalizedHeight {} => {
            Ok(to_json_binary(&queries::last_finalized_height(deps)?)?)
        }
    }
}

/// Handle contract migration.
/// This function is called when the contract is migrated to a new version.
/// For state-breaking migrations, this handles the migration of the Config struct.
pub fn migrate(deps: DepsMut, _env: Env, _msg: MigrateMsg) -> Result<Response, ContractError> {
    // Get the current version stored in the contract
    let prev_version = cw2::get_contract_version(deps.storage)?;

    // Validate that this is the expected contract
    if prev_version.contract != CONTRACT_NAME {
        return Err(ContractError::InvalidContractName {
            expected: CONTRACT_NAME.to_string(),
            actual: prev_version.contract,
        });
    }

    // Update to the new version
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    // Handle state migration based on the previous version
    match prev_version.version.as_str() {
        "1.0.0-rc.0" => {
            // Migrate from v1.0.0-rc.0 to v1.0.0-rc.1
            migrate_config_v1_0_0_rc_0_to_v1_0_0_rc_1(deps)?;
        }

        _ => {
            // No migration needed
        }
    }

    Ok(Response::new()
        .add_attribute("action", "migrate")
        .add_attribute("from_version", prev_version.version)
        .add_attribute("to_version", CONTRACT_VERSION))
}

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
            crate::msg::MsgAddFinalitySig {
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
            crate::msg::MsgCommitPubRand {
                fp_btc_pk_hex: fp_pubkey_hex,
                start_height,
                num_pub_rand,
                commitment: commitment.into(),
                sig: signature.into(),
            },
        ),
        ExecuteMsg::Unjail { fp_pubkey_hex } => handle_unjail(deps, &env, &info, &fp_pubkey_hex),
        ExecuteMsg::UpdateConfig {
            max_active_finality_providers,
            min_pub_rand,
            reward_interval,
            missed_blocks_window,
            jail_duration,
            finality_activation_height,
            max_pub_rand_commit_offset,
        } => handle_update_config(
            deps,
            info,
            max_active_finality_providers,
            min_pub_rand,
            reward_interval,
            missed_blocks_window,
            jail_duration,
            finality_activation_height,
            max_pub_rand_commit_offset,
        ),
    }
}

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

#[allow(clippy::too_many_arguments)]
fn handle_update_config(
    deps: DepsMut,
    info: MessageInfo,
    max_active_finality_providers: Option<u32>,
    min_pub_rand: Option<u64>,
    reward_interval: Option<u64>,
    missed_blocks_window: Option<u64>,
    jail_duration: Option<u64>,
    finality_activation_height: Option<u64>,
    max_pub_rand_commit_offset: Option<u64>,
) -> Result<Response, ContractError> {
    // Only admin can update config
    if !ADMIN.is_admin(deps.as_ref(), &info.sender)? {
        return Err(ContractError::Unauthorized {});
    }

    let mut cfg = CONFIG.load(deps.storage)?;

    // Update only the fields that are provided (non-None values)
    if let Some(max_active_finality_providers) = max_active_finality_providers {
        cfg.max_active_finality_providers = max_active_finality_providers;
    }
    if let Some(min_pub_rand) = min_pub_rand {
        cfg.min_pub_rand = min_pub_rand;
    }
    if let Some(reward_interval) = reward_interval {
        cfg.reward_interval = reward_interval;
    }
    if let Some(missed_blocks_window) = missed_blocks_window {
        cfg.missed_blocks_window = missed_blocks_window;
    }
    if let Some(jail_duration) = jail_duration {
        cfg.jail_duration = jail_duration;
    }
    if let Some(finality_activation_height) = finality_activation_height {
        cfg.finality_activation_height = finality_activation_height;
    }
    if let Some(max_pub_rand_commit_offset) = max_pub_rand_commit_offset {
        cfg.max_pub_rand_commit_offset = max_pub_rand_commit_offset;
    }

    CONFIG.save(deps.storage, &cfg)?;

    let attributes = vec![attr("action", "update_config"), attr("sender", info.sender)];
    Ok(Response::new().add_attributes(attributes))
}

fn handle_begin_block(deps: &mut DepsMut, env: Env) -> Result<Response, ContractError> {
    // Compute active finality provider set
    let max_active_fps = CONFIG.load(deps.storage)?.max_active_finality_providers as usize;
    let response = compute_active_finality_providers(deps, &env, max_active_fps)?;

    Ok(response)
}

fn handle_end_block(
    deps: &mut DepsMut,
    env: Env,
    _hash_hex: &str,
    app_hash_hex: &str,
) -> Result<Response, ContractError> {
    let mut res = Response::new();
    let cfg = CONFIG.load(deps.storage)?;

    // Should not proceed if not reached finality activation height
    if env.block.height < cfg.finality_activation_height {
        return Ok(res);
    }

    // Should not proceed if BTC staking is not activated
    let Some(activated_height) = get_btc_staking_activated_height(deps.storage) else {
        return Ok(res);
    };

    // Index the current block
    let ev = finality::index_block(deps, env.block.height, &hex::decode(app_hash_hex)?)?;
    res = res.add_event(ev);

    // Tally non-finalised blocks with a per-EndBlock cap
    let events = crate::tallying::tally_blocks(
        deps,
        &env,
        max(cfg.finality_activation_height, activated_height),
    )?;
    res = res.add_events(events);

    // Examine liveness of finality providers and jail them if they are inactive for a certain
    // duration.
    let liveness_events = handle_liveness(deps, &env, &cfg)?;
    res = res.add_events(liveness_events);

    // On an reward interval boundary, send rewards for distribution to Babylon Genesis
    if env.block.height > 0 && env.block.height % cfg.reward_interval == 0 {
        if let Some(rewards_msg) = handle_rewards_distribution(deps, &env)? {
            res = res.add_message(rewards_msg);
        }
    }

    Ok(res)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use babylon_test_utils::migration::MigrationTester;
    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};
    use cosmwasm_std::{coin, coins, from_json, Uint128, WasmMsg};
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
    fn test_calculate_rewards_distribution() {
        let mut deps = mock_dependencies();
        let mut env = mock_env();
        env.contract.address = deps.api.addr_make("finality_contract");

        // Set up the contract with config
        let babylon_addr = deps.api.addr_make("babylon");
        let staking_addr = deps.api.addr_make("staking");
        let config = Config::new_test(babylon_addr.clone(), staking_addr.clone());
        CONFIG.save(&mut deps.storage, &config).unwrap();

        // Set contract balance for rewards
        deps.querier
            .bank
            .update_balance(env.contract.address.clone(), vec![coin(1000, "TOKEN")]);

        // Set up accumulated voting weights (simulating FPs having voted)
        let fp1 = "fp1".to_string();
        let fp2 = "fp2".to_string();
        ACCUMULATED_VOTING_WEIGHTS
            .save(&mut deps.storage, &fp1, &2000u128)
            .unwrap();
        ACCUMULATED_VOTING_WEIGHTS
            .save(&mut deps.storage, &fp2, &1000u128)
            .unwrap();

        // Test handle_rewards_distribution
        let rewards_msg = handle_rewards_distribution(&mut deps.as_mut(), &env).unwrap();

        // Verify that a message was created (indicates rewards were distributed)
        assert!(rewards_msg.is_some());

        // Extract and verify the WasmMsg
        match &rewards_msg.unwrap() {
            WasmMsg::Execute {
                contract_addr,
                msg,
                funds,
            } => {
                assert_eq!(contract_addr, &babylon_addr.to_string());
                assert_eq!(funds, &coins(999, "TOKEN")); // 666 + 333 = 999 (due to floor division)

                // Verify the message is a RewardsDistribution message
                let msg_data: babylon_contract::msg::contract::ExecuteMsg = from_json(msg).unwrap();
                match msg_data {
                    babylon_contract::msg::contract::ExecuteMsg::RewardsDistribution {
                        fp_distribution,
                    } => {
                        assert_eq!(fp_distribution.len(), 2);
                        assert_eq!(fp_distribution[0].fp_pubkey_hex, fp1);
                        assert_eq!(fp_distribution[0].reward, Uint128::from(666u128));
                        assert_eq!(fp_distribution[1].fp_pubkey_hex, fp2);
                        assert_eq!(fp_distribution[1].reward, Uint128::from(333u128));
                    }
                    _ => panic!("Expected RewardsDistribution message"),
                }
            }
            _ => panic!("Expected WasmMsg::Execute"),
        }

        // Verify accumulated weights were cleared
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
    fn test_calculate_rewards_distribution_with_no_balance() {
        let mut deps = mock_dependencies();
        let mut env = mock_env();
        env.contract.address = deps.api.addr_make("finality_contract");

        // Set up the contract with config
        let babylon_addr = deps.api.addr_make("babylon");
        let staking_addr = deps.api.addr_make("staking");
        let config = Config::new_test(babylon_addr.clone(), staking_addr.clone());
        CONFIG.save(&mut deps.storage, &config).unwrap();

        // Set zero balance
        deps.querier
            .bank
            .update_balance(env.contract.address.clone(), vec![coin(0, "TOKEN")]);

        // Test handle_rewards_distribution with no balance
        let rewards_msg = handle_rewards_distribution(&mut deps.as_mut(), &env).unwrap();

        // Verify no message is returned (no rewards to distribute)
        assert!(rewards_msg.is_none());
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
    fn test_migration_basics() {
        MigrationTester::new(CONTRACT_NAME, CONTRACT_VERSION).test_migration_basics(
            migrate,
            instantiate,
            crate::msg::MigrateMsg {},
            InstantiateMsg::default(),
            |err| match err {
                ContractError::InvalidContractName { expected, actual } => Some((expected, actual)),
                _ => None,
            },
        );
    }

    #[test]
    fn test_update_config_admin() {
        let mut deps = mock_dependencies();
        let init_admin = deps.api.addr_make(INIT_ADMIN);

        // Create an InstantiateMsg with admin set
        let msg = InstantiateMsg {
            admin: Some(init_admin.to_string()),
            ..Default::default()
        };

        let info = message_info(&deps.api.addr_make(CREATOR), &[]);
        instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        // Test updating config as admin
        let update_config_msg = ExecuteMsg::UpdateConfig {
            max_active_finality_providers: Some(200),
            min_pub_rand: Some(5),
            reward_interval: Some(100),
            missed_blocks_window: Some(500),
            jail_duration: Some(172800), // 2 days
            finality_activation_height: Some(10),
            max_pub_rand_commit_offset: Some(2_000_000),
        };

        let admin_info = message_info(&init_admin, &[]);
        let res = execute(deps.as_mut(), mock_env(), admin_info, update_config_msg).unwrap();

        // Verify the response
        assert_eq!(res.attributes.len(), 2);
        assert_eq!(res.attributes[0].key, "action");
        assert_eq!(res.attributes[0].value, "update_config");
        assert_eq!(res.attributes[1].key, "sender");
        assert_eq!(res.attributes[1].value, init_admin.as_str());

        // Verify the config was updated
        let config = CONFIG.load(&deps.storage).unwrap();
        assert_eq!(config.max_active_finality_providers, 200);
        assert_eq!(config.min_pub_rand, 5);
        assert_eq!(config.reward_interval, 100);
        assert_eq!(config.missed_blocks_window, 500);
        assert_eq!(config.jail_duration, 172800);
        assert_eq!(config.finality_activation_height, 10);
        assert_eq!(config.max_pub_rand_commit_offset, 2_000_000);
    }

    #[test]
    fn test_update_config_unauthorized() {
        let mut deps = mock_dependencies();
        let init_admin = deps.api.addr_make(INIT_ADMIN);

        // Create an InstantiateMsg with admin set
        let msg = InstantiateMsg {
            admin: Some(init_admin.to_string()),
            ..Default::default()
        };

        let info = message_info(&deps.api.addr_make(CREATOR), &[]);
        instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        // Test updating config as non-admin, non-babylon
        let update_config_msg = ExecuteMsg::UpdateConfig {
            max_active_finality_providers: Some(200),
            min_pub_rand: None,
            reward_interval: None,
            missed_blocks_window: None,
            jail_duration: None,
            finality_activation_height: None,
            max_pub_rand_commit_offset: None,
        };

        let unauthorized_info = message_info(&deps.api.addr_make("unauthorized"), &[]);
        let err = execute(
            deps.as_mut(),
            mock_env(),
            unauthorized_info,
            update_config_msg,
        )
        .unwrap_err();

        // Verify the error
        assert_eq!(err, ContractError::Unauthorized {});
    }

    #[test]
    fn test_update_config_partial_update() {
        let mut deps = mock_dependencies();
        let init_admin = deps.api.addr_make(INIT_ADMIN);

        // Create an InstantiateMsg with admin set
        let msg = InstantiateMsg {
            admin: Some(init_admin.to_string()),
            ..Default::default()
        };

        let info = message_info(&deps.api.addr_make(CREATOR), &[]);
        instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        // Get initial config
        let initial_config = CONFIG.load(&deps.storage).unwrap();
        let initial_min_pub_rand = initial_config.min_pub_rand;

        // Test updating only some fields
        let update_config_msg = ExecuteMsg::UpdateConfig {
            max_active_finality_providers: Some(250),
            min_pub_rand: None, // This should not be updated
            reward_interval: Some(120),
            missed_blocks_window: None,       // This should not be updated
            jail_duration: Some(259200),      // 3 days
            finality_activation_height: None, // This should not be updated
            max_pub_rand_commit_offset: None, // This should not be updated
        };

        let admin_info = message_info(&init_admin, &[]);
        let res = execute(deps.as_mut(), mock_env(), admin_info, update_config_msg).unwrap();

        // Verify the response
        assert_eq!(res.attributes.len(), 2);

        // Verify only the specified fields were updated
        let config = CONFIG.load(&deps.storage).unwrap();
        assert_eq!(config.max_active_finality_providers, 250); // Updated
        assert_eq!(config.min_pub_rand, initial_min_pub_rand); // Not updated
        assert_eq!(config.reward_interval, 120); // Updated
        assert_eq!(
            config.missed_blocks_window,
            initial_config.missed_blocks_window
        ); // Not updated
        assert_eq!(config.jail_duration, 259200); // Updated
        assert_eq!(
            config.finality_activation_height,
            initial_config.finality_activation_height
        ); // Not updated
        assert_eq!(
            config.max_pub_rand_commit_offset,
            initial_config.max_pub_rand_commit_offset
        ); // Not updated
    }
}
