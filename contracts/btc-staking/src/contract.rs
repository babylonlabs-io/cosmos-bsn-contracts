use crate::error::ContractError;
use crate::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::queries;
use crate::staking::{
    handle_btc_staking, handle_distribute_rewards, handle_slash_fp, handle_withdraw_rewards,
    process_expired_btc_delegations,
};
use crate::state::config::{Config, ADMIN, CONFIG, PARAMS};
use babylon_apis::btc_staking_api::SudoMsg;
use babylon_bindings::BabylonMsg;
#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    attr, to_json_binary, Addr, Deps, DepsMut, Empty, Env, MessageInfo, QueryResponse, Reply,
    Response, StdResult,
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
) -> Result<Response<BabylonMsg>, ContractError> {
    nonpayable(&info)?;
    let denom = deps.querier.query_bonded_denom()?;
    let config = Config {
        btc_light_client: Addr::unchecked("UNSET"), // To be set later, through `UpdateContractAddresses`
        babylon: info.sender,
        finality: Addr::unchecked("UNSET"), // To be set later, through `UpdateContractAddresses`
        denom,
    };
    CONFIG.save(deps.storage, &config)?;

    let api = deps.api;
    ADMIN.set(deps.branch(), maybe_addr(api, msg.admin.clone())?)?;

    let params = msg.params.unwrap_or_default();
    PARAMS.save(deps.storage, &params)?;
    // initialize storage, so no issue when reading for the first time

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
        QueryMsg::Config {} => Ok(to_json_binary(&queries::config(deps)?)?),
        QueryMsg::Params {} => Ok(to_json_binary(&queries::params(deps)?)?),
        QueryMsg::Admin {} => to_json_binary(&ADMIN.query_admin(deps)?).map_err(Into::into),
        QueryMsg::FinalityProvider { btc_pk_hex } => Ok(to_json_binary(
            &queries::finality_provider(deps, btc_pk_hex)?,
        )?),
        QueryMsg::FinalityProviders { start_after, limit } => Ok(to_json_binary(
            &queries::finality_providers(deps, start_after, limit)?,
        )?),
        QueryMsg::Delegation {
            staking_tx_hash_hex,
        } => Ok(to_json_binary(&queries::delegation(
            deps,
            staking_tx_hash_hex,
        )?)?),
        QueryMsg::Delegations {
            start_after,
            limit,
            active,
        } => Ok(to_json_binary(&queries::delegations(
            deps,
            start_after,
            limit,
            active,
        )?)?),
        QueryMsg::DelegationsByFP { btc_pk_hex } => Ok(to_json_binary(
            &queries::delegations_by_fp(deps, btc_pk_hex)?,
        )?),
        QueryMsg::FinalityProviderInfo { btc_pk_hex, height } => Ok(to_json_binary(
            &queries::finality_provider_info(deps, btc_pk_hex, height)?,
        )?),
        QueryMsg::FinalityProvidersByPower { start_after, limit } => Ok(to_json_binary(
            &queries::finality_providers_by_power(deps, start_after, limit)?,
        )?),
        QueryMsg::PendingRewards {
            staker_addr,
            fp_pubkey_hex,
        } => Ok(to_json_binary(&queries::pending_rewards(
            deps,
            staker_addr,
            fp_pubkey_hex,
        )?)?),
        QueryMsg::AllPendingRewards {
            staker_addr,
            start_after,
            limit,
        } => Ok(to_json_binary(&queries::all_pending_rewards(
            deps,
            staker_addr,
            start_after,
            limit,
        )?)?),
        QueryMsg::ActivatedHeight {} => Ok(to_json_binary(&queries::activated_height(deps)?)?),
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
) -> Result<Response<BabylonMsg>, ContractError> {
    let api = deps.api;
    match msg {
        ExecuteMsg::UpdateAdmin { admin } => ADMIN
            .execute_update_admin(deps, info, maybe_addr(api, admin)?)
            .map_err(Into::into),
        ExecuteMsg::UpdateContractAddresses {
            btc_light_client,
            finality,
        } => handle_update_contract_addresses(deps, info, btc_light_client, finality),
        ExecuteMsg::BtcStaking {
            new_fp,
            active_del,
            slashed_del,
            unbonded_del,
        } => handle_btc_staking(
            deps,
            env,
            &info,
            &new_fp,
            &active_del,
            &slashed_del,
            &unbonded_del,
        ),
        ExecuteMsg::Slash { fp_btc_pk_hex } => handle_slash_fp(deps, env, &info, &fp_btc_pk_hex),
        ExecuteMsg::DistributeRewards { fp_distribution } => {
            let evts = handle_distribute_rewards(deps, &env, &info, &fp_distribution)?;
            Ok(Response::new().add_events(evts))
        }
        ExecuteMsg::WithdrawRewards {
            fp_pubkey_hex,
            staker_addr,
        } => {
            let res = handle_withdraw_rewards(deps, &env, &info, &fp_pubkey_hex, staker_addr)?;
            Ok(res)
        }
    }
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn sudo(deps: DepsMut, env: Env, msg: SudoMsg) -> Result<Response<BabylonMsg>, ContractError> {
    match msg {
        SudoMsg::BeginBlock { .. } => handle_begin_block(deps, env),
    }
}

// Handles the BeginBlock sudo message from the Consumer chain's x/babylon module.
fn handle_begin_block(deps: DepsMut, env: Env) -> Result<Response<BabylonMsg>, ContractError> {
    // This function processes expired BTC delegations in the begin blocker of the staking contract.
    // While this could also be done in the finality contract's begin blocker, it would require an
    // inter-contract call to the staking contract. Due to how CosmWasm handles state changes
    // (they only take effect at the end of the call execution in the caller's context), this would
    // create ordering issues. To avoid these complications and minimize inter-contract calls,
    // we process expired delegations directly in the staking contract's begin blocker.
    process_expired_btc_delegations(deps, env)?;

    // TODO: Add events (#124)
    Ok(Response::new())
}

fn handle_update_contract_addresses(
    deps: DepsMut,
    info: MessageInfo,
    btc_light_client_addr: String,
    finality_addr: String,
) -> Result<Response<BabylonMsg>, ContractError> {
    let mut cfg = CONFIG.load(deps.storage)?;
    if info.sender != cfg.babylon && !ADMIN.is_admin(deps.as_ref(), &info.sender)? {
        return Err(ContractError::Unauthorized {});
    }
    cfg.btc_light_client = deps.api.addr_validate(&btc_light_client_addr)?;
    cfg.finality = deps.api.addr_validate(&finality_addr)?;
    CONFIG.save(deps.storage, &cfg)?;

    let attributes = vec![
        attr("action", "update_contract_addresses"),
        attr("btc_light_client", btc_light_client_addr),
        attr("finality", finality_addr),
        attr("sender", info.sender),
    ];
    Ok(Response::new().add_attributes(attributes))
}

#[cfg(test)]
pub mod tests {
    use super::*;

    use cosmwasm_std::from_json;
    use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};
    use cw_controllers::AdminResponse;

    pub(crate) const CREATOR: &str = "creator";
    pub(crate) const INIT_ADMIN: &str = "initial_admin";
    const NEW_ADMIN: &str = "new_admin";

    #[test]
    fn instantiate_without_admin() {
        let mut deps = mock_dependencies();

        // Create an InstantiateMsg with admin set to None
        let msg = InstantiateMsg {
            params: None,
            admin: None, // No admin provided
        };

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
            params: None,
            admin: Some(init_admin.to_string()), // Admin provided
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
    fn test_update_admin() {
        let mut deps = mock_dependencies();
        let init_admin = deps.api.addr_make(INIT_ADMIN);
        let new_admin = deps.api.addr_make(NEW_ADMIN);

        // Create an InstantiateMsg with admin set to Some(INIT_ADMIN.into())
        let instantiate_msg = InstantiateMsg {
            params: None,
            admin: Some(init_admin.to_string()), // Admin provided
        };

        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        // Call the instantiate function
        let res = instantiate(deps.as_mut(), mock_env(), info.clone(), instantiate_msg).unwrap();

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
    fn test_update_contract_addresses() {
        let mut deps = mock_dependencies();
        let init_admin = deps.api.addr_make(INIT_ADMIN);

        // Create an InstantiateMsg with admin
        let instantiate_msg = InstantiateMsg {
            params: None,
            admin: Some(init_admin.to_string()),
        };

        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        // Call instantiate
        instantiate(deps.as_mut(), mock_env(), info.clone(), instantiate_msg).unwrap();

        const BABYLON_CONTRACT_ADDR: &str =
            "cosmwasm19mfs8tl4s396u7vqw9rrnsmrrtca5r66p7v8jvwdxvjn3shcmllqupdgxu";
        const BTC_LIGHT_CLIENT_CONTRACT_ADDR: &str =
            "cosmwasm14hj2tavq8fpesdwxxcu44rty3hh90vhujrvcmstl4zr3txmfvw9s8jef58";

        // Try to update addresses with non-admin/non-babylon
        let non_admin_info = message_info(&deps.api.addr_make("non_admin"), &[]);
        let update_msg = ExecuteMsg::UpdateContractAddresses {
            btc_light_client: BABYLON_CONTRACT_ADDR.to_string(),
            finality: BTC_LIGHT_CLIENT_CONTRACT_ADDR.to_string(),
        };
        let err = execute(
            deps.as_mut(),
            mock_env(),
            non_admin_info,
            update_msg.clone(),
        )
        .unwrap_err();
        assert_eq!(err, ContractError::Unauthorized {});

        // Update with admin
        let admin_info = message_info(&init_admin, &[]);
        let res = execute(deps.as_mut(), mock_env(), admin_info, update_msg).unwrap();
        assert_eq!(4, res.attributes.len());

        // Verify config was updated
        let config = queries::config(deps.as_ref()).unwrap();
        assert_eq!(
            config.finality,
            Addr::unchecked(BTC_LIGHT_CLIENT_CONTRACT_ADDR)
        );
        assert_eq!(
            config.btc_light_client,
            Addr::unchecked(BABYLON_CONTRACT_ADDR)
        );

        // Update with babylon
        let babylon_info = message_info(&deps.api.addr_make(CREATOR), &[]);
        let update_msg = ExecuteMsg::UpdateContractAddresses {
            btc_light_client: BABYLON_CONTRACT_ADDR.to_string(),
            finality: BTC_LIGHT_CLIENT_CONTRACT_ADDR.to_string(),
        };
        let res = execute(deps.as_mut(), mock_env(), babylon_info, update_msg).unwrap();
        assert_eq!(4, res.attributes.len());

        // Verify config was updated again
        let config = queries::config(deps.as_ref()).unwrap();
        assert_eq!(
            config.finality,
            Addr::unchecked(BTC_LIGHT_CLIENT_CONTRACT_ADDR)
        );
        assert_eq!(
            config.btc_light_client,
            Addr::unchecked(BABYLON_CONTRACT_ADDR)
        );
    }
}
