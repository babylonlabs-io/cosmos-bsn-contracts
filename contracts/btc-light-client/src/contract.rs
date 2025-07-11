use cosmwasm_std::{to_json_binary, Binary, Deps, DepsMut, Empty, Env, MessageInfo, Response};
use cw2::set_contract_version;

use babylon_bindings::BabylonMsg;
use bitcoin::block::Header as BlockHeader;

use crate::error::ContractError;
use crate::msg::contract::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::state::btc_light_client::{handle_btc_headers_from_user, set_base_header, set_tip};
use crate::state::config::{Config, CONFIG};

pub const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
pub const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response<BabylonMsg>, ContractError> {
    msg.validate()?;

    let InstantiateMsg {
        network,
        btc_confirmation_depth,
        checkpoint_finalization_timeout,
        initial_header,
    } = msg;

    let cfg = Config {
        network,
        btc_confirmation_depth,
        checkpoint_finalization_timeout,
    };

    // Initialises the BTC header chain storage.
    let base_header = initial_header.to_btc_header_info()?;

    let base_btc_header: BlockHeader =
        bitcoin::consensus::deserialize(base_header.header.as_ref())?;

    crate::bitcoin::check_proof_of_work(&cfg.network.chain_params(), &base_btc_header)?;

    // Store base header (immutable) and tip.
    set_base_header(deps.storage, &base_header)?;
    set_tip(deps.storage, &base_header)?;

    CONFIG.save(deps.storage, &cfg)?;

    // Set contract version
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    Ok(Response::new().add_attribute("action", "instantiate"))
}

pub fn migrate(
    deps: DepsMut,
    _env: Env,
    _msg: Empty,
) -> Result<Response<BabylonMsg>, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    Ok(Response::new().add_attribute("action", "migrate"))
}

pub fn execute(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response<BabylonMsg>, ContractError> {
    match msg {
        ExecuteMsg::BtcHeaders { headers } => {
            let headers_len = headers.len();

            handle_btc_headers_from_user(deps.storage, &headers)
                .map(|_| {
                    deps.api
                        .debug(&format!("Successfully handled {headers_len} BTC headers"));
                    Response::new().add_attribute("action", "update_btc_light_client")
                })
                .inspect_err(|e| {
                    deps.api
                        .debug(&format!("Failed to handle {headers_len} BTC headers: {e}"));
                })
        }
    }
}

pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> Result<Binary, ContractError> {
    use crate::queries::btc_header::*;

    match msg {
        QueryMsg::Config {} => Ok(to_json_binary(&CONFIG.load(deps.storage)?)?),
        QueryMsg::BtcBaseHeader {} => Ok(to_json_binary(&btc_base_header(&deps)?)?),
        QueryMsg::BtcTipHeader {} => Ok(to_json_binary(&btc_tip_header(&deps)?)?),
        QueryMsg::BtcHeader { height } => Ok(to_json_binary(&btc_header(&deps, height)?)?),
        QueryMsg::BtcHeaderByHash { hash } => {
            Ok(to_json_binary(&btc_header_by_hash(&deps, &hash)?)?)
        }
        QueryMsg::BtcHeaders {
            start_after,
            limit,
            reverse,
        } => Ok(to_json_binary(&btc_headers(
            &deps,
            start_after,
            limit,
            reverse,
        )?)?),
    }
}
