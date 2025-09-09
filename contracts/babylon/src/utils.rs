use crate::error::ContractError;
use crate::state::CONFIG;
use babylon_proto::babylon::btclightclient::v1::BtcHeaderInfo;
use btc_light_client::msg::btc_header::{btc_headers_from_info, BtcHeaderResponse};
use btc_light_client::msg::contract::ExecuteMsg as BtcLightClientExecuteMsg;
use cosmwasm_std::{to_json_binary, Deps, DepsMut, WasmMsg};

pub fn new_btc_headers_msg(
    deps: &mut DepsMut,
    headers: &[BtcHeaderInfo],
) -> Result<WasmMsg, ContractError> {
    let cfg = CONFIG.load(deps.storage)?;
    let contract_addr = cfg
        .btc_light_client
        .ok_or(ContractError::BtcLightClientNotSet {})?;

    let btc_headers = btc_headers_from_info(headers)?;

    let base_header = headers.first().ok_or(ContractError::BtcHeaderEmpty {})?;
    let first_work = hex::encode(base_header.work.as_ref());
    let first_height = base_header.height;

    let msg = BtcLightClientExecuteMsg::BtcHeaders {
        headers: btc_headers,
        first_work: Some(first_work),
        first_height: Some(first_height),
    };
    let wasm_msg = WasmMsg::Execute {
        contract_addr: contract_addr.to_string(),
        msg: to_json_binary(&msg)?,
        funds: vec![],
    };

    Ok(wasm_msg)
}

/// Get the BTC light client contract address
#[allow(dead_code)]
fn get_contract_addr(deps: Deps) -> Result<String, ContractError> {
    let cfg = CONFIG.load(deps.storage)?;
    let contract_addr = cfg
        .btc_light_client
        .ok_or(ContractError::BtcLightClientNotSet {})?;
    Ok(contract_addr.to_string())
}

/// Query the tip header from the BTC light client
#[allow(dead_code)]
pub fn query_tip_header(deps: Deps) -> Result<BtcHeaderResponse, ContractError> {
    let contract_addr = get_contract_addr(deps)?;
    let msg = btc_light_client::msg::contract::QueryMsg::BtcTipHeader {};
    let response: BtcHeaderResponse = deps.querier.query_wasm_smart(&contract_addr, &msg)?;
    Ok(response)
}

/// Query a header by hash from the BTC light client
/// NOTE: the hash has to be reversed in advance to match the BTC header hash format
#[allow(dead_code)]
pub fn query_header_by_hash(deps: Deps, hash: &str) -> Result<BtcHeaderResponse, ContractError> {
    let contract_addr = get_contract_addr(deps)?;
    let msg = btc_light_client::msg::contract::QueryMsg::BtcHeaderByHash {
        hash: hash.to_string(),
    };
    let response: BtcHeaderResponse = deps.querier.query_wasm_smart(&contract_addr, &msg)?;
    Ok(response)
}
