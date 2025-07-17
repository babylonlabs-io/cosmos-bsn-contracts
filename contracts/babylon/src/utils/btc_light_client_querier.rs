use crate::error::ContractError;
use crate::state::config::CONFIG;
use btc_light_client::msg::btc_header::BtcHeaderResponse;
use cosmwasm_std::Deps;

/// Get the BTC light client contract address
fn get_contract_addr(deps: Deps) -> Result<String, ContractError> {
    let cfg = CONFIG.load(deps.storage)?;
    cfg.btc_light_client_addr()
}

/// Query the tip header from the BTC light client
pub fn query_tip_header(deps: Deps) -> Result<BtcHeaderResponse, ContractError> {
    let contract_addr = get_contract_addr(deps)?;
    let msg = btc_light_client::msg::contract::QueryMsg::BtcTipHeader {};
    let response: BtcHeaderResponse = deps.querier.query_wasm_smart(&contract_addr, &msg)?;
    Ok(response)
}

/// Query a header by hash from the BTC light client
/// NOTE: the hash has to be reversed in advance to match the BTC header hash format
pub fn query_header_by_hash(deps: Deps, hash: &str) -> Result<BtcHeaderResponse, ContractError> {
    let contract_addr = get_contract_addr(deps)?;
    let msg = btc_light_client::msg::contract::QueryMsg::BtcHeaderByHash {
        hash: hash.to_string(),
    };
    let response: BtcHeaderResponse = deps.querier.query_wasm_smart(&contract_addr, &msg)?;
    Ok(response)
}
