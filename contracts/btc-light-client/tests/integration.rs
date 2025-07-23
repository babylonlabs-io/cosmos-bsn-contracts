use btc_light_client::msg::contract::InstantiateMsg;
use cosmwasm_std::testing::message_info;
use cosmwasm_std::{Addr, ContractResult, Response};
use cosmwasm_vm::testing::{instantiate, mock_env, mock_instance};

#[cfg(clippy)]
static BTC_LIGHT_CLIENT_CONTRACT_WASM: &[u8] = &[];

#[cfg(not(clippy))]
static BTC_LIGHT_CLIENT_CONTRACT_WASM: &[u8] =
    include_bytes!("../../../artifacts/btc_light_client.wasm");

/// Wasm size limit: https://github.com/CosmWasm/wasmd/blob/main/x/wasm/types/validation.go#L24-L25
const MAX_WASM_SIZE: usize = 1024 * 1024; // 1 MB

const CREATOR: &str = "creator";

#[test]
fn wasm_size_limit_check() {
    assert!(
        BTC_LIGHT_CLIENT_CONTRACT_WASM.len() < MAX_WASM_SIZE,
        "BTC light client contract wasm binary is too large: {} (target: {MAX_WASM_SIZE})",
        BTC_LIGHT_CLIENT_CONTRACT_WASM.len(),
    );
}

#[test]
fn instantiate_works() {
    let mut deps = mock_instance(BTC_LIGHT_CLIENT_CONTRACT_WASM, &[]);

    let msg = InstantiateMsg {
        network: btc_light_client::BitcoinNetwork::Regtest,
        btc_confirmation_depth: 10,
        checkpoint_finalization_timeout: 100,
        initial_header: Some(babylon_test_utils::initial_header()),
    };
    let info = message_info(&Addr::unchecked(CREATOR), &[]);
    let res: ContractResult<Response> = instantiate(&mut deps, mock_env(), info, msg);
    let msgs = res.unwrap().messages;
    assert_eq!(0, msgs.len());
}
