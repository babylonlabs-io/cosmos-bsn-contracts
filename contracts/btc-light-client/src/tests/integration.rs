//! This integration test tries to run and call the generated wasm.
//! It depends on a Wasm build being available, which you can create with `cargo wasm`.
//! Then running `cargo integration-test` will validate we can properly call into that generated Wasm.
//!
//! You can easily convert unit tests to integration tests.
//! 1. First copy them over verbatum,
//! 2. Then change
//!      let mut deps = mock_dependencies(20, &[]);
//!    to
//!      let mut deps = mock_instance(WASM, &[]);
//! 3. If you access raw storage, where ever you see something like:
//!      deps.storage.get(CONFIG_KEY).expect("no data stored");
//!    replace it with:
//!      deps.with_storage(|store| {
//!          let data = store.get(CONFIG_KEY).expect("no data stored");
//!          //...
//!      });
//! 4. Anywhere you see query(&deps, ...) you must replace it with query(&mut deps, ...)
use cosmwasm_std::testing::{message_info, mock_ibc_channel_open_try};
use cosmwasm_std::{from_json, Addr, ContractResult, IbcOrder, Response};
use cosmwasm_vm::testing::{
    execute, ibc_channel_open, instantiate, mock_env, mock_info, mock_instance,
    mock_instance_with_gas_limit, query, MockApi, MockQuerier, MockStorage,
};
use cosmwasm_vm::Instance;
use test_utils::{get_btc_lc_fork_msg, get_btc_lc_mainchain_resp};

use crate::msg::btc_header::{BtcHeader, BtcHeadersResponse};
use crate::msg::contract::{ExecuteMsg, InstantiateMsg};

static BABYLON_CONTRACT_WASM: &[u8] = include_bytes!("../../../artifacts/btc_light_client.wasm");
/// Wasm size limit: https://github.com/CosmWasm/wasmd/blob/main/x/wasm/types/validation.go#L24-L25
const MAX_WASM_SIZE: usize = 1024 * 1024; // 1 MB

const CREATOR: &str = "creator";

#[track_caller]
fn setup() -> Instance<MockApi, MockStorage, MockQuerier> {
    let mut deps = mock_instance_with_gas_limit(BABYLON_CONTRACT_WASM, 2_250_000_000_000);
    let msg = InstantiateMsg {
        network: btc_light_client::BitcoinNetwork::Regtest,
        babylon_tag: "01020304".to_string(),
        consumer_name: None,
        consumer_description: None,
        btc_confirmation_depth: 10,
        checkpoint_finalization_timeout: 99,
        notify_cosmos_zone: false,
        btc_light_client_code_id: None,
        btc_light_client_msg: None,
        btc_staking_code_id: None,
        btc_staking_msg: None,
        btc_finality_code_id: None,
        btc_finality_msg: None,
        admin: None,
        ics20_channel_id: None,
    };
    let info = message_info(&Addr::unchecked(CREATOR), &[]);
    let res: Response = instantiate(&mut deps, mock_env(), info, msg).unwrap();
    assert_eq!(0, res.messages.len());
    deps
}

#[test]
fn wasm_size_limit_check() {
    assert!(
        BABYLON_CONTRACT_WASM.len() < MAX_WASM_SIZE,
        "Babylon contract wasm binary is too large: {} (target: {})",
        BABYLON_CONTRACT_WASM.len(),
        MAX_WASM_SIZE
    );
}

#[test]
fn instantiate_works() {
    let mut deps = mock_instance(BABYLON_CONTRACT_WASM, &[]);

    let msg = InstantiateMsg {
        network: btc_light_client::BitcoinNetwork::Regtest,
        babylon_tag: "01020304".to_string(),
        consumer_name: None,
        consumer_description: None,
        btc_confirmation_depth: 10,
        checkpoint_finalization_timeout: 100,
        notify_cosmos_zone: false,
        btc_light_client_code_id: None,
        btc_light_client_msg: None,
        btc_staking_code_id: None,
        btc_staking_msg: None,
        btc_finality_code_id: None,
        btc_finality_msg: None,
        admin: None,
        ics20_channel_id: None,
    };
    let info = message_info(&Addr::unchecked(CREATOR), &[]);
    let res: ContractResult<Response> = instantiate(&mut deps, mock_env(), info, msg);
    let msgs = res.unwrap().messages;
    assert_eq!(0, msgs.len());
}

#[test]
fn btc_headers_works() {
    let mut deps = setup();
    let env = mock_env();
    let info = mock_info("anyone", &[]);

    let test_headers = get_main_msg_test_headers();

    let execute_msg = babylon_contract::msg::contract::ExecuteMsg::BtcHeaders {
        headers: test_headers,
    };

    execute::<_, _, _, _, BabylonMsg>(&mut deps, env, info, execute_msg).unwrap();
}

#[test]
fn btc_headers_fork_works() {
    let mut deps = setup();
    let env = mock_env();
    let info = mock_info("anyone", &[]);

    // Initialization
    let test_headers = get_main_msg_test_headers();

    let execute_msg = babylon_contract::msg::contract::ExecuteMsg::BtcHeaders {
        headers: test_headers,
    };

    execute::<_, _, _, _, BabylonMsg>(&mut deps, env.clone(), info.clone(), execute_msg).unwrap();

    // Fork / continuation
    let test_headers = get_fork_msg_test_headers();

    let execute_msg = babylon_contract::msg::contract::ExecuteMsg::BtcHeaders {
        headers: test_headers,
    };

    execute::<_, _, _, _, BabylonMsg>(&mut deps, env, info, execute_msg).unwrap();
}

#[test]
fn btc_headers_query_works() {
    let mut deps = setup();
    let env = mock_env();
    let info = mock_info("anyone", &[]);

    let test_headers = get_main_msg_test_headers();

    let execute_msg = babylon_contract::msg::contract::ExecuteMsg::BtcHeaders {
        headers: test_headers.clone(),
    };

    execute::<_, _, _, _, BabylonMsg>(&mut deps, env.clone(), info, execute_msg).unwrap();

    let query_msg = babylon_contract::msg::contract::QueryMsg::BtcHeaders {
        start_after: None,
        limit: None,
        reverse: None,
    };
    let res: BtcHeadersResponse = from_json(query(&mut deps, env, query_msg).unwrap()).unwrap();

    assert_eq!(res.headers.len(), 10); // default limit
    assert_eq!(
        test_headers[..10],
        res.headers.iter().map(Into::into).collect::<Vec<_>>()
    );
}
