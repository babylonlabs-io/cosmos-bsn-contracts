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
        initial_header: babylon_test_utils::initial_header(),
    };
    let info = message_info(&Addr::unchecked(CREATOR), &[]);
    let res: ContractResult<Response> = instantiate(&mut deps, mock_env(), info, msg);
    let msgs = res.unwrap().messages;
    assert_eq!(0, msgs.len());
}
