use cosmwasm_std::testing::{message_info, mock_ibc_channel_open_try};
use cosmwasm_std::{to_json_binary, Addr, ContractResult, IbcOrder, Response};
use cosmwasm_vm::testing::{
    ibc_channel_open, instantiate, mock_env, mock_instance, mock_instance_with_gas_limit, MockApi,
    MockQuerier, MockStorage,
};
use cosmwasm_vm::Instance;

use babylon_contract::ibc::IBC_VERSION;
use babylon_contract::msg::contract::InstantiateMsg;
use btc_light_client::msg::InstantiateMsg as BtcLightClientInstantiateMsg;
use btc_light_client::BitcoinNetwork;

#[cfg(clippy)]
static BABYLON_CONTRACT_WASM: &[u8] = &[];

#[cfg(not(clippy))]
static BABYLON_CONTRACT_WASM: &[u8] = include_bytes!("../../../artifacts/babylon_contract.wasm");

/// Wasm size limit: https://github.com/CosmWasm/wasmd/blob/main/x/wasm/types/validation.go#L24-L25
const MAX_WASM_SIZE: usize = 1024 * 1024; // 1 MB

const CREATOR: &str = "creator";

#[track_caller]
fn setup() -> Instance<MockApi, MockStorage, MockQuerier> {
    let mut deps = mock_instance_with_gas_limit(BABYLON_CONTRACT_WASM, 2_250_000_000_000);
    let mut msg = InstantiateMsg::new_test();
    msg.btc_confirmation_depth = 10;
    msg.checkpoint_finalization_timeout = 99;
    msg.btc_light_client_msg.replace(
        to_json_binary(&BtcLightClientInstantiateMsg {
            network: BitcoinNetwork::Testnet,
            btc_confirmation_depth: 1,
            checkpoint_finalization_timeout: 1,
            initial_header: babylon_test_utils::get_btc_initial_header(),
        })
        .unwrap(),
    );
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
    let mut msg = InstantiateMsg::new_test();
    msg.btc_confirmation_depth = 10;
    msg.checkpoint_finalization_timeout = 100;
    let info = message_info(&Addr::unchecked(CREATOR), &[]);
    let res: ContractResult<Response> = instantiate(&mut deps, mock_env(), info, msg);
    let msgs = res.unwrap().messages;
    assert_eq!(0, msgs.len());
}

#[test]
fn enforce_version_in_handshake() {
    let mut deps = setup();

    let wrong_order = mock_ibc_channel_open_try("channel-1234", IbcOrder::Unordered, IBC_VERSION);
    ibc_channel_open(&mut deps, mock_env(), wrong_order).unwrap_err();

    let wrong_version = mock_ibc_channel_open_try("channel-1234", IbcOrder::Ordered, "reflect");
    ibc_channel_open(&mut deps, mock_env(), wrong_version).unwrap_err();

    let valid_handshake = mock_ibc_channel_open_try("channel-1234", IbcOrder::Ordered, IBC_VERSION);
    ibc_channel_open(&mut deps, mock_env(), valid_handshake).unwrap();
}
