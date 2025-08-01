use cosmwasm_std::{ContractResult, Response};
use cosmwasm_vm::testing::{instantiate, mock_env, mock_info, mock_instance};

use btc_finality::msg::InstantiateMsg;

#[cfg(clippy)]
static WASM: &[u8] = &[];
// wasm binary lite version
#[cfg(not(clippy))]
static WASM: &[u8] = include_bytes!("../../../artifacts/btc_finality.wasm");
/// Wasm size limit: https://github.com/CosmWasm/wasmd/blob/main/x/wasm/types/validation.go#L24-L25
const MAX_WASM_SIZE: usize = 800 * 1024; // 800 KB

const CREATOR: &str = "creator";

#[test]
fn wasm_size_limit_check() {
    assert!(
        WASM.len() < MAX_WASM_SIZE,
        "BTC finality contract wasm binary is too large: {} (target: {})",
        WASM.len(),
        MAX_WASM_SIZE
    );
}

#[test]
#[ignore = "Unsupported query type: GRPC"]
fn instantiate_works() {
    let mut deps = mock_instance(WASM, &[]);

    let msg = InstantiateMsg::default();
    let info = mock_info(CREATOR, &[]);
    let res: ContractResult<Response> = instantiate(&mut deps, mock_env(), info, msg);
    let msgs = res.unwrap().messages;
    assert_eq!(0, msgs.len());
}
