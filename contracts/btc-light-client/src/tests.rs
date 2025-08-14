use crate::contract::{execute, instantiate};
use crate::msg::btc_header::BtcHeader;
use crate::msg::{ExecuteMsg, InstantiateMsg};
use crate::state::{BTC_HEIGHTS, CONFIG};
use crate::BitcoinNetwork;
use babylon_proto::babylon::btclightclient::v1::BtcHeaderInfoResponse;
use babylon_test_utils::get_btc_lc_mainchain_resp;
use bitcoin::block::Header as BlockHeader;
use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};
use cosmwasm_std::{Addr, Uint256};
use std::str::FromStr;

#[test]
fn instantiate_should_work() {
    let mut deps = mock_dependencies();

    let info = message_info(&deps.api.addr_make("creator"), &[]);

    let msg = InstantiateMsg {
        network: BitcoinNetwork::Mainnet,
        btc_confirmation_depth: 6,
        checkpoint_finalization_timeout: 100,
        admin: None,
    };

    let res = instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

    // Basic assertions
    assert_eq!(res.attributes[0].key, "action");
    assert_eq!(res.attributes[0].value, "instantiate");

    // Config should be saved
    let cfg = CONFIG.load(&deps.storage).unwrap();
    assert_eq!(cfg.btc_confirmation_depth, 6);
    assert_eq!(cfg.checkpoint_finalization_timeout, 100);
    assert_eq!(cfg.network, BitcoinNetwork::Mainnet);
}

#[test]
fn instantiate_without_initial_header_should_work() {
    let mut deps = mock_dependencies();
    let info = message_info(&deps.api.addr_make("creator"), &[]);

    let msg = InstantiateMsg {
        network: BitcoinNetwork::Mainnet,
        btc_confirmation_depth: 6,
        checkpoint_finalization_timeout: 100,
        admin: None,
    };

    let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

    // Basic assertions
    assert_eq!(res.attributes[0].key, "action");
    assert_eq!(res.attributes[0].value, "instantiate");

    // Config should be saved
    let cfg = CONFIG.load(&deps.storage).unwrap();
    assert_eq!(cfg.btc_confirmation_depth, 6);
    assert_eq!(cfg.checkpoint_finalization_timeout, 100);
    assert_eq!(cfg.network, BitcoinNetwork::Mainnet);
}

#[test]
fn auto_init_on_first_header_works() {
    let mut deps = mock_dependencies();

    // Instantiate without initial header
    let msg = InstantiateMsg {
        network: crate::state::BitcoinNetwork::Regtest,
        btc_confirmation_depth: 6,
        checkpoint_finalization_timeout: 99,
        admin: None,
    };
    let info = message_info(&Addr::unchecked("creator"), &[]);
    instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

    // Submit a batch of headers (from the boundary test vector)
    let res = get_btc_lc_mainchain_resp();
    let headers: Vec<BtcHeader> = res
        .headers
        .iter()
        .map(|h| h.clone().try_into().unwrap())
        .collect();

    let base_header: BtcHeaderInfoResponse = res.headers.first().unwrap().clone();
    // Convert work from Uint256 to Bytes
    let first_work_bytes = Uint256::from_str(&base_header.work)
        .unwrap()
        .to_be_bytes()
        .to_vec();
    // And hex encode it
    let first_work_hex = hex::encode(first_work_bytes);
    let first_height = base_header.height;

    let exec_msg = ExecuteMsg::BtcHeaders {
        headers: headers.clone(),
        first_work: Some(first_work_hex),
        first_height: Some(first_height),
    };
    let result = execute(deps.as_mut(), mock_env(), info, exec_msg);

    assert!(result.is_ok(), "Auto-init on first header should succeed");

    // Convert BtcHeader to BlockHeader to get the hash
    let base_header = &headers[0];
    let base_block_header: BlockHeader = base_header.clone().try_into().unwrap();
    let base_header_hash = base_block_header.block_hash();

    // The height should be the first height in the test vector
    let expected_height = res.headers[0].height;
    let stored_height = BTC_HEIGHTS
        .load(&deps.storage, base_header_hash.as_ref())
        .unwrap();
    assert_eq!(stored_height, expected_height);
}
