use crate::contract::{execute, instantiate};
use crate::msg::contract::InitialHeader;
use crate::msg::InstantiateMsg;
use crate::state::btc_light_client::{BTC_HEADERS, BTC_HEIGHTS};
use crate::state::config::CONFIG;
use crate::state::get_tip;
#[cfg(feature = "full-validation")]
use crate::ContractError;
use crate::{BitcoinNetwork, ExecuteMsg};
use babylon_proto::babylon::btclightclient::v1::BtcHeaderInfo;
use bitcoin::block::Header as BlockHeader;
use bitcoin::consensus::deserialize;
use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};
use prost::Message;

// TODO: update the test headers in babylon-test-utils so that we can reuse it here.
fn test_headers() -> Vec<BtcHeaderInfo> {
    let headers = vec![
        // Initial base header on Babylon Genesis mainnet, https://www.blockchain.com/explorer/blocks/btc/854784.
        ("0000c020f382af1f6d228721b49f3da2f5b831587803b16597b301000000000000000000e4f76aae64d8316d195a92424871b74168b58d1c3c6988548e0e9890b15fc2fc3c00aa66be1a0317082e4bc7", 854784),
        ("0000003acbfbbb0a8d32aa0e739dc4f910a58299a8015b1cd48902000000000000000000a32c4a6ca3d399cc5146c28af944b807f298c6de063c161c13a1b3ca6fd2632e6500aa66be1a031783eb001c", 854785)
    ];

    headers
        .into_iter()
        .map(|(header, height)| {
            let header: BlockHeader = bitcoin::consensus::encode::deserialize_hex(header)
                .expect("Static value must be correct");
            BtcHeaderInfo {
                header: bitcoin::consensus::serialize(&header).into(),
                hash: bitcoin::consensus::serialize(&header.block_hash()).into(),
                height,
                work: header.work().to_be_bytes().to_vec().into(),
            }
        })
        .collect()
}

#[test]
fn instantiate_should_work() {
    let mut deps = mock_dependencies();

    let info = message_info(&deps.api.addr_make("creator"), &[]);

    let headers = test_headers();

    let initial_header: InitialHeader = headers[0].clone().try_into().unwrap();

    let msg = InstantiateMsg {
        network: BitcoinNetwork::Mainnet,
        btc_confirmation_depth: 6,
        checkpoint_finalization_timeout: 100,
        initial_header: Some(initial_header.clone()),
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

    let initial_header_info = initial_header.to_btc_header_info().unwrap();
    let base_header_height = BTC_HEIGHTS
        .load(&deps.storage, initial_header_info.hash.as_ref())
        .unwrap();
    assert_eq!(base_header_height, 854784);

    let base_header_in_storage = BTC_HEADERS.load(&deps.storage, base_header_height).unwrap();
    assert_eq!(base_header_in_storage, initial_header_info.encode_to_vec());

    // Submit new headers should work.
    let new_header: BlockHeader = deserialize(&headers[1].header).unwrap();
    let msg = ExecuteMsg::BtcHeaders {
        headers: vec![new_header.into()],
    };
    execute(deps.as_mut(), mock_env(), info, msg).expect("Submit new headers should work");

    // Tip updated when new headers are submitted successfully.
    let tip = get_tip(&deps.storage).unwrap();
    assert_eq!(tip.height, headers[1].height);
}

#[cfg(not(feature = "full-validation"))]
#[test]
fn instantiate_without_initial_header_should_work() {
    let mut deps = mock_dependencies();
    let info = message_info(&deps.api.addr_make("creator"), &[]);

    let msg = InstantiateMsg {
        network: BitcoinNetwork::Mainnet,
        btc_confirmation_depth: 6,
        checkpoint_finalization_timeout: 100,
        initial_header: None,
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

#[cfg(feature = "full-validation")]
#[test]
fn instantiate_without_initial_header_should_fail_in_full_validation_mode() {
    let mut deps = mock_dependencies();
    let info = message_info(&deps.api.addr_make("creator"), &[]);

    let msg = InstantiateMsg {
        network: BitcoinNetwork::Mainnet,
        btc_confirmation_depth: 6,
        checkpoint_finalization_timeout: 100,
        initial_header: None,
    };

    let res = instantiate(deps.as_mut(), mock_env(), info, msg);
    assert!(res.is_err());
    assert_eq!(res.unwrap_err(), ContractError::InitialHeaderRequired);
}
