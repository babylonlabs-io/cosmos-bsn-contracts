use crate::contract::{execute, instantiate};
use crate::msg::contract::BaseHeader;
use crate::msg::InstantiateMsg;
use crate::state::{get_tip, BTC_HEADERS, BTC_HEIGHTS, CONFIG};
#[cfg(feature = "full-validation")]
use crate::ContractError;
use crate::{BitcoinNetwork, ExecuteMsg};
use babylon_proto::babylon::btclightclient::v1::BtcHeaderInfo;
use bitcoin::block::Header as BlockHeader;
use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};
use prost::Message;

/// Helper function to get the appropriate initial header value based on the full-validation feature
fn get_btc_base_header() -> Option<BaseHeader> {
    #[cfg(feature = "full-validation")]
    {
        let headers = test_headers();
        Some(headers[0].clone().try_into().unwrap())
    }
    #[cfg(not(feature = "full-validation"))]
    {
        None
    }
}

// TODO: update the test headers in babylon-test-utils so that we can reuse it here.
fn test_headers() -> Vec<BtcHeaderInfo> {
    let headers = vec![
        // Initial base header on Babylon Genesis mainnet, https://www.blockchain.com/explorer/blocks/btc/854784.
        ("0000c020f382af1f6d228721b49f3da2f5b831587803b16597b301000000000000000000e4f76aae64d8316d195a92424871b74168b58d1c3c6988548e0e9890b15fc2fc3c00aa66be1a0317082e4bc7", 854784),
        ("0000003acbfbbb0a8d32aa0e739dc4f910a58299a8015b1cd48902000000000000000000a32c4a6ca3d399cc5146c28af944b807f298c6de063c161c13a1b3ca6fd2632e6500aa66be1a031783eb001c", 854785),
        ("0000ff3f12bb9ddf58d472db3c7d581777dad9c0da5435e5c118010000000000000000006bb7ef21df7439a5d4d13f6512eb6e51b581eb2a87df8425fa5822ed6631d8160c01aa66be1a0317a5bfec4c", 854786),
        ("00e0052026f431477d18714037778fdb02e3cd11a5c990db34f60100000000000000000058eb4d249aa132c62cb8fe60649ba7dfbd543c0498aed881df0f03eed340d7adbb0aaa66be1a03175cf66971", 854787),
        ("00400220314eaeb216d401fea45075e7df1ba8481c00a47d4f2f01000000000000000000efb137c1df8d40882034a8e974259ee577754fe1677c4c3ce595e49030b5c0956f0baa66be1a03172534f76f", 854788)
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
fn test_xlc() {
    let mut deps = mock_dependencies();

    let info = message_info(&deps.api.addr_make("creator"), &[]);

    let headers = test_headers();

    let msg = InstantiateMsg {
        network: BitcoinNetwork::Mainnet,
        btc_confirmation_depth: 6,
        checkpoint_finalization_timeout: 2,
        base_header: None,
    };

    let res = instantiate(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

    // Basic assertions
    assert_eq!(res.attributes[0].key, "action");
    assert_eq!(res.attributes[0].value, "instantiate");

    // Config should be saved
    let cfg = CONFIG.load(&deps.storage).unwrap();
    assert_eq!(cfg.btc_confirmation_depth, 6);
    assert_eq!(cfg.checkpoint_finalization_timeout, 2);
    assert_eq!(cfg.network, BitcoinNetwork::Mainnet);

    // Convert work from Uint256 to Bytes
    let first_work_hex = hex::encode(&headers[0].work.to_vec());

    let msg = ExecuteMsg::BtcHeaders {
        headers: vec![
            headers[0].clone().try_into().unwrap(),
            headers[1].clone().try_into().unwrap(),
            headers[2].clone().try_into().unwrap(),
        ],
        first_work: Some(first_work_hex),
        first_height: Some(headers[0].height),
    };
    execute(deps.as_mut(), mock_env(), info.clone(), msg).expect("Submit new headers should work");

    let msg = ExecuteMsg::BtcHeaders {
        headers: vec![
            headers[2].clone().try_into().unwrap(),
            headers[3].clone().try_into().unwrap(),
            headers[4].clone().try_into().unwrap(),
        ],
        first_work: None,
        first_height: None,
    };
    execute(deps.as_mut(), mock_env(), info, msg).expect("Submit new headers should work");
}

#[test]
fn instantiate_should_work() {
    let mut deps = mock_dependencies();

    let info = message_info(&deps.api.addr_make("creator"), &[]);

    let headers = test_headers();

    let msg = InstantiateMsg {
        network: BitcoinNetwork::Mainnet,
        btc_confirmation_depth: 6,
        checkpoint_finalization_timeout: 100,
        base_header: get_btc_base_header(),
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

    // Test header storage only if base header was provided
    if let Some(base_header) = get_btc_base_header() {
        let base_header_info = base_header.to_btc_header_info().unwrap();
        let base_header_height = BTC_HEIGHTS
            .load(&deps.storage, base_header_info.hash.as_ref())
            .unwrap();
        assert_eq!(base_header_height, 854784);

        let base_header_in_storage = BTC_HEADERS.load(&deps.storage, base_header_height).unwrap();
        assert_eq!(base_header_in_storage, base_header_info.encode_to_vec());
    }

    // Submit new headers should work only if we have an initial header
    if get_btc_base_header().is_some() {
        let new_header = headers[1].block_header().unwrap();
        let msg = ExecuteMsg::BtcHeaders {
            headers: vec![new_header.into()],
            first_work: None,
            first_height: None,
        };
        execute(deps.as_mut(), mock_env(), info, msg).expect("Submit new headers should work");

        // Tip updated when new headers are submitted successfully.
        let tip = get_tip(&deps.storage).unwrap();
        assert_eq!(tip.height, headers[1].height);
    }
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
        base_header: None,
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
        base_header: None,
    };

    let res = instantiate(deps.as_mut(), mock_env(), info, msg);
    assert!(res.is_err());
    assert_eq!(res.unwrap_err(), ContractError::InitialHeaderRequired);
}

#[cfg(not(feature = "full-validation"))]
#[test]
fn auto_init_on_first_header_works() {
    use std::str::FromStr;

    use crate::contract::{execute, instantiate};
    use crate::msg::btc_header::BtcHeader;
    use crate::msg::{ExecuteMsg, InstantiateMsg};
    use crate::state::BTC_HEIGHTS;
    use babylon_proto::babylon::btclightclient::v1::BtcHeaderInfoResponse;
    use babylon_test_utils::get_btc_lc_mainchain_resp;
    use bitcoin::block::Header as BlockHeader;
    use cosmwasm_std::testing::{mock_dependencies, mock_env};
    use cosmwasm_std::{Addr, Uint256};

    let mut deps = mock_dependencies();

    // Instantiate without initial header
    let msg = InstantiateMsg {
        network: crate::state::BitcoinNetwork::Regtest,
        btc_confirmation_depth: 6,
        checkpoint_finalization_timeout: 99,
        base_header: None,
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
