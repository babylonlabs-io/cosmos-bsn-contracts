use crate::contract::{execute, instantiate};
use crate::msg::btc_header::BtcHeader;
use crate::msg::{ExecuteMsg, InstantiateMsg};
use crate::state::{BTC_HEIGHTS, CONFIG};
use crate::BitcoinNetwork;
use babylon_proto::babylon::btclightclient::v1::{BtcHeaderInfo, BtcHeaderInfoResponse};
use babylon_test_utils::get_btc_lc_mainchain_resp;
use bitcoin::block::Header as BlockHeader;
use bitcoin::hashes::Hash;
use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};
use cosmwasm_std::{Addr, Uint256};
use std::str::FromStr;

/// Helper function to create a chain of valid Bitcoin headers for testing
fn create_valid_test_headers(count: usize, start_height: u32) -> Vec<BtcHeaderInfo> {
    let mut headers = Vec::new();
    let mut prev_hash = bitcoin::BlockHash::all_zeros();
    let regtest_target = bitcoin::CompactTarget::from_consensus(0x207fffff);
    let mut cumulative_work = bitcoin::Work::from_be_bytes([0; 32]);

    for i in 0..count {
        let header = create_valid_header_for_test(prev_hash, regtest_target, 1234567890 + i as u32);
        prev_hash = header.block_hash();

        // Calculate cumulative work correctly
        cumulative_work = cumulative_work + header.work();

        // Convert to BtcHeaderInfo using the cumulative work
        let header_info = BtcHeaderInfo {
            header: bitcoin::consensus::serialize(&header).into(),
            hash: bitcoin::consensus::serialize(&header.block_hash()).into(),
            height: start_height + i as u32,
            work: cumulative_work.to_be_bytes().to_vec().into(),
        };

        headers.push(header_info);
    }

    headers
}

/// Helper function to mine a valid Bitcoin header for tests
fn create_valid_header_for_test(
    prev_hash: bitcoin::BlockHash,
    target: bitcoin::CompactTarget,
    time: u32,
) -> bitcoin::block::Header {
    let mut header = bitcoin::block::Header {
        version: bitcoin::block::Version::ONE,
        prev_blockhash: prev_hash,
        merkle_root: bitcoin::TxMerkleNode::all_zeros(),
        time,
        bits: target,
        nonce: 0,
    };

    // Mine the header by incrementing nonce until we find valid proof-of-work
    let target_threshold = target.into();

    for nonce in 0..u32::MAX {
        header.nonce = nonce;
        let hash = header.block_hash();
        let hash_target = bitcoin::Target::from_be_bytes(*hash.as_ref());

        if hash_target <= target_threshold {
            return header; // Found valid proof-of-work!
        }
    }

    panic!("Could not mine valid header - target too restrictive");
}

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

    // Create valid headers with proper proof-of-work
    let valid_headers = create_valid_test_headers(5, 100); // 5 headers starting at height 100
    let headers: Vec<BtcHeader> = valid_headers
        .iter()
        .map(|h| h.clone().try_into().unwrap())
        .collect();

    let base_header = &valid_headers[0];
    // Convert work from bytes to hex string
    let first_work_hex = hex::encode(&base_header.work);
    let first_height = base_header.height;

    let exec_msg = ExecuteMsg::BtcHeaders {
        headers: headers.clone(),
        first_work: Some(first_work_hex),
        first_height: Some(first_height),
    };
    let result = execute(deps.as_mut(), mock_env(), info, exec_msg);

    assert!(result.is_ok(), "Auto-init on first header should succeed");

    // Convert BtcHeader to BlockHeader to get the hash
    let base_header_msg = &headers[0];
    let base_block_header: BlockHeader = base_header_msg.clone().try_into().unwrap();
    let base_header_hash = base_block_header.block_hash();

    // The height should match our test data
    let expected_height = first_height;
    let stored_height = BTC_HEIGHTS
        .load(&deps.storage, base_header_hash.as_ref())
        .unwrap();
    assert_eq!(stored_height, expected_height);
}
