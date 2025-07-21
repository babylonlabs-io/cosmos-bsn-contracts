use crate::contract::instantiate;
use crate::msg::InstantiateMsg;
use crate::state::btc_light_client::{BTC_HEADERS, BTC_HEIGHTS};
use crate::state::config::CONFIG;
use crate::BitcoinNetwork;
use babylon_proto::babylon::btclightclient::v1::BtcHeaderInfo;
use bitcoin::block::Header as BlockHeader;
use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};
use prost::Message;

/// Returns the initial BTC header for the babylon contract instantiation.
pub fn initial_header() -> crate::msg::contract::InitialHeader {
    // Initial base header on Babylon Genesis mainnet, https://www.blockchain.com/explorer/blocks/btc/854784.
    // TODO: This hardcodes a mainnet header in `initial_header()`, which may be incorrect in a
    // different network context, and we do often use different networks (e.g., testnet or regtest) in the test environment.
    // It's fine for now, but we should make this function network-aware to avoid subtle bugs down the line.
    let header = "0000c020f382af1f6d228721b49f3da2f5b831587803b16597b301000000000000000000e4f76aae64d8316d195a92424871b74168b58d1c3c6988548e0e9890b15fc2fc3c00aa66be1a0317082e4bc7";
    let height = 854784;
    let header: BlockHeader =
        bitcoin::consensus::encode::deserialize_hex(header).expect("Static value must be correct");
    let btc_header_info = BtcHeaderInfo {
        header: bitcoin::consensus::serialize(&header).into(),
        hash: bitcoin::consensus::serialize(&header.block_hash()).into(),
        height,
        work: header.work().to_be_bytes().to_vec().into(),
    };

    btc_header_info.try_into().unwrap()
}

#[test]
fn instantiate_should_work() {
    let mut deps = mock_dependencies();

    let info = message_info(&deps.api.addr_make("creator"), &[]);

    let initial_header = initial_header();

    let msg = InstantiateMsg {
        network: BitcoinNetwork::Regtest,
        btc_confirmation_depth: 6,
        checkpoint_finalization_timeout: 100,
        initial_header: initial_header.clone(),
    };

    let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

    // Basic assertions
    assert_eq!(res.attributes[0].key, "action");
    assert_eq!(res.attributes[0].value, "instantiate");

    // Config should be saved
    let cfg = CONFIG.load(&deps.storage).unwrap();
    assert_eq!(cfg.btc_confirmation_depth, 6);
    assert_eq!(cfg.checkpoint_finalization_timeout, 100);
    assert_eq!(cfg.network, BitcoinNetwork::Regtest);

    let initial_header_info = initial_header.to_btc_header_info().unwrap();
    let base_header_height = BTC_HEIGHTS
        .load(&deps.storage, initial_header_info.hash.as_ref())
        .unwrap();
    assert_eq!(base_header_height, 854784);

    let base_header_in_storage = BTC_HEADERS.load(&deps.storage, base_header_height).unwrap();
    assert_eq!(base_header_in_storage, initial_header_info.encode_to_vec());
}
