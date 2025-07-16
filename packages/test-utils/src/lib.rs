use babylon_apis::btc_staking_api::{
    ActiveBtcDelegation, BtcUndelegationInfo, CovenantAdaptorSignatures, DelegatorUnbondingInfo,
    FinalityProviderDescription, NewFinalityProvider, ProofOfPossessionBtc,
};
use babylon_apis::finality_api::PubRandCommit;
use babylon_proto::babylon::btclightclient::v1::{BtcHeaderInfo, QueryMainChainResponse};
use babylon_proto::babylon::btcstaking::v1::{BtcDelegation, FinalityProvider, Params};
use babylon_proto::babylon::finality::v1::{MsgAddFinalitySig, MsgCommitPubRandList};
use babylon_proto::babylon::zoneconcierge::v1::BtcTimestamp;
use bitcoin::block::Header as BlockHeader;
use bitcoin::consensus::deserialize;
use bitcoin::BlockHash;
use cosmwasm_std::{Binary, Decimal, Uint256};
use hex::ToHex;
use k256::schnorr::{Signature, SigningKey};
use prost::{bytes::Bytes, Message};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::str::FromStr;
use std::{env, fs};

const BTC_LC_MAIN: &str = "btc_light_client.dat";
const BTC_LC_FORK: &str = "btc_light_client_fork.dat";
const BTC_LC_FORK_MSG: &str = "btc_light_client_fork_msg.json";

const BTC_TIMESTAMP: &str = "btc_timestamp.dat";
const BTC_TIMESTAMP_HEADER0: &str = "btc_timestamp_header0.dat";
const BTC_TIMESTAMP_HEADER1: &str = "btc_timestamp_header1.dat";

const PARAMS_DATA: &str = "btcstaking_params.dat";
const FINALITY_PROVIDER_DATA: &str = "finality_provider_{}.dat";
const FP_SK_DATA: &str = "fp_sk_{}.dat";
const BTC_DELEGATION_DATA: &str = "btc_delegation_{idx}_{fp_idx_list}.dat";
const BTC_DEL_UNBONDING_SIG_DATA: &str = "btc_unbonding_sig_{idx}_{fp_idx_list}.dat";
const COMMIT_PUB_RAND_DATA: &str = "commit_pub_rand_msg.dat";
const PUB_RAND_VALUE: &str = "pub_rand_value.dat";
const ADD_FINALITY_SIG_DATA: &str = "add_finality_sig_{}_msg.dat";

const EOTS_DATA: &str = "eots_testdata.json";

pub fn find_project_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn find_testdata_path() -> PathBuf {
    find_project_path().join("testdata")
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EotsTestData {
    pub sk: String,
    pub pk: String,
    pub sr: String,
    pub pr: String,
    pub msg1: String,
    pub msg2: String,
    pub sig1: String,
    pub sig2: String,
}

pub fn get_eots_testdata() -> EotsTestData {
    let file_path = find_testdata_path().join(EOTS_DATA);
    let testdata_bytes: &[u8] = &fs::read(file_path).unwrap();
    let testdata: EotsTestData = serde_json::from_slice(testdata_bytes).unwrap();

    testdata
}

pub fn get_btc_lc_mainchain_resp() -> QueryMainChainResponse {
    let file_path = find_testdata_path().join(BTC_LC_MAIN);

    let testdata: &[u8] = &fs::read(file_path).unwrap();
    QueryMainChainResponse::decode(testdata).unwrap()
}

pub fn get_btc_lc_headers() -> Vec<BtcHeaderInfo> {
    let resp = get_btc_lc_mainchain_resp();
    resp.headers
        .iter()
        .map(|h| BtcHeaderInfo {
            header: Bytes::from(hex::decode(&h.header_hex).unwrap()),
            // FIXME: Use BlockHash / Hash helper / encapsulation to reverse the hash under the hood
            hash: Bytes::from(
                hex::decode(&h.hash_hex)
                    .unwrap()
                    .into_iter()
                    .rev()
                    .collect::<Vec<_>>(),
            ),
            height: h.height,
            work: Uint256::from_str(&h.work)
                .unwrap()
                .to_be_bytes()
                .to_vec()
                .into(),
        })
        .collect()
}

pub fn get_btc_lc_fork_headers() -> Vec<BtcHeaderInfo> {
    let file_path = find_testdata_path().join(BTC_LC_FORK);
    let testdata: &[u8] = &fs::read(file_path).unwrap();
    let resp = QueryMainChainResponse::decode(testdata).unwrap();
    resp.headers
        .iter()
        .map(|h| BtcHeaderInfo {
            header: Bytes::from(hex::decode(&h.header_hex).unwrap()),
            // FIXME: Use BlockHash / Hash helper / encapsulation to reverse the hash under the hood
            hash: Bytes::from(
                hex::decode(&h.hash_hex)
                    .unwrap()
                    .into_iter()
                    .rev()
                    .collect::<Vec<_>>(),
            ),
            height: h.height,
            work: Uint256::from_str(&h.work)
                .unwrap()
                .to_be_bytes()
                .to_vec()
                .into(),
        })
        .collect()
}

pub fn get_btc_lc_fork_msg() -> Vec<u8> {
    let file_path = find_testdata_path().join(BTC_LC_FORK_MSG);
    let testdata: &[u8] = &fs::read(file_path).unwrap();
    testdata.to_vec()
}

pub fn get_btc_timestamp_and_headers() -> (BtcTimestamp, HashMap<BlockHash, BlockHeader>) {
    let mut header_map: HashMap<BlockHash, BlockHeader> = HashMap::new();

    let header0_path = find_testdata_path().join(BTC_TIMESTAMP_HEADER0);
    let header0_bytes: &[u8] = &fs::read(header0_path).unwrap();
    let header0: BlockHeader = deserialize(header0_bytes).unwrap();
    header_map.insert(header0.block_hash(), header0);

    let header1_path = find_testdata_path().join(BTC_TIMESTAMP_HEADER1);
    let header1_bytes: &[u8] = &fs::read(header1_path).unwrap();
    let header1: BlockHeader = deserialize(header1_bytes).unwrap();
    header_map.insert(header1.block_hash(), header1);

    let ts_path = find_testdata_path().join(BTC_TIMESTAMP);
    let testdata: &[u8] = &fs::read(ts_path).unwrap();
    let btc_ts = BtcTimestamp::decode(testdata).unwrap();

    (btc_ts, header_map)
}

pub fn get_params() -> Params {
    let params_path = find_testdata_path().join(PARAMS_DATA);
    let params_data: &[u8] = &fs::read(params_path).unwrap();
    Params::decode(params_data).unwrap()
}

pub fn get_finality_provider(id: i32) -> FinalityProvider {
    let fp_path = find_testdata_path().join(FINALITY_PROVIDER_DATA.replace("{}", &id.to_string()));
    let fp_data: &[u8] = &fs::read(fp_path).unwrap();
    FinalityProvider::decode(fp_data).unwrap()
}

pub fn get_fp_sk_bytes(id: i32) -> Vec<u8> {
    let fp_sk_path = find_testdata_path().join(FP_SK_DATA.replace("{}", &id.to_string()));
    let fp_sk_data: &[u8] = &fs::read(fp_sk_path).unwrap();
    fp_sk_data.to_vec()
}

pub fn get_btc_delegation(idx: i32, fp_idx_list: Vec<i32>) -> BtcDelegation {
    let fp_idx_list_str = format!(
        "{{{}}}",
        fp_idx_list
            .iter()
            .map(|&x| x.to_string())
            .collect::<Vec<_>>()
            .join(",")
    );
    let btc_del_filename = BTC_DELEGATION_DATA
        .replace("{idx}", &idx.to_string())
        .replace("{fp_idx_list}", &fp_idx_list_str);
    let btc_del_path = find_testdata_path().join(btc_del_filename);
    let btc_del_data: &[u8] = &fs::read(btc_del_path).unwrap();
    BtcDelegation::decode(btc_del_data).unwrap()
}

pub fn get_btc_del_unbonding_sig_bytes(idx: i32, fp_idx_list: Vec<i32>) -> Vec<u8> {
    let fp_idx_list_str = format!(
        "{{{}}}",
        fp_idx_list
            .iter()
            .map(|&x| x.to_string())
            .collect::<Vec<_>>()
            .join(",")
    );
    let sig_filename = BTC_DEL_UNBONDING_SIG_DATA
        .replace("{idx}", &idx.to_string())
        .replace("{fp_idx_list}", &fp_idx_list_str);
    let sig_path = find_testdata_path().join(sig_filename);
    let sig_data: &[u8] = &fs::read(sig_path).unwrap();
    sig_data.to_vec()
}

pub fn get_pub_rand_commit() -> MsgCommitPubRandList {
    let pub_rand_commit_path = find_testdata_path().join(COMMIT_PUB_RAND_DATA);
    let pub_rand_commit_data: &[u8] = &fs::read(pub_rand_commit_path).unwrap();

    MsgCommitPubRandList::decode(pub_rand_commit_data).unwrap()
}

/// Get public randomness value (at index 1)
//  TODO: Support indexed public randomness values
pub fn get_pub_rand_value() -> Vec<u8> {
    let pub_rand_value_path = find_testdata_path().join(PUB_RAND_VALUE);
    let pub_rand_value_data: Vec<u8> = fs::read(pub_rand_value_path).unwrap();

    pub_rand_value_data
}

pub fn get_add_finality_sig() -> MsgAddFinalitySig {
    let add_finality_sig_path = find_testdata_path().join(ADD_FINALITY_SIG_DATA.replace("{}", "1"));
    let add_finality_sig_data: &[u8] = &fs::read(add_finality_sig_path).unwrap();

    MsgAddFinalitySig::decode(add_finality_sig_data).unwrap()
}

pub fn get_add_finality_sig_2() -> MsgAddFinalitySig {
    let add_finality_sig_path = find_testdata_path().join(ADD_FINALITY_SIG_DATA.replace("{}", "2"));
    let add_finality_sig_data: &[u8] = &fs::read(add_finality_sig_path).unwrap();

    MsgAddFinalitySig::decode(add_finality_sig_data).unwrap()
}

pub fn new_finality_provider(fp: FinalityProvider) -> NewFinalityProvider {
    NewFinalityProvider {
        addr: fp.addr,
        description: fp.description.map(|desc| FinalityProviderDescription {
            moniker: desc.moniker,
            identity: desc.identity,
            website: desc.website,
            security_contact: desc.security_contact,
            details: desc.details,
        }),
        commission: Decimal::from_str(&fp.commission).unwrap(),
        btc_pk_hex: fp.btc_pk.encode_hex(),
        pop: match fp.pop {
            Some(pop) => Some(ProofOfPossessionBtc {
                btc_sig_type: pop.btc_sig_type,
                btc_sig: Binary::new(pop.btc_sig.to_vec()),
            }),
            None => None,
        },
        consumer_id: fp.bsn_id,
    }
}

pub fn new_active_btc_delegation(del: BtcDelegation) -> ActiveBtcDelegation {
    let btc_undelegation = del.btc_undelegation.unwrap();
    let delegator_unbonding_info =
        if let Some(delegator_unbonding_info) = btc_undelegation.delegator_unbonding_info {
            Some(DelegatorUnbondingInfo {
                spend_stake_tx: Binary::new(delegator_unbonding_info.spend_stake_tx.to_vec()),
            })
        } else {
            None
        };

    ActiveBtcDelegation {
        staker_addr: del.staker_addr,
        btc_pk_hex: del.btc_pk.encode_hex(),
        fp_btc_pk_list: del
            .fp_btc_pk_list
            .iter()
            .map(|fp_btc_pk| fp_btc_pk.encode_hex())
            .collect(),
        start_height: del.start_height,
        end_height: del.end_height,
        total_sat: del.total_sat,
        staking_tx: Binary::new(del.staking_tx.to_vec()),
        slashing_tx: Binary::new(del.slashing_tx.to_vec()),
        delegator_slashing_sig: Binary::new(del.delegator_sig.to_vec()),
        covenant_sigs: del
            .covenant_sigs
            .iter()
            .map(|cov_sig| CovenantAdaptorSignatures {
                cov_pk: Binary::new(cov_sig.cov_pk.to_vec()),
                adaptor_sigs: cov_sig
                    .adaptor_sigs
                    .iter()
                    .map(|adaptor_sig| Binary::new(adaptor_sig.to_vec()))
                    .collect(),
            })
            .collect(),
        staking_output_idx: del.staking_output_idx,
        unbonding_time: del.unbonding_time,
        undelegation_info: BtcUndelegationInfo {
            unbonding_tx: Binary::new(btc_undelegation.unbonding_tx.to_vec()),
            slashing_tx: Binary::new(btc_undelegation.slashing_tx.to_vec()),
            delegator_unbonding_info,
            delegator_slashing_sig: Binary::new(btc_undelegation.delegator_slashing_sig.to_vec()),
            covenant_unbonding_sig_list: vec![],
            covenant_slashing_sigs: vec![],
        },
        params_version: del.params_version,
    }
}

/// Build an active BTC delegation from a BTC delegation
pub fn get_active_btc_delegation() -> ActiveBtcDelegation {
    let del = get_btc_delegation(1, vec![1]);
    new_active_btc_delegation(del)
}

// Build a derived active BTC delegation from the base (from testdata) BTC delegation
pub fn get_derived_btc_delegation(del_id: i32, fp_ids: &[i32]) -> ActiveBtcDelegation {
    let del = get_btc_delegation(del_id, fp_ids.to_vec());
    new_active_btc_delegation(del)
}

pub fn get_btc_del_unbonding_sig(del_id: i32, fp_ids: &[i32]) -> Signature {
    let sig_bytes = get_btc_del_unbonding_sig_bytes(del_id, fp_ids.to_vec());
    Signature::try_from(sig_bytes.as_slice()).unwrap()
}

pub fn create_new_finality_provider(id: i32) -> NewFinalityProvider {
    let fp = get_finality_provider(id);
    new_finality_provider(fp)
}

pub fn create_new_fp_sk(id: i32) -> SigningKey {
    let fp_sk_bytes = get_fp_sk_bytes(id);
    SigningKey::from_bytes(&fp_sk_bytes).unwrap()
}

/// Get public randomness public key, commitment, and signature information
///
/// Signature is a Schnorr signature over the commitment
pub fn get_public_randomness_commitment() -> (String, PubRandCommit, Vec<u8>) {
    let pub_rand_commitment_msg = get_pub_rand_commit();
    (
        pub_rand_commitment_msg.fp_btc_pk.encode_hex(),
        PubRandCommit {
            start_height: pub_rand_commitment_msg.start_height,
            num_pub_rand: pub_rand_commitment_msg.num_pub_rand,
            height: 1,
            commitment: pub_rand_commitment_msg.commitment.to_vec(),
        },
        pub_rand_commitment_msg.sig.to_vec(),
    )
}

/// Returns the initial BTC header for the babylon contract instantiation.
pub fn initial_header() -> btc_light_client::msg::contract::InitialHeader {
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

/// Returns the initial BTC header encoded in json and hex-encoded form.
///
/// This format is suitable for embedding into messages such as `InstantiateMsg`.
pub fn initial_header_in_hex() -> String {
    hex::encode(serde_json::to_vec(&initial_header()).unwrap())
}
