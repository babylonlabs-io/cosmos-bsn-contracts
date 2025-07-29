use crate::bitcoin::{total_work, verify_headers};
use crate::error::{ContractError, InitHeadersError};
use crate::msg::btc_header::BtcHeader;
use crate::msg::contract::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::queries::*;
use crate::state::{
    expect_header_by_hash, get_tip, insert_headers, is_initialized, remove_headers,
    set_base_header, set_tip, Config, CONFIG,
};
use babylon_proto::babylon::btclightclient::v1::BtcHeaderInfo;
use bitcoin::BlockHash;
use cosmwasm_std::{
    to_json_binary, Binary, Deps, DepsMut, Empty, Env, MessageInfo, Response, Storage,
};
use cw2::set_contract_version;
use prost::Message;
use std::str::FromStr;

pub const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
pub const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    msg.validate()?;

    let InstantiateMsg {
        network,
        btc_confirmation_depth,
        checkpoint_finalization_timeout,
        base_header,
    } = msg;

    let mut res = Response::new();

    // Initialises the BTC header chain storage if base header is provided.
    if let Some(header) = base_header {
        let base_header_info = header.to_btc_header_info()?;
        // Store base header (immutable) and tip.
        set_base_header(deps.storage, &base_header_info)?;
        set_tip(deps.storage, &base_header_info)?;
        res = res.set_data(Binary::from(base_header_info.encode_to_vec()));
    }

    let cfg = Config {
        network,
        btc_confirmation_depth,
        checkpoint_finalization_timeout,
    };

    CONFIG.save(deps.storage, &cfg)?;
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;

    Ok(res.add_attribute("action", "instantiate"))
}

pub fn execute(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::BtcHeaders {
            headers,
            first_work,
            first_height,
        } => {
            let api = deps.api;
            let headers_len = headers.len();

            handle_btc_headers(deps, headers, first_work, first_height)
                .inspect(|_| {
                    api.debug(&format!("Successfully handled {headers_len} BTC headers"));
                })
                .inspect_err(|e| {
                    api.debug(&format!("Failed to handle {headers_len} BTC headers: {e}"));
                })
        }
    }
}

pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> Result<Binary, ContractError> {
    match msg {
        QueryMsg::Config {} => Ok(to_json_binary(&CONFIG.load(deps.storage)?)?),
        QueryMsg::BtcBaseHeader {} => Ok(to_json_binary(&btc_base_header(&deps)?)?),
        QueryMsg::BtcTipHeader {} => Ok(to_json_binary(&btc_tip_header(&deps)?)?),
        QueryMsg::BtcHeader { height } => Ok(to_json_binary(&btc_header(&deps, height)?)?),
        QueryMsg::BtcHeaderByHash { hash } => {
            Ok(to_json_binary(&btc_header_by_hash(&deps, &hash)?)?)
        }
        QueryMsg::BtcHeaders {
            start_after,
            limit,
            reverse,
        } => Ok(to_json_binary(&btc_headers(
            &deps,
            start_after,
            limit,
            reverse,
        )?)?),
    }
}

pub fn migrate(deps: DepsMut, _env: Env, _msg: Empty) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    Ok(Response::new().add_attribute("action", "migrate"))
}

fn handle_btc_headers(
    deps: DepsMut,
    headers: Vec<BtcHeader>,
    first_work: Option<String>,
    first_height: Option<u32>,
) -> Result<Response, ContractError> {
    // TODO: enforce only Babylon contract can call this function

    // Check if the BTC light client has been initialized
    if !is_initialized(deps.storage) {
        let first_work_hex = first_work.ok_or(InitHeadersError::MissingBaseWork)?;
        let first_height = first_height.ok_or(InitHeadersError::MissingBaseHeight)?;

        let first_work_bytes = hex::decode(first_work_hex)?;
        let first_work = total_work(&first_work_bytes)?;

        init_btc_headers(deps.storage, &headers, first_work, first_height)?;
        Ok(Response::new().add_attribute("action", "init_btc_light_client"))
    } else {
        extend_btc_headers(deps.storage, &headers)?;
        Ok(Response::new().add_attribute("action", "update_btc_light_client"))
    }
}

/// Initialises the BTC header chain storage.
///
/// It takes BTC headers between the BTC tip upon the last finalised epoch and the current tip.
fn init_btc_headers(
    storage: &mut dyn Storage,
    headers: &[BtcHeader],
    first_work: bitcoin::Work,
    first_height: u32,
) -> Result<(), ContractError> {
    let cfg = CONFIG.load(storage)?;

    // base header is the first header in the list
    let (base_header, new_headers) = headers
        .split_first()
        .expect("Headers must not be empty as checked above");

    let base_header = base_header.to_btc_header_info(first_height, first_work)?;

    // We need to initialize the base header (immutable) ahead of the subsequent headers
    // processing as `verify_headers` assumes the base header must already exist.
    set_base_header(storage, &base_header)?;

    let new_headers =
        convert_to_btc_header_info(new_headers, base_header.height, &base_header.work)?;

    // Verify subsequent headers
    let chain_params = cfg.network.chain_params();
    verify_headers(storage, &chain_params, &base_header, &new_headers)?;

    insert_headers(storage, &new_headers)?;
    let tip = new_headers.last().unwrap_or(&base_header);
    set_tip(storage, tip)?;

    Ok(())
}

/// Converts a slice of `BtcHeader` into a vector of `BtcHeaderInfo`s
/// using the given starting height and work.
fn convert_to_btc_header_info(
    headers: &[BtcHeader],
    start_height: u32,
    start_work: &[u8],
) -> Result<Vec<BtcHeaderInfo>, ContractError> {
    let mut cur_height = start_height;
    let mut cur_work = total_work(start_work)?;
    let mut result = Vec::with_capacity(headers.len());

    for header in headers {
        let info = header.to_btc_header_info_from_prev(cur_height, cur_work)?;
        cur_height += 1;
        cur_work = total_work(info.work.as_ref())?;
        result.push(info);
    }

    Ok(result)
}

/// Verifies and inserts a number of finalised BTC headers to the
/// header chain storage, and updates the chain's tip.
fn extend_btc_headers(
    storage: &mut dyn Storage,
    new_btc_headers: &[BtcHeader],
) -> Result<(), ContractError> {
    let first_new_btc_header = new_btc_headers
        .first()
        .ok_or(ContractError::EmptyHeaders {})?;

    // Decode the btc_header (byte-reversed) prev_blockhash
    let prev_blockhash = BlockHash::from_str(&first_new_btc_header.prev_blockhash)?;

    // Obtain previous header from storage
    let previous_header = expect_header_by_hash(storage, prev_blockhash.as_ref())?;

    let new_headers_info = convert_to_btc_header_info(
        new_btc_headers,
        previous_header.height,
        previous_header.work.as_ref(),
    )?;

    handle_btc_headers_from_babylon(storage, &new_headers_info)
}

/// handle_btc_headers_from_babylon verifies and inserts a number of
/// finalised BTC headers to the header chain storage, and update
/// the chain tip.
///
/// NOTE: upon each finalised epoch e, Babylon will send BTC headers between
/// - the common ancestor of
///   - BTC tip upon finalising epoch e-1
///   - BTC tip upon finalising epoch e,
/// - BTC tip upon finalising epoch e
///   such that Babylon contract maintains the same canonical BTC header chain
///   as Babylon.
///
/// Ref https://github.com/babylonlabs-io/babylon/blob/d3d81178dc38c172edaf5651c72b296bb9371a48/x/btclightclient/types/btc_light_client.go#L339
pub(crate) fn handle_btc_headers_from_babylon(
    storage: &mut dyn Storage,
    new_headers: &[BtcHeaderInfo],
) -> Result<(), ContractError> {
    let cfg = CONFIG.load(storage)?;
    let chain_params = cfg.network.chain_params();

    let cur_tip = get_tip(storage)?;
    let cur_tip_hash = cur_tip.hash.clone();

    // decode the first header in these new headers
    let first_new_header = new_headers.first().ok_or(ContractError::EmptyHeaders {})?;

    let first_new_btc_header = first_new_header.block_header()?;

    let new_tip = if first_new_btc_header.prev_blockhash.as_ref() == cur_tip_hash.to_vec() {
        // Most common case: extending the current tip

        verify_headers(storage, &chain_params, &cur_tip, new_headers)?;

        new_headers.last().ok_or(ContractError::EmptyHeaders {})?
    } else {
        // Here we received a potential new fork
        let parent_hash = first_new_btc_header.prev_blockhash.as_ref();
        let fork_parent = expect_header_by_hash(storage, parent_hash)?;

        verify_headers(storage, &chain_params, &fork_parent, new_headers)?;

        let new_tip = new_headers.last().expect("Must exist as checked above");

        let new_tip_work = total_work(new_tip.work.as_ref())?;
        let cur_tip_work = total_work(cur_tip.work.as_ref())?;

        if new_tip_work <= cur_tip_work {
            return Err(ContractError::InsufficientWork(new_tip_work, cur_tip_work));
        }

        // Remove all fork headers.
        remove_headers(storage, &cur_tip, &fork_parent)?;

        new_tip
    };

    // All good, insert new headers and update the tip.
    insert_headers(storage, new_headers)?;
    set_tip(storage, new_tip)?;

    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::bitcoin::HeaderError;
    use crate::state::{
        get_base_header, get_header, get_header_height, BitcoinNetwork, Config, CONFIG,
    };
    use crate::ExecuteMsg;
    use babylon_test_utils::{get_btc_lc_fork_headers, get_btc_lc_fork_msg, get_btc_lc_headers};
    use bitcoin::block::Header as BlockHeader;
    use cosmwasm_std::{from_json, testing::mock_dependencies};

    /// Initialze the contract state with given headers.
    pub(crate) fn init_contract(
        storage: &mut dyn Storage,
        headers: &[BtcHeaderInfo],
    ) -> Result<(), ContractError> {
        let base_header = headers.first().unwrap();

        // Convert headers to BtcHeaderInfo with work/height based on first block
        let mut cur_height = base_header.height;
        let mut cur_work = total_work(base_header.work.as_ref())?;

        let headers = headers
            .iter()
            .map(BtcHeader::try_from)
            .collect::<Result<Vec<BtcHeader>, _>>()?;

        let mut processed_headers = Vec::with_capacity(headers.len());
        processed_headers.push(base_header.clone());
        for header in headers.iter().skip(1) {
            let new_header_info = header.to_btc_header_info_from_prev(cur_height, cur_work)?;
            cur_height += 1;
            cur_work = total_work(new_header_info.work.as_ref())?;
            processed_headers.push(new_header_info);
        }

        set_base_header(storage, base_header)?;
        let tip = processed_headers.last().unwrap();
        set_tip(storage, tip)?;
        insert_headers(storage, &processed_headers)?;

        Ok(())
    }

    pub(crate) fn setup(storage: &mut dyn Storage) -> u32 {
        // set config first
        let w: u32 = 2;
        let cfg = Config {
            network: BitcoinNetwork::Regtest,
            btc_confirmation_depth: 1,
            checkpoint_finalization_timeout: w,
        };
        CONFIG.save(storage, &cfg).unwrap();
        w
    }

    fn get_fork_msg_test_headers() -> Vec<BtcHeader> {
        let testdata = get_btc_lc_fork_msg();
        let resp: ExecuteMsg = from_json(testdata).unwrap();
        match resp {
            ExecuteMsg::BtcHeaders { headers, .. } => headers,
        }
    }

    #[track_caller]
    fn ensure_headers(storage: &dyn Storage, headers: &[BtcHeaderInfo]) {
        for header_expected in headers {
            let header_actual = get_header(storage, header_expected.height).unwrap();
            assert_eq!(*header_expected, header_actual);
            let header_by_hash =
                expect_header_by_hash(storage, header_expected.hash.as_ref()).unwrap();
            assert_eq!(*header_expected, header_by_hash);
        }
    }

    #[track_caller]
    fn ensure_btc_headers(storage: &dyn Storage, headers: &[BtcHeader]) {
        // Existence / inclusion check only, as we don't have the height and cumulative work info
        for header_expected in headers {
            let block_header_expected: BlockHeader = header_expected.try_into().unwrap();
            expect_header_by_hash(storage, block_header_expected.block_hash().as_ref()).unwrap();
        }
    }

    #[track_caller]
    fn ensure_base_and_tip(storage: &dyn Storage, test_init_headers: &[BtcHeaderInfo]) {
        // ensure the base header is set
        let base_expected = test_init_headers.first().unwrap();
        let base_actual = get_base_header(storage).unwrap();
        assert_eq!(*base_expected, base_actual);
        // ensure the tip header is set
        let tip_expected = test_init_headers.last().unwrap();
        let tip_actual = get_tip(storage).unwrap();
        assert_eq!(*tip_expected, tip_actual);
    }

    // btc_lc_works simulates initialisation of BTC light client storage, then insertion of
    // a number of headers. It ensures that the correctness of initialisation/insertion upon
    // a list of correct BTC headers on Bitcoin regtest net.
    #[test]
    fn btc_lc_works() {
        let deps = mock_dependencies();
        let mut storage = deps.storage;
        let w = setup(&mut storage);

        let test_headers = get_btc_lc_headers();

        // testing initialisation with w+1 headers
        let test_init_headers: &[BtcHeaderInfo] = &test_headers[0..(w + 1) as usize];
        init_contract(&mut storage, test_init_headers).unwrap();

        ensure_base_and_tip(&storage, test_init_headers);

        // ensure all headers are correctly inserted
        ensure_headers(&storage, test_init_headers);

        // handling subsequent headers
        let test_new_headers = &test_headers[(w + 1) as usize..test_headers.len()];
        handle_btc_headers_from_babylon(&mut storage, test_new_headers).unwrap();

        // ensure tip is set
        ensure_base_and_tip(&storage, &test_headers);
        // ensure all new headers are correctly inserted
        ensure_headers(&storage, test_new_headers);
    }

    // Must match `forkHeaderHeight` in datagen/main.go
    const FORK_HEADER_HEIGHT: u64 = 90;

    // btc_lc_fork_accepted simulates initialization of BTC light client storage,
    // then insertion of a number of headers.
    // It checks the correctness of the fork choice rule for an accepted fork.
    #[test]
    fn btc_lc_fork_accepted() {
        let deps = mock_dependencies();
        let mut storage = deps.storage;
        setup(&mut storage);

        let test_headers = get_btc_lc_headers();

        // initialize with all headers
        init_contract(&mut storage, &test_headers).unwrap();

        // ensure base and tip are set
        ensure_base_and_tip(&storage, &test_headers);
        // ensure all headers are correctly inserted
        ensure_headers(&storage, &test_headers);

        // get fork headers
        let test_fork_headers = get_btc_lc_fork_headers();

        // handling fork headers
        handle_btc_headers_from_babylon(&mut storage, &test_fork_headers).unwrap();

        // ensure the base header is set
        let base_expected = test_headers.first().unwrap();
        let base_actual = get_base_header(&storage).unwrap();
        assert_eq!(*base_expected, base_actual);
        // ensure the tip is set
        let tip_expected = test_fork_headers.last().unwrap();
        let tip_actual = get_tip(&storage).unwrap();
        assert_eq!(*tip_expected, tip_actual);

        // ensure all initial headers are still inserted
        ensure_headers(&storage, &test_headers[..FORK_HEADER_HEIGHT as usize]);

        // ensure all forked headers are correctly inserted
        ensure_headers(&storage, &test_fork_headers);

        // check that the original forked headers have been removed from the hash-to-height map
        for header_expected in test_headers[FORK_HEADER_HEIGHT as usize..].iter() {
            assert!(get_header_height(&storage, header_expected.hash.as_ref()).is_err());
        }
    }

    // btc_lc_fork_rejected simulates initialization of BTC light client storage,
    // then insertion of a number of headers.
    // It checks the correctness of the fork choice rule for a rejected fork.
    #[test]
    fn btc_lc_fork_rejected() {
        let deps = mock_dependencies();
        let mut storage = deps.storage;
        setup(&mut storage);

        let test_headers = get_btc_lc_headers();

        // initialize with all headers
        init_contract(&mut storage, &test_headers).unwrap();

        // ensure the base and tip are set
        ensure_base_and_tip(&storage, &test_headers);
        // ensure all headers are correctly inserted
        ensure_headers(&storage, &test_headers);

        // get fork headers
        let test_fork_headers = get_btc_lc_fork_headers();

        // handling fork headers minus the last
        let res = handle_btc_headers_from_babylon(
            &mut storage,
            &test_fork_headers[..test_fork_headers.len() - 1],
        );
        assert!(matches!(
            res.unwrap_err(),
            ContractError::InsufficientWork(_, _)
        ));

        // ensure base and tip are unchanged
        ensure_base_and_tip(&storage, &test_headers);
        // ensure all headers are correctly inserted
        ensure_headers(&storage, &test_headers);
    }

    // btc_lc_fork_invalid simulates initialization of BTC light client storage,
    // then insertion of a number of headers.
    // It checks the correctness of the fork choice rule for an invalid fork (non-consecutive headers).
    #[test]
    fn btc_lc_fork_invalid() {
        let deps = mock_dependencies();
        let mut storage = deps.storage;
        setup(&mut storage);

        let test_headers = get_btc_lc_headers();

        // initialize with all headers
        init_contract(&mut storage, &test_headers).unwrap();

        // ensure base and tip are set
        ensure_base_and_tip(&storage, &test_headers);
        // ensure all headers are correctly inserted
        ensure_headers(&storage, &test_headers);

        // get fork headers
        let test_fork_headers = get_btc_lc_fork_headers();

        // Make the fork headers invalid
        let mut invalid_fork_headers = test_fork_headers.clone();
        invalid_fork_headers.push(test_fork_headers.last().unwrap().clone());

        // handling invalid fork headers
        let res = handle_btc_headers_from_babylon(&mut storage, &invalid_fork_headers);
        assert!(matches!(
            res.unwrap_err(),
            ContractError::Header(HeaderError::PrevHashMismatch { .. })
        ));

        // ensure base and tip are unchanged
        ensure_base_and_tip(&storage, &test_headers);
        // ensure that all headers are correctly inserted
        ensure_headers(&storage, &test_headers);
    }

    // btc_lc_fork_invalid_height simulates initialization of BTC light client storage,
    // then insertion of a number of headers.
    // It checks the correctness of the fork choice rule for an invalid fork due to a wrong header
    // height.
    #[test]
    fn btc_lc_fork_invalid_height() {
        let deps = mock_dependencies();
        let mut storage = deps.storage;
        setup(&mut storage);

        let test_headers = get_btc_lc_headers();

        // initialize with all headers
        init_contract(&mut storage, &test_headers).unwrap();

        // ensure base and tip are set
        ensure_base_and_tip(&storage, &test_headers);
        // ensure all headers are correctly inserted
        ensure_headers(&storage, &test_headers);

        // get fork headers
        let test_fork_headers = get_btc_lc_fork_headers();

        // Make the fork headers invalid due to one of the headers having the wrong height
        let mut invalid_fork_headers = test_fork_headers.clone();
        let mut wrong_header = invalid_fork_headers.last().unwrap().clone();
        let height = wrong_header.height;
        wrong_header.height += 1;
        let len = invalid_fork_headers.len();
        invalid_fork_headers[len - 1] = wrong_header;

        // handling invalid fork headers
        let res = handle_btc_headers_from_babylon(&mut storage, &invalid_fork_headers);
        assert_eq!(
            res.unwrap_err(),
            ContractError::Header(HeaderError::WrongHeight(len - 1, height, height + 1))
        );

        // ensure base and tip are unchanged
        ensure_base_and_tip(&storage, &test_headers);
        // ensure that all headers are correctly inserted
        ensure_headers(&storage, &test_headers);
    }

    // btc_lc_fork_msg_accepted simulates initialization of BTC light client storage,
    // then insertion of a number of headers through a user execution message.
    // It checks the correctness of the fork choice rule for an accepted fork received through
    // the `handle_btc_headers` function.
    #[test]
    fn btc_lc_fork_msg_accepted() {
        let deps = mock_dependencies();
        let mut storage = deps.storage;
        setup(&mut storage);

        let test_headers = get_btc_lc_headers();

        // initialize with all headers
        init_contract(&mut storage, &test_headers).unwrap();

        // ensure base and tip are set
        ensure_base_and_tip(&storage, &test_headers);
        // ensure all headers are correctly inserted
        ensure_headers(&storage, &test_headers);

        // get fork messages headers
        let test_fork_msg_headers = get_fork_msg_test_headers();

        // handling fork headers
        extend_btc_headers(&mut storage, &test_fork_msg_headers).unwrap();

        // ensure the base header is set
        let base_expected = test_headers.first().unwrap();
        let base_actual = get_base_header(&storage).unwrap();
        assert_eq!(*base_expected, base_actual);
        // ensure the tip btc header is set and is correct
        let tip_btc_expected: BlockHeader =
            test_fork_msg_headers.last().unwrap().try_into().unwrap();
        let tip_btc_actual = get_tip(&storage).unwrap().block_header().unwrap();
        assert_eq!(tip_btc_expected, tip_btc_actual);

        // ensure all initial headers are still inserted
        ensure_headers(&storage, &test_headers[..FORK_HEADER_HEIGHT as usize]);

        // ensure all forked btc headers are correctly inserted
        ensure_btc_headers(&storage, &test_fork_msg_headers);

        // check that the original forked headers have been removed from the hash-to-height map
        for header_expected in test_headers[FORK_HEADER_HEIGHT as usize..].iter() {
            assert!(get_header_height(&storage, header_expected.hash.as_ref()).is_err());
        }
    }
}
