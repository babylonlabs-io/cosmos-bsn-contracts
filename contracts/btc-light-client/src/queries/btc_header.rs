use std::str::FromStr;

use babylon_bitcoin::BlockHash;
use cosmwasm_std::Deps;

use crate::error::ContractError;
use crate::msg::btc_header::{BtcHeaderResponse, BtcHeadersResponse};
use crate::state::{get_base_header, get_header, get_header_by_hash, get_headers, get_tip};

const MAX_LIMIT: u32 = 30;
const DEFAULT_LIMIT: u32 = 10;

pub fn btc_base_header(deps: &Deps) -> Result<BtcHeaderResponse, ContractError> {
    get_base_header(deps.storage)?.try_into()
}

pub fn btc_tip_header(deps: &Deps) -> Result<BtcHeaderResponse, ContractError> {
    get_tip(deps.storage)?.try_into()
}

pub fn btc_header(deps: &Deps, height: u32) -> Result<BtcHeaderResponse, ContractError> {
    get_header(deps.storage, height)?.try_into()
}

pub fn btc_header_by_hash(deps: &Deps, hash: &str) -> Result<BtcHeaderResponse, ContractError> {
    let hash = BlockHash::from_str(hash)?;
    get_header_by_hash(deps.storage, hash.as_ref())?.try_into()
}

pub fn btc_headers(
    deps: &Deps,
    start_after: Option<u32>,
    limit: Option<u32>,
    reverse: Option<bool>,
) -> Result<BtcHeadersResponse, ContractError> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT);
    get_headers(deps.storage, start_after, Some(limit), reverse)?.try_into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use babylon_test_utils::get_btc_lc_headers;
    use cosmwasm_std::testing::mock_dependencies;

    use crate::state::btc_light_client::tests::init_contract;
    use crate::state::config::{Config, CONFIG};
    use crate::state::BitcoinNetwork;

    fn setup_test_state(
        deps: &mut cosmwasm_std::OwnedDeps<
            cosmwasm_std::MemoryStorage,
            cosmwasm_std::testing::MockApi,
            cosmwasm_std::testing::MockQuerier,
        >,
    ) {
        // Set config
        let cfg = Config {
            network: BitcoinNetwork::Regtest,
            btc_confirmation_depth: 1,
            checkpoint_finalization_timeout: 2,
        };
        CONFIG.save(&mut deps.storage, &cfg).unwrap();

        // Initialize with test headers
        let test_headers = get_btc_lc_headers();
        init_contract(&mut deps.storage, &test_headers).unwrap();
    }

    #[test]
    fn test_btc_tip_header() {
        let mut deps = mock_dependencies();
        setup_test_state(&mut deps);

        let header_response = btc_tip_header(&deps.as_ref()).unwrap();
        assert!(header_response.height > 0); // Tip should be higher than base
    }

    #[test]
    fn test_btc_header() {
        let mut deps = mock_dependencies();
        setup_test_state(&mut deps);

        let header_response = btc_header(&deps.as_ref(), 1).unwrap();
        assert_eq!(header_response.height, 1);
    }
}
