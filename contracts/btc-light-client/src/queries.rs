use crate::error::ContractError;
use crate::msg::btc_header::{BtcHeaderResponse, BtcHeadersResponse};
use crate::state::{expect_header_by_hash, get_base_header, get_header, get_headers, get_tip};
use bitcoin::BlockHash;
use cosmwasm_std::Deps;
use std::str::FromStr;

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
    expect_header_by_hash(deps.storage, hash.as_ref())?.try_into()
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
    use crate::contract::tests::{init_contract, setup};
    use crate::state::{BitcoinNetwork, Config, CONFIG};
    use babylon_test_utils::get_btc_lc_headers;
    use cosmwasm_std::testing::mock_dependencies;

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

    #[test]
    fn btc_headers_work() {
        let mut deps = mock_dependencies();
        setup(deps.as_mut().storage);

        let test_headers = get_btc_lc_headers();

        init_contract(deps.as_mut().storage, &test_headers).unwrap();
        // get headers
        let headers = btc_headers(&deps.as_ref(), None, None, None)
            .unwrap()
            .headers;
        assert_eq!(headers.len(), 10); // default limit

        for (i, header) in headers.iter().enumerate() {
            assert_eq!(header, &TryFrom::try_from(&test_headers[i]).unwrap());
        }

        // get next 5 headers
        let headers = btc_headers(
            &deps.as_ref(),
            Some(headers.last().unwrap().height),
            Some(5),
            None,
        )
        .unwrap()
        .headers;
        assert_eq!(headers.len(), 5);

        for (i, header) in headers.iter().enumerate() {
            assert_eq!(header, &TryFrom::try_from(&test_headers[i + 10]).unwrap());
        }

        // get next 30 headers
        let headers = btc_headers(
            &deps.as_ref(),
            Some(headers.last().unwrap().height),
            Some(100),
            None,
        )
        .unwrap()
        .headers;
        assert_eq!(headers.len(), 30); // max limit

        for (i, header) in headers.iter().enumerate() {
            assert_eq!(header, &TryFrom::try_from(&test_headers[i + 15]).unwrap());
        }

        // get the last headers
        let headers = btc_headers(&deps.as_ref(), Some(90), Some(30), None)
            .unwrap()
            .headers;

        assert_eq!(headers.len(), 10); // no more headers than that
        for (i, header) in headers.iter().enumerate() {
            assert_eq!(header, &TryFrom::try_from(&test_headers[i + 90]).unwrap());
        }
    }

    #[test]
    fn btc_headers_reverse_order_work() {
        let mut deps = mock_dependencies();
        crate::contract::tests::setup(deps.as_mut().storage);

        let test_headers = get_btc_lc_headers();

        init_contract(deps.as_mut().storage, &test_headers).unwrap();

        // get headers in reverse order
        let headers = btc_headers(&deps.as_ref(), None, None, Some(true))
            .unwrap()
            .headers;
        assert_eq!(headers.len(), 10); // default limit

        for (i, header) in headers.iter().enumerate() {
            assert_eq!(
                header,
                &TryFrom::try_from(&test_headers[100 - i - 1]).unwrap()
            );
        }

        // get previous 5 headers
        let headers = btc_headers(
            &deps.as_ref(),
            Some(headers.last().unwrap().height),
            Some(5),
            Some(true),
        )
        .unwrap()
        .headers;
        assert_eq!(headers.len(), 5);

        for (i, header) in headers.iter().enumerate() {
            assert_eq!(
                header,
                &TryFrom::try_from(&test_headers[100 - 10 - i - 1]).unwrap()
            );
        }

        // get previous 30 headers
        let headers = btc_headers(
            &deps.as_ref(),
            Some(headers.last().unwrap().height),
            Some(100),
            Some(true),
        )
        .unwrap()
        .headers;
        assert_eq!(headers.len(), 30); // max limit

        for (i, header) in headers.iter().enumerate() {
            assert_eq!(
                header,
                &TryFrom::try_from(&test_headers[100 - 15 - i - 1]).unwrap()
            );
        }

        // get the first ten headers
        let headers = btc_headers(&deps.as_ref(), Some(11), Some(30), Some(true))
            .unwrap()
            .headers;

        assert_eq!(headers.len(), 10); // no more headers than that
        for (i, header) in headers.iter().enumerate() {
            assert_eq!(
                header,
                &TryFrom::try_from(&test_headers[100 - 90 - i - 1]).unwrap()
            );
        }
    }
}
