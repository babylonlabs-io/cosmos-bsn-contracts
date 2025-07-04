pub mod btc_header;

pub use btc_header::{
    btc_base_header, btc_header, btc_header_by_hash, btc_headers, btc_tip_header,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::btc_light_client::tests::{init_contract, setup};
    use babylon_test_utils::get_btc_lc_headers;
    use cosmwasm_std::testing::mock_dependencies;

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
        crate::state::btc_light_client::tests::setup(deps.as_mut().storage);

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
