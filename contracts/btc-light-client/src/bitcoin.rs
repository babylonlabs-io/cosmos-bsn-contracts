//! This module provides some Bitcoin related helper functions.

use crate::error::ContractError;
use babylon_bitcoin::{deserialize, BlockHeader, Work};
use babylon_proto::babylon::btclightclient::v1::BtcHeaderInfo;
use cosmwasm_std::{StdError, StdResult};

/// Verifies whether `new_headers` are valid consecutive headers
/// after the given `first_header`.
pub fn verify_headers(
    chain_params: &babylon_bitcoin::Params,
    first_header: &BtcHeaderInfo,
    new_headers: &[BtcHeaderInfo],
) -> Result<(), ContractError> {
    // verify each new header iteratively
    let mut last_header = first_header.clone();
    let mut cum_work_old = total_work(last_header.work.as_ref())?;
    for (i, new_header) in new_headers.iter().enumerate() {
        let last_btc_header: BlockHeader = deserialize(last_header.header.as_ref())?;
        let btc_header: BlockHeader = deserialize(new_header.header.as_ref())?;

        check_header(chain_params, &last_btc_header, &btc_header)?;

        let header_work = btc_header.work();
        let cum_work = total_work(new_header.work.as_ref())?;

        // Validate cumulative work
        if cum_work_old + header_work != cum_work {
            return Err(ContractError::BTCWrongCumulativeWork(
                i,
                cum_work_old + header_work,
                cum_work,
            ));
        }
        cum_work_old = cum_work;
        // Validate height
        if new_header.height != last_header.height + 1 {
            return Err(ContractError::BTCWrongHeight(
                i,
                last_header.height + 1,
                new_header.height,
            ));
        }

        // this header is good, verify the next one
        last_header = new_header.clone();
    }
    Ok(())
}

// https://github.com/babylonlabs-io/babylon/blob/48617fb852e9cae4ea7ea38c80793cdcb6f2668c/x/btclightclient/types/btc_light_client.go#L416
fn check_header(
    chain_params: &babylon_bitcoin::Params,
    parent_header: &BlockHeader,
    header: &BlockHeader,
) -> Result<(), ContractError> {
    babylon_bitcoin::pow::verify_next_header_pow(chain_params, parent_header, header)?;
    Ok(())
}

/// Returns the total work of the given header.
/// The total work is the cumulative work of the given header and all of its ancestors.
pub fn total_work(work: &[u8]) -> StdResult<Work> {
    Ok(Work::from_be_bytes(work.try_into().map_err(|e| {
        StdError::generic_err(format!("Invalid work: {e:?}"))
    })?))
}
