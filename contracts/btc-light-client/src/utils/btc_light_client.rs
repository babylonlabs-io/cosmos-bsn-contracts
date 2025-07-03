use crate::error::ContractError;
use babylon_bitcoin::{deserialize, BlockHeader, Work};
use babylon_proto::babylon::btclightclient::v1::BtcHeaderInfo;
use cosmwasm_std::{StdResult, Uint256};
use std::str::{from_utf8, FromStr};

/// verify_headers verifies whether `new_headers` are valid consecutive headers
/// after the given `first_header`
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

        // validate whether btc_header extends last_btc_header
        babylon_bitcoin::pow::verify_next_header_pow(chain_params, &last_btc_header, &btc_header)?;

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

/// Zero work helper / constructor
pub fn zero_work() -> Work {
    Work::from_be_bytes(Uint256::zero().to_be_bytes())
}

/// Returns the total work of the given header.
/// The total work is the cumulative work of the given header and all of its ancestors.
pub fn total_work(work: &[u8]) -> StdResult<Work> {
    // TODO: Use a better encoding (String / binary)
    let header_work = from_utf8(work)?;
    let header_work_cw = cosmwasm_std::Uint256::from_str(header_work)?;
    Ok(Work::from_be_bytes(header_work_cw.to_be_bytes()))
}
