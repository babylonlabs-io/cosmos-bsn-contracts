//! This module includes functions that invoke custom messages to the Consumer chain.

use cosmwasm_std::StdError;

use babylon_bindings::BabylonMsg;

use babylon_proto::babylon::zoneconcierge::v1::IndexedHeader;

/// msg_btc_finalized_header returns a message that reports a BTC-finalised header
/// from a given IndexedHeader
pub fn msg_btc_finalized_header(consumer_header: &IndexedHeader) -> Result<BabylonMsg, StdError> {
    let height = consumer_header.height as i64;
    let time = consumer_header
        .time
        .as_ref()
        .ok_or(StdError::generic_err("empty time"))?
        .seconds;
    Ok(BabylonMsg::FinalizedHeader { height, time })
}
