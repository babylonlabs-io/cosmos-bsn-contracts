//! `consumer_header_chain` is the storage for the chain of **finalised** Consumer headers.
//! It maintains a chain of finalised Consumer headers.
//! NOTE: The Consumer header chain is always finalised, i.e., w-deep on BTC.

use crate::state::config::CONFIG;
use crate::{error, utils};
use babylon_proto::babylon::epoching::v1::Epoch;
use babylon_proto::babylon::zoneconcierge::v1::IndexedHeader;
use cosmwasm_std::{Deps, DepsMut, StdResult};
use cw_storage_plus::{Item, Map};
use prost::Message;
use tendermint_proto::crypto::ProofOps;

pub const CONSUMER_HEADERS: Map<u64, Vec<u8>> = Map::new("consumer_headers");
pub const CONSUMER_HEADER_LAST: Item<Vec<u8>> = Item::new("consumer_header_last");
pub const CONSUMER_HEIGHT_LAST: Item<u64> = Item::new("consumer_height_last");

// getter/setter for last finalised Consumer header
pub fn get_last_consumer_header(
    deps: Deps,
) -> Result<IndexedHeader, error::ConsumerHeaderChainError> {
    let last_consumer_header_bytes = CONSUMER_HEADER_LAST
        .load(deps.storage)
        .map_err(|_| error::ConsumerHeaderChainError::NoConsumerHeader {})?;
    IndexedHeader::decode(last_consumer_header_bytes.as_slice())
        .map_err(error::ConsumerHeaderChainError::DecodeError)
}

// Getter/setter for last finalised Consumer height.
// Zero means no finalised Consumer header yet
pub fn get_last_consumer_height(deps: Deps) -> StdResult<u64> {
    CONSUMER_HEIGHT_LAST.load(deps.storage)
}

fn set_last_consumer_header(
    deps: &mut DepsMut,
    last_consumer_header: &IndexedHeader,
) -> StdResult<()> {
    let last_consumer_header_bytes = &last_consumer_header.encode_to_vec();
    CONSUMER_HEADER_LAST
        .save(deps.storage, last_consumer_header_bytes)
        // Save the height of the last finalised Consumer header in passing as well
        .and(CONSUMER_HEIGHT_LAST.save(deps.storage, &last_consumer_header.height))
}

/// Returns a Consumer header of a given height.
pub fn get_consumer_header(
    deps: Deps,
    height: u64,
) -> Result<IndexedHeader, error::ConsumerHeaderChainError> {
    // try to find the indexed header at the given height
    let consumer_header_bytes = CONSUMER_HEADERS
        .load(deps.storage, height)
        .map_err(|_| error::ConsumerHeaderChainError::ConsumerHeaderNotFoundError { height })?;

    // try to decode the indexed_header
    let indexed_header = IndexedHeader::decode(consumer_header_bytes.as_slice())?;

    Ok(indexed_header)
}

/// Verifies whether a Consumer header is committed to a Babylon epoch, including
/// - The Babylon tx carrying this header is included in a Babylon block
/// - The Babylon block's AppHash is committed to the AppHashRoot of the epoch
fn verify_consumer_header(
    deps: Deps,
    consumer_header: &IndexedHeader,
    epoch: &Epoch,
    proof_consumer_header_in_epoch: &ProofOps,
) -> Result<(), error::ConsumerHeaderChainError> {
    let _cfg = CONFIG.load(deps.storage)?;

    // check if the corresponding Consumer header is in the Babylon epoch
    utils::consumer_header_chain::verify_consumer_header_in_epoch(
        consumer_header,
        epoch,
        proof_consumer_header_in_epoch,
    )?;

    // TODO: check if IndexedHeader is conflicted or not. Still not sure if this check should happen
    // in a relayer/monitor or the smart contract, given that smart contract has no access to the
    // Tendermint ledger

    Ok(())
}

fn insert_consumer_header(deps: &mut DepsMut, consumer_header: &IndexedHeader) -> StdResult<()> {
    // insert indexed header
    let consumer_header_bytes = consumer_header.encode_to_vec();
    CONSUMER_HEADERS.save(deps.storage, consumer_header.height, &consumer_header_bytes)?;

    // update last finalised header
    set_last_consumer_header(deps, consumer_header)
}

// TODO: unit test
pub fn handle_consumer_header(
    deps: &mut DepsMut,
    consumer_header: &IndexedHeader,
    epoch: &Epoch,
    proof_consumer_header_in_epoch: &ProofOps,
) -> Result<(), error::ConsumerHeaderChainError> {
    verify_consumer_header(
        deps.as_ref(),
        consumer_header,
        epoch,
        proof_consumer_header_in_epoch,
    )?;
    insert_consumer_header(deps, consumer_header)?;

    Ok(())
}
