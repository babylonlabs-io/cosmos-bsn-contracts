//! This module manages contract's system state.

use babylon_proto::babylon::zoneconcierge::v1::BtcTimestamp;
use cosmwasm_logging::debug;
use cosmwasm_std::{DepsMut, StdError, WasmMsg};

pub mod babylon_epoch_chain;
pub mod config;
pub mod consumer_header_chain;

/// Handles a BTC timestamp.
/// It returns an Option<WasmMsg>.
/// The returned WasmMsg, if Some, is a message to submit BTC headers to the BTC light client.
/// Returns None if there are no BTC headers to submit or if processing fails.
pub fn handle_btc_timestamp(
    deps: &mut DepsMut,
    btc_ts: &BtcTimestamp,
) -> Result<Option<WasmMsg>, StdError> {
    deps.api
        .debug("CONTRACT: handle_btc_timestamp: starting to process BTC timestamp");

    let mut wasm_msg = None;

    // only process BTC headers if they exist and are not empty
    if let Some(btc_headers) = btc_ts.btc_headers.as_ref() {
        debug!(
            "handle_btc_timestamp: found {} BTC headers",
            btc_headers.headers.len()
        );
        if !btc_headers.headers.is_empty() {
            debug!("handle_btc_timestamp: creating BTC headers message");
            wasm_msg = Some(
                crate::utils::btc_light_client_executor::new_btc_headers_msg(
                    deps,
                    &btc_headers.headers,
                )
                .map_err(|e| {
                    let err_msg = format!("failed to submit BTC headers: {e}");
                    debug!("handle_btc_timestamp: {err_msg}");
                    StdError::generic_err(err_msg)
                })?,
            );
        }
    } else {
        debug!("handle_btc_timestamp: no BTC headers found");
    }

    // extract and init/handle Babylon epoch chain
    let (epoch, raw_ckpt, proof_epoch_sealed, txs_info) =
        babylon_epoch_chain::extract_data_from_btc_ts(btc_ts)?;

    debug!(
        "handle_btc_timestamp: extracted epoch {}",
        epoch.epoch_number
    );

    if babylon_epoch_chain::is_initialized(deps) {
        debug!("handle_btc_timestamp: Babylon epoch chain is initialized, handling epoch and checkpoint");
        babylon_epoch_chain::handle_epoch_and_checkpoint(
            deps,
            btc_ts.btc_headers.as_ref(),
            epoch,
            raw_ckpt,
            proof_epoch_sealed,
            &txs_info,
        )
        .map_err(|e| {
            let err_msg = format!("failed to handle Babylon epoch from Babylon: {e}");
            deps.api
                .debug(&format!("CONTRACT: handle_btc_timestamp: {err_msg}"));
            StdError::generic_err(err_msg)
        })?;
    } else {
        deps.api
            .debug("handle_btc_timestamp: Babylon epoch chain not initialized, initializing");
        babylon_epoch_chain::init(
            deps,
            btc_ts.btc_headers.as_ref(),
            epoch,
            raw_ckpt,
            proof_epoch_sealed,
            &txs_info,
        )
        .map_err(|e| {
            let err_msg = format!("failed to initialize Babylon epoch: {e}");
            deps.api
                .debug(&format!("CONTRACT: handle_btc_timestamp: {err_msg}"));
            StdError::generic_err(err_msg)
        })?;
    }

    // Try to extract and handle the Consumer header.
    // It's possible that there is no Consumer header checkpointed in this epoch
    if let Some(consumer_header) = btc_ts.header.as_ref() {
        deps.api
            .debug("handle_btc_timestamp: found consumer header, processing");
        consumer_header_chain::handle_consumer_header(deps, consumer_header).map_err(|e| {
            let err_msg = format!("failed to handle Consumer header from Babylon: {e}");
            deps.api
                .debug(&format!("CONTRACT: handle_btc_timestamp: {err_msg}"));
            StdError::generic_err(err_msg)
        })?;
    } else {
        deps.api
            .debug("handle_btc_timestamp: no consumer header found in this epoch");
    }

    deps.api
        .debug("handle_btc_timestamp: completed processing BTC timestamp");
    Ok(wasm_msg)
}
