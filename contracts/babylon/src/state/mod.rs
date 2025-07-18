//! state is the module that manages smart contract's system state

use babylon_proto::babylon::zoneconcierge::v1::BtcTimestamp;
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
    let mut wasm_msg = None;

    // only process BTC headers if they exist and are not empty
    if let Some(btc_headers) = btc_ts.btc_headers.as_ref() {
        if !btc_headers.headers.is_empty() {
            wasm_msg = Some(
                crate::utils::btc_light_client_executor::new_btc_headers_msg(
                    deps,
                    &btc_headers.headers,
                )
                .map_err(|e| StdError::generic_err(format!("failed to submit BTC headers: {e}")))?,
            );
        }
    }

    // extract and init/handle Babylon epoch chain
    let (epoch, raw_ckpt, proof_epoch_sealed, txs_info) =
        babylon_epoch_chain::extract_data_from_btc_ts(btc_ts)?;
    if babylon_epoch_chain::is_initialized(deps) {
        babylon_epoch_chain::handle_epoch_and_checkpoint(
            deps,
            btc_ts.btc_headers.as_ref(),
            epoch,
            raw_ckpt,
            proof_epoch_sealed,
            &txs_info,
        )
        .map_err(|e| {
            StdError::generic_err(format!("failed to handle Babylon epoch from Babylon: {e}"))
        })?;
    } else {
        babylon_epoch_chain::init(
            deps,
            btc_ts.btc_headers.as_ref(),
            epoch,
            raw_ckpt,
            proof_epoch_sealed,
            &txs_info,
        )
        .map_err(|e| StdError::generic_err(format!("failed to initialize Babylon epoch: {e}")))?;
    }

    // Try to extract and handle the Consumer header.
    // It's possible that there is no Consumer header checkpointed in this epoch
    if let Some(consumer_header) = btc_ts.header.as_ref() {
        let proof = btc_ts
            .proof
            .as_ref()
            .ok_or(StdError::generic_err("empty proof"))?;
        let proof_consumer_header_in_epoch =
            proof
                .proof_consumer_header_in_epoch
                .as_ref()
                .ok_or(StdError::generic_err(
                    "empty proof_consumer_header_in_epoch",
                ))?;
        consumer_header_chain::handle_consumer_header(
            deps,
            consumer_header,
            epoch,
            proof_consumer_header_in_epoch,
        )
        .map_err(|e| {
            StdError::generic_err(format!(
                "failed to handle Consumer header from Babylon: {e}"
            ))
        })?;
    }

    Ok(wasm_msg)
}
