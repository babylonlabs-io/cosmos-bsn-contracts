//! Contract system-state management:
//! - Track finalized Babylon epochs & raw checkpoints.
//! - Track finalized Consumer headers & heights.

use crate::error;
use crate::error::BabylonEpochChainError;
use babylon_proto::babylon::btccheckpoint::v1::TransactionInfo;
use babylon_proto::babylon::checkpointing::v1::RawCheckpoint;
use babylon_proto::babylon::epoching::v1::Epoch;
use babylon_proto::babylon::zoneconcierge::v1::{
    BtcHeaders, BtcTimestamp, IndexedHeader, ProofEpochSealed,
};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, Deps, DepsMut, StdError, StdResult, WasmMsg};
use cw_storage_plus::{Item, Map};
use prost::Message;
use tendermint_proto::crypto::ProofOps;

pub const NUM_BTC_TXS: usize = 2;

pub const DEFAULT_IBC_PACKET_TIMEOUT_DAYS: u64 = 28; // 28 days

pub(crate) const CONFIG: Item<Config> = Item::new("config");

/// Map of the epoch number to the **finalised** Babylon epochs.
/// It maintains a chain of finalised Babylon epochs.
/// NOTE: the Babylon epoch chain is always finalised, i.e. w-deep on BTC.
pub const BABYLON_EPOCHS: Map<u64, Vec<u8>> = Map::new("babylon_epochs");
pub const BABYLON_EPOCH_BASE: Item<Vec<u8>> = Item::new("babylon_epoch_base");
pub const BABYLON_EPOCH_EPOCH_LAST_FINALIZED: Item<Vec<u8>> = Item::new("babylon_epoch_last");
pub const BABYLON_CHECKPOINTS: Map<u64, Vec<u8>> = Map::new("babylon_checkpoints");

/// Map for consumer header chain height to the **finalised** Consumer headers.
/// It maintains a chain of finalised Consumer headers.
/// NOTE: The Consumer header chain is always finalised, i.e., w-deep on BTC.
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

#[allow(dead_code)]
fn verify_consumer_header(
    _deps: Deps,
    _consumer_header: &IndexedHeader,
    _epoch: &Epoch,
    _proof_consumer_header_in_epoch: &ProofOps,
) -> Result<(), error::ConsumerHeaderChainError> {
    // NOTE: we don't verify timestamped BSN header here,
    // as we assume it is already verified by Babylon
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
fn handle_consumer_header(
    deps: &mut DepsMut,
    consumer_header: &IndexedHeader,
) -> Result<(), error::ConsumerHeaderChainError> {
    insert_consumer_header(deps, consumer_header)?;

    Ok(())
}

#[cw_serde]
pub struct Config {
    pub network: btc_light_client::BitcoinNetwork,
    pub btc_confirmation_depth: u32,
    pub checkpoint_finalization_timeout: u32,
    /// If set, this stores the address of the BTC light client contract on the Consumer.
    pub btc_light_client: Option<Addr>,
    /// If set, this stores a BTC staking contract used for BTC re-staking
    pub btc_staking: Option<Addr>,
    /// If set, this stores a BTC finality contract used for BTC finality on the Consumer
    pub btc_finality: Option<Addr>,
    /// Consumer name
    pub consumer_name: String,
    /// Consumer description
    pub consumer_description: String,
    pub denom: String,
    /// IBC packet timeout in days
    pub ibc_packet_timeout_days: u64,
    /// Babylon module name for receiving ICS-20 transfers
    pub destination_module: String,
}

// Checks if the BTC light client has been initialised or not
// the check is done by checking existence of base epoch
pub fn is_initialized(deps: &DepsMut) -> bool {
    BABYLON_EPOCH_BASE.load(deps.storage).is_ok()
}

// getter/setter for base epoch
pub fn get_base_epoch(deps: Deps) -> Result<Epoch, BabylonEpochChainError> {
    // NOTE: if init is successful, then base epoch is guaranteed to be in storage and decodable
    let base_epoch_bytes = BABYLON_EPOCH_BASE.load(deps.storage)?;

    Epoch::decode(base_epoch_bytes.as_slice()).map_err(BabylonEpochChainError::DecodeError)
}

fn set_base_epoch(deps: &mut DepsMut, base_epoch: &Epoch) -> StdResult<()> {
    let base_epoch_bytes = &base_epoch.encode_to_vec();
    BABYLON_EPOCH_BASE.save(deps.storage, base_epoch_bytes)
}

// getter/setter for last finalised epoch
pub fn get_last_finalized_epoch(deps: Deps) -> Result<Epoch, BabylonEpochChainError> {
    let last_finalized_epoch_bytes = BABYLON_EPOCH_EPOCH_LAST_FINALIZED
        .load(deps.storage)
        .map_err(|_| BabylonEpochChainError::NoFinalizedEpoch {})?;
    Epoch::decode(last_finalized_epoch_bytes.as_slice())
        .map_err(BabylonEpochChainError::DecodeError)
}

fn set_last_finalized_epoch(deps: &mut DepsMut, last_finalized_epoch: &Epoch) -> StdResult<()> {
    let last_finalized_epoch_bytes = &last_finalized_epoch.encode_to_vec();
    BABYLON_EPOCH_EPOCH_LAST_FINALIZED.save(deps.storage, last_finalized_epoch_bytes)
}

/// Retrieves the metadata of a given epoch.
pub fn get_epoch(deps: Deps, epoch_number: u64) -> Result<Epoch, BabylonEpochChainError> {
    // try to find the epoch metadata of the given epoch
    let epoch_bytes = BABYLON_EPOCHS
        .load(deps.storage, epoch_number)
        .map_err(|_| BabylonEpochChainError::EpochNotFoundError { epoch_number })?;

    // try to decode the epoch
    let epoch = Epoch::decode(epoch_bytes.as_slice())?;

    Ok(epoch)
}

/// Retrieves the checkpoint of a given epoch.
pub fn get_checkpoint(
    deps: Deps,
    epoch_number: u64,
) -> Result<RawCheckpoint, BabylonEpochChainError> {
    // try to find the checkpoint of the given epoch
    let ckpt_bytes = BABYLON_CHECKPOINTS
        .load(deps.storage, epoch_number)
        .map_err(|_| BabylonEpochChainError::CheckpointNotFoundError { epoch_number })?;

    // try to decode the checkpoint
    let ckpt_res = RawCheckpoint::decode(ckpt_bytes.as_slice())?;

    Ok(ckpt_res)
}

struct VerifiedEpochAndCheckpoint {
    pub epoch: Epoch,
    pub raw_ckpt: RawCheckpoint,
}

/// Verifies an epoch metadata and a raw checkpoint.
fn verify_epoch_and_checkpoint(
    _deps: Deps,
    _new_btc_headers: Option<&BtcHeaders>,
    epoch: &Epoch,
    raw_ckpt: &RawCheckpoint,
    _proof_epoch_sealed: &ProofEpochSealed,
    _txs_info: &[TransactionInfo; NUM_BTC_TXS],
) -> Result<VerifiedEpochAndCheckpoint, BabylonEpochChainError> {
    // NOTE: we don't verify the epoch and checkpoint here,
    // as we assume the epoch and checkpoint are already verified by Babylon
    Ok(VerifiedEpochAndCheckpoint {
        epoch: epoch.clone(),
        raw_ckpt: raw_ckpt.clone(),
    })
}

/// Inserts an epoch and the corresponding raw checkpoint, and update the last finalised
/// checkpoint.
/// NOTE: epoch/raw_ckpt have already passed all verifications
fn insert_epoch_and_checkpoint(
    deps: &mut DepsMut,
    verified_tuple: &VerifiedEpochAndCheckpoint,
) -> StdResult<()> {
    // insert epoch metadata
    let epoch_number = verified_tuple.epoch.epoch_number;
    let epoch_bytes = verified_tuple.epoch.encode_to_vec();
    BABYLON_EPOCHS.save(deps.storage, epoch_number, &epoch_bytes)?;

    // insert raw ckpt
    let raw_ckpt_bytes = verified_tuple.raw_ckpt.encode_to_vec();
    BABYLON_CHECKPOINTS.save(deps.storage, epoch_number, &raw_ckpt_bytes)?;

    // update last finalised epoch
    set_last_finalized_epoch(deps, &verified_tuple.epoch)
}

/// Extracts data needed for verifying Babylon epoch chain from a given BTC timestamp.
fn extract_data_from_btc_ts(
    btc_ts: &BtcTimestamp,
) -> Result<
    (
        &Epoch,
        &RawCheckpoint,
        &ProofEpochSealed,
        [TransactionInfo; NUM_BTC_TXS],
    ),
    StdError,
> {
    let epoch = btc_ts
        .epoch_info
        .as_ref()
        .ok_or(StdError::generic_err("empty epoch info"))?;
    let raw_ckpt = btc_ts
        .raw_checkpoint
        .as_ref()
        .ok_or(StdError::generic_err("empty raw checkpoint"))?;
    let proof = btc_ts
        .proof
        .as_ref()
        .ok_or(StdError::generic_err("empty proof"))?;
    let proof_epoch_sealed = proof
        .proof_epoch_sealed
        .as_ref()
        .ok_or(StdError::generic_err("empty proof_epoch_sealed"))?;
    let txs_info: [TransactionInfo; NUM_BTC_TXS] = proof
        .proof_epoch_submitted
        .clone()
        .try_into()
        .map_err(|_| {
        StdError::generic_err("proof_epoch_submitted is not correctly formatted")
    })?;

    Ok((epoch, raw_ckpt, proof_epoch_sealed, txs_info))
}

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
        deps.api.debug(&format!(
            "CONTRACT: handle_btc_timestamp: found {} BTC headers",
            btc_headers.headers.len()
        ));
        if !btc_headers.headers.is_empty() {
            deps.api
                .debug("CONTRACT: handle_btc_timestamp: creating BTC headers message");
            wasm_msg = Some(
                crate::utils::btc_light_client_executor::new_btc_headers_msg(
                    deps,
                    &btc_headers.headers,
                )
                .map_err(|e| {
                    let err_msg = format!("failed to submit BTC headers: {e}");
                    deps.api
                        .debug(&format!("CONTRACT: handle_btc_timestamp: {err_msg}"));
                    StdError::generic_err(err_msg)
                })?,
            );
        }
    } else {
        deps.api
            .debug("CONTRACT: handle_btc_timestamp: no BTC headers found");
    }

    // extract and init/handle Babylon epoch chain
    let (epoch, raw_ckpt, proof_epoch_sealed, txs_info) = extract_data_from_btc_ts(btc_ts)?;

    deps.api.debug(&format!(
        "CONTRACT: handle_btc_timestamp: extracted epoch {}",
        epoch.epoch_number
    ));

    if is_initialized(deps) {
        deps.api.debug("CONTRACT: handle_btc_timestamp: Babylon epoch chain is initialized, handling epoch and checkpoint");

        // Handles a BTC-finalised epoch by using the raw checkpoint and inclusion proofs.
        let mut handle_epoch_and_checkpoint = || -> Result<(), BabylonEpochChainError> {
            let verified_tuple = verify_epoch_and_checkpoint(
                deps.as_ref(),
                btc_ts.btc_headers.as_ref(),
                epoch,
                raw_ckpt,
                proof_epoch_sealed,
                &txs_info,
            )?;

            // all good, insert everything and update last finalised epoch
            Ok(insert_epoch_and_checkpoint(deps, &verified_tuple)?)
        };

        handle_epoch_and_checkpoint().map_err(|e| {
            let err_msg = format!("failed to handle Babylon epoch from Babylon: {e}");
            deps.api
                .debug(&format!("CONTRACT: handle_btc_timestamp: {err_msg}"));
            StdError::generic_err(err_msg)
        })?;
    } else {
        deps.api
            .debug("handle_btc_timestamp: Babylon epoch chain not initialized, initializing");

        // Initialises the Babylon epoch chain storage.
        let mut init = || -> Result<(), BabylonEpochChainError> {
            let verified_tuple = verify_epoch_and_checkpoint(
                deps.as_ref(),
                btc_ts.btc_headers.as_ref(),
                epoch,
                raw_ckpt,
                proof_epoch_sealed,
                &txs_info,
            )?;

            set_base_epoch(deps, epoch)?;
            Ok(insert_epoch_and_checkpoint(deps, &verified_tuple)?)
        };

        init().map_err(|e| {
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
        handle_consumer_header(deps, consumer_header).map_err(|e| {
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
