//! babylon_epoch_chain is the storage for the chain of **finalised** Babylon epochs.
//! It maintains a chain of finalised Babylon epochs.
//! NOTE: the Babylon epoch chain is always finalised, i.e. w-deep on BTC.

use crate::error::BabylonEpochChainError;
use babylon_proto::babylon::btccheckpoint::v1::TransactionInfo;
use babylon_proto::babylon::checkpointing::v1::RawCheckpoint;
use babylon_proto::babylon::epoching::v1::Epoch;
use babylon_proto::babylon::zoneconcierge::v1::{BtcHeaders, BtcTimestamp, ProofEpochSealed};
use cosmwasm_std::{Deps, DepsMut, StdError, StdResult};
use cw_storage_plus::{Item, Map};
use prost::Message;
pub const BABYLON_EPOCHS: Map<u64, Vec<u8>> = Map::new("babylon_epochs");
pub const BABYLON_EPOCH_BASE: Item<Vec<u8>> = Item::new("babylon_epoch_base");
pub const BABYLON_EPOCH_EPOCH_LAST_FINALIZED: Item<Vec<u8>> = Item::new("babylon_epoch_last");
pub const BABYLON_CHECKPOINTS: Map<u64, Vec<u8>> = Map::new("babylon_checkpoints");

pub const NUM_BTC_TXS: usize = 2;

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
pub fn extract_data_from_btc_ts(
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

/// Initialises the Babylon epoch chain storage.
pub fn init(
    deps: &mut DepsMut,
    btc_headers: Option<&BtcHeaders>,
    epoch: &Epoch,
    raw_ckpt: &RawCheckpoint,
    proof_epoch_sealed: &ProofEpochSealed,
    txs_info: &[TransactionInfo; NUM_BTC_TXS],
) -> Result<(), BabylonEpochChainError> {
    let verified_tuple = verify_epoch_and_checkpoint(
        deps.as_ref(),
        btc_headers,
        epoch,
        raw_ckpt,
        proof_epoch_sealed,
        txs_info,
    )?;

    // all good, init base
    set_base_epoch(deps, epoch)?;
    // then insert everything and update last finalised epoch
    Ok(insert_epoch_and_checkpoint(deps, &verified_tuple)?)
}

/// Handles a BTC-finalised epoch by using the raw checkpoint and inclusion proofs.
pub fn handle_epoch_and_checkpoint(
    deps: &mut DepsMut,
    btc_headers: Option<&BtcHeaders>,
    epoch: &Epoch,
    raw_ckpt: &RawCheckpoint,
    proof_epoch_sealed: &ProofEpochSealed,
    txs_info: &[TransactionInfo; NUM_BTC_TXS],
) -> Result<(), BabylonEpochChainError> {
    let verified_tuple = verify_epoch_and_checkpoint(
        deps.as_ref(),
        btc_headers,
        epoch,
        raw_ckpt,
        proof_epoch_sealed,
        txs_info,
    )?;

    // all good, insert everything and update last finalised epoch
    Ok(insert_epoch_and_checkpoint(deps, &verified_tuple)?)
}
