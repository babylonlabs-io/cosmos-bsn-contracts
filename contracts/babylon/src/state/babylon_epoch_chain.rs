//! babylon_epoch_chain is the storage for the chain of **finalised** Babylon epochs.
//! It maintains a chain of finalised Babylon epochs.
//! NOTE: the Babylon epoch chain is always finalised, i.e. w-deep on BTC.

use bitcoin::block::Header as BlockHeader;
use btc_light_client::msg::btc_header::BtcHeaderResponse;
use prost::Message;
use std::cmp::min;

use cosmwasm_std::{Deps, DepsMut, StdError, StdResult};
use cw_storage_plus::{Item, Map};

use babylon_proto::babylon::btccheckpoint::v1::TransactionInfo;
use babylon_proto::babylon::checkpointing::v1::RawCheckpoint;
use babylon_proto::babylon::epoching::v1::Epoch;
use babylon_proto::babylon::zoneconcierge::v1::{BtcHeaders, BtcTimestamp, ProofEpochSealed};

use crate::error::BabylonEpochChainError;
use crate::state::config::CONFIG;
use crate::utils::babylon_epoch_chain::{
    verify_checkpoint_submitted, verify_epoch_sealed, NUM_BTC_TXS,
};
use crate::utils::btc_light_client_querier::{query_header_by_hash, query_tip_header};
use btc_light_client::error::ContractError as BtcLightclientError;

pub const BABYLON_EPOCHS: Map<u64, Vec<u8>> = Map::new("babylon_epochs");
pub const BABYLON_EPOCH_BASE: Item<Vec<u8>> = Item::new("babylon_epoch_base");
pub const BABYLON_EPOCH_EPOCH_LAST_FINALIZED: Item<Vec<u8>> = Item::new("babylon_epoch_last");
pub const BABYLON_CHECKPOINTS: Map<u64, Vec<u8>> = Map::new("babylon_checkpoints");

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
///
/// The verifications include:
/// - whether the raw checkpoint is BTC-finalised, i.e., in a w-deep BTC header
/// - whether the epoch is sealed by the validator set of this epoch
fn verify_epoch_and_checkpoint(
    deps: Deps,
    new_btc_headers: Option<&BtcHeaders>,
    epoch: &Epoch,
    raw_ckpt: &RawCheckpoint,
    proof_epoch_sealed: &ProofEpochSealed,
    txs_info: &[TransactionInfo; NUM_BTC_TXS],
) -> Result<VerifiedEpochAndCheckpoint, BabylonEpochChainError> {
    let cfg = CONFIG.load(deps.storage)?;

    // ensure that raw_ckpt is corresponding to the epoch
    if epoch.epoch_number != raw_ckpt.epoch_num {
        return Err(BabylonEpochChainError::CheckpointNotMatchError {
            ckpt_epoch_number: raw_ckpt.epoch_num,
            epoch_number: epoch.epoch_number,
        });
    }

    // get BTC headers from local BTC light client
    let btc_headers: [BtcHeaderResponse; NUM_BTC_TXS] = txs_info
        .iter()
        .map(|tx_info| {
            let tx_key = tx_info
                .key
                .clone()
                .ok_or(BabylonEpochChainError::EmptyTxKey {})?;
            let btc_header_hash = tx_key.hash.to_vec();

            // get hash string in reverse order for matching BTC header hash
            let mut btc_header_hash_reversed = btc_header_hash.clone();
            btc_header_hash_reversed.reverse();
            let btc_header_hash_str = hex::encode(btc_header_hash_reversed);

            // First try to find header in new_btc_headers
            // NOTE: we need to do this because the new_btc_headers will only be
            // inserted after executing this message as a submessage. This is because
            // of the actor model of CosmWasm contracts.
            // TODO: find a better way to handle this
            let btc_header_info = match new_btc_headers
                .and_then(|headers| headers.headers.iter().find(|h| h.hash == btc_header_hash))
            {
                Some(header) => BtcHeaderResponse::try_from(header)?,
                None => {
                    // If not found in new headers, query from light client
                    query_header_by_hash(deps, &btc_header_hash_str)
                        .map_err(|_| BabylonEpochChainError::BTCHeaderDecodeError {})?
                }
            };
            Ok(btc_header_info)
        })
        .collect::<Result<Vec<BtcHeaderResponse>, BabylonEpochChainError>>()?
        .try_into()
        .map_err(|_| BabylonEpochChainError::BTCHeaderDecodeError {})?;

    // refresh min_height
    // this will be used for checking w-deep later
    let mut min_height: u32 = u32::MAX;
    for btc_header in btc_headers.iter() {
        min_height = min(min_height, btc_header.height);
    }

    // ensure at least 1 given btc headers are finalised, i.e., w-deep
    let tip_height = query_tip_header(deps)
        .map_err(|_| BabylonEpochChainError::BTCHeaderDecodeError {})?
        .height
        + new_btc_headers.map_or(0, |headers| headers.headers.len() as u32);
    if min_height + cfg.checkpoint_finalization_timeout > tip_height {
        return Err(BabylonEpochChainError::BTCHeaderNotDeepEnough {
            w: cfg.checkpoint_finalization_timeout,
        });
    }

    // Convert BtcHeaderResponse array into BlockHeader vec
    let btc_block_headers: [BlockHeader; NUM_BTC_TXS] = btc_headers
        .iter()
        .map(BlockHeader::try_from)
        .collect::<Result<Vec<BlockHeader>, BtcLightclientError>>()?
        .try_into()
        .map_err(|_| BabylonEpochChainError::BTCHeaderDecodeError {})?;

    // verify the checkpoint is submitted, i.e., committed to the 2 BTC headers
    verify_checkpoint_submitted(raw_ckpt, txs_info, &btc_block_headers, &cfg.babylon_tag)
        .map_err(|e| BabylonEpochChainError::CheckpointNotSubmitted { err_msg: e })?;

    // verify the epoch is sealed by its validator set
    verify_epoch_sealed(epoch, raw_ckpt, proof_epoch_sealed)
        .map_err(|e| BabylonEpochChainError::EpochNotSealed { err_msg: e })?;

    // all good
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
    // verify epoch and checkpoint, including
    // - whether the epoch is sealed or not
    // - whether the checkpoint is finalised
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
    // verify epoch and checkpoint, including
    // - whether the epoch/checkpoint are sealed or not
    // - whether the checkpoint is finalised
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
