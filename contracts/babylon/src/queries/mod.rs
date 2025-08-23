use crate::error::{BabylonEpochChainError, ConsumerHeaderChainError, ContractError};
use crate::ibc::IBC_TRANSFER_CHANNEL;
use crate::msg::{
    CheckpointResponse, ConsumerHeaderResponse, ConsumerHeightResponse, EpochResponse,
    TransferInfoResponse,
};
use crate::state::{
    get_base_epoch, get_checkpoint, get_consumer_header, get_epoch, get_last_consumer_header,
    get_last_consumer_height, get_last_finalized_epoch, Config, CONFIG,
};
use cosmwasm_std::{Deps, StdResult};

pub fn config(deps: Deps) -> StdResult<Config> {
    CONFIG.load(deps.storage)
}

pub fn babylon_base_epoch(deps: Deps) -> Result<EpochResponse, BabylonEpochChainError> {
    let epoch = get_base_epoch(deps)?;
    Ok(EpochResponse::from(&epoch))
}

pub fn babylon_last_epoch(deps: Deps) -> Result<EpochResponse, BabylonEpochChainError> {
    let epoch = get_last_finalized_epoch(deps)?;
    Ok(EpochResponse::from(&epoch))
}

pub fn babylon_epoch(
    deps: Deps,
    epoch_number: u64,
) -> Result<EpochResponse, BabylonEpochChainError> {
    let epoch = get_epoch(deps, epoch_number)?;
    Ok(EpochResponse::from(&epoch))
}

pub fn babylon_checkpoint(
    deps: Deps,
    epoch_number: u64,
) -> Result<CheckpointResponse, BabylonEpochChainError> {
    let raw_checkpoint = get_checkpoint(deps, epoch_number)?;
    Ok(CheckpointResponse::from(&raw_checkpoint))
}

pub fn last_consumer_header(
    deps: Deps,
) -> Result<ConsumerHeaderResponse, ConsumerHeaderChainError> {
    let header = get_last_consumer_header(deps)?;
    Ok(ConsumerHeaderResponse::from(&header))
}

pub fn last_consumer_height(
    deps: Deps,
) -> Result<ConsumerHeightResponse, ConsumerHeaderChainError> {
    let height = get_last_consumer_height(deps)?;
    Ok(ConsumerHeightResponse { height })
}

pub(crate) fn consumer_header(
    deps: Deps,
    height: u64,
) -> Result<ConsumerHeaderResponse, ConsumerHeaderChainError> {
    let header = get_consumer_header(deps, height)?;
    Ok(ConsumerHeaderResponse::from(&header))
}

pub(crate) fn transfer_info(deps: Deps) -> Result<TransferInfoResponse, ContractError> {
    let transfer_info = IBC_TRANSFER_CHANNEL.may_load(deps.storage)?;
    Ok(transfer_info)
}
