use cosmwasm_std::Order::{Ascending, Descending};
use cosmwasm_std::{Deps, StdResult};
use cw_storage_plus::Bound;

use babylon_apis::finality_api::IndexedBlock;

use crate::error::ContractError;
use crate::msg::{
    ActiveFinalityProvidersResponse, BlocksResponse, EvidenceResponse, FinalityProviderPowerResponse,
    FinalitySignatureResponse, JailedFinalityProvider, JailedFinalityProvidersResponse,
};
use crate::state::config::{Config, Params};
use crate::state::config::{CONFIG, PARAMS};
use crate::state::finality::{get_power_table_at_height, BLOCKS, EVIDENCES, JAIL, SIGNATURES};

pub fn config(deps: Deps) -> StdResult<Config> {
    CONFIG.load(deps.storage)
}

pub fn params(deps: Deps) -> StdResult<Params> {
    PARAMS.load(deps.storage)
}

// Settings for pagination
const MAX_LIMIT: u32 = 30;
const DEFAULT_LIMIT: u32 = 10;

pub fn finality_signature(
    deps: Deps,
    btc_pk_hex: String,
    height: u64,
) -> StdResult<FinalitySignatureResponse> {
    match SIGNATURES.may_load(deps.storage, (height, &btc_pk_hex))? {
        Some(sig) => Ok(FinalitySignatureResponse { signature: sig }),
        None => Ok(FinalitySignatureResponse {
            signature: Vec::new(),
        }), // Empty signature response
    }
}

pub fn block(deps: Deps, height: u64) -> StdResult<IndexedBlock> {
    BLOCKS.load(deps.storage, height)
}

/// Get list of blocks.
/// `start_after`: The height to start after, if any.
/// `finalised`: List only finalised blocks if true, otherwise list all blocks.
/// `reverse`: List in descending order if present and true, otherwise in ascending order.
pub fn blocks(
    deps: Deps,
    start_after: Option<u64>,
    limit: Option<u32>,
    finalised: Option<bool>,
    reverse: Option<bool>,
) -> Result<BlocksResponse, ContractError> {
    let finalised = finalised.unwrap_or_default();
    let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
    let start_after = start_after.map(Bound::exclusive);
    let (start, end, order) = if reverse.unwrap_or(false) {
        (None, start_after, Descending)
    } else {
        (start_after, None, Ascending)
    };
    let blocks = BLOCKS
        .range_raw(deps.storage, start, end, order)
        .filter(|item| {
            if let Ok((_, block)) = item {
                !finalised || block.finalized
            } else {
                true // don't filter errors
            }
        })
        .take(limit)
        .map(|item| item.map(|(_, v)| v))
        .collect::<Result<Vec<IndexedBlock>, _>>()?;
    Ok(BlocksResponse { blocks })
}

pub fn evidence(deps: Deps, btc_pk_hex: String, height: u64) -> StdResult<EvidenceResponse> {
    let evidence = EVIDENCES.may_load(deps.storage, (&btc_pk_hex, height))?;
    Ok(EvidenceResponse { evidence })
}

pub fn jailed_finality_providers(
    deps: Deps,
    start_after: Option<String>,
    limit: Option<u32>,
) -> Result<JailedFinalityProvidersResponse, ContractError> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
    let start_after = start_after.as_ref().map(|s| Bound::exclusive(&**s));
    let jailed_finality_providers = JAIL
        .range(deps.storage, start_after, None, Ascending)
        .take(limit)
        .map(|item| {
            item.map(|(k, v)| JailedFinalityProvider {
                btc_pk_hex: k,
                jailed_until: v,
            })
        })
        .collect::<Result<Vec<JailedFinalityProvider>, _>>()?;
    Ok(JailedFinalityProvidersResponse {
        jailed_finality_providers,
    })
}

pub fn active_finality_providers(
    deps: Deps,
    height: u64,
) -> Result<ActiveFinalityProvidersResponse, ContractError> {
    let active_fps = get_power_table_at_height(deps.storage, height)?;

    Ok(ActiveFinalityProvidersResponse {
        active_finality_providers: active_fps,
    })
}

pub fn finality_provider_power(
    deps: Deps,
    btc_pk_hex: String,
    height: u64,
) -> Result<FinalityProviderPowerResponse, ContractError> {
    let power_table = get_power_table_at_height(deps.storage, height)?;
    let power = power_table.get(&btc_pk_hex).copied().unwrap_or(0);

    Ok(FinalityProviderPowerResponse { power })
}
