use crate::error::ContractError;
use crate::msg::{
    ActiveFinalityProvidersResponse, BlocksResponse, EvidenceResponse,
    FinalityProviderPowerResponse, FinalityProviderPowerBatchResponse, FinalitySignatureResponse,
    JailedFinalityProvider, JailedFinalityProvidersResponse, SigningInfoResponse, VotesResponse,
};
use crate::state::finality::{
    get_last_signed_height, get_power_table_at_height, BLOCKS, EVIDENCES, FP_START_HEIGHT, JAIL,
    NEXT_HEIGHT, SIGNATURES,
};
use babylon_apis::finality_api::IndexedBlock;
use cosmwasm_std::Order::{Ascending, Descending};
use cosmwasm_std::{Deps, StdError, StdResult};
use cw_storage_plus::Bound;

// Settings for pagination
const MAX_LIMIT: u32 = 30;
const DEFAULT_LIMIT: u32 = 10;

// Maximum number of heights allowed in batch queries
const MAX_HEIGHTS_LIMIT: usize = 100;

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

pub fn finality_provider_power_batch(
    deps: Deps,
    btc_pk_hex: String,
    heights: Vec<u64>,
) -> Result<FinalityProviderPowerBatchResponse, ContractError> {
    if heights.len() > MAX_HEIGHTS_LIMIT {
        return Err(ContractError::Std(StdError::generic_err(format!(
            "Too many heights requested: {}. Maximum allowed: {}",
            heights.len(),
            MAX_HEIGHTS_LIMIT
        ))));
    }

    let mut powers = Vec::with_capacity(heights.len());
    
    for height in heights {
        let power_table = get_power_table_at_height(deps.storage, height)?;
        let power = power_table.get(&btc_pk_hex).copied().unwrap_or(0);
        powers.push((height, power));
    }

    Ok(FinalityProviderPowerBatchResponse { powers })
}

pub fn votes(deps: Deps, height: u64) -> Result<VotesResponse, ContractError> {
    let btc_pks = SIGNATURES
        .prefix(height)
        .keys(deps.storage, None, None, Ascending)
        .collect::<StdResult<Vec<_>>>()?;
    Ok(VotesResponse { btc_pks })
}

pub fn signing_info(
    deps: Deps,
    fp_btc_pk_hex: String,
) -> Result<Option<SigningInfoResponse>, ContractError> {
    let Some(start_height) = FP_START_HEIGHT.may_load(deps.storage, &fp_btc_pk_hex)? else {
        // Can not find the FP entry for the given fp_btc_pk_hex.
        return Ok(None);
    };
    let last_signed_height = get_last_signed_height(deps.storage, &fp_btc_pk_hex)?
        .expect("Must be Some as start_height exists");
    let jailed_until = JAIL.may_load(deps.storage, &fp_btc_pk_hex)?;
    Ok(Some(SigningInfoResponse {
        fp_btc_pk_hex,
        start_height,
        last_signed_height,
        jailed_until,
    }))
}

pub fn last_finalized_height(deps: Deps) -> Result<Option<u64>, ContractError> {
    // NEXT_HEIGHT represents the next block to be processed for finalization
    // So the last finalized height is NEXT_HEIGHT - 1
    match NEXT_HEIGHT.may_load(deps.storage)? {
        Some(next_height) => {
            if next_height > 0 {
                Ok(Some(next_height - 1))
            } else {
                // Edge case: NEXT_HEIGHT is 0, meaning no blocks have been finalized yet
                Ok(None)
            }
        }
        None => Ok(None), // NEXT_HEIGHT not set yet, no blocks processed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::finality::set_voting_power_table;
    use cosmwasm_std::testing::mock_dependencies;
    use std::collections::HashMap;

    #[test]
    fn test_finality_provider_power_batch() {
        let mut deps = mock_dependencies();
        let btc_pk_hex = "test_fp".to_string();

        // Set up power tables for different heights
        let mut power_table_100 = HashMap::new();
        power_table_100.insert(btc_pk_hex.clone(), 1000u64);
        set_voting_power_table(deps.as_mut().storage, 100, power_table_100).unwrap();

        let mut power_table_200 = HashMap::new();
        power_table_200.insert(btc_pk_hex.clone(), 2000u64);
        set_voting_power_table(deps.as_mut().storage, 200, power_table_200).unwrap();

        let mut power_table_300 = HashMap::new();
        power_table_300.insert(btc_pk_hex.clone(), 3000u64);
        set_voting_power_table(deps.as_mut().storage, 300, power_table_300).unwrap();

        // Test successful batch query
        let heights = vec![100, 200, 300];
        let result = finality_provider_power_batch(deps.as_ref(), btc_pk_hex.clone(), heights).unwrap();
        
        assert_eq!(result.powers.len(), 3);
        assert_eq!(result.powers[0], (100, 1000));
        assert_eq!(result.powers[1], (200, 2000));
        assert_eq!(result.powers[2], (300, 3000));

        // Test with missing height (should return 0 power)
        let heights_with_missing = vec![100, 150, 200];
        let result = finality_provider_power_batch(deps.as_ref(), btc_pk_hex.clone(), heights_with_missing).unwrap();
        
        assert_eq!(result.powers.len(), 3);
        assert_eq!(result.powers[0], (100, 1000));
        assert_eq!(result.powers[1], (150, 0)); // Missing height
        assert_eq!(result.powers[2], (200, 2000));

        // Test with unknown FP (should return 0 power for all heights)
        let unknown_fp = "unknown_fp".to_string();
        let heights = vec![100, 200, 300];
        let result = finality_provider_power_batch(deps.as_ref(), unknown_fp, heights).unwrap();
        
        assert_eq!(result.powers.len(), 3);
        assert_eq!(result.powers[0], (100, 0));
        assert_eq!(result.powers[1], (200, 0));
        assert_eq!(result.powers[2], (300, 0));
    }

    #[test]
    fn test_finality_provider_power_batch_limit() {
        let deps = mock_dependencies();
        let btc_pk_hex = "test_fp".to_string();

        // Test exceeding the limit
        let too_many_heights: Vec<u64> = (0..=MAX_HEIGHTS_LIMIT as u64).collect();
        let result = finality_provider_power_batch(deps.as_ref(), btc_pk_hex.clone(), too_many_heights);
        
        match result {
            Err(ContractError::Std(std_err)) => {
                let msg = std_err.to_string();
                assert!(msg.contains("Too many heights requested"));
                assert!(msg.contains(&format!("{}", MAX_HEIGHTS_LIMIT + 1)));
                assert!(msg.contains(&format!("Maximum allowed: {}", MAX_HEIGHTS_LIMIT)));
            }
            _ => panic!("Expected Std error with generic message"),
        }

        // Test at the limit (should succeed)
        let max_heights: Vec<u64> = (0..MAX_HEIGHTS_LIMIT as u64).collect();
        let result = finality_provider_power_batch(deps.as_ref(), btc_pk_hex, max_heights);
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap().powers.len(), MAX_HEIGHTS_LIMIT);
    }

    #[test]
    fn test_finality_provider_power_batch_empty() {
        let deps = mock_dependencies();
        let btc_pk_hex = "test_fp".to_string();

        // Test with empty heights vector
        let empty_heights = vec![];
        let result = finality_provider_power_batch(deps.as_ref(), btc_pk_hex, empty_heights).unwrap();
        
        assert_eq!(result.powers.len(), 0);
    }
}
