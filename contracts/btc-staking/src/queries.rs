use crate::error::ContractError;
use crate::msg::{
    BtcDelegationsResponse, DelegationsByFPResponse, FinalityProviderInfo,
    FinalityProvidersByTotalActiveSatsResponse, FinalityProvidersResponse,
};
use crate::state::staking::{
    get_fp_state_map, BtcDelegation, FinalityProviderState, BTC_DELEGATIONS, FPS, FP_DELEGATIONS,
};
use babylon_apis::btc_staking_api::FinalityProvider;
use bitcoin::hashes::Hash;
use bitcoin::Txid;
use cosmwasm_std::Order::Descending;
use cosmwasm_std::{Deps, Env, Order, StdResult};
use cw_storage_plus::Bound;
use std::str::FromStr;

pub fn finality_provider(deps: Deps, btc_pk_hex: String) -> StdResult<FinalityProvider> {
    FPS.load(deps.storage, &btc_pk_hex)
}

// Settings for pagination
const MAX_LIMIT: u32 = 30;
const DEFAULT_LIMIT: u32 = 10;

pub fn finality_providers(
    deps: Deps,
    start_after: Option<String>,
    limit: Option<u32>,
) -> StdResult<FinalityProvidersResponse> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
    let start_after = start_after.as_ref().map(|s| Bound::exclusive(&**s));
    let fps = FPS
        .range_raw(deps.storage, start_after, None, Order::Ascending)
        .take(limit)
        .map(|item| item.map(|(_, v)| v))
        .collect::<StdResult<Vec<FinalityProvider>>>()?;
    Ok(FinalityProvidersResponse { fps })
}

/// Get the delegation info by staking tx hash.
///
/// # Arguments
///
/// - `staking_tx_hash_hex`: The (reversed) staking tx hash, in hex
pub fn delegation(deps: Deps, staking_tx_hash_hex: String) -> Result<BtcDelegation, ContractError> {
    let staking_tx_hash = Txid::from_str(&staking_tx_hash_hex)?;
    Ok(BTC_DELEGATIONS.load(deps.storage, staking_tx_hash.as_ref())?)
}

/// Get list of delegations.
///
/// # Arguments
///
/// - `start_after`: The (reversed) associated staking tx hash of the delegation in hex, if provided.
/// - `active`: List only active delegations if true, otherwise list all delegations.
pub fn delegations(
    deps: Deps,
    start_after: Option<String>,
    limit: Option<u32>,
    active: Option<bool>,
) -> Result<BtcDelegationsResponse, ContractError> {
    let active = active.unwrap_or_default();
    let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
    let start_after = start_after
        .as_ref()
        .map(|s| Txid::from_str(s))
        .transpose()?;
    let start_after = start_after.as_ref().map(|s| s.as_ref());
    let start_after = start_after.map(Bound::exclusive);
    let delegations = BTC_DELEGATIONS
        .range_raw(deps.storage, start_after, None, Order::Ascending)
        .filter(|item| {
            if let Ok((_, del)) = item {
                !active || del.is_active()
            } else {
                true // don't filter errors
            }
        })
        .take(limit)
        .map(|item| item.map(|(_, v)| v))
        .collect::<Result<Vec<BtcDelegation>, _>>()?;
    Ok(BtcDelegationsResponse { delegations })
}

/// Delegation hashes by FP query.
///
/// # Arguments
///
/// - `btc_pk_hex`: The BTC public key of the finality provider, in hex
pub fn delegations_by_fp(
    deps: Deps,
    btc_pk_hex: String,
) -> Result<DelegationsByFPResponse, ContractError> {
    let tx_hashes = FP_DELEGATIONS.load(deps.storage, &btc_pk_hex)?;
    let tx_hashes = tx_hashes
        .iter()
        .map(|h| Ok(Txid::from_slice(h)?.to_string()))
        .collect::<Result<_, ContractError>>()?;
    Ok(DelegationsByFPResponse { hashes: tx_hashes })
}

/// Active / all delegations by FP convenience query.
///
/// This is an alternative to `delegations_by_fp` that returns the actual delegations instead of
/// just the hashes.
///
/// `btc_pk_hex`: The BTC public key of the finality provider, in hex.
/// `active` is a filter to return only active delegations
pub fn active_delegations_by_fp(
    deps: Deps,
    btc_pk_hex: String,
    active: bool,
) -> Result<BtcDelegationsResponse, ContractError> {
    let tx_hashes = FP_DELEGATIONS.load(deps.storage, &btc_pk_hex)?;
    let delegations = tx_hashes
        .iter()
        .map(|h| Ok(BTC_DELEGATIONS.load(deps.storage, Txid::from_slice(h)?.as_ref())?))
        .filter(|item| {
            if let Ok(del) = item {
                !active || del.is_active()
            } else {
                true // don't filter errors
            }
        })
        .collect::<Result<Vec<_>, ContractError>>()?;
    Ok(BtcDelegationsResponse { delegations })
}

pub fn finality_provider_info(
    deps: Deps,
    env: &Env,
    btc_pk_hex: String,
    height: Option<u64>,
) -> Result<FinalityProviderInfo, ContractError> {
    let fp_state = match height {
        Some(h) => get_fp_state_map().may_load_at_height(deps.storage, &btc_pk_hex, h),
        None => get_fp_state_map().may_load(deps.storage, &btc_pk_hex),
    }?
    .ok_or_else(|| ContractError::FinalityProviderNotFound(btc_pk_hex.clone()))?;

    Ok(FinalityProviderInfo {
        btc_pk_hex,
        total_active_sats: fp_state.total_active_sats,
        slashed: fp_state.slashed,
        height: height.unwrap_or(env.block.height),
    })
}

pub fn finality_providers_by_total_active_sats(
    deps: Deps,
    env: &Env,
    start_after: Option<FinalityProviderInfo>,
    limit: Option<u32>,
) -> StdResult<FinalityProvidersByTotalActiveSatsResponse> {
    let limit = limit.unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT) as usize;
    let start =
        start_after.map(|fpp| Bound::exclusive((fpp.total_active_sats, fpp.btc_pk_hex.clone())));
    let fps = get_fp_state_map()
        .idx
        .power
        .range(deps.storage, None, start, Descending)
        .take(limit)
        .map(|item| {
            let (
                btc_pk_hex,
                FinalityProviderState {
                    total_active_sats,
                    slashed,
                },
            ) = item?;
            Ok(FinalityProviderInfo {
                btc_pk_hex,
                total_active_sats,
                slashed,
                height: env.block.height,
            })
        })
        .collect::<StdResult<Vec<_>>>()?;

    Ok(FinalityProvidersByTotalActiveSatsResponse { fps })
}

#[cfg(test)]
mod tests {
    use crate::contract::{execute, instantiate};
    use crate::error::ContractError;
    use crate::msg::{ExecuteMsg, FinalityProviderInfo, InstantiateMsg};
    use crate::staking::tests::staking_tx_hash;
    use crate::state::staking::{BtcDelegation, FinalityProviderState, FP_STATE_KEY};
    use babylon_apis::btc_staking_api::{FinalityProvider, UnbondedBtcDelegation};
    use babylon_test_utils::{create_new_finality_provider, get_btc_del_unbonding_sig};
    use cosmwasm_std::storage_keys::namespace_with_key;
    use cosmwasm_std::testing::message_info;
    use cosmwasm_std::testing::{mock_dependencies, mock_env};
    use cosmwasm_std::StdError::NotFound;
    use cosmwasm_std::{from_json, Env, Storage};

    const CREATOR: &str = "creator";

    fn mock_env_height(height: u64) -> Env {
        let mut env = mock_env();
        env.block.height = height;

        env
    }

    // Sort delegations by staking tx hash
    fn sort_delegations(dels: &[BtcDelegation]) -> Vec<BtcDelegation> {
        let mut dels = dels.to_vec();
        dels.sort_by_key(staking_tx_hash);
        dels
    }

    #[test]
    fn test_finality_providers() {
        let mut deps = mock_dependencies();
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        instantiate(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            InstantiateMsg::default(),
        )
        .unwrap();

        // Add a couple finality providers
        let new_fp1 = create_new_finality_provider(1);
        let new_fp2 = create_new_finality_provider(2);

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![new_fp1.clone(), new_fp2.clone()],
            active_del: vec![],
            unbonded_del: vec![],
        };

        let _res = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Query finality providers
        let fps = crate::queries::finality_providers(deps.as_ref(), None, None)
            .unwrap()
            .fps;

        let fp1 = FinalityProvider::from(&new_fp1);
        let fp2 = FinalityProvider::from(&new_fp2);
        let expected_fps = vec![fp1.clone(), fp2.clone()];
        assert_eq!(fps.len(), expected_fps.len());
        for fp in fps {
            assert!(expected_fps.contains(&fp));
        }

        // Query finality providers with limit
        let fps = crate::queries::finality_providers(deps.as_ref(), None, Some(1))
            .unwrap()
            .fps;
        assert_eq!(fps.len(), 1);
        assert!(fps[0] == fp1 || fps[0] == fp2);

        // Query finality providers with start_after
        let fp_pk = fps[0].btc_pk_hex.clone();
        let fps = crate::queries::finality_providers(deps.as_ref(), Some(fp_pk), None)
            .unwrap()
            .fps;
        assert_eq!(fps.len(), 1);
        assert!(fps[0] == fp1 || fps[0] == fp2);
    }

    #[test]
    fn test_delegations() {
        let mut deps = mock_dependencies();
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        instantiate(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            InstantiateMsg::default(),
        )
        .unwrap();

        // Add a couple finality providers
        let new_fp1 = create_new_finality_provider(1);
        let new_fp2 = create_new_finality_provider(2);

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![new_fp1.clone(), new_fp2.clone()],
            active_del: vec![],
            unbonded_del: vec![],
        };

        let _res = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Add a couple delegations
        let del1 = babylon_test_utils::get_derived_btc_delegation(1, &[1]);
        let del2 = babylon_test_utils::get_derived_btc_delegation(2, &[2]);

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![],
            active_del: vec![del1.clone(), del2.clone()],
            unbonded_del: vec![],
        };

        execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Query delegations
        let dels = crate::queries::delegations(deps.as_ref(), None, None, None)
            .unwrap()
            .delegations;

        assert_eq!(dels.len(), 2);
        // Sort original delegations by staking tx hash (to compare with the query result)
        let sorted_dels = sort_delegations(&[del1.into(), del2.into()]);
        assert_eq!(dels[0], sorted_dels[0]);
        assert_eq!(dels[1], sorted_dels[1]);

        // Query delegations with limit
        let dels = crate::queries::delegations(deps.as_ref(), None, Some(1), None)
            .unwrap()
            .delegations;

        assert_eq!(dels.len(), 1);
        assert_eq!(dels[0], sorted_dels[0]);

        // Query delegations with start_after
        let staking_tx_hash_hex = staking_tx_hash(&sorted_dels[0]).to_string();
        let dels =
            crate::queries::delegations(deps.as_ref(), Some(staking_tx_hash_hex), None, None)
                .unwrap()
                .delegations;

        assert_eq!(dels.len(), 1);
        assert_eq!(dels[0], sorted_dels[1]);
    }

    #[test]
    fn test_active_delegations() {
        let mut deps = mock_dependencies();
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        instantiate(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            InstantiateMsg::default(),
        )
        .unwrap();

        // Add a finality provider
        let new_fp1 = create_new_finality_provider(1);

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![new_fp1.clone()],
            active_del: vec![],
            unbonded_del: vec![],
        };

        let _res = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Add a couple delegations
        let del1 = babylon_test_utils::get_derived_btc_delegation(1, &[1]);
        let del2 = babylon_test_utils::get_derived_btc_delegation(2, &[1]);

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![],
            active_del: vec![del1.clone(), del2.clone()],
            unbonded_del: vec![],
        };

        execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Query only active delegations
        let dels = crate::queries::delegations(deps.as_ref(), None, None, Some(true))
            .unwrap()
            .delegations;
        assert_eq!(dels.len(), 2);
        // Sort original delegations by staking tx hash (to compare with the query result)
        let sorted_dels = sort_delegations(&[del1.clone().into(), del2.clone().into()]);
        assert_eq!(dels[0], sorted_dels[0]);
        assert_eq!(dels[1], sorted_dels[1]);

        // Unbond the second delegation
        // Compute staking tx hash
        let staking_tx_hash_hex = staking_tx_hash(&del2.into()).to_string();
        let unbonding_sig = babylon_test_utils::get_btc_del_unbonding_sig(2, &[1]);
        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![],
            active_del: vec![],
            unbonded_del: vec![UnbondedBtcDelegation {
                staking_tx_hash: staking_tx_hash_hex,
                unbonding_tx_sig: unbonding_sig.to_bytes().into(),
            }],
        };
        execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Query only active delegations
        let dels = crate::queries::delegations(deps.as_ref(), None, None, Some(true))
            .unwrap()
            .delegations;
        assert_eq!(dels.len(), 1);
        assert_eq!(dels[0], del1.into());

        // Query all delegations (with active set to false)
        let dels = crate::queries::delegations(deps.as_ref(), None, None, Some(false))
            .unwrap()
            .delegations;
        assert_eq!(dels.len(), 2);

        // Query all delegations (without active set)
        let dels = crate::queries::delegations(deps.as_ref(), None, None, None)
            .unwrap()
            .delegations;
        assert_eq!(dels.len(), 2);
    }

    #[test]
    fn test_delegations_by_fp() {
        let mut deps = mock_dependencies();
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        instantiate(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            InstantiateMsg::default(),
        )
        .unwrap();

        // Add a couple finality providers
        let new_fp1 = create_new_finality_provider(1);
        let fp1_pk = new_fp1.btc_pk_hex.clone();
        let new_fp2 = create_new_finality_provider(2);
        let fp2_pk = new_fp2.btc_pk_hex.clone();

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![new_fp1.clone(), new_fp2.clone()],
            active_del: vec![],
            unbonded_del: vec![],
        };

        let _res = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Add a couple delegations
        let del1 = babylon_test_utils::get_derived_btc_delegation(1, &[1]);
        let del2 = babylon_test_utils::get_derived_btc_delegation(2, &[2]);

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![],
            active_del: vec![del1.clone(), del2.clone()],
            unbonded_del: vec![],
        };

        execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Query delegations by finality provider
        let dels1 = crate::queries::delegations_by_fp(deps.as_ref(), fp1_pk.clone())
            .unwrap()
            .hashes;
        assert_eq!(dels1.len(), 1);
        let dels2 = crate::queries::delegations_by_fp(deps.as_ref(), fp2_pk.clone())
            .unwrap()
            .hashes;
        assert_eq!(dels2.len(), 1);
        assert_ne!(dels1[0], dels2[0]);
        let err = crate::queries::delegations_by_fp(deps.as_ref(), "f3".to_string()).unwrap_err();
        assert!(matches!(err, ContractError::Std(NotFound { .. })));
    }

    #[test]
    fn test_active_delegations_by_fp() {
        let mut deps = mock_dependencies();
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        instantiate(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            InstantiateMsg::default(),
        )
        .unwrap();

        // Add a finality provider
        let new_fp1 = create_new_finality_provider(1);
        let fp1_pk = new_fp1.btc_pk_hex.clone();

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![new_fp1.clone()],
            active_del: vec![],
            unbonded_del: vec![],
        };

        let _res = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Add a couple delegations
        let mut del1 = babylon_test_utils::get_derived_btc_delegation(1, &[1]);
        let mut del2 = babylon_test_utils::get_derived_btc_delegation(2, &[1]);

        // Adjust staking amounts
        del1.total_sat = 100;
        del2.total_sat = 200;

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![],
            active_del: vec![del1.clone(), del2.clone()],
            unbonded_del: vec![],
        };

        execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Query all delegations by finality provider
        let dels1 = crate::queries::active_delegations_by_fp(deps.as_ref(), fp1_pk.clone(), false)
            .unwrap()
            .delegations;
        assert_eq!(dels1.len(), 2);

        // Query active delegations by finality provider
        let dels1 = crate::queries::active_delegations_by_fp(deps.as_ref(), fp1_pk.clone(), true)
            .unwrap()
            .delegations;
        assert_eq!(dels1.len(), 2);

        // Unbond the first delegation
        // Compute staking tx hash
        let staking_tx_hash_hex = staking_tx_hash(&del1.into()).to_string();
        let unbonding_sig = get_btc_del_unbonding_sig(1, &[1]);
        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![],
            active_del: vec![],
            unbonded_del: vec![UnbondedBtcDelegation {
                staking_tx_hash: staking_tx_hash_hex,
                unbonding_tx_sig: unbonding_sig.to_bytes().into(),
            }],
        };
        execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Query all delegations by finality provider
        let dels1 = crate::queries::active_delegations_by_fp(deps.as_ref(), fp1_pk.clone(), false)
            .unwrap()
            .delegations;
        assert_eq!(dels1.len(), 2);

        // Query active delegations by finality provider
        let dels1 = crate::queries::active_delegations_by_fp(deps.as_ref(), fp1_pk.clone(), true)
            .unwrap()
            .delegations;
        assert_eq!(dels1.len(), 1);
        let err = crate::queries::active_delegations_by_fp(deps.as_ref(), "f2".to_string(), false)
            .unwrap_err();
        assert!(matches!(err, ContractError::Std(NotFound { .. })));
    }

    #[test]
    fn test_fp_info() {
        let mut deps = mock_dependencies();
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        let initial_env = mock_env_height(10);

        instantiate(
            deps.as_mut(),
            initial_env.clone(),
            info.clone(),
            InstantiateMsg::default(),
        )
        .unwrap();

        // Add a finality provider
        let new_fp1 = create_new_finality_provider(1);
        let fp1_pk = new_fp1.btc_pk_hex.clone();

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![new_fp1.clone()],
            active_del: vec![],
            unbonded_del: vec![],
        };

        let _res = execute(deps.as_mut(), initial_env, info.clone(), msg).unwrap();

        // Add a couple delegations
        let mut del1 = babylon_test_utils::get_derived_btc_delegation(1, &[1]);
        let mut del2 = babylon_test_utils::get_derived_btc_delegation(2, &[1]);

        // Adjust staking amounts
        del1.total_sat = 100;
        del2.total_sat = 150;

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![],
            active_del: vec![del1.clone(), del2.clone()],
            unbonded_del: vec![],
        };

        execute(deps.as_mut(), mock_env_height(11), info.clone(), msg).unwrap();

        // Query finality provider info
        let fp = crate::queries::finality_provider_info(
            deps.as_ref(),
            &mock_env_height(11),
            fp1_pk.clone(),
            None,
        )
        .unwrap();
        assert_eq!(
            fp,
            FinalityProviderInfo {
                btc_pk_hex: fp1_pk.clone(),
                total_active_sats: 250,
                slashed: false,
                height: 11,
            }
        );

        // Query finality provider info with same height as execute call
        let fp = crate::queries::finality_provider_info(
            deps.as_ref(),
            &mock_env_height(11),
            fp1_pk.clone(),
            Some(11),
        )
        .unwrap();
        assert_eq!(
            fp,
            FinalityProviderInfo {
                btc_pk_hex: fp1_pk.clone(),
                total_active_sats: 0, // Historical data is not checkpoint yet
                slashed: false,
                height: 11,
            }
        );

        // Query finality provider info with past height as execute call
        let fp = crate::queries::finality_provider_info(
            deps.as_ref(),
            &mock_env_height(11),
            fp1_pk.clone(),
            Some(12),
        )
        .unwrap();
        assert_eq!(
            fp,
            FinalityProviderInfo {
                btc_pk_hex: fp1_pk.clone(),
                total_active_sats: 250,
                slashed: false,
                height: 12,
            }
        );

        // Query finality provider info with some larger height
        let fp = crate::queries::finality_provider_info(
            deps.as_ref(),
            &mock_env_height(11),
            fp1_pk.clone(),
            Some(1000),
        )
        .unwrap();
        assert_eq!(
            fp,
            FinalityProviderInfo {
                btc_pk_hex: fp1_pk.clone(),
                total_active_sats: 250,
                slashed: false,
                height: 1000,
            }
        );

        // Query finality provider info for a non-existent FP
        let non_existent_fp = "010203040506".to_string();
        let result = crate::queries::finality_provider_info(
            deps.as_ref(),
            &mock_env_height(11),
            non_existent_fp.clone(),
            None,
        );

        // Assert that the result is a FinalityProviderNotFound error
        assert!(matches!(
            result,
            Err(ContractError::FinalityProviderNotFound(pk)) if pk == non_existent_fp
        ));
    }

    #[test]
    fn test_fp_info_raw_query() {
        let mut deps = mock_dependencies();
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        instantiate(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            InstantiateMsg::default(),
        )
        .unwrap();

        // Add a finality provider
        let new_fp1 = create_new_finality_provider(1);
        let fp1_pk = new_fp1.btc_pk_hex.clone();

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![new_fp1.clone()],
            active_del: vec![],
            unbonded_del: vec![],
        };

        let _res = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Add a delegation
        let mut del1 = babylon_test_utils::get_derived_btc_delegation(1, &[1]);
        // Adjust staking amount
        del1.total_sat = 100;

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![],
            active_del: vec![del1.clone()],
            unbonded_del: vec![],
        };

        execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Build raw key
        let prefixed_key = namespace_with_key(&[FP_STATE_KEY.as_bytes()], fp1_pk.as_bytes());
        // Read directly from storage
        let fp_state_raw = deps.storage.get(&prefixed_key).unwrap();
        // Deserialize result
        let fp_state: FinalityProviderState = from_json(fp_state_raw).unwrap();

        assert_eq!(fp_state.total_active_sats, 100);
    }

    #[test]
    fn test_fps_by_total_active_sats() {
        let mut deps = mock_dependencies();
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);

        instantiate(
            deps.as_mut(),
            mock_env(),
            info.clone(),
            InstantiateMsg::default(),
        )
        .unwrap();

        // Add a couple finality providers
        let new_fp1 = create_new_finality_provider(1);
        let fp1_pk = new_fp1.btc_pk_hex.clone();
        let new_fp2 = create_new_finality_provider(2);
        let fp2_pk = new_fp2.btc_pk_hex.clone();
        let new_fp3 = create_new_finality_provider(3);
        let fp3_pk = new_fp3.btc_pk_hex.clone();

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![new_fp1.clone(), new_fp2.clone(), new_fp3.clone()],
            active_del: vec![],
            unbonded_del: vec![],
        };

        let _res = execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Add some delegations
        let mut del1 = babylon_test_utils::get_derived_btc_delegation(1, &[1, 3]);
        let mut del2 = babylon_test_utils::get_derived_btc_delegation(2, &[2]);
        let mut del3 = babylon_test_utils::get_derived_btc_delegation(3, &[2]);

        // Adjust staking amounts
        del1.total_sat = 100;
        del2.total_sat = 150;
        del3.total_sat = 75;

        let msg = ExecuteMsg::BtcStaking {
            new_fp: vec![],
            active_del: vec![del1.clone(), del2.clone(), del3],
            unbonded_del: vec![],
        };

        execute(deps.as_mut(), mock_env(), info.clone(), msg).unwrap();

        // Query finality providers by total active sats
        let fps = crate::queries::finality_providers_by_total_active_sats(
            deps.as_ref(),
            &mock_env(),
            None,
            None,
        )
        .unwrap()
        .fps;
        assert_eq!(fps.len(), 3);
        assert_eq!(fps[0], {
            FinalityProviderInfo {
                btc_pk_hex: fp2_pk.clone(),
                total_active_sats: 225,
                slashed: false,
                height: mock_env().block.height,
            }
        });
        // fp1 and fp3 can be in arbitrary order
        let fp1_info = FinalityProviderInfo {
            btc_pk_hex: fp1_pk.clone(),
            total_active_sats: 100,
            slashed: false,
            height: mock_env().block.height,
        };
        let fp3_info = FinalityProviderInfo {
            btc_pk_hex: fp3_pk.clone(),
            total_active_sats: 100,
            slashed: false,
            height: mock_env().block.height,
        };
        assert!(
            (fps[1] == fp1_info && fps[2] == fp3_info)
                || (fps[1] == fp3_info && fps[2] == fp1_info)
        );

        // Query finality providers power with limit
        let fps = crate::queries::finality_providers_by_total_active_sats(
            deps.as_ref(),
            &mock_env(),
            None,
            Some(2),
        )
        .unwrap()
        .fps;
        assert_eq!(fps.len(), 2);
        assert_eq!(fps[0], {
            FinalityProviderInfo {
                btc_pk_hex: fp2_pk.clone(),
                total_active_sats: 225,
                slashed: false,
                height: mock_env().block.height,
            }
        });
        assert!(fps[1] == fp1_info || fps[1] == fp3_info);

        // Query finality providers power with start_after
        let fps = crate::queries::finality_providers_by_total_active_sats(
            deps.as_ref(),
            &mock_env(),
            Some(fps[1].clone()),
            None,
        )
        .unwrap()
        .fps;
        assert_eq!(fps.len(), 1);
        assert!(fps[0] == fp1_info || fps[0] == fp3_info);
    }
}
