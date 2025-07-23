use crate::error::ContractError;
use bitcoin::Txid;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{CanonicalAddr, Order, StdResult, Storage, Uint128};
use cw_storage_plus::{Index, IndexList, IndexedMap, KeyDeserialize, MultiIndex};

const DELEGATIONS_KEY: &str = "delegations";
const FP_SUBKEY: &str = "fp";
const STAKER_SUBKEY: &str = "staker";

/// Indexed map for delegations and finality providers.
pub fn delegations<'a>() -> Delegations<'a> {
    Delegations::new(DELEGATIONS_KEY, FP_SUBKEY, STAKER_SUBKEY)
}

/// Single delegation related information - entry per `(staking hash, finality provider public key)`
/// pair, including distribution alignment
#[cw_serde]
pub struct DelegationDistribution {
    /// The delegator's canonical address
    pub staker_addr: CanonicalAddr,
    /// How many satoshis the user stakes in this delegation
    pub stake: u64,
    /// Rewards already withdrawn by this user
    pub withdrawn_funds: Uint128,
}

#[allow(clippy::type_complexity)]
pub struct DelegationIndexes<'a> {
    // Delegations by finality provider's public key and staking hash.
    // Last type param defines the pk deserialization type
    pub rev: MultiIndex<'a, (String, Vec<u8>), DelegationDistribution, (Vec<u8>, String)>,
    // Delegations by staker's (raw, canonical) address and finality provider's public key.
    // Last type param defines the pk deserialization type
    pub staker: MultiIndex<'a, (Vec<u8>, String), DelegationDistribution, (Vec<u8>, String)>,
}

impl IndexList<DelegationDistribution> for DelegationIndexes<'_> {
    fn get_indexes(
        &'_ self,
    ) -> Box<dyn Iterator<Item = &'_ dyn Index<DelegationDistribution>> + '_> {
        let v: Vec<&dyn Index<DelegationDistribution>> = vec![&self.rev, &self.staker];
        Box::new(v.into_iter())
    }
}

pub struct Delegations<'a> {
    pub delegation: IndexedMap<(&'a [u8], &'a str), DelegationDistribution, DelegationIndexes<'a>>,
}

impl Delegations<'_> {
    fn deserialize_pk(pk: &[u8]) -> (Vec<u8>, String) {
        <(Vec<u8>, String)>::from_slice(pk).expect("TODO: why must not fail")
    }

    pub fn new(
        storage_key: &'static str,
        fp_subkey: &'static str,
        staker_subkey: &'static str,
    ) -> Self {
        let indexes = DelegationIndexes {
            rev: MultiIndex::new(
                |pk, _| {
                    let (staking_hash, fp) = Self::deserialize_pk(pk);
                    (fp, staking_hash)
                },
                storage_key,
                fp_subkey,
            ),
            staker: MultiIndex::new(
                |pk, del| {
                    let (_, fp) = Self::deserialize_pk(pk);
                    (del.staker_addr.to_vec(), fp)
                },
                storage_key,
                staker_subkey,
            ),
        };
        let delegations = IndexedMap::new(storage_key, indexes);

        Self {
            delegation: delegations,
        }
    }

    pub fn create_distribution(
        &mut self,
        storage: &mut dyn Storage,
        staking_tx_hash: Txid,
        fp_btc_pk_hex: &str,
        staker_canonical_addr: &CanonicalAddr,
        delegation_stake: u64,
    ) -> Result<(), ContractError> {
        self.delegation
            .update(storage, (staking_tx_hash.as_ref(), fp_btc_pk_hex), |del| {
                match del {
                    Some(_) => Err(ContractError::DelegationToFpAlreadyExists(
                        staking_tx_hash.to_string(),
                        fp_btc_pk_hex.to_string(),
                    )),
                    None => {
                        // Distribution alignment
                        let delegation = DelegationDistribution {
                            staker_addr: staker_canonical_addr.clone(),
                            stake: delegation_stake,
                            withdrawn_funds: Uint128::zero(),
                        };
                        Ok::<_, ContractError>(delegation)
                    }
                }
            })?;
        Ok(())
    }

    pub fn reduce_distribution(
        &mut self,
        storage: &mut dyn Storage,
        staking_tx_hash: Txid,
        fp_pubkey_hex: &str,
        delegation_stake: u64,
    ) -> Result<(), ContractError> {
        self.delegation.update(
            storage,
            (staking_tx_hash.as_ref(), fp_pubkey_hex),
            |del| match del {
                Some(mut del) => {
                    del.stake = del.stake.saturating_sub(delegation_stake);
                    Ok(del)
                }
                None => Err(ContractError::DelegationToFpNotFound(
                    staking_tx_hash.to_string(),
                    fp_pubkey_hex.to_string(),
                )),
            },
        )?;
        Ok(())
    }

    pub fn delegations_by_fp(
        &self,
        storage: &dyn Storage,
        fp: &str,
    ) -> StdResult<Vec<(Vec<u8>, DelegationDistribution)>> {
        self.delegation
            .idx
            .rev
            .sub_prefix(fp.to_string())
            .range(storage, None, None, Order::Ascending)
            .map(|item| {
                let ((hash, _), del) = item?;
                Ok((hash, del))
            })
            .collect::<StdResult<Vec<(Vec<u8>, DelegationDistribution)>>>()
    }
}
