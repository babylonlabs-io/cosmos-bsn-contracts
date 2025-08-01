// Adapted from Tgrade's poe-contracts/packages/utils/src/member_indexes.rs
use crate::state::staking::FinalityProviderState;
use cw_storage_plus::{Index, IndexList, MultiIndex};

pub struct FinalityProviderIndexes<'a> {
    // Power (multi-)index (deserializing the (hidden) pk to String)
    pub power: MultiIndex<'a, u64, FinalityProviderState, String>,
}

impl IndexList<FinalityProviderState> for FinalityProviderIndexes<'_> {
    fn get_indexes(
        &'_ self,
    ) -> Box<dyn Iterator<Item = &'_ dyn Index<FinalityProviderState>> + '_> {
        let v: Vec<&dyn Index<FinalityProviderState>> = vec![&self.power];
        Box::new(v.into_iter())
    }
}
