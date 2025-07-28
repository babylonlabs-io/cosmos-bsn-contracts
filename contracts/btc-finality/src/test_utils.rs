use crate::state::config::Params;

// TODO: Support the other param overrides
// https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/252
pub fn finality_params(missed_blocks_window: Option<u64>) -> Params {
    let missed_blocks_window = missed_blocks_window.unwrap_or(250);
    Params {
        max_active_finality_providers: 100,
        min_pub_rand: 1,
        epoch_length: 50,
        missed_blocks_window,
        jail_duration: 86400,
    }
}
