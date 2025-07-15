//! Signing context utilities for BTC staking-related operations.
//!
//! This module is a direct Rust translation of the signing context builder:
//! <https://github.com/babylonlabs-io/babylon/blob/bb2139fdeba412d6704e90f809bbbae6be082fa7/app/signingcontext/builder.go>

use sha2::{Digest, Sha256};

const PROTOCOL_NAME: &str = "btcstaking";
const VERSION_V0: &str = "0";
const FP_POP: &str = "fp_pop";
const FP_RAND_COMMIT: &str = "fp_rand_commit";
const FP_FIN_VOTE: &str = "fp_fin_vote";
const STAKER_POP: &str = "staker_pop";

fn btc_staking_v0_context(operation_tag: &str, chain_id: &str, address: &str) -> String {
    format!("{PROTOCOL_NAME}/{VERSION_V0}/{operation_tag}/{chain_id}/{address}",)
}

/// Returns the hex encoded sha256 hash of the context string
fn hashed_hex_context(context_string: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(context_string.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

/// Returns context string in format: btcstaking/0/fp_pop/{chainId}/{address}
pub fn fp_pop_context_v0(chain_id: &str, address: &str) -> String {
    hashed_hex_context(&btc_staking_v0_context(FP_POP, chain_id, address))
}

/// Returns context string in format: btcstaking/0/fp_rand_commit/{chainId}/{address}
pub fn fp_rand_commit_context_v0(chain_id: &str, address: &str) -> String {
    hashed_hex_context(&btc_staking_v0_context(FP_RAND_COMMIT, chain_id, address))
}

/// Returns context string in format: btcstaking/0/fp_fin_vote/{chainId}/{address}
pub fn fp_fin_vote_context_v0(chain_id: &str, address: &str) -> String {
    hashed_hex_context(&btc_staking_v0_context(FP_FIN_VOTE, chain_id, address))
}

/// Returns context string in format: btcstaking/0/staker_pop/{chainId}/{address}
pub fn staker_pop_context_v0(chain_id: &str, address: &str) -> String {
    hashed_hex_context(&btc_staking_v0_context(STAKER_POP, chain_id, address))
}
