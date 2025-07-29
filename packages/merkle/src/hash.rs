//! Translation of https://github.com/cometbft/cometbft/blob/v0.38.17/crypto/merkle/hash.go

use sha2::{Digest, Sha256};

const LEAF_PREFIX: u8 = 0;
const INNER_PREFIX: u8 = 1;

pub(crate) fn empty_hash() -> Vec<u8> {
    Sha256::digest([]).into()
}

/// tmhash(0x00 || leaf)
pub(crate) fn leaf_hash(leaf: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(leaf);
    hasher.finalize().to_vec()
}

/// tmhash(0x00 || leaf)
pub(crate) fn leaf_hash_opt(hasher: &mut Sha256, leaf: &[u8]) -> Vec<u8> {
    hasher.reset();
    hasher.update([LEAF_PREFIX]);
    hasher.update(leaf);
    hasher.finalize_reset().to_vec()
}

/// tmhash(0x00 || left || right)
pub(crate) fn inner_hash(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update([INNER_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().to_vec()
}

pub(crate) fn inner_hash_opt(hasher: &mut Sha256, left: &[u8], right: &[u8]) -> Vec<u8> {
    hasher.reset();
    hasher.update([INNER_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize_reset().to_vec()
}
