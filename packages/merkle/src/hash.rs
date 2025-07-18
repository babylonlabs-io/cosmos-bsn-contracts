//! Based on comebft@0.38.6/crypto/merkle/hash.go

use sha2::{Digest, Sha256};

const LEAF_PREFIX: u8 = 0;
const INNER_PREFIX: u8 = 1;

pub fn empty_hash() -> Vec<u8> {
    Sha256::digest([]).to_vec()
}

pub fn leaf_hash(leaf: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(leaf);
    hasher.finalize().to_vec()
}

pub fn leaf_hash_opt(hasher: &mut Sha256, leaf: &[u8]) -> Vec<u8> {
    hasher.reset();
    hasher.update([LEAF_PREFIX]);
    hasher.update(leaf);
    hasher.finalize_reset().to_vec()
}

pub fn inner_hash(left: &[u8], right: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update([INNER_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().to_vec()
}

pub fn inner_hash_opt(hasher: &mut Sha256, left: &[u8], right: &[u8]) -> Vec<u8> {
    hasher.reset();
    hasher.update([INNER_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize_reset().to_vec()
}
