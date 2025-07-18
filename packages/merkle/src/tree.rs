use crate::error::MerkleError;
use crate::hash::{empty_hash, inner_hash_opt, leaf_hash_opt};
use sha2::{Digest, Sha256};

/// Computes a Merkle tree where the leaves are the byte slice,
/// in the provided order. It follows RFC-6962.
pub fn hash_from_byte_slices(items: Vec<Vec<u8>>) -> Vec<u8> {
    hash_from_byte_slices_internal(&mut Sha256::new(), items)
}

fn hash_from_byte_slices_internal(sha: &mut Sha256, items: Vec<Vec<u8>>) -> Vec<u8> {
    match items.len() {
        0 => empty_hash(),
        1 => leaf_hash_opt(sha, &items[0]),
        _ => {
            let k = get_split_point(items.len() as u64).unwrap() as usize;
            let left = hash_from_byte_slices_internal(sha, items[..k].to_vec());
            let right = hash_from_byte_slices_internal(sha, items[k..].to_vec());
            inner_hash_opt(sha, &left, &right)
        }
    }
}

/// Returns the largest power of 2 less than length.
pub(crate) fn get_split_point(length: u64) -> Result<u64, MerkleError> {
    if length < 1 {
        return Err(MerkleError::generic_err(
            "Trying to split a tree with size < 1",
        ));
    }
    let u_length = length as usize;
    let bit_len = u_length.next_power_of_two().trailing_zeros();
    let k = 1 << bit_len.saturating_sub(1);
    if k == length {
        Ok(k >> 1)
    } else {
        Ok(k)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_split_point() {
        let tests = [
            (1, 0),
            (2, 1),
            (3, 2),
            (4, 2),
            (5, 4),
            (10, 8),
            (20, 16),
            (100, 64),
            (255, 128),
            (256, 128),
            (257, 256),
        ];
        for (length, want) in tests {
            let got = get_split_point(length).unwrap();
            assert_eq!(got, want, "got {}, want {}", got, want);
        }
    }
}
