//! Based on comebft@0.38.6/crypto/merkle/proof.go

use crate::error::MerkleError;
use crate::hash::{inner_hash, leaf_hash};
use crate::tree::get_split_point;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::Binary;
use sha2::{Digest, Sha256};

/// A `Proof` is a proof of a leaf's existence in a Merkle tree.
///
/// The convention for proofs is to include leaf hashes, but to
/// exclude the root hash.
/// This convention is implemented across IAVL range proofs as well.
/// Keep this consistent unless there's a very good reason to change
/// everything.
/// This affects the generalized proof system as well.
///
/// Equivalent to / adapted from cometbft/crypto/merkle/proof.go.
#[cw_serde]
pub struct Proof {
    pub total: u64,
    pub index: u64,
    pub leaf_hash: Binary,
    pub aunts: Vec<Binary>,
}

impl From<&tendermint_proto::crypto::Proof> for Proof {
    fn from(proof_proto: &tendermint_proto::crypto::Proof) -> Self {
        // Outright reject negative values for robustness
        assert!(proof_proto.total >= 0);
        assert!(proof_proto.index >= 0);
        Proof {
            total: proof_proto.total as u64,
            index: proof_proto.index as u64,
            leaf_hash: proof_proto.leaf_hash.clone().into(),
            aunts: proof_proto
                .aunts
                .iter()
                .cloned()
                .map(|aunt| aunt.into())
                .collect(),
        }
    }
}

impl From<tendermint_proto::crypto::Proof> for Proof {
    fn from(proof_proto: tendermint_proto::crypto::Proof) -> Self {
        Proof::from(&proof_proto)
    }
}

impl Proof {
    pub const MAX_AUNTS: usize = 100;

    /// Performs basic validation.
    ///
    /// NOTE: it expects the `leaf_hash` and the elements of `aunts` to be of size `HASH_SIZE`,
    /// and it expects at most `MAX_AUNTS` elements in `aunts`.
    ///
    /// Adapted from cometbft/crypto/bft/proof.go
    /// (https://github.com/cometbft/cometbft/blob/68e5e1b4e3bd342a653a73091a1af7cc5e88b86b/crypto/merkle/proof.go#L145)
    pub fn validate_basic(&self) -> Result<(), MerkleError> {
        if self.leaf_hash.len() != Sha256::output_size() {
            return Err(MerkleError::generic_err(format!(
                "Expected leaf_hash size to be {}, got {}",
                Sha256::output_size(),
                self.leaf_hash.len()
            )));
        }
        if self.aunts.len() > Proof::MAX_AUNTS {
            return Err(MerkleError::generic_err(format!(
                "Expected no more than {} aunts, got {}",
                Proof::MAX_AUNTS,
                self.aunts.len()
            )));
        }
        for (i, aunt_hash) in self.aunts.iter().enumerate() {
            if aunt_hash.len() != Sha256::output_size() {
                return Err(MerkleError::generic_err(format!(
                    "Expected aunt #{} size to be {}, got {}",
                    i,
                    Sha256::output_size(),
                    aunt_hash.len()
                )));
            }
        }
        Ok(())
    }

    /// Verifies that the Proof proves the root hash.
    ///
    /// Adapted from `cometbft/crypto/bft/proof.go`
    pub fn verify(&self, root_hash: &[u8], leaf: &[u8]) -> Result<bool, MerkleError> {
        if root_hash.is_empty() {
            return Err(MerkleError::generic_err(
                "Invalid root hash: cannot be empty",
            ));
        }
        self.validate_basic()?;
        let leaf_hash = leaf_hash(leaf);

        if self.leaf_hash != leaf_hash {
            return Err(MerkleError::generic_err(format!(
                "Invalid leaf hash: wanted {:X?} got {:X?}",
                self.leaf_hash, leaf_hash
            )));
        }
        let computed_hash = self.compute_root_hash()?;
        if computed_hash != root_hash {
            return Err(MerkleError::generic_err(format!(
                "Invalid root hash: wanted {:X?} got {:X?}",
                root_hash, computed_hash
            )));
        }
        Ok(true)
    }

    fn compute_root_hash(&self) -> Result<Vec<u8>, MerkleError> {
        compute_hash_from_aunts(
            self.index,
            self.total,
            &self.leaf_hash,
            &self
                .aunts
                .iter()
                .map(|aunt| aunt.to_vec())
                .collect::<Vec<_>>(),
        )
    }
}

// Use the leaf hash and inner hashes to get the root Merkle hash.
// If the length of the inner_hashes slice isn't exactly correct,
// the result is nil.
// Recursive impl.
pub fn compute_hash_from_aunts(
    index: u64,
    total: u64,
    leaf_hash: &[u8],
    inner_hashes: &[Vec<u8>],
) -> Result<Vec<u8>, MerkleError> {
    if index >= total || total == 0 {
        return Err(MerkleError::generic_err(format!(
            "Invalid index ({}) and/or total ({})",
            index, total
        )));
    }
    match total {
        0 => Err(MerkleError::generic_err(
            "Cannot call compute_hash_from_aunts() with 0 total",
        )),
        1 => {
            if !inner_hashes.is_empty() {
                return Err(MerkleError::generic_err("Unexpected inner hashes"));
            }
            Ok(leaf_hash.to_vec())
        }
        _ => {
            if inner_hashes.is_empty() {
                return Err(MerkleError::generic_err("Expected at least one inner hash"));
            }
            let num_left = get_split_point(total)?;
            if index < num_left {
                let left_hash = compute_hash_from_aunts(
                    index,
                    num_left,
                    leaf_hash,
                    &inner_hashes[..inner_hashes.len() - 1],
                )?;
                Ok(inner_hash(
                    &left_hash,
                    &inner_hashes[inner_hashes.len() - 1],
                ))
            } else {
                let right_hash = compute_hash_from_aunts(
                    index - num_left,
                    total - num_left,
                    leaf_hash,
                    &inner_hashes[..inner_hashes.len() - 1],
                )?;
                Ok(inner_hash(
                    &inner_hashes[inner_hashes.len() - 1],
                    &right_hash,
                ))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proof_validate_basic() {
        let proof = Proof {
            total: 0,
            index: 0,
            leaf_hash: vec![].into(),
            aunts: vec![],
        };
        assert_eq!(
            proof.validate_basic(),
            Err(MerkleError::generic_err(
                "Expected leaf_hash size to be 32, got 0"
            ))
        );

        let proof = Proof {
            total: 0,
            index: 0,
            leaf_hash: vec![0; 32].into(),
            aunts: vec![vec![0; 31].into()],
        };
        assert_eq!(
            proof.validate_basic(),
            Err(MerkleError::generic_err(
                "Expected aunt #0 size to be 32, got 31"
            ))
        );

        let proof = Proof {
            total: 0,
            index: 0,
            leaf_hash: vec![0; 32].into(),
            aunts: vec![vec![0; 32].into(); Proof::MAX_AUNTS + 1],
        };
        assert_eq!(
            proof.validate_basic(),
            Err(MerkleError::generic_err(
                "Expected no more than 100 aunts, got 101"
            ))
        );

        // Good case
        let proof = Proof {
            total: 1,
            index: 0,
            leaf_hash: vec![0; 32].into(),
            aunts: vec![],
        };
        assert_eq!(proof.validate_basic(), Ok(()));
    }

    #[test]
    fn test_compute_hash_from_aunts() {
        let leaf = b"foo";
        let leaf_hash = leaf_hash(leaf);

        // Invalid total
        assert_eq!(
            compute_hash_from_aunts(0, 0, &leaf_hash, &[]),
            Err(MerkleError::generic_err(
                "Invalid index (0) and/or total (0)"
            ))
        );

        // Invalid inner hashes
        assert_eq!(
            compute_hash_from_aunts(0, 2, &leaf_hash, &[]),
            Err(MerkleError::generic_err("Expected at least one inner hash"))
        );

        // Good case
        let root_hash = compute_hash_from_aunts(0, 1, &leaf_hash, &[]).unwrap();
        assert_eq!(root_hash, leaf_hash);
    }

    #[test]
    fn test_proof_verify() {
        let leaf = b"foo";
        let leaf_hash = leaf_hash(leaf);
        let root_hash = compute_hash_from_aunts(0, 1, &leaf_hash, &[]).unwrap();

        // Empty root hash
        let proof = Proof {
            total: 1,
            index: 0,
            leaf_hash: leaf_hash.clone().into(),
            aunts: vec![],
        };
        assert_eq!(
            proof.verify(&[], leaf),
            Err(MerkleError::generic_err(
                "Invalid root hash: cannot be empty"
            ))
        );

        // Invalid leaf hash
        let proof = Proof {
            total: 1,
            index: 0,
            leaf_hash: vec![0; 32].into(),
            aunts: vec![],
        };

        let err = proof.verify(&root_hash, leaf).unwrap_err();
        assert!(err
            .to_string()
            .starts_with("Merkle error: Invalid leaf hash"));

        // Unexpected inner hashes
        let proof = Proof {
            total: 1,
            index: 0,
            leaf_hash: leaf_hash.clone().into(),
            aunts: vec![vec![0; 32].into()],
        };
        let err = proof.verify(&root_hash, leaf).unwrap_err();
        println!("{}", err);
        assert!(err
            .to_string()
            .starts_with("Merkle error: Unexpected inner hashes"));

        // Good case
        let proof = Proof {
            total: 1,
            index: 0,
            leaf_hash: leaf_hash.clone().into(),
            aunts: vec![],
        };
        assert_eq!(proof.verify(&root_hash, leaf), Ok(true));

        // Good case with aunts
        let proof = Proof {
            total: 2,
            index: 0,
            leaf_hash: leaf_hash.clone().into(),
            aunts: vec![inner_hash(&leaf_hash, &leaf_hash).into()],
        };
        let root_hash =
            compute_hash_from_aunts(0, 2, &leaf_hash, &[inner_hash(&leaf_hash, &leaf_hash)])
                .unwrap();
        assert_eq!(proof.verify(&root_hash, leaf), Ok(true));

        let proof = Proof {
            total: 2,
            index: 1,
            leaf_hash: leaf_hash.clone().into(),
            aunts: vec![inner_hash(&leaf_hash, &leaf_hash).into()],
        };
        let root_hash =
            compute_hash_from_aunts(1, 2, &leaf_hash, &[inner_hash(&leaf_hash, &leaf_hash)])
                .unwrap();
        assert_eq!(proof.verify(&root_hash, leaf), Ok(true));

        // Invalid proof
        let proof = Proof {
            total: 2,
            index: 1,
            leaf_hash: leaf_hash.clone().into(),
            aunts: vec![inner_hash(&leaf_hash, &leaf_hash).into()],
        };
        let root_hash =
            compute_hash_from_aunts(0, 2, &leaf_hash, &[inner_hash(&leaf_hash, &leaf_hash)])
                .unwrap();
        let err = proof.verify(&root_hash, leaf).unwrap_err();
        assert!(err
            .to_string()
            .starts_with("Merkle error: Invalid root hash"));
    }
}
