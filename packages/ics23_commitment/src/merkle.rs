use crate::error::CommitmentError;
use crate::specs::ProofSpecs;
use ics23::commitment_proof::Proof;
use ics23::{calculate_existence_root, verify_membership, CommitmentProof};

#[derive(Clone, Debug, PartialEq)]
pub struct MerkleProof {
    pub proofs: Vec<CommitmentProof>,
}

impl MerkleProof {
    pub fn verify_membership(
        &self,
        specs: &ProofSpecs,
        root: Vec<u8>,
        keys: Vec<Vec<u8>>,
        value: Vec<u8>,
        start_index: usize,
    ) -> Result<(), CommitmentError> {
        // validate arguments
        if self.proofs.is_empty() {
            return Err(CommitmentError::EmptyMerkleProof);
        }
        if root.is_empty() {
            return Err(CommitmentError::EmptyMerkleRoot);
        }
        let num = self.proofs.len();
        let ics23_specs = Vec::<ics23::ProofSpec>::from(specs.clone());
        if ics23_specs.len() != num {
            return Err(CommitmentError::NumberOfSpecsMismatch);
        }
        if keys.len() != num {
            return Err(CommitmentError::NumberOfKeysMismatch);
        }
        if value.is_empty() {
            return Err(CommitmentError::EmptyVerifiedValue);
        }

        let mut subroot = value.clone();
        let mut value = value;
        // keys are represented from root-to-leaf
        for ((proof, spec), key) in self
            .proofs
            .iter()
            .zip(ics23_specs.iter())
            .zip(keys.iter().rev())
            .skip(start_index)
        {
            match &proof.proof {
                Some(Proof::Exist(existence_proof)) => {
                    subroot =
                        calculate_existence_root::<ics23::HostFunctionsManager>(existence_proof)
                            .map_err(|_| CommitmentError::InvalidMerkleProof)?;

                    if !verify_membership::<ics23::HostFunctionsManager>(
                        proof, spec, &subroot, key, &value,
                    ) {
                        return Err(CommitmentError::VerificationFailure);
                    }
                    value.clone_from(&subroot);
                }
                _ => return Err(CommitmentError::InvalidMerkleProof),
            }
        }

        if root != subroot {
            return Err(CommitmentError::VerificationFailure);
        }

        Ok(())
    }
}

pub fn convert_tm_proto_to_ics_merkle_proof(
    tm_proto_proof: &tendermint_proto::crypto::ProofOps,
) -> Result<MerkleProof, CommitmentError> {
    let mut proofs = Vec::new();

    for op in &tm_proto_proof.ops {
        let mut parsed = CommitmentProof { proof: None };
        prost::Message::merge(&mut parsed, op.data.as_slice())
            .map_err(|_err| CommitmentError::CommitmentProofDecodingFailed)?;

        proofs.push(parsed);
    }

    Ok(MerkleProof { proofs })
}
