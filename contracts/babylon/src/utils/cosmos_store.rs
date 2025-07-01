use ibc_core_commitment_types::commitment::CommitmentRoot;
use ibc_core_commitment_types::merkle::{MerklePath, MerkleProof};
use ibc_core_commitment_types::proto::ics23::{CommitmentProof, HostFunctionsManager};
use ibc_core_commitment_types::specs::ProofSpecs;
use ibc_core_host_types::path::PathBytes;
use prost::Message;

// the below keys are hard-coded for now. They have to be consistent with the Babylon repo.
// TODO: integration tests for ensuring they are the same, or parametrise them upon instantiation
// https://github.com/babylonlabs-io/babylon/blob/v0.8.0-rc.0/x/epoching/types/keys.go
pub const EPOCHING_STORE_KEY: &[u8] = b"epoching";
// https://github.com/babylonlabs-io/babylon/blob/v0.8.0-rc.0/x/checkpointing/types/keys.go
pub const CHECKPOINTING_STORE_KEY: &[u8] = b"checkpointing";
// https://github.com/babylonlabs-io/babylon/blob/v0.8.0-rc.0/x/zoneconcierge/types/keys.go
pub const ZONECONCIERGE_STORE_KEY: &[u8] = b"zoneconcierge";

pub fn get_epoch_info_key(epoch_number: u64) -> Vec<u8> {
    // https://github.com/babylonlabs-io/babylon/blob/8638c950fd2de1ac5dc69a8b9f710c1fa720c155/x/epoching/types/keys.go#L21
    let mut epoch_info_key = [0x11].to_vec();
    epoch_info_key.extend(epoch_number.to_be_bytes());
    epoch_info_key
}

pub fn get_valset_key(epoch_number: u64) -> Vec<u8> {
    // https://github.com/babylonlabs-io/babylon/blob/8638c950fd2de1ac5dc69a8b9f710c1fa720c155/x/checkpointing/types/keys.go#L28
    let mut epoch_valset_key = [0x03].to_vec();
    epoch_valset_key.extend(epoch_number.to_be_bytes());
    epoch_valset_key
}

// Follows
// https://github.com/babylonlabs-io/babylon/blob/7d5a8c83c48a14d98682e3e6677a9bd7b216f3e1/x/zoneconcierge/types/btc_timestamp.go#L22
pub fn get_consumer_header_key(chain_id: &String, height: u64) -> Vec<u8> {
    // https://github.com/babylonlabs-io/babylon/blob/7d5a8c83c48a14d98682e3e6677a9bd7b216f3e1/x/zoneconcierge/types/keys.go#L33
    let mut key = [0x13].to_vec();
    key.extend(chain_id.as_bytes());
    key.extend(height.to_be_bytes());
    key
}

pub fn verify_store(
    root: &[u8],
    module_key: &[u8],
    key: &[u8],
    value: &[u8],
    proof: &tendermint_proto::crypto::ProofOps,
) -> Result<(), String> {
    // convert tendermint_proto::crypto::ProofOps to ics23 proof
    let proofs = proof
        .ops
        .clone()
        .into_iter()
        .map(|op| CommitmentProof::decode(op.data.as_slice()))
        .collect::<Result<_, _>>()
        .map_err(|err| format!("failed to convert tendermint proof to ics23 proof: {err:?}"))?;
    let ics23_proof = MerkleProof { proofs };

    // construct values for verifying Merkle proofs
    let merkle_root = CommitmentRoot::from_bytes(root).into();
    let merkle_keys = vec![module_key.to_vec(), key.to_vec()];
    let merkle_path = MerklePath::new(merkle_keys.into_iter().map(PathBytes::from_bytes).collect());

    ics23_proof
        .verify_membership::<HostFunctionsManager>(
            &ProofSpecs::cosmos(),
            merkle_root,
            merkle_path,
            value.to_vec(),
            0,
        )
        .map_err(|err| format!("failed to verify Tendermint Merkle proof: {err:?}"))?;

    Ok(())
}
