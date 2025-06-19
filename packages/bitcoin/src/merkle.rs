use bitcoin::blockdata::transaction::Transaction;
use bitcoin::hashes::{sha256d, Hash};

pub fn verify_merkle_proof(
    tx: &Transaction,
    proof: &[&[u8]],
    tx_index: usize,
    root: &sha256d::Hash,
) -> bool {
    let mut current_hash = *tx.compute_txid().as_raw_hash();

    for (i, next_hash) in proof.iter().enumerate() {
        let mut concat = vec![];
        // extracts the i-th bit of tx idx
        if ((tx_index >> i) & 1) == 1 {
            // If the bit is 1, the transaction is in the right subtree of the current hash
            // Append the next hash and then the current hash to the concatenated hash value
            concat.extend_from_slice(next_hash);
            concat.extend_from_slice(&current_hash[..]);
        } else {
            // If the bit is 0, the transaction is in the left subtree of the current hash
            // Append the current hash and then the next hash to the concatenated hash value
            concat.extend_from_slice(&current_hash[..]);
            concat.extend_from_slice(next_hash);
        }

        current_hash = sha256d::Hash::hash(&concat);
    }

    &current_hash == root
}
