pub mod error;
pub mod schnorr;

use bitcoin::blockdata::opcodes;
use bitcoin::hashes::{sha256d, Hash};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub use bitcoin::{
    block::{Header as BlockHeader, Version},
    consensus::encode::Error as EncodeError,
    consensus::{deserialize, serialize, Params},
    hash_types,
    hashes::hex::HexToArrayError as HexError,
    BlockHash, CompactTarget, Target, Transaction, Work,
};
pub use cosmwasm_std::Uint256;

pub type Result<T> = std::result::Result<T, error::Error>;

pub use bitcoin::Network;

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

    current_hash == *root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_serialize_btc_header() {
        // https://babylon.explorers.guru/transaction/8CEC6D605A39378F560C2134ABC931AE7DED0D055A6655B82CC5A31D5DA0BE26
        let btc_header_hex = "00400720b2559c9eb13821d6df53ffab9ddf3a645c559f030cac050000000000000000001ff22ffaa13c41df6aebc4b9b09faf328748c3a45772b6a4c4da319119fd5be3b53a1964817606174cc4c4b0";
        let btc_header_bytes = hex::decode(btc_header_hex).unwrap();
        let btc_header: BlockHeader = deserialize(&btc_header_bytes).unwrap();
        let serialized_btc_header = serialize(&btc_header);
        assert_eq!(btc_header_bytes, serialized_btc_header);
    }
}
