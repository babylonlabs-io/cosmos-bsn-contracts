use crate::babylon::checkpointing::v1::{
    RawCheckpoint, ValidatorWithBlsKey, ValidatorWithBlsKeySet,
};
use bitvec::prelude::*;
use sha2::{Digest, Sha256};

// constants for txs that encode a BTC checkpoint
pub const CURRENT_VERSION: u8 = 0;
pub const TAG_LEN: usize = 4;
pub const FIRST_PART_LEN: usize = 78;
pub const FIRST_PART_HASH_LEN: usize = 10;
pub const SECOND_PART_LEN: usize = 63;
pub const HEADER_LEN: usize = 5;

// constants for the BTC checkpoint
pub const EPOCH_LEN: usize = 8;
pub const BLOCK_HASH_LEN: usize = 32;
pub const BITMAP_LEN: usize = 13;
pub const ADDRESS_LEN: usize = 20;
pub const BLS_SIG_LEN: usize = 48;

pub const MERKLE_PROOF_ELEM_SIZE: usize = 32;

impl ValidatorWithBlsKeySet {
    pub fn get_total_power(&self) -> u64 {
        let mut total_power: u64 = 0;
        for val in self.val_set.iter() {
            total_power += val.voting_power;
        }
        total_power
    }

    pub fn find_subset_with_power_sum(
        &self,
        bitmap_bytes: &[u8],
    ) -> Result<(ValidatorWithBlsKeySet, u64), String> {
        let mut sum: u64 = 0;
        let mut val_subset: Vec<ValidatorWithBlsKey> = vec![];

        // initialise bitmap
        let bitmap = bitmap_bytes.view_bits::<Lsb0>();
        let bitmap_size = bitmap.len() * 8;

        // ensure bitmap is big enough to contain ks
        if bitmap_size < self.val_set.len() {
            return Err(format!("bitmap (with {} bits) is not large enough to contain the validator set with size {}", bitmap_size, self.val_set.len()));
        }

        for i in 0..self.val_set.len() {
            let bit = *bitmap
                .get(i)
                .ok_or(format!("bitmap does not contain bit at index {}", i))?;
            if bit {
                let voted_val = self.val_set.get(i).ok_or(format!(
                    "validator set does not contain validator at index {}",
                    i
                ))?;
                val_subset.push(voted_val.clone());
                sum += voted_val.voting_power;
            }
        }

        let subset = ValidatorWithBlsKeySet {
            val_set: val_subset,
        };

        Ok((subset, sum))
    }
}

impl RawCheckpoint {
    pub fn signed_msg(&self) -> Vec<u8> {
        let mut msg_bytes = self.epoch_num.to_be_bytes().to_vec();
        msg_bytes.extend(&self.block_hash);
        msg_bytes
    }

    pub fn from_checkpoint_data(version: u8, f: Vec<u8>, s: Vec<u8>) -> Result<Self, String> {
        if version > CURRENT_VERSION {
            return Err("not supported version".to_string());
        }
        if f.len() != FIRST_PART_LEN - HEADER_LEN {
            return Err("not valid first part".to_string());
        }
        if s.len() != SECOND_PART_LEN - HEADER_LEN {
            return Err("not valid second part".to_string());
        }
        let first_hash = Sha256::digest(&f);
        let exp_hash = &s[s.len() - FIRST_PART_HASH_LEN..];
        if &first_hash[0..FIRST_PART_HASH_LEN] != exp_hash {
            return Err("parts do not connect".to_string());
        }

        // all good, connect
        let mut raw_ckpt_bytes: Vec<u8> = vec![];
        raw_ckpt_bytes.extend(f);
        raw_ckpt_bytes.extend(s);

        // start decoding
        let mut idx: usize = 0;
        let epoch_num_bytes: [u8; 8] = raw_ckpt_bytes[idx..idx + EPOCH_LEN]
            .try_into()
            .map_err(|_| "wrong epoch number bytes length")?;
        let epoch_num = u64::from_be_bytes(epoch_num_bytes);
        idx += EPOCH_LEN;
        let block_hash: Vec<u8> = raw_ckpt_bytes[idx..idx + BLOCK_HASH_LEN].to_vec();
        idx += BLOCK_HASH_LEN;
        let bitmap: Vec<u8> = raw_ckpt_bytes[idx..idx + BITMAP_LEN].to_vec();
        idx += BITMAP_LEN;
        let _: Vec<u8> = raw_ckpt_bytes[idx..idx + ADDRESS_LEN].to_vec();
        idx += ADDRESS_LEN;
        let bls_multi_sig: Vec<u8> = raw_ckpt_bytes[idx..idx + BLS_SIG_LEN].to_vec();

        let raw_ckpt = RawCheckpoint {
            epoch_num,
            block_hash: block_hash.into(),
            bitmap: bitmap.into(),
            bls_multi_sig: bls_multi_sig.into(),
        };

        Ok(raw_ckpt)
    }
}
