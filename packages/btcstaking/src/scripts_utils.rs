use crate::error::Error;
use crate::Result;
use bitcoin::blockdata::script::Builder;
use bitcoin::opcodes::all::{
    OP_CHECKSIG, OP_CHECKSIGADD, OP_CHECKSIGVERIFY, OP_CSV, OP_NUMEQUAL, OP_NUMEQUALVERIFY,
};

use bitcoin::ScriptBuf;

use k256::schnorr::VerifyingKey;

/// private helper to assemble multisig script
/// if `withVerify` is true script will end with OP_NUMEQUALVERIFY otherwise with OP_NUMEQUAL
/// SCRIPT: <Pk1> OP_CHEKCSIG <Pk2> OP_CHECKSIGADD <Pk3> OP_CHECKSIGADD ... <PkN> OP_CHECKSIGADD <threshold> OP_NUMEQUALVERIFY (or OP_NUMEQUAL)
fn assemble_multisig_script(
    pubkeys: &[VerifyingKey],
    threshold: usize,
    with_verify: bool,
) -> Result<ScriptBuf> {
    let mut builder = Builder::new();
    for (i, key) in pubkeys.iter().enumerate() {
        let pk_bytes: [u8; 32] = key.to_bytes().into();
        builder = builder.push_slice(pk_bytes);
        if i == 0 {
            builder = builder.push_opcode(OP_CHECKSIG);
        } else {
            builder = builder.push_opcode(OP_CHECKSIGADD);
        }
    }

    builder = builder.push_int(threshold as i64);
    if with_verify {
        builder = builder.push_opcode(OP_NUMEQUALVERIFY);
    } else {
        builder = builder.push_opcode(OP_NUMEQUAL);
    }

    Ok(builder.into_script())
}

/// prepare_keys_for_multisig_script prepares keys to be used in multisig script
/// Validates whether there are at least 2 keys
/// and returns copy of the slice of keys sorted lexicographically.
///
/// Note: It is up to the caller to ensure that the keys are unique
fn prepare_keys_for_multisig_script(keys: &[VerifyingKey]) -> Result<Vec<VerifyingKey>> {
    if keys.len() < 2 {
        return Err(Error::InsufficientMultisigKeys {});
    }

    let mut sorted_keys = keys.to_vec();
    sorted_keys.sort_by(|a, b| {
        let a_serialized = a.to_bytes();
        let b_serialized = b.to_bytes();
        a_serialized.cmp(&b_serialized)
    });

    Ok(sorted_keys)
}

/// build_multisig_script creates multisig script with given keys and signer threshold to
/// successfully execute script
/// it validates whether threshold is not greater than number of keys
/// If there is only one key provided it will return single key sig script
/// Note: It is up to the caller to ensure that the keys are unique
pub(crate) fn build_multisig_script(
    keys: &[VerifyingKey],
    threshold: usize,
    with_verify: bool,
) -> Result<ScriptBuf> {
    if keys.is_empty() {
        return Err(Error::NoKeysProvided {});
    }

    if threshold > keys.len() {
        return Err(Error::ThresholdExceedsKeyCount {
            threshold,
            keys_count: keys.len(),
        });
    }

    if keys.len() == 1 {
        return build_single_key_sig_script(&keys[0], with_verify);
    }

    let prepared_keys = prepare_keys_for_multisig_script(keys)?;
    assemble_multisig_script(&prepared_keys, threshold, with_verify)
}

/// build_time_lock_script creates a timelock script
pub(crate) fn build_time_lock_script(pub_key: &VerifyingKey, lock_time: u16) -> Result<ScriptBuf> {
    let pk_bytes: [u8; 32] = pub_key.to_bytes().into();
    let builder = Builder::new()
        .push_slice(pk_bytes)
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_int(lock_time as i64)
        .push_opcode(OP_CSV);
    let script = builder.into_script();
    Ok(script)
}

/// build_single_key_sig_script builds a single key signature script
/// SCRIPT: <pubKey> OP_CHECKSIGVERIFY
pub(crate) fn build_single_key_sig_script(
    pub_key: &VerifyingKey,
    with_verify: bool,
) -> Result<ScriptBuf> {
    let pk_bytes: [u8; 32] = pub_key.to_bytes().into();

    let mut builder = Builder::new().push_slice(pk_bytes);

    if with_verify {
        builder = builder.push_opcode(OP_CHECKSIGVERIFY);
    } else {
        builder = builder.push_opcode(OP_CHECKSIG);
    }

    Ok(builder.into_script())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

    // Function to generate a public key from a secret key
    fn generate_public_key(data: &[u8]) -> VerifyingKey {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(data).expect("slice with correct length");
        let (pk_x, _) = PublicKey::from_secret_key(&secp, &secret_key).x_only_public_key();

        VerifyingKey::from_bytes(pk_x.serialize().as_slice()).unwrap()
    }

    #[test]
    fn test_prepare_keys_for_multisig_script() {
        // Test with insufficient keys (0 and 1 key)
        let empty_keys: Vec<VerifyingKey> = vec![];
        let result = prepare_keys_for_multisig_script(&empty_keys);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::InsufficientMultisigKeys {}
        ));

        let single_key = vec![generate_public_key(&[1; 32])];
        let result = prepare_keys_for_multisig_script(&single_key);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            Error::InsufficientMultisigKeys {}
        ));

        // Test with sufficient keys (3 keys)
        let keys = vec![
            generate_public_key(&[3; 32]), // Third key
            generate_public_key(&[1; 32]), // First key
            generate_public_key(&[2; 32]), // Second key
        ];

        // Prepare the keys using the function under test
        let prepared_keys = prepare_keys_for_multisig_script(&keys).unwrap();

        // Serialize the keys to compare them easily
        let serialized_keys: Vec<Vec<u8>> = prepared_keys
            .iter()
            .map(|key| key.to_bytes().to_vec())
            .collect();

        // Ensure they are sorted lexicographically
        assert!(
            serialized_keys.windows(2).all(|w| w[0] <= w[1]),
            "Keys should be sorted lexicographically"
        );
    }
}
