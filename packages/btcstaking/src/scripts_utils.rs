use crate::error::Error;
use crate::Result;
use bitcoin::blockdata::script::Builder;
use bitcoin::opcodes::all::{
    OP_CHECKSIG, OP_CHECKSIGADD, OP_CHECKSIGVERIFY, OP_CSV, OP_NUMEQUAL, OP_NUMEQUALVERIFY,
    OP_PUSHNUM_1,
};

use bitcoin::secp256k1::PublicKey;
use bitcoin::taproot::LeafVersion;
use bitcoin::ScriptBuf;
use bitcoin::{TapNodeHash, TapTweakHash, XOnlyPublicKey};

use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::subtle::Choice;
use k256::schnorr::VerifyingKey;
use k256::{
    elliptic_curve::{ops::MulByGenerator, point::DecompressPoint, PrimeField},
    AffinePoint, ProjectivePoint, Scalar,
};

const UNSPENDABLE_KEY: &str = "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

fn unspendable_key_path_internal_pub_key() -> XOnlyPublicKey {
    let key_bytes = hex::decode(UNSPENDABLE_KEY).unwrap();

    let (pk_x, _) = PublicKey::from_slice(&key_bytes)
        .unwrap()
        .x_only_public_key();
    pk_x
}

// sort_keys sorts public keys in lexicographical order
pub fn sort_keys(keys: &mut [VerifyingKey]) {
    keys.sort_by(|a, b| {
        let a_serialized = a.to_bytes();
        let b_serialized = b.to_bytes();
        a_serialized.cmp(&b_serialized)
    });
}

/// prepare_keys_for_multisig_script prepares keys to be used in multisig script
/// Validates whether there are at least 2 keys
/// and returns copy of the slice of keys sorted lexicographically.
///
/// Note: It is up to the caller to ensure that the keys are unique
pub fn prepare_keys_for_multisig_script(keys: &[VerifyingKey]) -> Result<Vec<VerifyingKey>> {
    if keys.len() < 2 {
        return Err(Error::InsufficientMultisigKeys {});
    }

    let mut sorted_keys = keys.to_vec();
    sort_keys(&mut sorted_keys);

    Ok(sorted_keys)
}

/// assemble_multisig_script is a private helper to assemble multisig script
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

/// build_multisig_script creates multisig script with given keys and signer threshold to
/// successfully execute script
/// it validates whether threshold is not greater than number of keys
/// If there is only one key provided it will return single key sig script
/// Note: It is up to the caller to ensure that the keys are unique
pub fn build_multisig_script(
    keys: &[VerifyingKey],
    threshold: usize,
    with_verify: bool,
) -> Result<ScriptBuf> {
    if keys.is_empty() {
        return Err(Error::NoKeysProvided {});
    }

    if threshold > keys.len() {
        return Err(Error::ThresholdExceedsKeyCount {});
    }

    if keys.len() == 1 {
        return build_single_key_sig_script(&keys[0], with_verify);
    }

    let prepared_keys = prepare_keys_for_multisig_script(keys)?;
    assemble_multisig_script(&prepared_keys, threshold, with_verify)
}

/// build_time_lock_script creates a timelock script
pub fn build_time_lock_script(pub_key: &VerifyingKey, lock_time: u16) -> Result<ScriptBuf> {
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
pub fn build_single_key_sig_script(pub_key: &VerifyingKey, with_verify: bool) -> Result<ScriptBuf> {
    let pk_bytes: [u8; 32] = pub_key.to_bytes().into();

    let mut builder = Builder::new().push_slice(pk_bytes);

    if with_verify {
        builder = builder.push_opcode(OP_CHECKSIGVERIFY);
    } else {
        builder = builder.push_opcode(OP_CHECKSIG);
    }

    Ok(builder.into_script())
}

fn point_to_bytes(p: ProjectivePoint) -> [u8; 32] {
    let encoded_p = p.to_encoded_point(false);
    // Extract the x-coordinate as bytes
    let x_bytes = encoded_p.x().unwrap();
    x_bytes.as_slice().try_into().unwrap() // cannot fail
}

/// compute_tweaked_key_bytes computes the tweaked key bytes using k256 library
/// NOTE: this is to avoid using add_tweak in rust-bitcoin
/// as it uses secp256k1 FFI and will bloat the binary size
fn compute_tweaked_key_bytes(merkle_root: TapNodeHash) -> [u8; 32] {
    let internal_key = unspendable_key_path_internal_pub_key();

    // compute tweak point
    let tweak = TapTweakHash::from_key_and_tweak(internal_key, Some(merkle_root)).to_scalar();
    let tweak_bytes = &tweak.to_be_bytes();
    let tweak_bytes = k256::FieldBytes::from_slice(tweak_bytes);
    let tweak_scalar = Scalar::from_repr_vartime(*tweak_bytes).unwrap();
    let tweak_point = ProjectivePoint::mul_by_generator(&tweak_scalar);

    // compute internal key point
    let internal_key_bytes = internal_key.serialize();
    let x = k256::FieldBytes::from_slice(internal_key_bytes.as_slice());
    let ap_option = AffinePoint::decompress(x, Choice::from(false as u8));
    let internal_key_point = ProjectivePoint::from(ap_option.unwrap());

    // tweak internal key point with the tweak point
    let tweaked_point = internal_key_point + tweak_point;

    point_to_bytes(tweaked_point)
}

/// build_relative_time_lock_pk_script builds a relative timelocked taproot script
/// NOTE: this function is heavily optimised by manually computing the tweaked key
/// This is to avoid using any secp256k1 FFI that will bloat the binary size
pub fn build_relative_time_lock_pk_script(pk: &VerifyingKey, lock_time: u16) -> Result<ScriptBuf> {
    // build timelock script
    let script = build_time_lock_script(pk, lock_time)?;

    // compute Merkle root of the taproot script
    // NOTE: avoid using TaprootBuilder as this bloats the binary size
    let merkle_root = TapNodeHash::from_script(&script, LeafVersion::TapScript);

    // compute the tweaked key in bytes
    let tweaked_key_bytes = compute_tweaked_key_bytes(merkle_root);
    // construct the Taproot output script
    let mut builder = Builder::new();
    builder = builder
        .push_opcode(OP_PUSHNUM_1)
        .push_slice(tweaked_key_bytes);
    let taproot_pk_script = builder.into_script();
    Ok(taproot_pk_script)
}

fn aggregate_scripts(scripts: &[ScriptBuf]) -> ScriptBuf {
    let mut final_script = Vec::new();

    for script in scripts {
        final_script.extend_from_slice(script.as_bytes());
    }

    ScriptBuf::from_bytes(final_script)
}

/// BabylonScriptPaths is a structure that holds all paths of a Babylon staking
/// script, including timelock path, on-demand unbonding path, and slashing path
/// It is used in the output of the staking tx and unbonding tx
pub struct BabylonScriptPaths {
    // time_lock_path_script is the script path for normal unbonding
    // <Staker_PK> OP_CHECKSIGVERIFY  <Staking_Time_Blocks> OP_CHECKSEQUENCEVERIFY
    pub time_lock_path_script: ScriptBuf,
    // unbonding_path_script is the script path for on-demand early unbonding
    // <Staker_PK> OP_CHECKSIGVERIFY
    // <Covenant_PK1> OP_CHECKSIG ... <Covenant_PKN> OP_CHECKSIGADD M OP_NUMEQUAL
    pub unbonding_path_script: ScriptBuf,
    // slashing_path_script is the script path for slashing
    // <Staker_PK> OP_CHECKSIGVERIFY
    // <FP_PK1> OP_CHECKSIG ... <FP_PKN> OP_CHECKSIGADD 1 OP_NUMEQUALVERIFY
    // <Covenant_PK1> OP_CHECKSIG ... <Covenant_PKN> OP_CHECKSIGADD M OP_NUMEQUAL
    pub slashing_path_script: ScriptBuf,
}

impl BabylonScriptPaths {
    pub fn new(
        staker_key: &VerifyingKey,
        fp_keys: &[VerifyingKey],
        covenant_keys: &[VerifyingKey],
        covenant_quorum: usize,
        lock_time: u16,
    ) -> Result<Self> {
        let time_lock_path_script = build_time_lock_script(staker_key, lock_time)?;
        let covenant_multisig_script =
            build_multisig_script(covenant_keys, covenant_quorum, false)?;
        let staker_sig_script = build_single_key_sig_script(staker_key, true)?;
        let fp_script = if fp_keys.len() == 1 {
            build_single_key_sig_script(&fp_keys[0], true)?
        } else {
            build_multisig_script(fp_keys, 1, true)?
        };
        let unbonding_path_script =
            aggregate_scripts(&[staker_sig_script.clone(), covenant_multisig_script.clone()]);
        let slashing_path_script =
            aggregate_scripts(&[staker_sig_script, fp_script, covenant_multisig_script]);

        Ok(BabylonScriptPaths {
            time_lock_path_script,
            unbonding_path_script,
            slashing_path_script,
        })
    }

    // TODO: implement a function for aggregating all scripts to a single ScriptBuf
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
    fn test_sort_keys() {
        // Generate public keys with known secret keys
        let mut keys = vec![
            generate_public_key(&[1; 32]), // Minimal valid secret key
            generate_public_key(&[2; 32]), // Another minimal valid secret key
            generate_public_key(&[3; 32]), // Another minimal valid secret key
        ];

        // Sort the keys using the function under test
        sort_keys(&mut keys);

        // Serialize the keys to compare them easily
        let serialized_keys: Vec<Vec<u8>> =
            keys.iter().map(|key| key.to_bytes().to_vec()).collect();

        // Ensure they are sorted lexicographically
        assert!(
            serialized_keys.windows(2).all(|w| w[0] <= w[1]),
            "Keys should be sorted lexicographically"
        );
    }
}
