use crate::error::Error;
use crate::Result;
use bitcoin::blockdata::script::Builder;
use bitcoin::opcodes::all::OP_PUSHNUM_1;

use bitcoin::secp256k1::PublicKey;
use bitcoin::taproot::LeafVersion;
use bitcoin::ScriptBuf;
use bitcoin::{TapNodeHash, TapTweakHash, XOnlyPublicKey};

use rust_decimal::{prelude::*, Decimal};

use crate::scripts_utils::{
    build_multisig_script, build_single_key_sig_script, build_time_lock_script,
};
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

/// Checks if the given rate is between the valid range i.e., (0,1) with a precision of at most 2 decimal places.
pub(crate) fn is_rate_valid(rate: f64) -> bool {
    // Check if the slashing rate is between 0 and 1
    if rate <= 0.0 || rate >= 1.0 {
        return false;
    }

    // Multiply by 10000 to move the decimal places and check if precision is at most 4 decimal places
    let multiplied_rate = Decimal::from_f64(rate * 10000.0).unwrap();

    // Truncate the rate to remove decimal places
    let truncated_rate = multiplied_rate.trunc();

    // Check if the truncated rate is equal to the original rate
    multiplied_rate == truncated_rate
}

fn key_to_string(key: &VerifyingKey) -> String {
    hex::encode(key.to_bytes())
}

fn check_for_duplicate_keys(
    staker_key: &VerifyingKey,
    fp_keys: &[VerifyingKey],
    covenant_keys: &[VerifyingKey],
) -> Result<()> {
    let mut seen = std::collections::HashSet::new();
    for key in std::iter::once(staker_key)
        .chain(fp_keys.iter())
        .chain(covenant_keys.iter())
    {
        let key_str = key_to_string(key);
        if !seen.insert(key_str) {
            return Err(Error::DuplicateKeys {});
        }
    }
    Ok(())
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

/// build_relative_timelock_taproot_script_pk_script builds just the pk_script part
/// of a relative timelocked taproot script. This aligns with the Go library's
/// BuildRelativeTimelockTaprootScript function when only the pk_script is needed.
///
/// NOTE: this function is heavily optimised by manually computing the tweaked key
/// This is to avoid using any secp256k1 FFI that will bloat the binary size
pub fn build_relative_timelock_taproot_script_pk_script(
    pk: &VerifyingKey,
    lock_time: u16,
) -> Result<ScriptBuf> {
    // build timelock script
    let script = build_time_lock_script(pk, lock_time)?;

    // compute Merkle root of the taproot script
    // NOTE: avoid using TaprootBuilder as this bloats the binary size
    let merkle_root = TapNodeHash::from_script(&script, LeafVersion::TapScript);

    // compute the tweaked key in bytes
    let tweaked_key_bytes = compute_tweaked_key_bytes(merkle_root);

    // construct the Taproot output script
    // NOTE: This produces the same format as Go's txscript.PayToAddrScript()
    let mut builder = Builder::new();
    builder = builder
        .push_opcode(OP_PUSHNUM_1)
        .push_slice(tweaked_key_bytes);
    let taproot_pk_script = builder.into_script();
    Ok(taproot_pk_script)
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
        check_for_duplicate_keys(staker_key, fp_keys, covenant_keys)?;

        let time_lock_path_script = build_time_lock_script(staker_key, lock_time)?;
        let covenant_multisig_script =
            build_multisig_script(covenant_keys, covenant_quorum, false)?;
        let staker_sig_script = build_single_key_sig_script(staker_key, true)?;
        let fp_multisig_script = build_multisig_script(fp_keys, 1, true)?;
        let unbonding_path_script =
            aggregate_scripts(&[staker_sig_script.clone(), covenant_multisig_script.clone()]);
        let slashing_path_script = aggregate_scripts(&[
            staker_sig_script,
            fp_multisig_script,
            covenant_multisig_script,
        ]);

        Ok(BabylonScriptPaths {
            time_lock_path_script,
            unbonding_path_script,
            slashing_path_script,
        })
    }

    // TODO: implement a function for aggregating all scripts to a single ScriptBuf
}

fn point_to_bytes(p: ProjectivePoint) -> [u8; 32] {
    let encoded_p = p.to_encoded_point(false);
    // Extract the x-coordinate as bytes
    let x_bytes = encoded_p.x().unwrap();
    x_bytes.as_slice().try_into().unwrap() // cannot fail
}

fn aggregate_scripts(scripts: &[ScriptBuf]) -> ScriptBuf {
    let mut final_script = Vec::new();

    for script in scripts {
        final_script.extend_from_slice(script.as_bytes());
    }

    ScriptBuf::from_bytes(final_script)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_rate_valid_comprehensive() {
        // Test valid rates
        assert!(is_rate_valid(0.01)); // 1%
        assert!(is_rate_valid(0.1234)); // 12.34%
        assert!(is_rate_valid(0.54)); // 54%
        assert!(is_rate_valid(0.9999)); // 99.99%
        assert!(is_rate_valid(0.0001)); // 0.01%

        // Test invalid rates - boundary cases
        assert!(!is_rate_valid(0.0)); // Exactly 0
        assert!(!is_rate_valid(1.0)); // Exactly 1
        assert!(!is_rate_valid(-0.1)); // Negative
        assert!(!is_rate_valid(1.1)); // Greater than 1

        // Test invalid rates - too many decimal places
        assert!(!is_rate_valid(0.00001)); // 0.001% (5 decimal places)
        assert!(!is_rate_valid(0.12345)); // 12.345% (5 decimal places)
    }

    #[test]
    fn test_build_relative_timelock_taproot_script_pk_script() {
        // Test that the function produces valid taproot scripts
        // This ensures alignment with Go library behavior
        let test_pk = VerifyingKey::from_bytes(&[0x02; 32]).unwrap();
        let lock_time: u16 = 100;

        let result = build_relative_timelock_taproot_script_pk_script(&test_pk, lock_time).unwrap();

        // Test that the output is a valid taproot script
        // Should be: [0x51, 0x20, ...32_byte_tweaked_key...]
        let script_bytes = result.as_bytes();
        assert_eq!(
            script_bytes.len(),
            34,
            "Taproot script should be exactly 34 bytes (1 + 1 + 32)"
        );
        assert_eq!(
            script_bytes[0],
            OP_PUSHNUM_1.to_u8(),
            "Script should start with OP_PUSHNUM_1"
        );
        assert_eq!(
            script_bytes[1],
            bitcoin::opcodes::all::OP_PUSHBYTES_32.to_u8(),
            "Script should have OP_PUSHBYTES_32 at index 1"
        );
        // The rest should be 32 bytes (the tweaked key)
        assert_eq!(
            script_bytes[2..].len(),
            32,
            "Tweaked key should be 32 bytes"
        );

        // Test with different lock times
        let lock_time_2: u16 = 1000;
        let result_2 =
            build_relative_timelock_taproot_script_pk_script(&test_pk, lock_time_2).unwrap();
        assert_ne!(
            result, result_2,
            "Different lock times should produce different scripts"
        );
    }
}
