use crate::error::Error;
use crate::Result;

use k256::elliptic_curve::group::prime::PrimeCurveAffine;
use k256::schnorr::VerifyingKey;
use k256::{
    elliptic_curve::{
        ops::{MulByGenerator, Reduce},
        point::{AffineCoordinates, DecompressPoint},
        PrimeField,
    },
    AffinePoint, ProjectivePoint, Scalar, U256,
};
use sha2::{Digest, Sha256};

/// MODNSCALAR_SIZE is the size of a scalar on the secp256k1 curve
const MODNSCALAR_SIZE: usize = 32;

/// JACOBIAN_POINT_SIZE is the size of a point on the secp256k1 curve in
/// compressed form
const JACOBIAN_POINT_SIZE: usize = 33;

/// ADAPTOR_SIGNATURE_SIZE is the size of a Schnorr adaptor signature
/// It is in the form of (R, s, needsNegation) where `R` is a point,
/// `s` is a scalar, and `needsNegation` is a boolean value
const ADAPTOR_SIGNATURE_SIZE: usize = JACOBIAN_POINT_SIZE + MODNSCALAR_SIZE + 1;

const CHALLENGE_TAG: &[u8] = b"BIP0340/challenge";

pub struct AdaptorSignature {
    r: ProjectivePoint,
    s_hat: Scalar,
    needs_negation: bool,
}

// Adapted from https://github.com/RustCrypto/elliptic-curves/blob/520f67d26be1773bd600d05796cc26d797dd7182/k256/src/schnorr.rs#L181-L187
fn tagged_hash(tag: &[u8]) -> Sha256 {
    let tag_hash = Sha256::digest(tag);
    let mut digest = Sha256::new();
    // The hash is in sha256d, so we need to hash twice
    digest.update(tag_hash);
    digest.update(tag_hash);
    digest
}

pub fn bytes_to_point(bytes: &[u8]) -> Result<ProjectivePoint> {
    let r_option = AffinePoint::decompress(
        k256::FieldBytes::from_slice(bytes),
        k256::elliptic_curve::subtle::Choice::from(false as u8),
    );
    let r = if r_option.is_some().into() {
        r_option.unwrap()
    } else {
        return Err(Error::DecompressPointFailed {});
    };
    // Convert AffinePoint to ProjectivePoint
    Ok(ProjectivePoint::from(r))
}

impl AdaptorSignature {
    pub fn verify(
        &self,
        pub_key: &VerifyingKey,
        enc_key: &VerifyingKey,
        msg: [u8; 32],
    ) -> Result<()> {
        // Convert public keys to points
        let pk = pub_key.to_bytes();
        let p = bytes_to_point(pk.as_slice())?;
        let ek = enc_key.to_bytes();
        let t = bytes_to_point(ek.as_slice())?;

        // Calculate R' = R - T (or R + T if negation is needed)
        let r_hat = if self.needs_negation {
            self.r + t
        } else {
            self.r - t
        };
        // Convert R' to affine coordinates
        let r_hat = r_hat.to_affine();

        // Calculate e = tagged_hash("BIP0340/challenge", bytes(R) || bytes(P) || m)
        // mod n
        let r_bytes = self.r.to_affine().x();
        let p_bytes = pub_key.to_bytes();
        let e = <Scalar as Reduce<U256>>::reduce_bytes(
            &tagged_hash(CHALLENGE_TAG)
                .chain_update(r_bytes)
                .chain_update(p_bytes.as_slice())
                .chain_update(msg)
                .finalize(),
        );

        // Calculate expected R' = s'*G - e*P
        let s_hat_g = ProjectivePoint::mul_by_generator(&self.s_hat);
        let e_p = p * e;
        let expected_r_hat = s_hat_g - e_p;

        // Convert expected R' to affine coordinates
        let expected_r_hat = expected_r_hat.to_affine();

        // Ensure expected R' is not the point at infinity
        if expected_r_hat.is_identity().into() {
            return Err(Error::PointAtInfinity("expected R'".to_string()));
        }

        // Ensure R.y is even
        if self.r.to_affine().y_is_odd().into() {
            return Err(Error::PointWithOddY("R".to_string()));
        }

        // Ensure R' == expected R'
        if !r_hat.eq(&expected_r_hat) {
            return Err(Error::VerifyAdaptorSigFailed {});
        }

        Ok(())
    }

    pub fn new(asig_bytes: &[u8]) -> Result<Self> {
        if asig_bytes.len() != ADAPTOR_SIGNATURE_SIZE {
            return Err(Error::MalformedAdaptorSignature(
                ADAPTOR_SIGNATURE_SIZE,
                asig_bytes.len(),
            ));
        }
        // get R
        if asig_bytes[0] != 0x02 && asig_bytes[0] != 0x03 {
            return Err(Error::InvalidAdaptorSignatureFirstByte(asig_bytes[0]));
        }
        let is_y_odd = asig_bytes[0] == 0x03;
        let r_option = AffinePoint::decompress(
            k256::FieldBytes::from_slice(&asig_bytes[1..JACOBIAN_POINT_SIZE]),
            k256::elliptic_curve::subtle::Choice::from(is_y_odd as u8),
        );
        let r = if r_option.is_some().into() {
            r_option.unwrap().into()
        } else {
            return Err(Error::DecompressPointFailed {});
        };

        // get s_hat
        let s_hat_bytes = &asig_bytes[JACOBIAN_POINT_SIZE..JACOBIAN_POINT_SIZE + MODNSCALAR_SIZE];
        let s_hat_field_bytes = *k256::FieldBytes::from_slice(s_hat_bytes);
        let s_hat =
            Scalar::from_repr_vartime(s_hat_field_bytes).ok_or(Error::FailedToParseScalar {})?;

        let needs_negation = asig_bytes[JACOBIAN_POINT_SIZE + MODNSCALAR_SIZE] == 0x01;
        Ok(AdaptorSignature {
            r,
            s_hat,
            needs_negation,
        })
    }
}
