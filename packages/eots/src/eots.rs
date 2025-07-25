use crate::error::Error;
use crate::Result;

use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{
    elliptic_curve::{
        group::Group,
        ops::{MulByGenerator, Reduce},
        point::{AffineCoordinates, DecompressPoint},
        subtle::Choice,
        PrimeField,
    },
    AffinePoint, ProjectivePoint, Scalar, U256,
};
use sha2::{Digest, Sha256};
use std::ops::{Deref, Mul};

pub const CHALLENGE_TAG: &[u8] = b"BIP0340/challenge";

// Adapted from https://github.com/RustCrypto/elliptic-curves/blob/520f67d26be1773bd600d05796cc26d797dd7182/k256/src/schnorr.rs#L181-L187
pub fn tagged_hash(tag: &[u8]) -> Sha256 {
    let tag_hash = Sha256::digest(tag);
    let mut digest = Sha256::new();
    // The hash is in sha256d, so we need to hash twice
    digest.update(tag_hash);
    digest.update(tag_hash);
    digest
}

/// hash function is used for hashing the message input for all functions of the library.
/// Wrapper around sha256 in order to change only one function if the input hashing function is changed.
pub fn hash(message: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(message);
    hasher.finalize().into()
}

/// `SecRand` is the type for a secret randomness.
/// It is formed as a scalar on the secp256k1 curve
pub struct SecRand {
    inner: Scalar,
}

impl SecRand {
    /// Parses the given bytes into a new secret randomness.
    /// The given byte slice has to be a 32-byte scalar.
    /// NOTE: we enforce the secret randomness to correspond to a point
    /// with even y-coordinate
    pub fn new(r: &[u8]) -> Result<SecRand> {
        let array: [u8; 32] = r
            .try_into()
            .map_err(|_| Error::InvalidInputLength(r.len()))?;
        let scalar =
            Scalar::from_repr_vartime(array.into()).ok_or(Error::SecretRandomnessParseFailed {})?;
        if ProjectivePoint::mul_by_generator(&scalar)
            .to_affine()
            .y_is_odd()
            .into()
        {
            Ok(Self { inner: -scalar })
        } else {
            Ok(Self { inner: scalar })
        }
    }
}

impl Deref for SecRand {
    type Target = Scalar;

    fn deref(&self) -> &<Self as Deref>::Target {
        &self.inner
    }
}

/// `PubRand` is the type for a public randomness.
/// It is formed as a point on the secp256k1 curve
pub struct PubRand {
    inner: ProjectivePoint,
}

impl PubRand {
    /// Parses the given bytes into a new public randomness value on the secp256k1 curve.
    /// The given byte slice can be:
    ///   - A 32-byte representation of an x coordinate (the y-coordinate is derived as even).
    ///   - A 33-byte compressed representation of an x coordinate (the y-coordinate is derived).
    ///   - A 65-byte uncompressed representation of an x-y coordinate pair (the y-coordinate is _also_
    ///     derived).
    ///
    /// See https://crypto.stackexchange.com/a/108092/119110 for format / prefix details
    pub fn new(pr_bytes: &[u8]) -> Result<PubRand> {
        // Reject if the input is not 32 (naked), 33 (compressed) or 65 (uncompressed) bytes
        let (x_bytes, y_is_odd) = match pr_bytes.len() {
            32 => (pr_bytes, false), // Assume even y-coordinate
            33 => {
                if pr_bytes[0] != 0x02 && pr_bytes[0] != 0x03 {
                    return Err(Error::InvalidInputLength(pr_bytes.len()));
                }
                (&pr_bytes[1..], pr_bytes[0] == 0x03) // y-coordinate parity
            }
            65 => {
                if pr_bytes[0] != 0x04 {
                    return Err(Error::InvalidInputLength(pr_bytes.len()));
                }
                // FIXME: Deserialize y-coordinate directly, instead of deriving it below
                (&pr_bytes[1..33], pr_bytes[64] & 0x01 == 0x01) // y-coordinate parity
            }
            _ => return Err(Error::InvalidInputLength(pr_bytes.len())),
        };
        // Convert x_array to a FieldElement
        let x = k256::FieldBytes::from_slice(x_bytes);

        // Attempt to derive the corresponding y-coordinate
        let ap_option = AffinePoint::decompress(x, Choice::from(y_is_odd as u8));
        if ap_option.is_some().into() {
            Ok(Self {
                inner: ProjectivePoint::from(ap_option.unwrap()),
            })
        } else {
            Err(Error::PublicRandomnessParseFailed {})
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        point_to_bytes(&self.inner).to_vec()
    }
}

impl Deref for PubRand {
    type Target = ProjectivePoint;

    fn deref(&self) -> &<Self as Deref>::Target {
        &self.inner
    }
}

impl From<ProjectivePoint> for PubRand {
    fn from(p: ProjectivePoint) -> Self {
        Self { inner: p }
    }
}

/// `Signature` is an extractable one-time signature (EOTS), i.e., `s` in a Schnorr signature `(R, s)`
pub struct Signature {
    inner: Scalar,
}

impl Signature {
    /// Parses the given bytes into a new signature.
    /// The given byte slice has to be a 32-byte scalar
    pub fn new(r: &[u8]) -> Result<Signature> {
        let array: [u8; 32] = r
            .try_into()
            .map_err(|_| Error::InvalidInputLength(r.len()))?;
        Ok(Self {
            inner: Scalar::from_repr_vartime(array.into()).ok_or(Error::SignatureParseFailed {})?,
        })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }
}

impl Deref for Signature {
    type Target = Scalar;

    fn deref(&self) -> &<Self as Deref>::Target {
        &self.inner
    }
}

impl From<Scalar> for Signature {
    fn from(s: Scalar) -> Self {
        Self { inner: s }
    }
}

/// `SecretKey` is a secret key, formed as a 32-byte scalar
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretKey {
    inner: k256::SecretKey,
}

impl SecretKey {
    pub fn from_bytes(x: &[u8]) -> Result<Self> {
        let x_array: [u8; 32] = x
            .try_into()
            .map_err(|_| Error::InvalidInputLength(x.len()))?;
        let inner =
            Scalar::from_repr_vartime(x_array.into()).ok_or(Error::SecretKeyParseFailed {})?;

        let sk = k256::SecretKey::new(inner.into());
        Ok(SecretKey { inner: sk })
    }

    pub fn from_hex(x_hex: &str) -> Result<Self> {
        let x = hex::decode(x_hex)?;
        SecretKey::from_bytes(&x)
    }

    /// Gets the public key corresponding to the secret key.
    pub fn pubkey(&self) -> PublicKey {
        let pk = self.inner.public_key();
        PublicKey { inner: pk }
    }

    /// Sign returns an extractable Schnorr signature for a message, signed with a private key and private randomness value.
    /// Note that the Signature is only the second (S) part of the typical bitcoin signature, the first (R) can be deduced from
    /// the public randomness value and the message.
    pub fn sign(&self, private_rand: &[u8], message: &[u8]) -> Result<Signature> {
        let h = hash(message);
        self.sign_hash(private_rand, h)
    }

    /// signHash returns an extractable Schnorr signature for a hashed message.
    /// The caller MUST ensure that hash is the output of a cryptographically secure hash function.
    /// Based on unexported schnorrSign of btcd.
    pub fn sign_hash(&self, private_rand: &[u8], hash: [u8; 32]) -> Result<Signature> {
        // Check if private key is zero
        if self.inner.to_nonzero_scalar().is_zero().into() {
            return Err(Error::PrivateKeyIsZero);
        }

        // d' = int(d)
        let priv_key_scalar = *self.inner.to_nonzero_scalar();

        let pub_key = self.pubkey();

        // Always negate d to avoid timing attack and pick the
        // negated value later if P.y odd
        let pub_key_bytes = pub_key.to_bytes();
        let priv_key_scalar_negated = -priv_key_scalar;
        let is_py_odd = pub_key.is_y_odd();

        let k = *SecRand::new(private_rand)?;

        // R = kG (with blinding in order to prevent timing side channel attacks)
        // Note: we use standard scalar base multiplication here instead of blinding
        // as k256 crate doesn't expose the blinding functionality
        let r_point = ProjectivePoint::mul_by_generator(&k);

        // Always negate nonce k to avoid timing attack and pick the
        // negated value later if R.y is odd
        // (R.y is the y coordinate of the point R)
        //
        // Note that R must be in affine coordinates for this check.
        let r_affine = r_point.to_affine();
        let k_negated = -k;
        let is_ry_odd = r_affine.y_is_odd().into();

        // e = tagged_hash("BIP0340/challenge", bytes(R) || bytes(P) || m) mod n
        let r_bytes = point_to_bytes(&r_point);
        let p_bytes = pub_key_bytes;

        let e = <Scalar as Reduce<U256>>::reduce_bytes(
            &tagged_hash(CHALLENGE_TAG)
                .chain_update(r_bytes)
                .chain_update(p_bytes)
                .chain_update(hash)
                .finalize(),
        );

        // s = k + e*d mod n
        // choose negated values for
        // priv_key_scalar and k to avoid timing attack
        let sig = match (is_py_odd, is_ry_odd) {
            (true, true) => k_negated + e * priv_key_scalar_negated,
            (true, false) => k + e * priv_key_scalar_negated,
            (false, true) => k_negated + e * priv_key_scalar,
            (false, false) => k + e * priv_key_scalar,
        };

        // If Verify(bytes(P), m, sig) fails, abort.
        // optional

        // Return s
        Ok(Signature::from(sig))
    }

    /// Converts the secret key into bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }
}

/// `PublicKey` is a public key, formed as a point on the secp256k1 curve
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    inner: k256::PublicKey,
}

impl PublicKey {
    pub fn from_bytes(x_bytes: &[u8]) -> Result<Self> {
        // Reject if the input is not 32 (naked), 33 (compressed) or 65 (uncompressed) bytes
        let (x_bytes, y_is_odd) = match x_bytes.len() {
            32 => (x_bytes, false), // Assume even y-coordinate as even
            33 => {
                if x_bytes[0] != 0x02 && x_bytes[0] != 0x03 {
                    return Err(Error::InvalidInputLength(x_bytes.len()));
                }
                (&x_bytes[1..], x_bytes[0] == 0x03) // y-coordinate parity
            }
            65 => {
                if x_bytes[0] != 0x04 {
                    return Err(Error::InvalidInputLength(x_bytes.len()));
                }
                // FIXME: Deserialize y-coordinate directly, instead of deriving it below
                (&x_bytes[1..33], x_bytes[64] & 0x01 == 0x01) // y-coordinate parity
            }
            _ => return Err(Error::InvalidInputLength(x_bytes.len())),
        };
        let x = k256::FieldBytes::from_slice(x_bytes);

        // Attempt to derive the corresponding y-coordinate
        let ap_option = AffinePoint::decompress(x, Choice::from(y_is_odd as u8));
        if ap_option.is_some().into() {
            let pk = k256::PublicKey::from_affine(ap_option.unwrap())
                .map_err(|e| Error::EllipticCurveError(e.to_string()))?;
            Ok(PublicKey { inner: pk })
        } else {
            Err(Error::PublicKeyParseFailed {})
        }
    }

    pub fn from_hex(p_hex: &str) -> Result<Self> {
        let p = hex::decode(p_hex)?;
        PublicKey::from_bytes(&p)
    }

    /// Converts the public key into bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        point_to_bytes(&self.inner.to_projective()).to_vec()
    }

    /// Verify verifies that the signature is valid for this message, public key and random value.
    /// Precondition: r must be normalized
    pub fn verify(&self, r_bytes: &[u8], message: &[u8], sig: &[u8]) -> Result<bool> {
        let h = hash(message);
        self.verify_hash(r_bytes, h, sig)
    }

    /// Verify verifies that the signature is valid for this hashed message, public key and random value.
    /// Based on unexported schnorrVerify of btcd.
    pub fn verify_hash(&self, r_bytes: &[u8], hash: [u8; 32], sig: &[u8]) -> Result<bool> {
        // Parse public randomness
        let r = PubRand::new(r_bytes)?;

        // Parse signature
        let s = Signature::new(sig)?;

        // e = int(tagged_hash("BIP0340/challenge", bytes(r) || bytes(P) || M)) mod n.
        let r_point_bytes = r.to_bytes();
        let p_bytes = self.to_bytes();

        let e = <Scalar as Reduce<U256>>::reduce_bytes(
            &tagged_hash(CHALLENGE_TAG)
                .chain_update(r_point_bytes)
                .chain_update(p_bytes)
                .chain_update(hash)
                .finalize(),
        );

        // Negate e here so we can use addition below to subtract the s*G
        // point from e*P.
        let e_neg = -e;

        // R = s*G - e*P
        let s_g = ProjectivePoint::mul_by_generator(&*s);
        let e_p = self.inner.to_projective().mul(e_neg);
        let recovered_r = s_g + e_p;

        // Fail if R is the point at infinity
        if recovered_r.is_identity().into() {
            return Ok(false);
        }

        // Fail if R.y is odd
        //
        // Note that R must be in affine coordinates for this check.
        let r_affine = recovered_r.to_affine();
        if r_affine.y_is_odd().into() {
            return Ok(false);
        }

        // verify signed with the right k random value
        Ok(recovered_r.eq(&*r))
    }

    pub fn extract_secret_key(
        &self,
        r_bytes: &[u8],
        hash1: [u8; 32],
        sig1: &[u8],
        hash2: [u8; 32],
        sig2: &[u8],
    ) -> Result<SecretKey> {
        let r = PubRand::new(r_bytes)?;
        let r_point_bytes = r.to_bytes();
        let p_bytes = self.to_bytes();

        let s1 = Signature::new(sig1)?;
        let s2 = Signature::new(sig2)?;

        if s1.to_bytes() == s2.to_bytes() {
            return Err(Error::EllipticCurveError(
                "The two signatures need to be different in order to extract".to_string(),
            ));
        }

        let e1 = <Scalar as Reduce<U256>>::reduce_bytes(
            &tagged_hash(CHALLENGE_TAG)
                .chain_update(r_point_bytes.clone())
                .chain_update(p_bytes.clone())
                .chain_update(hash1)
                .finalize(),
        );

        let e2 = <Scalar as Reduce<U256>>::reduce_bytes(
            &tagged_hash(CHALLENGE_TAG)
                .chain_update(r_point_bytes)
                .chain_update(p_bytes)
                .chain_update(hash2)
                .finalize(),
        );

        // x = (s1 - s2) / (e1 - e2)
        let denom = e1 - e2;
        let x = (*s1 - *s2) * denom.invert().unwrap();

        // Adjust for y-coordinate parity as in Go implementation
        let mut x_adjusted = x;
        if self.is_y_odd() {
            x_adjusted = -x_adjusted;
        }

        let sk = k256::SecretKey::new(x_adjusted.into());
        let extracted_sk = SecretKey { inner: sk };

        // Verify that the extracted private key matches the public key
        if extracted_sk.pubkey().to_bytes() != self.to_bytes() {
            return Err(Error::EllipticCurveError(
                "Extracted private key does not match public key".to_string(),
            ));
        }

        Ok(extracted_sk)
    }

    /// Returns true if the y-coordinate of the public key is odd.
    pub fn is_y_odd(&self) -> bool {
        let point = self.inner.to_projective().to_affine();
        point.y_is_odd().into()
    }
}

fn point_to_bytes(p: &ProjectivePoint) -> [u8; 32] {
    let encoded_p = p.to_encoded_point(false);
    // Extract the x-coordinate as bytes
    let x_bytes = encoded_p.x().unwrap();
    x_bytes.as_slice().try_into().unwrap() // cannot fail
}

#[cfg(test)]
mod tests {
    use super::*;
    use babylon_test_utils::get_eots_testdata;
    use k256::{ProjectivePoint, Scalar};
    use rand::{thread_rng, RngCore};
    use sha2::{Digest, Sha256};

    pub fn rand_gen() -> (SecRand, PubRand) {
        let x = SecRand::new(&Scalar::generate_vartime(&mut thread_rng()).to_bytes()).unwrap();
        let p = PubRand::from(ProjectivePoint::mul_by_generator(&*x));
        (x, p)
    }

    impl Default for SecretKey {
        fn default() -> Self {
            let rng = &mut thread_rng();
            Self::new(rng)
        }
    }

    impl SecretKey {
        /// new creates a random secret key
        pub fn new<R: RngCore>(rng: &mut R) -> Self {
            let x = Scalar::generate_vartime(rng);
            let x = k256::SecretKey::new(x.into());
            SecretKey { inner: x }
        }
    }

    #[test]
    fn test_sign_verify() {
        // Use deterministic values to avoid any randomness issues
        let sk =
            SecretKey::from_hex("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef")
                .unwrap();
        let pk = sk.pubkey();

        // Use fixed randomness (32 bytes = 64 hex characters)
        let sec_rand_bytes =
            hex::decode("abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456789a")
                .unwrap();
        let sec_rand = SecRand::new(&sec_rand_bytes).unwrap();
        let pub_rand = PubRand::from(ProjectivePoint::mul_by_generator(&*sec_rand));

        let message = b"test message";
        let sig = sk.sign(&sec_rand.to_bytes(), message).unwrap();
        assert!(pk
            .verify(&pub_rand.to_bytes(), message, &sig.to_bytes())
            .unwrap());
    }

    #[test]
    fn test_extract() {
        let sk = SecretKey::new(&mut thread_rng());
        let pk = sk.pubkey();
        let (sec_rand, pub_rand) = rand_gen();
        let message1 = b"message1";
        let message2 = b"message2";
        let sig1 = sk.sign(&sec_rand.to_bytes(), message1).unwrap();
        let sig2 = sk.sign(&sec_rand.to_bytes(), message2).unwrap();

        let extracted_sk = pk
            .extract_secret_key(
                &pub_rand.to_bytes(),
                hash(message1),
                &sig1.to_bytes(),
                hash(message2),
                &sig2.to_bytes(),
            )
            .unwrap();
        assert_eq!(sk.pubkey().to_bytes(), extracted_sk.pubkey().to_bytes());
    }

    #[test]
    fn test_serialize() {
        let testdata = get_eots_testdata();

        // convert SK and PK from bytes to Rust types
        let sk = SecretKey::from_hex(&testdata.sk).unwrap();
        let pk = PublicKey::from_hex(&testdata.pk).unwrap();
        assert_eq!(sk.pubkey().to_bytes(), pk.to_bytes());

        // convert secret/public randomness to Rust types
        let sr_slice = hex::decode(testdata.sr).unwrap();
        let sr = SecRand::new(&sr_slice).unwrap();
        let pr_slice = hex::decode(testdata.pr).unwrap();
        let pr_bytes: [u8; 32] = pr_slice.try_into().unwrap();
        let pr = PubRand::new(&pr_bytes).unwrap();
        assert_eq!(ProjectivePoint::mul_by_generator(&*sr), *pr);

        // convert messages
        let mut hasher = Sha256::new();
        let msg1_slice = hex::decode(testdata.msg1).unwrap();
        hasher.update(msg1_slice);
        let msg1_hash: [u8; 32] = hasher.finalize().into();

        let mut hasher = Sha256::new();
        let msg2_slice = hex::decode(testdata.msg2).unwrap();
        hasher.update(msg2_slice);
        let msg2_hash: [u8; 32] = hasher.finalize().into();

        // convert signatures
        let sig1_slice = hex::decode(testdata.sig1).unwrap();
        let sig1 = Signature::new(&sig1_slice).unwrap();
        let sig2_slice = hex::decode(testdata.sig2).unwrap();
        let sig2 = Signature::new(&sig2_slice).unwrap();

        // verify signatures using hash-based methods since testdata contains pre-hashed messages
        assert!(pk
            .verify_hash(&pr.to_bytes(), msg1_hash, &sig1.to_bytes())
            .unwrap());
        assert!(pk
            .verify_hash(&pr.to_bytes(), msg2_hash, &sig2.to_bytes())
            .unwrap());

        // extract SK using hash-based method since testdata contains pre-hashed messages
        let extracted_sk = pk
            .extract_secret_key(
                &pr.to_bytes(),
                msg1_hash,
                &sig1.to_bytes(),
                msg2_hash,
                &sig2.to_bytes(),
            )
            .unwrap();
        assert_eq!(sk.pubkey().to_bytes(), extracted_sk.pubkey().to_bytes());
    }
}
