use crate::error::Error;
use crate::Result;

use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{
    elliptic_curve::{
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

    /// Creates a signature with the given secret randomness and message hash.
    pub fn sign(&self, sec_rand: &[u8], msg_hash: &[u8]) -> Result<Signature> {
        let msg_hash: [u8; 32] = msg_hash
            .try_into()
            .map_err(|_| Error::InvalidInputLength(msg_hash.len()))?;
        let x = self.inner.to_nonzero_scalar();
        let p = ProjectivePoint::mul_by_generator(&x);
        let p_bytes = point_to_bytes(&p);
        let r = SecRand::new(sec_rand)?;
        let r_point = ProjectivePoint::mul_by_generator(&r);
        let r_bytes = point_to_bytes(&r_point);
        let c = <Scalar as Reduce<U256>>::reduce_bytes(
            &tagged_hash(CHALLENGE_TAG)
                .chain_update(r_bytes)
                .chain_update(p_bytes)
                .chain_update(msg_hash)
                .finalize(),
        );

        Ok(Signature::from(*r + c * *x))
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

    /// Verifies whether the given signature w.r.t. the public key, public randomness and message hash.
    pub fn verify(&self, pub_rand: &[u8], msg_hash: &[u8], sig: &[u8]) -> Result<bool> {
        let msg_hash: [u8; 32] = msg_hash
            .try_into()
            .map_err(|_| Error::InvalidInputLength(msg_hash.len()))?;
        let p_bytes = self.to_bytes();
        let r = PubRand::new(pub_rand)?;
        let r_bytes = r.to_bytes();
        let c = <Scalar as Reduce<U256>>::reduce_bytes(
            &tagged_hash(CHALLENGE_TAG)
                .chain_update(r_bytes)
                .chain_update(p_bytes)
                .chain_update(msg_hash)
                .finalize(),
        );

        let s = Signature::new(sig)?;
        let recovered_r =
            ProjectivePoint::mul_by_generator(&*s) - self.inner.to_projective().mul(c);

        Ok(recovered_r.eq(&*r))
    }

    /// Extracts the secret key from the public key, public randomness,
    /// and two pairs of message hashes and signatures.
    pub fn extract_secret_key(
        &self,
        pub_rand: &[u8],
        msg1_hash: &[u8],
        sig1: &[u8],
        msg2_hash: &[u8],
        sig2: &[u8],
    ) -> Result<SecretKey> {
        if msg1_hash.len() != 32 {
            return Err(Error::InvalidInputLength(msg1_hash.len()));
        }
        if msg2_hash.len() != 32 {
            return Err(Error::InvalidInputLength(msg2_hash.len()));
        }
        let p_bytes = self.to_bytes();
        let r = PubRand::new(pub_rand)?;
        let r_bytes = r.to_bytes();

        // calculate e1 - e2
        let e1 = <Scalar as Reduce<U256>>::reduce_bytes(
            &tagged_hash(CHALLENGE_TAG)
                .chain_update(r_bytes.clone())
                .chain_update(p_bytes.clone())
                .chain_update(msg1_hash)
                .finalize(),
        );
        let e2 = <Scalar as Reduce<U256>>::reduce_bytes(
            &tagged_hash(CHALLENGE_TAG)
                .chain_update(r_bytes)
                .chain_update(p_bytes)
                .chain_update(msg2_hash)
                .finalize(),
        );
        let e_delta = e1 - e2;

        // calculate s1 - s2
        let s1 = Signature::new(sig1)?;
        let s2 = Signature::new(sig2)?;
        let s_delta = *s1 - *s2;

        // calculate (s1-s2) / (e1 - e2)
        let inverted_e_delta = e_delta.invert().unwrap();
        let sk = s_delta * inverted_e_delta;
        let sk = k256::SecretKey::new(sk.into());
        Ok(SecretKey { inner: sk })
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
    use rand::{thread_rng, RngCore};
    use sha2::{Digest, Sha256};

    use k256::{ProjectivePoint, Scalar};

    use babylon_test_utils::get_eots_testdata;

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
        let sk = SecretKey::new(&mut thread_rng());
        let pk = sk.pubkey();
        let (sec_rand, pub_rand) = rand_gen();
        let msg_hash = [1u8; 32];
        let sig = sk.sign(&sec_rand.to_bytes(), &msg_hash).unwrap();
        assert!(pk
            .verify(&pub_rand.to_bytes(), &msg_hash, &sig.to_bytes())
            .unwrap());
    }

    #[test]
    fn test_extract() {
        let sk = SecretKey::new(&mut thread_rng());
        let pk = sk.pubkey();
        let (sec_rand, pub_rand) = rand_gen();
        let msg_hash1 = [1u8; 32];
        let msg_hash2 = [2u8; 32];
        let sig1 = sk.sign(&sec_rand.to_bytes(), &msg_hash1).unwrap();
        let sig2 = sk.sign(&sec_rand.to_bytes(), &msg_hash2).unwrap();

        let extracted_sk = pk
            .extract_secret_key(
                &pub_rand.to_bytes(),
                &msg_hash1,
                &sig1.to_bytes(),
                &msg_hash2,
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

        // verify signatures
        assert!(pk
            .verify(&pr.to_bytes(), &msg1_hash, &sig1.to_bytes())
            .unwrap());
        assert!(pk
            .verify(&pr.to_bytes(), &msg2_hash, &sig2.to_bytes())
            .unwrap());

        // extract SK
        let extracted_sk = pk
            .extract_secret_key(
                &pr.to_bytes(),
                &msg1_hash,
                &sig1.to_bytes(),
                &msg2_hash,
                &sig2.to_bytes(),
            )
            .unwrap();
        assert_eq!(sk.pubkey().to_bytes(), extracted_sk.pubkey().to_bytes());
    }
}
