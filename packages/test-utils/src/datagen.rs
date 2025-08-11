use babylon_apis::btc_staking_api::NewFinalityProvider;
use babylon_merkle::Proof;
use eots::{PrivateRand, PubRand};
use k256::ecdsa::signature::{Signer, Verifier};
use k256::schnorr::SigningKey;
use k256::schnorr::{Signature, VerifyingKey};
use rand::{CryptoRng, Rng, RngCore};

/// Generate random bytes of specified length using the provided RNG
pub fn gen_random_bytes<R: RngCore>(rng: &mut R, len: usize) -> Vec<u8> {
    (0..len).map(|_| rng.gen()).collect()
}

/// Generate a random EOTS key pair (PrivateRand, PubRand) for testing
pub fn gen_random_eots_keypair() -> (PrivateRand, PubRand) {
    eots::rand_gen()
}

/// Generate a random Schnorr signing key
pub fn gen_random_signing_key<R: RngCore + CryptoRng>(rng: &mut R) -> SigningKey {
    SigningKey::random(rng)
}

// Constants for message sizes - these should match the ones in btc-finality contract
pub const BIP340_PUB_KEY_LEN: usize = 32;
pub const SCHNORR_EOTS_SIG_LEN: usize = 32;
pub const SCHNORR_PUB_RAND_LEN: usize = 32;
pub const TMHASH_SIZE: usize = 32;

/// Message structure for committing public randomness
/// Note: This is a simplified version for test data generation
#[derive(Debug, Clone)]
pub struct TestMsgCommitPubRand {
    pub fp_btc_pk_hex: String,
    pub start_height: u64,
    pub num_pub_rand: u64,
    pub commitment: Vec<u8>,
    pub sig: Vec<u8>,
}

/// Message structure for adding finality signature
/// Note: This is a simplified version for test data generation
#[derive(Debug, Clone)]
pub struct TestMsgAddFinalitySig {
    pub fp_btc_pk_hex: String,
    pub height: u64,
    pub pub_rand: Vec<u8>,
    pub proof: Proof,
    pub block_app_hash: Vec<u8>,
    pub signature: Vec<u8>,
}

/// Create a signed message for public randomness commitment
pub fn commit_pub_rand_signed_message(
    signing_context: String,
    start_height: u64,
    num_pub_rand: u64,
    commitment: &[u8],
) -> Vec<u8> {
    // Create the message to be signed
    let mut msg = Vec::new();
    msg.extend_from_slice(signing_context.as_bytes());
    msg.extend_from_slice(&start_height.to_be_bytes());
    msg.extend_from_slice(&num_pub_rand.to_be_bytes());
    msg.extend_from_slice(commitment);
    msg
}

/// Generate a list of random public randomness values and return their commitment
pub fn gen_random_pub_rand_list_and_commitment(num_pub_rand: u64) -> Vec<u8> {
    let (_eots_sks, eots_pks): (Vec<_>, Vec<_>) =
        (0..num_pub_rand).map(|_| gen_random_eots_keypair()).unzip();

    // Compute the commitment using Merkle tree
    babylon_merkle::hash_from_byte_slices(
        eots_pks
            .into_iter()
            .map(|pk| pk.to_x_bytes())
            .collect::<Vec<_>>(),
    )
}

/// Generate a random message for public randomness commitment
pub fn gen_random_msg_commit_pub_rand(
    signing_key: &SigningKey,
    signing_context: &str,
    start_height: u64,
    num_pub_rand: u64,
) -> TestMsgCommitPubRand {
    let verifying_key_bytes = signing_key.verifying_key().to_bytes();

    let commitment = gen_random_pub_rand_list_and_commitment(num_pub_rand);

    let signed_msg = commit_pub_rand_signed_message(
        signing_context.to_string(),
        start_height,
        num_pub_rand,
        &commitment,
    );

    let sig = signing_key.sign(&signed_msg).to_bytes().to_vec();

    let fp_btc_pk_hex = hex::encode(verifying_key_bytes);

    // Verify the signature for consistency
    let btc_pk = VerifyingKey::from_bytes(&verifying_key_bytes).unwrap();
    let sig_to_verify = Signature::try_from(sig.as_slice()).unwrap();

    btc_pk
        .verify(&signed_msg, &sig_to_verify)
        .expect("Verifying signature must succeed");

    TestMsgCommitPubRand {
        fp_btc_pk_hex,
        start_height,
        num_pub_rand,
        commitment,
        sig,
    }
}

/// Generate a random message for adding finality signature
pub fn gen_random_msg_add_finality_sig<R: RngCore>(rng: &mut R) -> TestMsgAddFinalitySig {
    TestMsgAddFinalitySig {
        fp_btc_pk_hex: hex::encode(gen_random_bytes(rng, BIP340_PUB_KEY_LEN)),
        height: rng.gen_range(1..1000),
        pub_rand: gen_random_bytes(rng, SCHNORR_PUB_RAND_LEN),
        proof: Proof {
            total: 0,
            index: 0,
            leaf_hash: Default::default(),
            aunts: Default::default(),
        },
        block_app_hash: gen_random_bytes(rng, TMHASH_SIZE),
        signature: gen_random_bytes(rng, SCHNORR_EOTS_SIG_LEN),
    }
}

/// Generate a random NewFinalityProvider for testing
pub fn gen_random_new_finality_provider<R: RngCore>(rng: &mut R) -> NewFinalityProvider {
    let btc_pk_bytes = gen_random_bytes(rng, BIP340_PUB_KEY_LEN);
    let btc_pk_hex = hex::encode(btc_pk_bytes);

    // Create proof of possession by signing the finality provider's address
    let addr = format!("bbn{}", hex::encode(gen_random_bytes(rng, 20)));

    NewFinalityProvider {
        addr,
        btc_pk_hex,
        pop: None,
        consumer_id: format!("consumer-{}", rng.gen::<u32>()),
    }
}
