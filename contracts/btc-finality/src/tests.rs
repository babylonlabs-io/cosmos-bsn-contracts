use crate::error::{FinalitySigError, PubRandCommitError};
use crate::msg::{
    commit_pub_rand_signed_message, MsgAddFinalitySig, MsgCommitPubRand, BIP340_PUB_KEY_LEN,
    BIP340_SIGNATURE_LEN, COMMITMENT_LENGTH_BYTES, SCHNORR_EOTS_SIG_LEN, SCHNORR_PUB_RAND_LEN,
    TMHASH_SIZE,
};
use babylon_merkle::Proof;
use eots::{PrivateRand, PubRand};
use k256::ecdsa::signature::{Signer, Verifier};
use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

struct MsgTestCase<Msg, MsgErr> {
    name: &'static str,
    msg_modifier: fn(&mut Msg),
    expected: Result<(), MsgErr>,
}

type MsgCommitPubRandTestCase = MsgTestCase<MsgCommitPubRand, PubRandCommitError>;
type MsgAddFinalitySigTestCase = MsgTestCase<MsgAddFinalitySig, FinalitySigError>;

// Helper function to generate random bytes
fn gen_random_bytes(rng: &mut StdRng, len: usize) -> Vec<u8> {
    (0..len).map(|_| rng.gen()).collect()
}

struct RandListInfo {
    eots_sks: Vec<PrivateRand>,
    eots_pks: Vec<PubRand>,
    commitment: Vec<u8>,
}

fn gen_random_pub_rand_list(num_pub_rand: u64) -> RandListInfo {
    let (eots_sks, eots_pks): (Vec<_>, Vec<_>) =
        (0..num_pub_rand).map(|_| eots::rand_gen()).unzip();

    let commitment = babylon_merkle::hash_from_byte_slices(
        eots_pks
            .clone()
            .into_iter()
            .map(|pk| pk.to_x_bytes())
            .collect::<Vec<_>>(),
    );

    RandListInfo {
        eots_sks,
        eots_pks,
        commitment,
    }
}

// Helper function to generate random message
fn gen_random_msg_commit_pub_rand(
    rng: &mut StdRng,
    signing_context: &str,
    start_height: u64,
    num_pub_rand: u64,
) -> MsgCommitPubRand {
    let signing_key = SigningKey::random(rng);
    let verifying_key_bytes = signing_key.verifying_key().to_bytes();

    let commitment = gen_random_pub_rand_list(num_pub_rand).commitment;

    let signed_msg = commit_pub_rand_signed_message(
        signing_context.to_string(),
        start_height,
        num_pub_rand,
        &commitment,
    );

    let sig = signing_key.sign(&signed_msg).to_bytes().to_vec();

    let fp_btc_pk_hex = hex::encode(&verifying_key_bytes);

    let btc_pk_raw = hex::decode(&fp_btc_pk_hex).unwrap();
    let btc_pk = VerifyingKey::from_bytes(&btc_pk_raw).unwrap();
    let sig_to_verify = Signature::try_from(sig.as_slice()).unwrap();

    btc_pk
        .verify(&signed_msg, &sig_to_verify)
        .expect("Verifying signature must succeed");

    MsgCommitPubRand {
        fp_btc_pk_hex,
        start_height,
        num_pub_rand,
        commitment,
        sig,
    }
}

#[test]
fn test_xlc() {
    let mut rng = StdRng::seed_from_u64(1);
    let start_height = rng.gen_range(1..10);
    let num_pub_rand = rng.gen_range(1..100);
    gen_random_msg_commit_pub_rand(&mut rng, "test", start_height, num_pub_rand);
}

// https://github.com/babylonlabs-io/babylon/blob/49972e2d3e35caf0a685c37e1f745c47b75bfc69/x/finality/types/msg_test.go#L85
#[test]
fn test_msg_commit_pub_rand_validate_basic() {
    let mut rng = StdRng::seed_from_u64(1);

    let test_cases = vec![
        MsgCommitPubRandTestCase {
            name: "valid message",
            msg_modifier: |_msg| {
                // No modification needed for valid message
            },
            expected: Ok(()),
        },
        MsgCommitPubRandTestCase {
            name: "invalid commitment size",
            msg_modifier: |msg: &mut MsgCommitPubRand| {
                msg.commitment = b"too-short".to_vec();
            },
            expected: Err(PubRandCommitError::BadCommitmentLength(9)),
        },
        MsgCommitPubRandTestCase {
            name: "empty FP BTC PubKey",
            msg_modifier: |msg: &mut MsgCommitPubRand| {
                msg.fp_btc_pk_hex = Default::default();
            },
            expected: Err(PubRandCommitError::EmptyFpBtcPubKey),
        },
        MsgCommitPubRandTestCase {
            name: "empty signature",
            msg_modifier: |msg| {
                msg.sig = vec![];
            },
            expected: Err(PubRandCommitError::EmptySignature),
        },
    ];

    for MsgCommitPubRandTestCase {
        name,
        msg_modifier,
        expected,
    } in test_cases
    {
        let start_height = rng.gen_range(1..10);
        let num_pub_rand = rng.gen_range(1..100);
        let mut msg = gen_random_msg_commit_pub_rand(&mut rng, "test", start_height, num_pub_rand);

        // Apply the test case modifier
        msg_modifier(&mut msg);

        // Validate the message
        assert_eq!(msg.validate_basic(), expected, "Test case failed: {name}");
    }

    // overflow in block height
    let start_height = u64::MAX;
    let num_pub_rand = rng.gen_range(1..100);
    let msg = gen_random_msg_commit_pub_rand(&mut rng, "test", start_height, num_pub_rand);
    assert_eq!(
        msg.validate_basic(),
        Err(PubRandCommitError::OverflowInBlockHeight(
            start_height,
            num_pub_rand
        ))
    );
}

// https://github.com/babylonlabs-io/babylon/blob/49972e2d3e35caf0a685c37e1f745c47b75bfc69/x/finality/types/msg_test.go#L167
#[test]
fn test_msg_add_finality_sig_validate_basic() {
    let mut rng = StdRng::seed_from_u64(1);

    let test_cases = vec![
        MsgAddFinalitySigTestCase {
            name: "valid message",
            // No modification needed for valid message
            msg_modifier: |_| {},
            expected: Ok(()),
        },
        MsgAddFinalitySigTestCase {
            name: "empty FP BTC PubKey",
            msg_modifier: |msg| msg.fp_btc_pk_hex.clear(),
            expected: Err(FinalitySigError::EmptyFpBtcPk),
        },
        MsgAddFinalitySigTestCase {
            name: "invalid FP BTC PubKey length",
            msg_modifier: |msg| {
                msg.fp_btc_pk_hex = hex::encode(vec![0u8; 16]); // Too short
            },
            expected: Err(FinalitySigError::InvalidFpBtcPkLength {
                actual: 16,
                expected: 32,
            }),
        },
        MsgAddFinalitySigTestCase {
            name: "empty Public Randomness",
            msg_modifier: |msg| msg.pub_rand.clear(),
            expected: Err(FinalitySigError::InvalidPubRandLength {
                actual: 0,
                expected: 32,
            }),
        },
        MsgAddFinalitySigTestCase {
            name: "invalid Public Randomness length",
            msg_modifier: |msg| {
                msg.pub_rand = vec![0u8; 16]; // Too short
            },
            expected: Err(FinalitySigError::InvalidPubRandLength {
                actual: 16,
                expected: 32,
            }),
        },
        MsgAddFinalitySigTestCase {
            name: "empty finality signature",
            msg_modifier: |msg| msg.signature.clear(),
            expected: Err(FinalitySigError::InvalidFinalitySigLength {
                actual: 0,
                expected: 32,
            }),
        },
        MsgAddFinalitySigTestCase {
            name: "invalid finality signature length",
            msg_modifier: |msg| {
                msg.signature = vec![0u8; 16]; // Too short
            },
            expected: Err(FinalitySigError::InvalidFinalitySigLength {
                actual: 16,
                expected: 32,
            }),
        },
        MsgAddFinalitySigTestCase {
            name: "invalid block app hash length",
            msg_modifier: |msg| {
                msg.block_app_hash = vec![0u8; 16]; // Too short
            },
            expected: Err(FinalitySigError::InvalidBlockAppHashLength {
                actual: 16,
                expected: 32,
            }),
        },
    ];

    for MsgAddFinalitySigTestCase {
        name,
        msg_modifier,
        expected,
    } in test_cases
    {
        // Create a valid message
        let mut msg = MsgAddFinalitySig {
            fp_btc_pk_hex: hex::encode(gen_random_bytes(&mut rng, BIP340_PUB_KEY_LEN)),
            height: rng.gen_range(1..1000),
            pub_rand: gen_random_bytes(&mut rng, SCHNORR_PUB_RAND_LEN),
            proof: Proof {
                total: 0,
                index: 0,
                leaf_hash: Default::default(),
                aunts: Default::default(),
            },
            block_app_hash: gen_random_bytes(&mut rng, TMHASH_SIZE),
            signature: gen_random_bytes(&mut rng, SCHNORR_EOTS_SIG_LEN),
        };

        // Apply the test case modifier
        msg_modifier(&mut msg);

        assert_eq!(msg.validate_basic(), expected, "Test case failed: {name}");
    }
}
