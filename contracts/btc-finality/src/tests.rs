use crate::finality::{FinalitySigError, PubRandCommitError};
use crate::msg::{
    MsgAddFinalitySig, MsgCommitPubRand, BIP340_PUB_KEY_LEN, COMMITMENT_LENGTH_BYTES,
    SCHNORR_EOTS_SIG_LEN, SCHNORR_PUB_RAND_LEN, TMHASH_SIZE,
};
use babylon_merkle::Proof;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

// Helper function to generate random bytes
fn gen_random_bytes(rng: &mut StdRng, len: usize) -> Vec<u8> {
    (0..len).map(|_| rng.gen()).collect()
}

// Helper function to generate random BTC key pair
fn gen_random_btc_key_pair(rng: &mut StdRng) -> (Vec<u8>, Vec<u8>) {
    let sk = gen_random_bytes(rng, 32);
    let pk = gen_random_bytes(rng, 32);
    (sk, pk)
}

struct MsgTestCase<Msg, MsgErr> {
    name: &'static str,
    msg_modifier: fn(&mut Msg),
    expected: Result<(), MsgErr>,
}

type MsgCommitPubRandTestCase = MsgTestCase<MsgCommitPubRand, PubRandCommitError>;
type MsgAddFinalitySigTestCase = MsgTestCase<MsgAddFinalitySig, FinalitySigError>;

// Helper function to generate random message
fn gen_random_msg_commit_pub_rand(
    rng: &mut StdRng,
    start_height: u64,
    num_pub_rand: u64,
) -> MsgCommitPubRand {
    let (_, pk) = gen_random_btc_key_pair(rng);
    let commitment = gen_random_bytes(rng, COMMITMENT_LENGTH_BYTES);
    let sig = gen_random_bytes(rng, 64); // BIP340 signature length

    MsgCommitPubRand {
        fp_btc_pk_hex: hex::encode(&pk),
        start_height,
        num_pub_rand,
        commitment,
        sig,
    }
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
        let mut msg = gen_random_msg_commit_pub_rand(&mut rng, start_height, num_pub_rand);

        // Apply the test case modifier
        msg_modifier(&mut msg);

        // Validate the message
        assert_eq!(msg.validate_basic(), expected, "Test case failed: {name}");
    }

    // overflow in block height
    let start_height = rng.gen_range(1..10);
    let num_pub_rand = rng.gen_range(1..100);
    let mut msg = gen_random_msg_commit_pub_rand(&mut rng, start_height, num_pub_rand);
    msg.num_pub_rand = 0;
    assert_eq!(
        msg.validate_basic(),
        Err(PubRandCommitError::OverflowInBlockHeight(
            start_height,
            start_height
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
