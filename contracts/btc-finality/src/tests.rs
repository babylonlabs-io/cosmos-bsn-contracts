use crate::error::{FinalitySigError, PubRandCommitError};
use crate::msg::{MsgAddFinalitySig, MsgCommitPubRand};
use babylon_test_utils::datagen::{
    gen_random_msg_add_finality_sig as gen_random_test_msg_add_finality_sig,
    gen_random_msg_commit_pub_rand as gen_random_test_msg_commit_pub_rand, gen_random_signing_key,
};
use k256::schnorr::SigningKey;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

struct MsgTestCase<Msg, MsgErr> {
    name: &'static str,
    msg_modifier: fn(&mut Msg),
    expected: Result<(), MsgErr>,
}

type MsgCommitPubRandTestCase = MsgTestCase<MsgCommitPubRand, PubRandCommitError>;
type MsgAddFinalitySigTestCase = MsgTestCase<MsgAddFinalitySig, FinalitySigError>;

pub(crate) fn gen_random_msg_commit_pub_rand(
    signing_key: &SigningKey,
    signing_context: &str,
    start_height: u64,
    num_pub_rand: u64,
) -> MsgCommitPubRand {
    let test_msg = gen_random_test_msg_commit_pub_rand(
        signing_key,
        signing_context,
        start_height,
        num_pub_rand,
    );
    MsgCommitPubRand {
        fp_btc_pk_hex: test_msg.fp_btc_pk_hex,
        start_height: test_msg.start_height,
        num_pub_rand: test_msg.num_pub_rand,
        commitment: test_msg.commitment,
        sig: test_msg.sig,
    }
}

pub(crate) fn gen_random_msg_add_finality_sig(rng: &mut StdRng) -> MsgAddFinalitySig {
    let test_msg = gen_random_test_msg_add_finality_sig(rng);
    MsgAddFinalitySig {
        fp_btc_pk_hex: test_msg.fp_btc_pk_hex,
        height: test_msg.height,
        pub_rand: test_msg.pub_rand,
        proof: test_msg.proof,
        block_app_hash: test_msg.block_app_hash,
        signature: test_msg.signature,
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

    let signing_key = gen_random_signing_key(&mut rng);

    for MsgCommitPubRandTestCase {
        name,
        msg_modifier,
        expected,
    } in test_cases
    {
        let start_height = rng.gen_range(1..10);
        let num_pub_rand = rng.gen_range(1..100);
        let mut msg =
            gen_random_msg_commit_pub_rand(&signing_key, "test", start_height, num_pub_rand);

        // Apply the test case modifier
        msg_modifier(&mut msg);

        // Validate the message
        assert_eq!(msg.validate_basic(), expected, "Test case failed: {name}");
    }

    // overflow in block height
    let start_height = u64::MAX;
    let num_pub_rand = rng.gen_range(1..100);
    let msg = gen_random_msg_commit_pub_rand(&signing_key, "test", start_height, num_pub_rand);
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
        let mut msg = gen_random_msg_add_finality_sig(&mut rng);

        // Apply the test case modifier
        msg_modifier(&mut msg);

        assert_eq!(msg.validate_basic(), expected, "Test case failed: {name}");
    }
}
