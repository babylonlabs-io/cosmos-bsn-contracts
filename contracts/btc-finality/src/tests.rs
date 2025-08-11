use crate::error::{ContractError, FinalitySigError, PubRandCommitError};
use crate::msg::{
    commit_pub_rand_signed_message, MsgAddFinalitySig, MsgCommitPubRand, BIP340_PUB_KEY_LEN,
    SCHNORR_EOTS_SIG_LEN, SCHNORR_PUB_RAND_LEN, TMHASH_SIZE,
};
use crate::state::public_randomness::{get_pub_rand_commit_for_height, PUB_RAND_COMMITS};
use babylon_apis::finality_api::PubRandCommit;
use babylon_merkle::Proof;
use cosmwasm_std::testing::MockStorage;
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

fn gen_random_pub_rand_list_and_return_commitment(num_pub_rand: u64) -> Vec<u8> {
    let (_eots_sks, eots_pks): (Vec<_>, Vec<_>) =
        (0..num_pub_rand).map(|_| eots::rand_gen()).unzip();

    // Compute the commitment.
    babylon_merkle::hash_from_byte_slices(
        eots_pks
            .clone()
            .into_iter()
            .map(|pk| pk.to_x_bytes())
            .collect::<Vec<_>>(),
    )
}

// Helper function to generate random message
pub(crate) fn gen_random_msg_commit_pub_rand(
    signing_key: &SigningKey,
    signing_context: &str,
    start_height: u64,
    num_pub_rand: u64,
) -> MsgCommitPubRand {
    let verifying_key_bytes = signing_key.verifying_key().to_bytes();

    let commitment = gen_random_pub_rand_list_and_return_commitment(num_pub_rand);

    let signed_msg = commit_pub_rand_signed_message(
        signing_context.to_string(),
        start_height,
        num_pub_rand,
        &commitment,
    );

    let sig = signing_key.sign(&signed_msg).to_bytes().to_vec();

    let fp_btc_pk_hex = hex::encode(verifying_key_bytes);

    let btc_pk = VerifyingKey::from_bytes(&verifying_key_bytes).unwrap();
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

    let signing_key = SigningKey::random(&mut rng);

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

type MutateStoreFn = Box<dyn Fn(&mut MockStorage, &str)>;

// Test case structure
struct TestCase {
    name: &'static str,
    height: u64,
    valid: bool,
    expected_commitment: Option<Vec<u8>>,
    mutate_store: Option<MutateStoreFn>,
    err_msg: Option<ContractError>,
}

// Helper function to generate a mock BIP340 public key hex.
fn gen_random_bip340_pub_key_hex() -> String {
    "02".to_string() + &"0".repeat(62)
}

// Removes all commits under the key `fp_btc_pk_hex`.
fn delete_index(storage: &mut MockStorage, fp_btc_pk_hex: &str) {
    let keys_to_remove = PUB_RAND_COMMITS
        .prefix(fp_btc_pk_hex)
        .range(storage, None, None, cosmwasm_std::Order::Ascending)
        .filter_map(|item| {
            if let Ok((key, _)) = item {
                Some(key)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    for key in keys_to_remove {
        PUB_RAND_COMMITS.remove(storage, (fp_btc_pk_hex, key));
    }
}

// Setup test function for `test_get_pub_rand_commit_for_height`.
fn setup_test(fp_btc_pk_hex: &str) -> MockStorage {
    let mut storage = MockStorage::new();

    // Setup: Add 3 commits [0-9], [10-19], [20-29]
    for i in 0..3 {
        let commit = PubRandCommit {
            start_height: i * 10,
            num_pub_rand: 10,
            commitment: format!("commit-{i}").as_bytes().to_vec(),
            height: i,
        };

        PUB_RAND_COMMITS
            .save(&mut storage, (fp_btc_pk_hex, i * 10), &commit)
            .unwrap();
    }

    storage
}

#[test]
fn test_get_pub_rand_commit_for_height() {
    let fp_btc_pk_hex = gen_random_bip340_pub_key_hex();

    let tests = vec![
        TestCase {
            name: "height within first commit",
            height: 5,
            valid: true,
            expected_commitment: Some(b"commit-0".to_vec()),
            mutate_store: None,
            err_msg: None,
        },
        TestCase {
            name: "height at start of second commit",
            height: 10,
            valid: true,
            expected_commitment: Some(b"commit-1".to_vec()),
            mutate_store: None,
            err_msg: None,
        },
        TestCase {
            name: "height at end of last commit",
            height: 29,
            valid: true,
            expected_commitment: Some(b"commit-2".to_vec()),
            mutate_store: None,
            err_msg: None,
        },
        TestCase {
            name: "height before first commit",
            height: 0,
            valid: true,
            expected_commitment: Some(b"commit-0".to_vec()),
            mutate_store: None,
            err_msg: None,
        },
        TestCase {
            name: "height after all commits",
            height: 30,
            valid: false,
            expected_commitment: None,
            mutate_store: None,
            err_msg: None,
        },
        TestCase {
            name: "empty index",
            height: 5,
            valid: false,
            expected_commitment: None,
            mutate_store: Some(Box::new(|storage, fp_btc_pk_hex| {
                delete_index(storage, fp_btc_pk_hex);
            })),
            err_msg: Some(ContractError::MissingPubRandCommit(
                fp_btc_pk_hex.clone(),
                5,
            )),
        },
        TestCase {
            name: "commit data missing in store",
            height: 15,
            valid: false,
            expected_commitment: None,
            mutate_store: Some(Box::new(|storage, fp_btc_pk_hex| {
                // Deletes specific commit data.
                PUB_RAND_COMMITS.remove(storage, (fp_btc_pk_hex, 10));
            })),
            err_msg: Some(ContractError::MissingPubRandCommit(
                fp_btc_pk_hex.clone(),
                15,
            )),
        },
    ];

    for tc in tests {
        let mut storage = setup_test(&fp_btc_pk_hex);

        if let Some(mutate_fn) = tc.mutate_store {
            mutate_fn(&mut storage, &fp_btc_pk_hex);
        }

        let result = get_pub_rand_commit_for_height(&storage, &fp_btc_pk_hex, tc.height);

        if tc.valid {
            assert_eq!(
                result.unwrap().commitment,
                tc.expected_commitment.unwrap(),
                "Committments mismatch for test {}",
                tc.name
            );
        } else {
            assert!(result.is_err(), "Expected error for test: {}", tc.name);
            if let Some(expected_err_msg) = tc.err_msg {
                assert_eq!(result.unwrap_err(), expected_err_msg);
            }
        }
    }
}
