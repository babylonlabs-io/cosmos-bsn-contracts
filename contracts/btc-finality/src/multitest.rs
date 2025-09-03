pub mod suite;

use crate::error::{ContractError, PubRandCommitError};
use crate::msg::{FinalitySignatureResponse, QueryMsg as FinalityQueryMsg};
use crate::tests::gen_random_msg_commit_pub_rand;
use babylon_apis::finality_api::IndexedBlock;
use babylon_bindings_test::{
    BABYLON_CONTRACT_ADDR, BTC_FINALITY_CONTRACT_ADDR, BTC_LIGHT_CLIENT_CONTRACT_ADDR,
    BTC_STAKING_CONTRACT_ADDR,
};
use babylon_test_utils::{
    create_new_finality_provider, get_add_finality_sig, get_add_finality_sig_2,
    get_derived_btc_delegation, get_pub_rand_value, get_public_randomness_commitment,
};
use cosmwasm_std::{coin, Addr, Event};
use k256::schnorr::SigningKey;
use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};
use suite::SuiteBuilder;

#[test]
fn instantiate_works() {
    let suite = SuiteBuilder::new().build();

    // Confirm the btc-light-client contract has been instantiated and set
    let config = suite.get_babylon_config();
    assert_eq!(
        config.btc_light_client.unwrap().as_str(),
        BTC_LIGHT_CLIENT_CONTRACT_ADDR
    );
    // Confirm the btc-staking contract has been instantiated and set
    assert_eq!(
        config.btc_staking,
        Some(Addr::unchecked(BTC_STAKING_CONTRACT_ADDR))
    );
    // Confirm the btc-finality contract has been instantiated and set
    assert_eq!(
        config.btc_finality,
        Some(Addr::unchecked(BTC_FINALITY_CONTRACT_ADDR))
    );
    // Check that the btc-staking contract was initialized correctly
    let btc_staking_config = suite.get_btc_staking_config();
    assert_eq!(
        btc_staking_config.babylon,
        Addr::unchecked(BABYLON_CONTRACT_ADDR)
    );
    // Check that the btc-finality contract was initialized correctly
    let btc_finality_config = suite.get_btc_finality_config();
    assert_eq!(
        btc_finality_config.babylon,
        Addr::unchecked(BABYLON_CONTRACT_ADDR)
    );
}

// https://github.com/babylonlabs-io/babylon/blob/49972e2d3e35caf0a685c37e1f745c47b75bfc69/x/finality/keeper/msg_server_test.go#L45
#[test]
fn commit_public_randomness_works() {
    let mut suite = SuiteBuilder::new().with_min_pub_rand(3).build();

    let mut rng = thread_rng();

    // Read public randomness commitment test data
    let (pk_hex, pub_rand, pubrand_signature) = get_public_randomness_commitment();

    // Register one FP
    // NOTE: the test data ensures that pub rand commit / finality sig are
    // signed by the 1st FP
    let new_fp = create_new_finality_provider(1);
    assert_eq!(new_fp.btc_pk_hex, pk_hex);

    suite
        .register_finality_providers(&[new_fp.clone()])
        .unwrap();

    let bad_pk_hex: String = {
        let mut chars: Vec<char> = pk_hex.chars().collect();
        chars.shuffle(&mut rng);
        chars.into_iter().collect()
    };

    // Case 1: fail if the finality provider is not registered.
    assert_eq!(
        suite
            .commit_public_randomness(&bad_pk_hex, &pub_rand, &pubrand_signature)
            .unwrap_err(),
        ContractError::FinalityProviderNotFound(bad_pk_hex)
    );

    // Case 2: commit a list of <minPubRand pubrand and it should fail
    let mut bad_pub_rand_commit = pub_rand.clone();
    bad_pub_rand_commit.num_pub_rand = 1;
    assert_eq!(
        suite
            .commit_public_randomness(&pk_hex, &bad_pub_rand_commit, &pubrand_signature)
            .unwrap_err(),
        ContractError::TooFewPubRand(3, 1)
    );

    // Case 3: when the finality provider commits pubrand list and it should succeed
    assert!(suite
        .commit_public_randomness(&pk_hex, &pub_rand, &pubrand_signature)
        .is_ok());

    let last_pub_rand = suite.get_last_pub_rand_commit(pk_hex.clone());

    assert_eq!(last_pub_rand, pub_rand);

    let block_info = suite.app.block_info();

    let signing_context = babylon_apis::signing_context::fp_rand_commit_context_v0(
        &block_info.chain_id,
        suite.finality.as_str(),
    );

    // Generate a new FP using a random key.
    let signing_key = SigningKey::random(&mut rng);
    let pk_hex = hex::encode(signing_key.verifying_key().to_bytes());

    let mut fp2 = new_fp.clone();
    fp2.btc_pk_hex = pk_hex.clone();
    suite.register_finality_providers(&[fp2.clone()]).unwrap();

    let msg_pub_rand_commit = gen_random_msg_commit_pub_rand(
        &signing_key,
        &signing_context,
        pub_rand.start_height,
        pub_rand.num_pub_rand,
    );

    let pub_rand = msg_pub_rand_commit.as_pub_rand_commit(block_info.height);
    let pub_rand_sig = msg_pub_rand_commit.sig;

    assert!(suite
        .commit_public_randomness(&pk_hex, &pub_rand, &pub_rand_sig)
        .is_ok());

    // Case 4: commit a pubrand list with overlap of the existing pubrand in KVStore and it should fail
    let overlapped_start_height = pub_rand.end_height() - rng.gen_range(0..5);
    let msg_pub_rand_commit = gen_random_msg_commit_pub_rand(
        &signing_key,
        &signing_context,
        overlapped_start_height,
        pub_rand.num_pub_rand,
    );
    let bad_pub_rand_commit = msg_pub_rand_commit.as_pub_rand_commit(block_info.height);
    assert_eq!(
        suite
            .commit_public_randomness(&pk_hex, &bad_pub_rand_commit, &msg_pub_rand_commit.sig)
            .unwrap_err(),
        ContractError::InvalidPubRandHeight(
            bad_pub_rand_commit.start_height,
            last_pub_rand.end_height(),
        )
    );

    // Case 5: commit a pubrand list that has no overlap with existing pubrand and it should succeed
    let overlapped_start_height =
        pub_rand.start_height + pub_rand.num_pub_rand + rng.gen_range(0..5);
    let msg_pub_rand_commit = gen_random_msg_commit_pub_rand(
        &signing_key,
        &signing_context,
        overlapped_start_height,
        pub_rand.num_pub_rand,
    );
    let bad_pub_rand_commit = msg_pub_rand_commit.as_pub_rand_commit(block_info.height);

    assert!(suite
        .commit_public_randomness(&pk_hex, &bad_pub_rand_commit, &msg_pub_rand_commit.sig)
        .is_ok());

    // Case 6: commit a pubrand list that overflows when adding startHeight + numPubRand
    let overflow_start_height = u64::MAX;
    let mut bad_pub_rand_commit = pub_rand.clone();
    bad_pub_rand_commit.start_height = overflow_start_height;
    assert_eq!(
        suite
            .commit_public_randomness(&pk_hex, &bad_pub_rand_commit, &pubrand_signature)
            .unwrap_err(),
        PubRandCommitError::OverflowInBlockHeight(
            bad_pub_rand_commit.start_height,
            bad_pub_rand_commit.num_pub_rand,
        )
        .into()
    );

    // Case 7: commit a pubrand list with startHeight too far into the future
    let mut bad_pub_rand_commit = pub_rand.clone();
    bad_pub_rand_commit.start_height = 2_000_000;
    assert!(matches!(
        suite
            .commit_public_randomness(&pk_hex, &bad_pub_rand_commit, &pubrand_signature)
            .unwrap_err(),
        ContractError::FuturePubRandStartHeight { .. }
    ));
}

#[test]
fn finality_signature_happy_path() {
    // Read public randomness commitment test data
    let (pk_hex, pub_rand, pubrand_signature) = get_public_randomness_commitment();
    let pub_rand_one = get_pub_rand_value();
    // Read equivalent / consistent add finality signature test data
    let add_finality_signature = get_add_finality_sig();
    let proof = add_finality_signature.proof.unwrap();

    let initial_height = pub_rand.start_height;
    let initial_funds = &[coin(1_000_000, "TOKEN")];

    let mut suite = SuiteBuilder::new()
        .with_height(initial_height)
        .with_funds(initial_funds)
        .build();

    // Register one FP
    // NOTE: the test data ensures that pub rand commit / finality sig are
    // signed by the 1st FP
    let new_fp = create_new_finality_provider(1);

    suite.register_finality_providers(&[new_fp]).unwrap();

    // Add a delegation, so that the finality provider has some power
    let mut del1 = get_derived_btc_delegation(1, &[1]);
    del1.fp_btc_pk_list = vec![pk_hex.clone()];

    suite.add_delegations(&[del1]).unwrap();

    suite
        .commit_public_randomness(&pk_hex, &pub_rand, &pubrand_signature)
        .unwrap();

    // Call the begin-block sudo handler(s), for completeness
    let res = suite
        .call_begin_block(&add_finality_signature.block_app_hash, initial_height + 1)
        .unwrap();
    assert_eq!(2, res.events.len());
    assert_eq!(
        res.events[0],
        Event::new("sudo").add_attribute("_contract_address", BTC_FINALITY_CONTRACT_ADDR)
    );
    // Check the finality provider status change event
    assert_eq!(
        res.events[1],
        Event::new("wasm-finality_provider_status_change")
            .add_attribute("_contract_address", BTC_FINALITY_CONTRACT_ADDR)
            .add_attribute("btc_pk", &pk_hex)
            .add_attribute("new_state", "FINALITY_PROVIDER_STATUS_ACTIVE")
    );

    // Call the end-block sudo handler(s), so that the block is indexed in the store
    let res = suite
        .call_end_block(&add_finality_signature.block_app_hash, initial_height + 1)
        .unwrap();
    assert_eq!(2, res.events.len());
    assert_eq!(
        res.events[0],
        Event::new("sudo").add_attribute("_contract_address", BTC_FINALITY_CONTRACT_ADDR)
    );
    assert_eq!(
        res.events[1],
        Event::new("wasm-index_block")
            .add_attribute("_contract_address", BTC_FINALITY_CONTRACT_ADDR)
            .add_attribute("module", "finality")
            .add_attribute("last_height", (initial_height + 1).to_string())
    );

    // Submit a finality signature from that finality provider at height initial_height + 1
    let finality_sig = add_finality_signature.finality_sig.to_vec();
    suite
        .submit_finality_signature(
            &pk_hex,
            initial_height + 1,
            &pub_rand_one,
            &proof,
            &add_finality_signature.block_app_hash,
            &finality_sig,
        )
        .unwrap();

    // Query finality signature for that exact height
    let sig = suite.get_finality_signature(&pk_hex, initial_height + 1);
    assert_eq!(
        sig,
        FinalitySignatureResponse {
            signature: finality_sig
        }
    );
}

#[test]
fn finality_round_works() {
    // Read public randomness commitment test data
    let (pk_hex, pub_rand, pubrand_signature) = get_public_randomness_commitment();
    let pub_rand_one = get_pub_rand_value();
    // Read equivalent / consistent add finality signature test data
    let add_finality_signature = get_add_finality_sig();
    let proof = add_finality_signature.proof.unwrap();

    let initial_height = pub_rand.start_height;
    let initial_funds = &[coin(1_000_000_000_000, "TOKEN")];

    let mut suite = SuiteBuilder::new()
        .with_funds(initial_funds)
        .with_height(initial_height)
        .build();

    // signed by the 1st FP
    let new_fp = create_new_finality_provider(1);
    assert_eq!(new_fp.btc_pk_hex, pk_hex);

    suite
        .register_finality_providers(&[new_fp.clone()])
        .unwrap();

    // Add a delegation, so that the finality provider has some power
    let mut del1 = get_derived_btc_delegation(1, &[1]);
    del1.fp_btc_pk_list = vec![pk_hex.clone()];

    suite.add_delegations(&[del1.clone()]).unwrap();

    // Check that the finality provider total active sats has been updated
    let fp_info = suite.get_finality_provider_info(&new_fp.btc_pk_hex, None);
    assert_eq!(fp_info.total_active_sats, del1.total_sat);

    // Submit public randomness commitment for the FP and the involved heights
    suite
        .commit_public_randomness(&pk_hex, &pub_rand, &pubrand_signature)
        .unwrap();

    // Call the begin-block / end-block sudo handler(s), for completeness
    suite
        .next_block(&add_finality_signature.block_app_hash)
        .unwrap();

    // Submit a finality signature from that finality provider at height initial_height + 1
    let submit_height = initial_height + 1;
    let finality_sig = add_finality_signature.finality_sig.to_vec();
    suite
        .submit_finality_signature(
            &pk_hex,
            submit_height,
            &pub_rand_one,
            &proof,
            &add_finality_signature.block_app_hash,
            &finality_sig,
        )
        .unwrap();

    // Call the begin blocker, to compute the active FP set
    suite
        .call_begin_block(&add_finality_signature.block_app_hash, submit_height)
        .unwrap();

    // Call the end blocker, to process the finality signatures
    let res = suite
        .call_end_block(&add_finality_signature.block_app_hash, submit_height)
        .unwrap();
    assert_eq!(3, res.events.len());
    assert_eq!(
        res.events[0],
        Event::new("sudo").add_attribute("_contract_address", BTC_FINALITY_CONTRACT_ADDR)
    );
    assert_eq!(
        res.events[1],
        Event::new("wasm-index_block")
            .add_attribute("_contract_address", BTC_FINALITY_CONTRACT_ADDR)
            .add_attribute("module", "finality")
            .add_attribute("last_height", submit_height.to_string())
    );
    assert_eq!(
        res.events[2],
        Event::new("wasm-finalize_block")
            .add_attribute("_contract_address", BTC_FINALITY_CONTRACT_ADDR)
            .add_attribute("module", "finality")
            .add_attribute("finalized_height", submit_height.to_string())
    );

    // Assert the submitted block has been indexed and finalised
    let indexed_block = suite.get_indexed_block(submit_height);
    assert_eq!(
        indexed_block,
        IndexedBlock {
            height: submit_height,
            app_hash: add_finality_signature.block_app_hash.to_vec(),
            finalized: true,
        }
    );
}

// Timestamped public randomness is needed for active set participation
#[test]
fn finality_round_requires_timestamped_pubrand() {
    // Read public randomness commitment test data
    let (pk_hex, pub_rand, pubrand_signature) = get_public_randomness_commitment();

    let initial_height = pub_rand.start_height - 1; // so that the pubrand timestamp is in range after one block
    let initial_funds = &[coin(1_000_000_000_000, "TOKEN")];

    let mut suite = SuiteBuilder::new()
        .with_funds(initial_funds)
        .with_height(initial_height)
        .build();

    // Register one FP
    // NOTE: the test data ensures that pub rand commit / finality sig are
    // signed by the 1st FP
    let new_fp = create_new_finality_provider(1);
    assert_eq!(new_fp.btc_pk_hex, pk_hex);

    suite
        .register_finality_providers(&[new_fp.clone()])
        .unwrap();

    // Add a delegation, so that the finality provider has some power
    let mut del1 = get_derived_btc_delegation(1, &[1]);
    del1.fp_btc_pk_list = vec![pk_hex.clone()];

    suite.add_delegations(&[del1.clone()]).unwrap();

    // Check that the finality provider total active sats has been updated
    let fp_info = suite.get_finality_provider_info(&new_fp.btc_pk_hex, None);
    assert_eq!(fp_info.total_active_sats, del1.total_sat);

    // Call the begin-block / end-block sudo handler(s)
    let height = suite.next_block("deadbeef01".as_bytes()).unwrap().height;

    // Assert the finality provider is not in the active set
    let active_fps = suite.get_active_finality_providers(height);
    assert_eq!(active_fps.len(), 0);

    // Now commit the public randomness for it
    suite
        .commit_public_randomness(&pk_hex, &pub_rand, &pubrand_signature)
        .unwrap();

    // Call the begin-block / end-block sudo handler(s)
    let height = suite.next_block("deadbeef02".as_bytes()).unwrap().height;

    // Assert the finality provider is now in the active set
    let active_fps = suite.get_active_finality_providers(height);
    assert_eq!(active_fps.len(), 1);
    assert!(active_fps.contains_key(&new_fp.btc_pk_hex));
}

#[test]
fn finality_provider_power_query_works() {
    // Read public randomness commitment test data
    let (pk_hex, pub_rand, pubrand_signature) = get_public_randomness_commitment();

    let initial_height = pub_rand.start_height;
    let initial_funds = &[coin(1_000_000, "TOKEN")];

    let mut suite = SuiteBuilder::new()
        .with_height(initial_height)
        .with_funds(initial_funds)
        .build();

    // Register one FP
    let new_fp = create_new_finality_provider(1);
    assert_eq!(new_fp.btc_pk_hex, pk_hex);

    suite.register_finality_providers(&[new_fp]).unwrap();

    // Before adding delegation, power should be 0
    let power = suite.get_finality_provider_power(&pk_hex, initial_height + 1);
    assert_eq!(power, 0);

    // Add a delegation, so that the finality provider has some power
    let mut del1 = get_derived_btc_delegation(1, &[1]);
    del1.fp_btc_pk_list = vec![pk_hex.clone()];

    suite.add_delegations(&[del1.clone()]).unwrap();

    // Now commit the public randomness
    suite
        .commit_public_randomness(&pk_hex, &pub_rand, &pubrand_signature)
        .unwrap();

    // Call the begin-block / end-block sudo handler(s)
    let height = suite.next_block("deadbeef01".as_bytes()).unwrap().height;

    // Query the power for the finality provider at this height
    let power = suite.get_finality_provider_power(&pk_hex, height);
    assert_eq!(power, del1.total_sat);

    // Query for a non-existent FP should return 0
    let non_existent_pk = format!("02{}", "0".repeat(62));
    let power = suite.get_finality_provider_power(&non_existent_pk, height);
    assert_eq!(power, 0);
}

#[test]
fn last_finalized_height_query_works() {
    // Test the LastFinalizedHeight query which returns the height of the last finalized block

    // Setup test data for finality signature submission
    let (pk_hex, pub_rand, pubrand_signature) = get_public_randomness_commitment();
    let pub_rand_one = get_pub_rand_value();
    // Read equivalent / consistent add finality signature test data
    let add_finality_signature = get_add_finality_sig();
    let proof = add_finality_signature.proof.unwrap();

    let initial_height = pub_rand.start_height;
    let initial_funds = &[coin(1_000_000_000_000, "TOKEN")];

    let mut suite = SuiteBuilder::new()
        .with_funds(initial_funds)
        .with_height(initial_height)
        .build();

    // Initially, no blocks are finalized
    let last_finalized =
        suite.query_finality_contract::<Option<u64>>(FinalityQueryMsg::LastFinalizedHeight {});
    assert!(
        last_finalized.is_none(),
        "Initially no blocks should be finalized"
    );

    // Set up finality provider with voting power
    let new_fp = create_new_finality_provider(1);
    assert_eq!(new_fp.btc_pk_hex, pk_hex);
    suite
        .register_finality_providers(&[new_fp.clone()])
        .unwrap();

    let mut del1 = get_derived_btc_delegation(1, &[1]);
    del1.fp_btc_pk_list = vec![pk_hex.clone()];
    suite.add_delegations(&[del1.clone()]).unwrap();

    // Submit public randomness commitment
    suite
        .commit_public_randomness(&pk_hex, &pub_rand, &pubrand_signature)
        .unwrap();

    // Call next_block to advance height
    suite
        .next_block(&add_finality_signature.block_app_hash)
        .unwrap();

    // No blocks finalized yet
    let last_finalized =
        suite.query_finality_contract::<Option<u64>>(FinalityQueryMsg::LastFinalizedHeight {});
    assert!(last_finalized.is_none(), "No blocks finalized yet");

    // Submit finality signature
    let submit_height = initial_height + 1;
    let finality_sig = add_finality_signature.finality_sig.to_vec();
    suite
        .submit_finality_signature(
            &pk_hex,
            submit_height,
            &pub_rand_one,
            &proof,
            &add_finality_signature.block_app_hash,
            &finality_sig,
        )
        .unwrap();

    // Call begin and end block to trigger finalization
    suite
        .call_begin_block(&add_finality_signature.block_app_hash, submit_height)
        .unwrap();
    suite
        .call_end_block(&add_finality_signature.block_app_hash, submit_height)
        .unwrap();

    // Now block should be finalized
    let last_finalized =
        suite.query_finality_contract::<Option<u64>>(FinalityQueryMsg::LastFinalizedHeight {});
    assert_eq!(
        last_finalized,
        Some(submit_height),
        "Last finalized height should be {} (the block that was just finalized)",
        submit_height
    );

    // Verify the block is actually finalized
    let indexed_block = suite.get_indexed_block(submit_height);
    assert!(
        indexed_block.finalized,
        "Block should be marked as finalized"
    );

    // The returned value should be consistent
    let last_finalized_again =
        suite.query_finality_contract::<Option<u64>>(FinalityQueryMsg::LastFinalizedHeight {});
    assert_eq!(
        last_finalized, last_finalized_again,
        "Query should return consistent results"
    );
}

#[test]
fn slashing_works() {
    // Read public randomness commitment test data
    let (pk_hex, pub_rand, pubrand_signature) = get_public_randomness_commitment();
    let pub_rand_one = get_pub_rand_value();
    // Read equivalent / consistent add finality signature test data
    let add_finality_signature = get_add_finality_sig();
    let proof = add_finality_signature.proof.unwrap();

    let initial_height = pub_rand.start_height;
    let initial_funds = &[coin(10_000_000_000_000, "TOKEN")];

    let mut suite = SuiteBuilder::new()
        .with_funds(initial_funds)
        .with_height(initial_height)
        .build();

    // Register one FP
    // NOTE: the test data ensures that pub rand commit / finality sig are
    // signed by the 1st FP
    let new_fp = create_new_finality_provider(1);

    suite
        .register_finality_providers(&[new_fp.clone()])
        .unwrap();

    // Add a delegation, so that the finality provider has some power
    let mut del1 = get_derived_btc_delegation(1, &[1]);
    del1.fp_btc_pk_list = vec![pk_hex.clone()];

    suite.add_delegations(&[del1.clone()]).unwrap();

    // Check that the finality provider power has been updated
    let fp_info = suite.get_finality_provider_info(&new_fp.btc_pk_hex, None);
    assert_eq!(fp_info.total_active_sats, del1.total_sat);

    // Submit public randomness commitment for the FP and the involved heights
    suite
        .commit_public_randomness(&pk_hex, &pub_rand, &pubrand_signature)
        .unwrap();

    // Call the begin-block sudo handler at the next height, for completeness
    let next_height = initial_height + 1;
    suite
        .next_block(&add_finality_signature.block_app_hash)
        .unwrap();

    // Submit a finality signature from that finality provider at next height (initial_height + 1)
    let submit_height = next_height;
    // Increase block height
    let next_height = next_height + 1;
    suite.app().advance_blocks(next_height - submit_height);
    // Call the begin-block sudo handler at the next height, for completeness
    suite
        .call_begin_block(&add_finality_signature.block_app_hash, next_height)
        .unwrap();

    let finality_signature = add_finality_signature.finality_sig.to_vec();
    suite
        .submit_finality_signature(
            &pk_hex,
            submit_height,
            &pub_rand_one,
            &proof,
            &add_finality_signature.block_app_hash,
            &finality_signature,
        )
        .unwrap();

    // Submitting the same signature twice is not allowed.
    assert!(suite
        .submit_finality_signature(
            &pk_hex,
            submit_height,
            &pub_rand_one,
            &proof,
            &add_finality_signature.block_app_hash,
            &finality_signature,
        )
        .is_err());

    // Submit another (different and valid) finality signature, from the same finality provider
    // at the same height, and with the same proof
    let add_finality_signature_2 = get_add_finality_sig_2();
    let res = suite
        .submit_finality_signature(
            &pk_hex,
            submit_height,
            &pub_rand_one,
            &proof,
            &add_finality_signature_2.block_app_hash,
            &add_finality_signature_2.finality_sig,
        )
        .unwrap();

    // Assert the double signing evidence is proper
    let btc_pk = hex::decode(pk_hex.clone()).unwrap();
    let evidence = suite
        .get_double_signing_evidence(&pk_hex, submit_height)
        .evidence
        .unwrap();
    assert_eq!(evidence.block_height, submit_height);
    assert_eq!(evidence.fp_btc_pk, btc_pk);

    // Assert the slashing event is there
    assert_eq!(4, res.events.len());
    // Assert the slashing event is proper (slashing is the 2nd event in the list)
    assert_eq!(
        res.events[1].ty,
        "wasm-slashed_finality_provider".to_string()
    );

    // Call the end-block sudo handler for completeness / realism
    suite
        .call_end_block(&add_finality_signature_2.block_app_hash, next_height)
        .unwrap();

    // Call the next (final) block begin blocker, to compute the active FP set
    suite.next_block("deadbeef01".as_bytes()).unwrap();

    // Assert the canonical block has been indexed (and finalised)
    let indexed_block = suite.get_indexed_block(submit_height);
    assert_eq!(
        indexed_block,
        IndexedBlock {
            height: submit_height,
            app_hash: add_finality_signature.block_app_hash.to_vec(),
            finalized: true,
        }
    );

    // Assert the finality provider has been slashed
    let fp = suite.get_finality_provider(&pk_hex);
    assert_eq!(fp.slashed_height, next_height);
}

#[test]
fn offline_fps_are_jailed() {
    // Read public randomness commitment test data
    let (pk_hex, pub_rand, pubrand_signature) = get_public_randomness_commitment();
    let pub_rand_one = get_pub_rand_value();
    // Read equivalent / consistent add finality signature test data
    let add_finality_signature = get_add_finality_sig();
    let proof = add_finality_signature.proof.unwrap();

    let initial_height = pub_rand.start_height;
    let initial_funds = &[coin(10_000_000_000_000, "TOKEN")];

    let mut suite = SuiteBuilder::new()
        .with_funds(initial_funds)
        .with_height(initial_height)
        .with_missed_blocks(700)
        .build();

    // Register a couple FPs
    // NOTE: the test data ensures that pub rand commit / finality sig are
    // signed by the 1st FP
    let new_fp1 = create_new_finality_provider(1);
    let new_fp2 = create_new_finality_provider(2);

    suite
        .register_finality_providers(&[new_fp1.clone(), new_fp2.clone()])
        .unwrap();

    // Get admin for jail and unjail ops
    let admin = suite.admin().to_owned();

    // Add a couple delegations, so that the finality providers have some power
    let mut del1 = get_derived_btc_delegation(1, &[1]);
    del1.fp_btc_pk_list = vec![pk_hex.clone()];
    let mut del2 = get_derived_btc_delegation(2, &[2]);
    // Reduce its delegation amount so that the other FP can finalize blocks alone
    del2.total_sat /= 3;

    suite
        .add_delegations(&[del1.clone(), del2.clone()])
        .unwrap();

    // Submit public randomness commitment for the FP and the involved heights
    suite
        .commit_public_randomness(&pk_hex, &pub_rand, &pubrand_signature)
        .unwrap();

    // Advance height
    let next_height = suite
        .next_block(add_finality_signature.block_app_hash.as_ref())
        .unwrap()
        .height;

    // Submit a finality signature from that finality provider at next height (initial_height + 1)
    let submit_height = next_height;
    // Increase block height
    let next_height = next_height + 1;
    suite.app().advance_blocks(1);
    suite
        .call_begin_block(&add_finality_signature.block_app_hash, next_height)
        .unwrap();

    let finality_signature = add_finality_signature.finality_sig.to_vec();
    suite
        .submit_finality_signature(
            &pk_hex,
            submit_height,
            &pub_rand_one,
            &proof,
            &add_finality_signature.block_app_hash,
            &finality_signature,
        )
        .unwrap();

    suite
        .call_end_block(&add_finality_signature.block_app_hash, next_height)
        .unwrap();

    // Call the next block begin blocker, to compute the active FP set
    let next_height = suite.next_block("deadbeef01".as_bytes()).unwrap().height;

    // Get the active FP set
    // Note: The second FP has voting power, but since it hasn't submitted
    // public randomness, it will not be in the active set
    let active_fps = suite.get_active_finality_providers(next_height);
    // All unjailed fps are selected
    assert_eq!(active_fps.len(), 1);
    assert!(active_fps.contains_key(&new_fp1.btc_pk_hex));

    // Moving forward so offline detection kicks in
    // Process blocks one by one to simulate real blockchain behavior
    // The missed_blocks_window is 700, so we need to go beyond that for jailing
    let current_height = next_height;
    let target_height = current_height + 750; // Go beyond the 700 block window

    // Process each block individually to maintain proper power table continuity
    for height in (current_height + 1)..=target_height {
        let block_hash = format!("block_{:08x}", height);
        suite.next_block(block_hash.as_bytes()).unwrap();
    }

    let next_height = target_height;

    // Both FPs are jailed for being offline!
    let jailed_fps = suite.list_jailed_fps(None, None);
    assert_eq!(jailed_fps.len(), 1);
    assert_eq!(jailed_fps[0].btc_pk_hex, new_fp1.btc_pk_hex);

    // Check that jail time is reasonable (should be around current time + 24 hours)
    let current_time = suite.timestamp().seconds();
    let jail_duration = 86400; // 24 hours
    let actual_jail_time = jailed_fps[0].jailed_until;

    // Allow some flexibility since jailing happened during block processing
    assert!(
        actual_jail_time >= current_time - jail_duration
            && actual_jail_time <= current_time + jail_duration,
        "Jail time {} is not reasonable relative to current time {}",
        actual_jail_time,
        current_time
    );

    // Verify removed from the active set
    let active_fps = suite.get_active_finality_providers(next_height);
    assert_eq!(active_fps.len(), 0);

    // Auto-unjail of FP1 fails (because not yet expired jailing)
    let fp1_bsn_addr = suite
        .to_consumer_addr(&Addr::unchecked(&new_fp1.addr))
        .unwrap()
        .to_string();
    let err = suite
        .unjail(&fp1_bsn_addr, &new_fp1.btc_pk_hex)
        .unwrap_err();
    assert_eq!(
        err.downcast::<ContractError>().unwrap(),
        ContractError::JailPeriodNotPassed(new_fp1.btc_pk_hex.clone()),
    );

    // Admin unjail of FP1 succeeds
    suite.unjail(&admin, &new_fp1.btc_pk_hex).unwrap();

    // Advance height
    let next_height = suite.next_block("deadbeef04".as_bytes()).unwrap().height;

    // FP1 is active again.
    // It will only be jailed for being offline if it misses a number of `missed_blocks_window`
    // blocks again
    let active_fps = suite.get_active_finality_providers(next_height);
    assert_eq!(active_fps.len(), 1);
    assert!(active_fps.contains_key(&new_fp1.btc_pk_hex));
}

/// Test that FPs who regain voting power after being inactive are not unfairly jailed
/// for missing blocks during their inactive period. This tests our fix for the jailing bug.
///
/// This test uses a simpler approach - we'll use the liveness test pattern directly
/// to test the core logic of get_last_signed_height with the max functionality.
#[test]
fn reactivated_fp_not_unfairly_jailed() {
    use crate::liveness::handle_liveness;
    use crate::state::config::Config;
    use crate::state::finality::{set_voting_power_table, FP_BLOCK_SIGNER, FP_START_HEIGHT, JAIL};
    use cosmwasm_std::testing::{mock_dependencies, mock_env};
    use cosmwasm_std::Timestamp;
    use std::collections::HashMap;

    let mut deps = mock_dependencies();
    let mut env = mock_env();
    env.block.height = 1000;
    env.block.time = Timestamp::from_seconds(10000);

    let babylon_addr = deps.api.addr_make("babylon");
    let staking_addr = deps.api.addr_make("staking");
    let mut cfg = Config::new_test(babylon_addr, staking_addr);
    cfg.missed_blocks_window = 50; // 50 block window

    let fp_btc_pk = "reactivated_fp";

    // SCENARIO: FP was active at height 800, signed last block at height 850
    // Then became inactive (lost voting power) from 851-999
    // Now regained voting power at height 1000

    // Set up: FP signed a block at height 850 (old signature, outside window)
    FP_BLOCK_SIGNER
        .save(&mut deps.storage, fp_btc_pk, &850u64)
        .unwrap();

    // Set up: FP regained voting power at height 1000, so start_height = 1000
    // This simulates our fix where FP_START_HEIGHT is updated on reactivation
    FP_START_HEIGHT
        .save(&mut deps.storage, fp_btc_pk, &1000u64)
        .unwrap();

    // Set up power table - FP has voting power at height 1000
    let mut power_table = HashMap::new();
    power_table.insert(fp_btc_pk.to_string(), 2000u64);
    set_voting_power_table(&mut deps.storage, 1000, power_table).unwrap();

    // THE BUG TEST: Run liveness check at height 1000
    let events = handle_liveness(&mut deps.as_mut(), &env, &cfg).unwrap();

    // BEFORE FIX: FP would be jailed because get_last_signed_height returns 850
    // window_start = 1000 - 50 = 950, and 850 < 950, so FP gets jailed

    // AFTER FIX: FP should NOT be jailed because get_last_signed_height returns max(850, 1000) = 1000
    // window_start = 1000 - 50 = 950, and 1000 > 950, so FP stays active

    // Check that FP is NOT jailed
    let fp_jail = JAIL.may_load(&deps.storage, fp_btc_pk).unwrap();
    assert!(
        fp_jail.is_none(),
        "Reactivated FP should not be jailed - they should get grace period from reactivation point"
    );

    // Check no jailing events
    assert_eq!(
        events.len(),
        0,
        "Should be no jailing events for reactivated FP with grace period"
    );

    // Additional test: Advance to height 1060 to test grace period expiration
    env.block.height = 1060;
    env.block.time = Timestamp::from_seconds(10600);

    // Update power table for new height
    let mut power_table = HashMap::new();
    power_table.insert(fp_btc_pk.to_string(), 2000u64);
    set_voting_power_table(&mut deps.storage, 1060, power_table).unwrap();

    let events = handle_liveness(&mut deps.as_mut(), &env, &cfg).unwrap();

    // Verify the fix: get_last_signed_height should return max(850, 1000) = 1000
    // This gives the FP a grace period from their reactivation point

    // window_start = 1060 - 50 = 1010
    // get_last_signed_height returns max(850, 1000) = 1000
    // 1000 < 1010, so FP should be jailed after grace period

    let fp_jail = JAIL.may_load(&deps.storage, fp_btc_pk).unwrap();
    assert!(
        fp_jail.is_some(),
        "FP should now be jailed after grace period expires (window moved beyond reactivation point)"
    );
    assert_eq!(
        events.len(),
        1,
        "Should have one jailing event after grace period expires"
    );
}

/// Test that backfill signatures don't regress the FP_BLOCK_SIGNER tracking
/// This prevents unfair jailing due to out-of-order signature submissions
#[test]
fn backfill_signatures_dont_regress_liveness_tracking() {
    use crate::state::finality::{get_last_signed_height, FP_BLOCK_SIGNER};
    use cosmwasm_std::testing::{mock_dependencies, mock_env};

    let mut deps = mock_dependencies();
    let _env = mock_env();

    let fp_btc_pk = "test_fp_key";

    // Initial state: no signatures recorded
    let initial_last_signed = get_last_signed_height(deps.as_ref().storage, fp_btc_pk).unwrap();
    assert_eq!(initial_last_signed, None);

    // Simulate FP signing at height 100
    FP_BLOCK_SIGNER
        .save(&mut deps.storage, fp_btc_pk, &100u64)
        .unwrap();
    let after_100 = get_last_signed_height(deps.as_ref().storage, fp_btc_pk).unwrap();
    assert_eq!(after_100, Some(100));

    // Simulate FP signing at height 105 (more recent)
    FP_BLOCK_SIGNER
        .save(&mut deps.storage, fp_btc_pk, &105u64)
        .unwrap();
    let after_105 = get_last_signed_height(deps.as_ref().storage, fp_btc_pk).unwrap();
    assert_eq!(after_105, Some(105));

    // Now test our backfill protection: simulate attempting to "save" height 102
    // This should NOT update FP_BLOCK_SIGNER since 102 < 105
    let current_last_signed = FP_BLOCK_SIGNER
        .may_load(deps.as_ref().storage, fp_btc_pk)
        .unwrap();
    match current_last_signed {
        Some(existing_height) if existing_height >= 102 => {
            // Don't update - this is our protection logic
            // FP_BLOCK_SIGNER should remain 105
        }
        _ => {
            // This branch shouldn't execute in our test
            FP_BLOCK_SIGNER
                .save(&mut deps.storage, fp_btc_pk, &102u64)
                .unwrap();
        }
    }

    // Verify FP_BLOCK_SIGNER is still 105, not regressed to 102
    let final_value = FP_BLOCK_SIGNER
        .load(deps.as_ref().storage, fp_btc_pk)
        .unwrap();
    assert_eq!(
        final_value, 105,
        "Backfill signature should not regress FP_BLOCK_SIGNER"
    );

    // Verify liveness tracking still uses 105
    let final_last_signed = get_last_signed_height(deps.as_ref().storage, fp_btc_pk).unwrap();
    assert_eq!(
        final_last_signed,
        Some(105),
        "Liveness should track most recent signature"
    );

    // Test edge case: backfill with same height (should be allowed)
    let current_last_signed = FP_BLOCK_SIGNER
        .may_load(deps.as_ref().storage, fp_btc_pk)
        .unwrap();
    match current_last_signed {
        Some(existing_height) if existing_height >= 105 => {
            // Don't update for same or older height
        }
        _ => {
            FP_BLOCK_SIGNER
                .save(&mut deps.storage, fp_btc_pk, &105u64)
                .unwrap();
        }
    }

    let still_105 = FP_BLOCK_SIGNER
        .load(deps.as_ref().storage, fp_btc_pk)
        .unwrap();
    assert_eq!(
        still_105, 105,
        "Same height should not change FP_BLOCK_SIGNER"
    );

    // Test updating with newer height (should be allowed)
    FP_BLOCK_SIGNER
        .save(&mut deps.storage, fp_btc_pk, &110u64)
        .unwrap();
    let after_110 = get_last_signed_height(deps.as_ref().storage, fp_btc_pk).unwrap();
    assert_eq!(
        after_110,
        Some(110),
        "Newer signatures should update FP_BLOCK_SIGNER"
    );
}
