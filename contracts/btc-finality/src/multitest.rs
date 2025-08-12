pub mod suite;

use crate::error::{ContractError, PubRandCommitError};
use crate::msg::{FinalitySignatureResponse, JailedFinalityProvider};
use crate::state::finality::FP_POWER_TABLE;
use crate::state::finality::{get_fp_power, get_power_table_at_height};
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
    bad_pub_rand_commit.start_height = 500_000;
    assert!(matches!(
        suite
            .commit_public_randomness(&pk_hex, &bad_pub_rand_commit, &pubrand_signature)
            .unwrap_err(),
        ContractError::FuturePubRandStartHeight { .. }
    ));
}

#[test]
fn test_add_finality_sig() {
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

    // Case 1: fail if the finality provider does not have voting power.
    assert_eq!(
        suite
            .submit_finality_signature(
                &pk_hex,
                initial_height + 1,
                &pub_rand_one,
                &proof,
                &add_finality_signature.block_app_hash,
                &add_finality_signature.finality_sig,
            )
            .unwrap_err(),
        ContractError::NoVotingPower(pk_hex.clone(), initial_height + 1)
    );

    // Add a delegation, so that the finality provider has some power
    let mut del1 = get_derived_btc_delegation(1, &[1]);
    del1.fp_btc_pk_list = vec![pk_hex.clone()];

    suite.add_delegations(&[del1]).unwrap();

    suite
        .commit_public_randomness(&pk_hex, &pub_rand, &pubrand_signature)
        .unwrap();

    // Case 2: fail if the finality provider has not committed public randomness at that height
    let block_height2 = pub_rand.start_height + pub_rand.num_pub_rand + 1;

    FP_POWER_TABLE
        .save(suite.app.storage_mut(), (block_height2, &pk_hex), &1)
        .unwrap();

    assert_eq!(
        get_fp_power(suite.app.storage_mut(), block_height2, &pk_hex).unwrap(),
        1
    );

    assert_eq!(
        suite
            .submit_finality_signature(
                &pk_hex,
                block_height2,
                &pub_rand_one,
                &proof,
                &add_finality_signature.block_app_hash,
                &add_finality_signature.finality_sig,
            )
            .unwrap_err(),
        ContractError::NoVotingPower(pk_hex.clone(), block_height2),
        "Modifying the contract storage against suite.app.storage_mut() does not work"
    );

    FP_POWER_TABLE.remove(suite.app.storage_mut(), (block_height2, &pk_hex));

    assert!(get_fp_power(suite.app.storage_mut(), block_height2, &pk_hex).is_err());

    suite.set_power_table(&pk_hex, block_height2, 1).unwrap();

    assert_eq!(
        suite
            .submit_finality_signature(
                &pk_hex,
                block_height2,
                &pub_rand_one,
                &proof,
                &add_finality_signature.block_app_hash,
                &add_finality_signature.finality_sig,
            )
            .unwrap_err(),
        ContractError::MissingPubRandCommit(pk_hex.clone(), block_height2)
    );
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
    suite.advance_seconds(4000).unwrap();
    // It requires two blocks for the active FP set to be fully updated
    suite.next_block("deadbeef02".as_bytes()).unwrap();
    let next_height = suite.next_block("deadbeef03".as_bytes()).unwrap().height;

    // Both FPs are jailed for being offline!
    let jailed_until = &suite.timestamp().seconds() + 86400 - 5;
    assert_eq!(
        &suite.list_jailed_fps(None, None),
        &[JailedFinalityProvider {
            btc_pk_hex: new_fp1.btc_pk_hex.clone(),
            jailed_until,
        },],
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
