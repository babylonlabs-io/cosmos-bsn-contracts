mod suite;

use babylon_bindings_test::{
    BABYLON_CONTRACT_ADDR, BTC_FINALITY_CONTRACT_ADDR, BTC_LIGHT_CLIENT_CONTRACT_ADDR,
    BTC_STAKING_CONTRACT_ADDR,
};
use cosmwasm_std::Addr;
use suite::SuiteBuilder;

mod instantiation {
    use super::*;

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
}

mod finality {
    use super::*;

    use crate::msg::FinalitySignatureResponse;
    use babylon_apis::finality_api::IndexedBlock;

    use babylon_test_utils::{
        create_new_finality_provider, get_add_finality_sig, get_derived_btc_delegation,
        get_pub_rand_value, get_public_randomness_commitment,
    };
    use cosmwasm_std::{coin, Event};

    #[test]
    fn commit_public_randomness_works() {
        let mut suite = SuiteBuilder::new().build();

        // Read public randomness commitment test data
        let (pk_hex, pub_rand, pubrand_signature) = get_public_randomness_commitment();

        // Register one FP
        // NOTE: the test data ensures that pub rand commit / finality sig are
        // signed by the 1st FP
        let new_fp = create_new_finality_provider(1);
        assert_eq!(new_fp.btc_pk_hex, pk_hex);

        suite.register_finality_providers(&[new_fp]).unwrap();

        // Now commit the public randomness for it
        suite
            .commit_public_randomness(&pk_hex, &pub_rand, &pubrand_signature)
            .unwrap();
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
}

mod slashing {
    use babylon_apis::finality_api::IndexedBlock;
    use babylon_test_utils::{
        create_new_finality_provider, get_add_finality_sig, get_add_finality_sig_2,
        get_derived_btc_delegation, get_pub_rand_value, get_public_randomness_commitment,
    };
    use cosmwasm_std::coin;

    use crate::multitest::suite::SuiteBuilder;

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
}

mod jailing {
    use crate::msg::JailedFinalityProvider;
    use cosmwasm_std::{coin, Addr};

    use crate::error::ContractError;
    use crate::multitest::suite::SuiteBuilder;
    use babylon_test_utils::{
        create_new_finality_provider, get_add_finality_sig, get_derived_btc_delegation,
        get_pub_rand_value, get_public_randomness_commitment,
    };

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
}
