use std::collections::HashMap;

use anyhow::Result as AnyResult;
use derivative::Derivative;
use hex::ToHex;

use cosmwasm_std::testing::mock_dependencies;
use cosmwasm_std::{to_json_binary, Addr, BlockInfo, Coin, Timestamp};
use cw_multi_test::{next_block, AppResponse, Contract, ContractWrapper, Executor};

use babylon_apis::btc_staking_api::{ActiveBtcDelegation, FinalityProvider, NewFinalityProvider};
use babylon_apis::error::StakingApiError;
use babylon_apis::finality_api::{IndexedBlock, PubRandCommit};
use babylon_apis::{btc_staking_api, finality_api, to_bech32_addr, to_canonical_addr};
use babylon_bindings_test::BabylonApp;
use btc_light_client::msg::InstantiateMsg as BtcLightClientInstantiateMsg;
use btc_light_client::BitcoinNetwork;
use cosmwasm_std::Empty;

use btc_staking::msg::{ActivatedHeightResponse, FinalityProviderInfo};

use crate::msg::QueryMsg::JailedFinalityProviders;
use crate::msg::{
    ActiveFinalityProvidersResponse, EvidenceResponse, FinalitySignatureResponse, InstantiateMsg,
    JailedFinalityProvider, JailedFinalityProvidersResponse,
};
use babylon_bindings_test::{
    BTC_FINALITY_CONTRACT_ADDR, BTC_LIGHT_CLIENT_CONTRACT_ADDR, BTC_STAKING_CONTRACT_ADDR,
    USER_ADDR,
};

fn contract_btc_light_client() -> Box<dyn Contract<Empty>> {
    let contract = ContractWrapper::new(
        btc_light_client::contract::execute,
        btc_light_client::contract::instantiate,
        btc_light_client::contract::query,
    );
    Box::new(contract)
}

fn contract_btc_staking() -> Box<dyn Contract<Empty>> {
    let contract = ContractWrapper::new(
        btc_staking::contract::execute,
        btc_staking::contract::instantiate,
        btc_staking::contract::query,
    );
    Box::new(contract)
}

fn contract_btc_finality() -> Box<dyn Contract<Empty>> {
    let contract = ContractWrapper::new(
        crate::contract::execute,
        crate::contract::instantiate,
        crate::contract::query,
    )
    .with_sudo(crate::contract::sudo);
    Box::new(contract)
}

fn contract_babylon() -> Box<dyn Contract<Empty>> {
    let contract = ContractWrapper::new(
        babylon_contract::execute,
        babylon_contract::instantiate,
        babylon_contract::query,
    )
    .with_reply(babylon_contract::reply)
    .with_migrate(babylon_contract::migrate);
    Box::new(contract)
}

#[derive(Derivative)]
#[derivative(Default = "new")]
pub struct SuiteBuilder {
    height: Option<u64>,
    init_funds: Vec<Coin>,
    missed_blocks_window: Option<u64>,
}

impl SuiteBuilder {
    pub fn with_height(mut self, height: u64) -> Self {
        self.height = Some(height);
        self
    }

    pub fn with_funds(mut self, funds: &[Coin]) -> Self {
        self.init_funds = funds.to_vec();
        self
    }

    pub fn with_missed_blocks(mut self, missed_blocks: u64) -> Self {
        self.missed_blocks_window = Some(missed_blocks);
        self
    }

    #[track_caller]
    pub fn build(self) -> Suite {
        let owner = mock_dependencies().api.addr_make("owner");

        let mut app = BabylonApp::new_at_height(owner.as_str(), self.height.unwrap_or(1));

        let _block_info = app.block_info();

        let btc_light_client_addr = Addr::unchecked(BTC_LIGHT_CLIENT_CONTRACT_ADDR);
        let staking_contract_addr = Addr::unchecked(BTC_STAKING_CONTRACT_ADDR);
        let finality_contract_addr = Addr::unchecked(BTC_FINALITY_CONTRACT_ADDR);

        app.init_modules(|router, _api, storage| -> AnyResult<()> {
            router.bank.init_balance(storage, &owner, self.init_funds)
        })
        .unwrap();

        let btc_light_client_code_id =
            app.store_code_with_creator(owner.clone(), contract_btc_light_client());
        let btc_staking_code_id =
            app.store_code_with_creator(owner.clone(), contract_btc_staking());
        let btc_finality_code_id =
            app.store_code_with_creator(owner.clone(), contract_btc_finality());
        let contract_code_id = app.store_code_with_creator(owner.clone(), contract_babylon());
        let staking_params = btc_staking::test_utils::staking_params();
        let finality_params = crate::test_utils::finality_params(self.missed_blocks_window);

        let btc_light_client_msg = {
            let btc_lc_init_msg = BtcLightClientInstantiateMsg {
                network: BitcoinNetwork::Testnet,
                btc_confirmation_depth: 1,
                checkpoint_finalization_timeout: 1,
                admin: None,
            };

            to_json_binary(&btc_lc_init_msg).unwrap()
        };

        let contract = app
            .instantiate_contract(
                contract_code_id,
                owner.clone(),
                &babylon_contract::msg::contract::InstantiateMsg {
                    network: BitcoinNetwork::Testnet,
                    babylon_tag: "01020304".to_string(),
                    btc_confirmation_depth: 1,
                    checkpoint_finalization_timeout: 1,
                    notify_cosmos_zone: false,
                    btc_light_client_code_id: Some(btc_light_client_code_id),
                    btc_light_client_msg: Some(btc_light_client_msg),
                    btc_staking_code_id: Some(btc_staking_code_id),
                    btc_staking_msg: Some(
                        to_json_binary(&btc_staking::msg::InstantiateMsg {
                            params: Some(staking_params),
                            admin: None,
                        })
                        .unwrap(),
                    ),
                    btc_finality_code_id: Some(btc_finality_code_id),
                    btc_finality_msg: Some(
                        to_json_binary(&InstantiateMsg {
                            params: Some(finality_params),
                            admin: Some(owner.to_string()),
                        })
                        .unwrap(),
                    ),
                    admin: Some(owner.to_string()),
                    consumer_name: Some("TestConsumer".to_string()),
                    consumer_description: Some("Test Consumer Description".to_string()),
                    ics20_channel_id: "channel-0".to_string(),
                    ibc_packet_timeout_days: None,
                    destination_module: "btcstaking".to_string(),
                },
                &[],
                "babylon",
                Some(owner.to_string()),
            )
            .unwrap();

        Suite {
            app,
            code_id: contract_code_id,
            babylon: contract,
            btc_light_client: btc_light_client_addr,
            staking: staking_contract_addr,
            finality: finality_contract_addr,
            owner,
        }
    }
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct Suite {
    #[derivative(Debug = "ignore")]
    app: BabylonApp,
    /// The code id of the babylon contract
    code_id: u64,
    /// Babylon contract address
    pub babylon: Addr,
    /// BTC Light Client contract address
    pub btc_light_client: Addr,
    /// Staking contract address
    pub staking: Addr,
    /// Finality contract address
    pub finality: Addr,
    /// Admin of babylon and btc-staking contracts
    pub owner: Addr,
}

impl Suite {
    pub fn to_consumer_addr(&self, bbn_addr: &Addr) -> Result<Addr, StakingApiError> {
        let babylon_prefix = Self::extract_prefix(bbn_addr);
        let consumer_prefix = Self::extract_prefix(&self.babylon);
        let addr_canonical = to_canonical_addr(bbn_addr.as_str(), babylon_prefix)?;
        to_bech32_addr(consumer_prefix, &addr_canonical)
    }

    fn extract_prefix(addr: &Addr) -> &str {
        let bech32_prefix = addr.as_str().split('1').collect::<Vec<_>>()[0];
        bech32_prefix
    }

    #[allow(dead_code)]
    #[track_caller]
    pub fn get_balance(&self, addr: &Addr, denom: &str) -> Coin {
        self.app.wrap().query_balance(addr, denom).unwrap()
    }

    #[allow(dead_code)]
    pub fn admin(&self) -> &str {
        self.owner.as_str()
    }

    pub fn app(&mut self) -> &mut BabylonApp {
        &mut self.app
    }

    pub fn next_block(&mut self, app_hash: &[u8]) -> AnyResult<BlockInfo> {
        self.app.update_block(next_block);
        let block = self.app().block_info();

        self.call_begin_block(app_hash, block.height)?;
        // Call the end-block sudo handler, so that the block is indexed in the store
        self.call_end_block(app_hash, block.height)?;

        Ok(block)
    }

    pub fn advance_seconds(&mut self, seconds: u64) -> AnyResult<()> {
        self.app.advance_seconds(seconds);
        Ok(())
    }

    /// Timestamp of current block
    pub fn timestamp(&self) -> Timestamp {
        self.app.block_info().time
    }

    /// Height of current block
    #[allow(dead_code)]
    pub fn height(&self) -> u64 {
        self.app.block_info().height
    }

    #[track_caller]
    pub fn get_babylon_config(&self) -> babylon_contract::state::config::Config {
        self.app
            .wrap()
            .query_wasm_smart(
                self.babylon.clone(),
                &babylon_contract::msg::contract::QueryMsg::Config {},
            )
            .unwrap()
    }

    #[track_caller]
    pub fn get_btc_staking_config(&self) -> btc_staking::state::config::Config {
        self.app
            .wrap()
            .query_wasm_smart(self.staking.clone(), &btc_staking::msg::QueryMsg::Config {})
            .unwrap()
    }

    #[track_caller]
    #[allow(dead_code)]
    pub fn get_btc_staking_params(&self) -> btc_staking::state::config::Params {
        self.app
            .wrap()
            .query_wasm_smart(self.staking.clone(), &btc_staking::msg::QueryMsg::Params {})
            .unwrap()
    }

    #[track_caller]
    pub fn get_btc_finality_config(&self) -> crate::state::config::Config {
        self.app
            .wrap()
            .query_wasm_smart(self.finality.clone(), &crate::msg::QueryMsg::Config {})
            .unwrap()
    }

    #[track_caller]
    pub fn get_activated_height(&self) -> ActivatedHeightResponse {
        self.app
            .wrap()
            .query_wasm_smart(
                self.staking.clone(),
                &btc_staking::msg::QueryMsg::ActivatedHeight {},
            )
            .unwrap()
    }

    #[track_caller]
    pub fn get_finality_provider(&self, pk_hex: &str) -> FinalityProvider {
        self.app
            .wrap()
            .query_wasm_smart(
                self.staking.clone(),
                &btc_staking::msg::QueryMsg::FinalityProvider {
                    btc_pk_hex: pk_hex.to_string(),
                },
            )
            .unwrap()
    }

    #[track_caller]
    pub fn get_finality_provider_info(
        &self,
        pk_hex: &str,
        height: Option<u64>,
    ) -> FinalityProviderInfo {
        self.app
            .wrap()
            .query_wasm_smart(
                self.staking.clone(),
                &btc_staking::msg::QueryMsg::FinalityProviderInfo {
                    btc_pk_hex: pk_hex.to_string(),
                    height,
                },
            )
            .unwrap()
    }

    #[track_caller]
    pub fn get_finality_signature(&self, pk_hex: &str, height: u64) -> FinalitySignatureResponse {
        self.app
            .wrap()
            .query_wasm_smart(
                self.finality.clone(),
                &crate::msg::QueryMsg::FinalitySignature {
                    btc_pk_hex: pk_hex.to_string(),
                    height,
                },
            )
            .unwrap()
    }

    #[track_caller]
    pub fn get_indexed_block(&self, height: u64) -> IndexedBlock {
        self.app
            .wrap()
            .query_wasm_smart(
                self.finality.clone(),
                &crate::msg::QueryMsg::Block { height },
            )
            .unwrap()
    }

    #[track_caller]
    pub fn get_double_signing_evidence(&self, pk_hex: &str, height: u64) -> EvidenceResponse {
        self.app
            .wrap()
            .query_wasm_smart(
                self.finality.clone(),
                &crate::msg::QueryMsg::Evidence {
                    btc_pk_hex: pk_hex.to_string(),
                    height,
                },
            )
            .unwrap()
    }

    #[track_caller]
    pub fn register_finality_providers(
        &mut self,
        fps: &[NewFinalityProvider],
    ) -> anyhow::Result<AppResponse> {
        self.app.execute_contract(
            self.babylon.clone(),
            self.staking.clone(),
            &btc_staking_api::ExecuteMsg::BtcStaking {
                new_fp: fps.to_vec(),
                active_del: vec![],
                slashed_del: vec![],
                unbonded_del: vec![],
            },
            &[],
        )
    }

    #[track_caller]
    pub fn add_delegations(&mut self, dels: &[ActiveBtcDelegation]) -> anyhow::Result<AppResponse> {
        self.app.execute_contract(
            self.babylon.clone(),
            self.staking.clone(),
            &btc_staking_api::ExecuteMsg::BtcStaking {
                new_fp: vec![],
                active_del: dels.to_vec(),
                slashed_del: vec![],
                unbonded_del: vec![],
            },
            &[],
        )
    }

    #[track_caller]
    pub fn commit_public_randomness(
        &mut self,
        pk_hex: &str,
        pub_rand: &PubRandCommit,
        pubrand_signature: &[u8],
    ) -> anyhow::Result<AppResponse> {
        self.app.execute_contract(
            Addr::unchecked(USER_ADDR),
            self.finality.clone(),
            &finality_api::ExecuteMsg::CommitPublicRandomness {
                fp_pubkey_hex: pk_hex.to_string(),
                start_height: pub_rand.start_height,
                num_pub_rand: pub_rand.num_pub_rand,
                commitment: pub_rand.commitment.clone().into(),
                signature: pubrand_signature.into(),
            },
            &[],
        )
    }

    #[track_caller]
    pub fn call_begin_block(
        &mut self,
        app_hash: &[u8],
        height: u64,
    ) -> anyhow::Result<AppResponse> {
        // Set the block height
        let mut block = self.app.block_info();
        block.height = height;
        self.app.set_block(block);

        // Hash is not used in the begin-block handler
        let hash_hex = format!("deadbeef{height}");
        let app_hash_hex: String = app_hash.encode_hex();

        self.app.wasm_sudo(
            self.finality.clone(),
            &finality_api::SudoMsg::BeginBlock {
                hash_hex: hash_hex.clone(),
                app_hash_hex: app_hash_hex.clone(),
            },
        )
    }

    #[track_caller]
    pub fn call_end_block(&mut self, app_hash: &[u8], height: u64) -> anyhow::Result<AppResponse> {
        // Set the block height
        let mut block = self.app.block_info();
        block.height = height;
        self.app.set_block(block);

        // Hash is not used in the begin-block handler
        let hash_hex = format!("deadbeef{height}");
        let app_hash_hex: String = app_hash.encode_hex();

        self.app.wasm_sudo(
            self.finality.clone(),
            &finality_api::SudoMsg::EndBlock {
                hash_hex: hash_hex.clone(),
                app_hash_hex: app_hash_hex.clone(),
            },
        )
    }

    #[track_caller]
    pub fn submit_finality_signature(
        &mut self,
        pk_hex: &str,
        height: u64,
        pub_rand: &[u8],
        proof: &tendermint_proto::crypto::Proof,
        block_app_hash: &[u8],
        finality_sig: &[u8],
    ) -> anyhow::Result<AppResponse> {
        // Execute the message at a higher height, so that:
        // 1. It's not rejected because of height being too low.
        // 2. The FP has consolidated power at such height
        let mut block = self.app.block_info();
        block.height = height + 1;
        self.app.set_block(block);

        self.app.execute_contract(
            Addr::unchecked(USER_ADDR),
            self.finality.clone(),
            &finality_api::ExecuteMsg::SubmitFinalitySignature {
                fp_pubkey_hex: pk_hex.to_string(),
                height,
                pub_rand: pub_rand.into(),
                proof: proof.try_into().expect("Invalid Merkle proof"),
                block_hash: block_app_hash.into(),
                signature: finality_sig.into(),
            },
            &[],
        )
    }

    #[track_caller]
    pub fn unjail(&mut self, sender: &str, fp_pubkey_hex: &str) -> AnyResult<AppResponse> {
        self.app.execute_contract(
            Addr::unchecked(sender),
            self.finality.clone(),
            &finality_api::ExecuteMsg::Unjail {
                fp_pubkey_hex: fp_pubkey_hex.to_owned(),
            },
            &[],
        )
    }

    #[track_caller]
    pub fn list_jailed_fps(
        &self,
        start_after: Option<String>,
        limit: Option<u32>,
    ) -> Vec<JailedFinalityProvider> {
        self.app
            .wrap()
            .query_wasm_smart::<JailedFinalityProvidersResponse>(
                self.finality.clone(),
                &JailedFinalityProviders { start_after, limit },
            )
            .unwrap()
            .jailed_finality_providers
    }

    pub fn get_active_finality_providers(&self, height: u64) -> HashMap<String, u64> {
        self.app
            .wrap()
            .query_wasm_smart::<ActiveFinalityProvidersResponse>(
                self.finality.clone(),
                &crate::msg::QueryMsg::ActiveFinalityProviders { height },
            )
            .unwrap()
            .active_finality_providers
    }

    pub fn get_finality_provider_power(&self, btc_pk_hex: &str, height: u64) -> u64 {
        self.app
            .wrap()
            .query_wasm_smart::<crate::msg::FinalityProviderPowerResponse>(
                self.finality.clone(),
                &crate::msg::QueryMsg::FinalityProviderPower {
                    btc_pk_hex: btc_pk_hex.to_string(),
                    height,
                },
            )
            .unwrap()
            .power
    }
}
