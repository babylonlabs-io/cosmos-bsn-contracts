use anyhow::{bail, Result as AnyResult};
use schemars::JsonSchema;
use serde::de::DeserializeOwned;
use std::cmp::max;
use std::fmt::Debug;
use std::ops::{Deref, DerefMut};
use thiserror::Error;

use cosmwasm_std::testing::{MockApi, MockQuerier, MockStorage};
use cosmwasm_std::{CustomMsg, OwnedDeps};
use std::marker::PhantomData;

use cosmwasm_std::Order::Ascending;
use cosmwasm_std::{
    Addr, Api, Binary, BlockInfo, CustomQuery, Empty, Querier, QuerierResult, StdError, StdResult,
    Storage, Timestamp,
};
use cw_multi_test::{
    App, AppResponse, BankKeeper, BankSudo, BasicAppBuilder, CosmosRouter, Module, WasmKeeper,
};
use cw_storage_plus::{Item, Map};

use babylon_bindings::{BabylonMsg, BabylonQuery};

pub struct BabylonModule {}

/// How many seconds per block
/// (when we increment block.height, use this multiplier for block.time)
pub const BLOCK_TIME: u64 = 5;

const PINNED: Item<Vec<u64>> = Item::new("pinned");
// const PLANNED_UPGRADE: Item<UpgradePlan> = Item::new("planned_upgrade");
const PARAMS: Map<String, String> = Map::new("params");

pub type BabylonDeps = OwnedDeps<MockStorage, MockApi, MockQuerier, BabylonQuery>;

pub fn mock_deps_babylon() -> BabylonDeps {
    OwnedDeps {
        storage: MockStorage::default(),
        api: MockApi::default(),
        querier: MockQuerier::default(),
        custom_query_type: PhantomData,
    }
}

impl BabylonModule {
    /// Intended for init_modules to set someone who can grant privileges or call arbitrary
    /// BabylonMsg externally
    pub fn set_owner(&self, _storage: &mut dyn Storage, _owner: &Addr) -> StdResult<()> {
        // TODO: Manage privileges / ownership
        // PRIVILEGES.save(storage, owner, &ADMIN_PRIVILEGES.to_vec())?;
        Ok(())
    }

    pub fn is_pinned(&self, storage: &dyn Storage, code: u64) -> StdResult<bool> {
        let pinned = PINNED.may_load(storage)?;
        match pinned {
            Some(pinned) => Ok(pinned.contains(&code)),
            None => Ok(false),
        }
    }

    pub fn get_params(&self, storage: &dyn Storage) -> StdResult<Vec<(String, String)>> {
        PARAMS.range(storage, None, None, Ascending).collect()
    }
}

impl Module for BabylonModule {
    type ExecT = BabylonMsg;
    type QueryT = Empty;
    type SudoT = Empty;

    fn execute<ExecC, QueryC>(
        &self,
        api: &dyn Api,
        storage: &mut dyn Storage,
        router: &dyn CosmosRouter<ExecC = ExecC, QueryC = QueryC>,
        block: &BlockInfo,
        _sender: Addr,
        msg: BabylonMsg,
    ) -> AnyResult<AppResponse>
    where
        ExecC: Debug + Clone + PartialEq + JsonSchema + DeserializeOwned + CustomMsg,
        QueryC: CustomQuery + DeserializeOwned + 'static,
    {
        match msg {
            BabylonMsg::MintRewards { amount, recipient } => {
                let mint_msg = BankSudo::Mint {
                    to_address: recipient,
                    amount: vec![amount],
                };
                router.sudo(api, storage, block, mint_msg.into())?;
                Ok(AppResponse::default())
            }
        }
    }

    fn query(
        &self,
        _api: &dyn Api,
        _storage: &dyn Storage,
        _querier: &dyn Querier,
        _block: &BlockInfo,
        _request: BabylonQuery,
    ) -> anyhow::Result<Binary> {
        bail!("query not implemented for BabylonModule")
    }

    fn sudo<ExecC, QueryC>(
        &self,
        _api: &dyn Api,
        _storage: &mut dyn Storage,
        _router: &dyn CosmosRouter<ExecC = ExecC, QueryC = QueryC>,
        _block: &BlockInfo,
        _msg: Self::SudoT,
    ) -> AnyResult<AppResponse>
    where
        ExecC: Debug + Clone + PartialEq + JsonSchema + DeserializeOwned + 'static,
        QueryC: CustomQuery + DeserializeOwned + 'static,
    {
        bail!("sudo not implemented for BabylonModule")
    }
}

#[derive(Error, Debug, PartialEq)]
pub enum BabylonError {
    #[error("{0}")]
    Std(#[from] StdError),

    #[error("Unauthorized: {0}")]
    Unauthorized(String),
}

pub type BabylonAppWrapped =
    App<BankKeeper, MockApi, MockStorage, BabylonModule, WasmKeeper<BabylonMsg, BabylonQuery>>;

pub struct BabylonApp(BabylonAppWrapped);

impl Deref for BabylonApp {
    type Target = BabylonAppWrapped;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for BabylonApp {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl Querier for BabylonApp {
    fn raw_query(&self, bin_request: &[u8]) -> QuerierResult {
        self.0.raw_query(bin_request)
    }
}

impl BabylonApp {
    pub fn new(owner: &str) -> Self {
        let owner = Addr::unchecked(owner);
        Self(
            BasicAppBuilder::<BabylonMsg, BabylonQuery>::new_custom()
                .with_custom(BabylonModule {})
                .build(|router, _, storage| {
                    router.custom.set_owner(storage, &owner).unwrap();
                }),
        )
    }

    pub fn new_genesis(owner: &str) -> Self {
        BabylonApp::new_at_height(owner, 0)
    }

    pub fn new_at_height(owner: &str, height: u64) -> Self {
        let owner = Addr::unchecked(owner);
        let block_info = BlockInfo {
            height,
            time: Timestamp::from_seconds(1714119228),
            chain_id: "babylon-testnet-phase-3".to_owned(),
        };

        Self(
            BasicAppBuilder::<BabylonMsg, BabylonQuery>::new_custom()
                .with_custom(BabylonModule {})
                .with_block(block_info)
                .build(|router, _, storage| {
                    router.custom.set_owner(storage, &owner).unwrap();
                }),
        )
    }

    pub fn block_info(&self) -> BlockInfo {
        self.0.block_info()
    }

    /// This reverses to genesis (based on current time/height)
    pub fn back_to_genesis(&mut self) {
        self.update_block(|block| {
            block.time = block.time.minus_seconds(BLOCK_TIME * block.height);
            block.height = 0;
        });
    }

    /// This advances BlockInfo by given number of blocks.
    /// It does not do any callbacks, but keeps the ratio of seconds/block
    pub fn advance_blocks(&mut self, blocks: u64) {
        self.update_block(|block| {
            block.time = block.time.plus_seconds(BLOCK_TIME * blocks);
            block.height += blocks;
        });
    }

    /// This advances BlockInfo by given number of seconds.
    /// It does not do any callbacks, but keeps the ratio of seconds/blokc
    pub fn advance_seconds(&mut self, seconds: u64) {
        self.update_block(|block| {
            block.time = block.time.plus_seconds(seconds);
            block.height += max(1, seconds / BLOCK_TIME);
        });
    }
}
