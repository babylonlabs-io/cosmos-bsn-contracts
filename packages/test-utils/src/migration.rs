//! Migration testing utilities for CosmWasm contracts
//!
//! This module provides a test builder pattern for testing contract migrations
//! that can be reused across all contracts to avoid code duplication.

use cosmwasm_std::testing::{message_info, mock_dependencies, mock_env};
use cosmwasm_std::{attr, DepsMut, Env, MessageInfo, Response};
use cw2::{get_contract_version, set_contract_version};
use std::fmt::Debug;

/// Type alias for contract migration functions
pub type MigrateFn<M, E> = fn(DepsMut, Env, M) -> Result<Response, E>;

/// Type alias for contract instantiate functions
pub type InstantiateFn<I, E> = fn(DepsMut, Env, MessageInfo, I) -> Result<Response, E>;

/// Tester for contract migration scenarios
///
/// This tester provides a clean API for testing common migration scenarios
/// across different contracts while avoiding code duplication.
pub struct MigrationTester {
    contract_name: &'static str,
    contract_version: &'static str,
}

impl MigrationTester {
    /// Create a new migration tester
    ///
    /// # Arguments
    /// * `contract_name` - The contract's name constant (usually CONTRACT_NAME)
    /// * `contract_version` - The contract's version constant (usually CONTRACT_VERSION)
    pub fn new(contract_name: &'static str, contract_version: &'static str) -> Self {
        Self {
            contract_name,
            contract_version,
        }
    }

    /// Test the basic migration scenarios
    ///
    /// This convenience method runs the three fundamental migration tests that every contract should have:
    /// - Basic migration from a previous version
    /// - Migration after instantiation
    /// - Migration with wrong contract name (expects failure)
    ///
    /// Contracts can define additional custom migration tests beyond these basics.
    ///
    /// # Arguments
    /// * `migrate_fn` - The contract's migrate function
    /// * `instantiate_fn` - The contract's instantiate function
    /// * `migration_msg` - The migrate message to use in tests
    /// * `instantiate_msg` - The instantiate message to use in tests
    /// * `error_matcher` - Function that extracts (expected, actual) from InvalidContractName error
    pub fn test_migration_basics<M, I, E>(
        &self,
        migrate_fn: MigrateFn<M, E>,
        instantiate_fn: InstantiateFn<I, E>,
        migration_msg: M,
        instantiate_msg: I,
        error_matcher: impl Fn(&E) -> Option<(&str, &str)>,
    ) where
        E: Debug,
        M: Clone,
        I: Clone,
    {
        self.test_basic_migration(migrate_fn, migration_msg.clone());
        self.test_after_instantiate(
            migrate_fn,
            instantiate_fn,
            migration_msg.clone(),
            instantiate_msg,
        );
        self.test_wrong_contract(migrate_fn, migration_msg, error_matcher);
    }

    /// Test basic migration from a previous version
    ///
    /// This test:
    /// 1. Sets up a contract with a fake previous version ("0.1.0")
    /// 2. Calls migrate with the provided migrate message
    /// 3. Verifies response attributes and version update
    ///
    /// # Arguments
    /// * `migrate_fn` - The contract's migrate function
    /// * `migration_msg` - The migrate message to use in the test
    pub fn test_basic_migration<M, E>(&self, migrate_fn: MigrateFn<M, E>, migration_msg: M)
    where
        M: Clone,
        E: Debug,
    {
        let mut deps = mock_dependencies();

        // Set a fake previous version to simulate a deployed contract
        set_contract_version(&mut deps.storage, self.contract_name, "0.1.0").unwrap();

        // Call migrate with the provided migrate message
        let res = migrate_fn(deps.as_mut(), mock_env(), migration_msg).unwrap();

        // Check that the response contains the expected attributes
        assert_eq!(res.attributes.len(), 3);
        assert_eq!(res.attributes[0], attr("action", "migrate"));
        assert_eq!(res.attributes[1], attr("from_version", "0.1.0"));
        assert_eq!(res.attributes[2], attr("to_version", self.contract_version));

        // Verify the version was updated
        let version_info = get_contract_version(&deps.storage).unwrap();
        assert_eq!(version_info.contract, self.contract_name);
        assert_eq!(version_info.version, self.contract_version);
    }

    /// Test migration after contract instantiation
    ///
    /// This test:
    /// 1. Instantiates the contract normally
    /// 2. Verifies the initial version is set
    /// 3. Attempts migration (same version to same version)
    /// 4. Verifies migration succeeds with proper attributes
    ///
    /// # Arguments
    /// * `migrate_fn` - The contract's migrate function
    /// * `instantiate_fn` - The contract's instantiate function
    /// * `migration_msg` - The migrate message to use in the test
    /// * `instantiate_msg` - The instantiate message to use in the test
    pub fn test_after_instantiate<M, I, E>(
        &self,
        migrate_fn: MigrateFn<M, E>,
        instantiate_fn: InstantiateFn<I, E>,
        migration_msg: M,
        instantiate_msg: I,
    ) where
        M: Clone,
        I: Clone,
        E: Debug,
    {
        let mut deps = mock_dependencies();
        let info = message_info(&deps.api.addr_make("creator"), &[]);

        // Instantiate the contract first
        instantiate_fn(deps.as_mut(), mock_env(), info, instantiate_msg).unwrap();

        // Verify initial version is set
        let version_info = get_contract_version(&deps.storage).unwrap();
        assert_eq!(version_info.contract, self.contract_name);
        assert_eq!(version_info.version, self.contract_version);

        // Now attempt migration
        let res = migrate_fn(deps.as_mut(), mock_env(), migration_msg).unwrap();

        // Check that the response contains the expected attributes
        assert_eq!(res.attributes.len(), 3);
        assert_eq!(res.attributes[0], attr("action", "migrate"));
        assert_eq!(
            res.attributes[1],
            attr("from_version", self.contract_version)
        );
        assert_eq!(res.attributes[2], attr("to_version", self.contract_version));

        // Verify the version remains the same
        let version_info = get_contract_version(&deps.storage).unwrap();
        assert_eq!(version_info.contract, self.contract_name);
        assert_eq!(version_info.version, self.contract_version);
    }

    /// Test migration with wrong contract name
    ///
    /// This test:
    /// 1. Sets up storage with a wrong contract name
    /// 2. Attempts migration and expects it to fail
    /// 3. Verifies the error is InvalidContractName with correct expected/actual values
    ///
    /// # Arguments
    /// * `migrate_fn` - The contract's migrate function
    /// * `migration_msg` - The migrate message to use in the test
    /// * `error_matcher` - Function that extracts (expected, actual) from InvalidContractName error
    pub fn test_wrong_contract<M, E>(
        &self,
        migrate_fn: MigrateFn<M, E>,
        migration_msg: M,
        error_matcher: impl Fn(&E) -> Option<(&str, &str)>,
    ) where
        M: Clone,
        E: Debug,
    {
        let mut deps = mock_dependencies();

        // Set a wrong contract name to simulate migration from different contract
        set_contract_version(&mut deps.storage, "wrong-contract", "0.1.0").unwrap();

        // Call migrate and expect error
        let err = migrate_fn(deps.as_mut(), mock_env(), migration_msg).unwrap_err();

        // Check the error is InvalidContractName with correct values
        match error_matcher(&err) {
            Some((expected, actual)) => {
                assert_eq!(expected, self.contract_name);
                assert_eq!(actual, "wrong-contract");
            }
            None => panic!("Expected InvalidContractName error, got: {err:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::{Response, StdError};

    const TEST_CONTRACT_NAME: &str = "test-contract";
    const TEST_CONTRACT_VERSION: &str = "1.0.0";

    #[derive(Debug, PartialEq)]
    enum TestError {
        Std(StdError),
        InvalidContractName { expected: String, actual: String },
    }

    impl From<StdError> for TestError {
        fn from(err: StdError) -> Self {
            TestError::Std(err)
        }
    }

    #[derive(Default, Clone)]
    struct TestMigrateMsg;

    #[derive(Default, Clone)]
    struct TestInstantiateMsg;

    fn test_migrate(
        _deps: DepsMut,
        _env: Env,
        _msg: TestMigrateMsg,
    ) -> Result<Response, TestError> {
        let prev_version = get_contract_version(_deps.storage)?;

        if prev_version.contract != TEST_CONTRACT_NAME {
            return Err(TestError::InvalidContractName {
                expected: TEST_CONTRACT_NAME.to_string(),
                actual: prev_version.contract,
            });
        }

        set_contract_version(_deps.storage, TEST_CONTRACT_NAME, TEST_CONTRACT_VERSION)?;

        Ok(Response::new()
            .add_attribute("action", "migrate")
            .add_attribute("from_version", prev_version.version)
            .add_attribute("to_version", TEST_CONTRACT_VERSION))
    }

    fn test_instantiate(
        _deps: DepsMut,
        _env: Env,
        _info: MessageInfo,
        _msg: TestInstantiateMsg,
    ) -> Result<Response, TestError> {
        set_contract_version(_deps.storage, TEST_CONTRACT_NAME, TEST_CONTRACT_VERSION)?;
        Ok(Response::new().add_attribute("action", "instantiate"))
    }

    #[test]
    fn test_migration_tester_basic() {
        let tester = MigrationTester::new(TEST_CONTRACT_NAME, TEST_CONTRACT_VERSION);
        tester.test_basic_migration(test_migrate, TestMigrateMsg);
    }

    #[test]
    fn test_migration_tester_after_instantiate() {
        let tester = MigrationTester::new(TEST_CONTRACT_NAME, TEST_CONTRACT_VERSION);
        tester.test_after_instantiate(
            test_migrate,
            test_instantiate,
            TestMigrateMsg,
            TestInstantiateMsg,
        );
    }

    #[test]
    fn test_migration_tester_wrong_contract() {
        let tester = MigrationTester::new(TEST_CONTRACT_NAME, TEST_CONTRACT_VERSION);
        tester.test_wrong_contract(test_migrate, TestMigrateMsg, |err| match err {
            TestError::InvalidContractName { expected, actual } => Some((expected, actual)),
            _ => None,
        });
    }

    #[test]
    fn test_migration_basics() {
        let tester = MigrationTester::new(TEST_CONTRACT_NAME, TEST_CONTRACT_VERSION);
        tester.test_migration_basics(
            test_migrate,
            test_instantiate,
            TestMigrateMsg,
            TestInstantiateMsg,
            |err| match err {
                TestError::InvalidContractName { expected, actual } => Some((expected, actual)),
                _ => None,
            },
        );
    }
}
