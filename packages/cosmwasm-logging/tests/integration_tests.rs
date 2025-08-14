use cosmwasm_logging::{debug, error, info, trace, warn, ContractLogger, LogLevel};
use cosmwasm_std::testing::{MockApi, MockQuerier, MockStorage};
use cosmwasm_std::{Deps, DepsMut, OwnedDeps};

type MockDeps = OwnedDeps<MockStorage, MockApi, MockQuerier>;

#[test]
fn test_deps_logging() {
    let mut deps = MockDeps::default();
    let deps_mut = deps.as_mut();
    let deps_ref = deps.as_ref();

    // Test simple string logging
    deps_mut.error("This is an error");
    deps_mut.warn("This is a warning");
    deps_mut.info("This is info");
    deps_mut.debug("This is debug");
    deps_mut.trace("This is trace");

    // Test with read-only deps
    deps_ref.info("Read-only info");
    deps_ref.debug("Read-only debug");
}

#[test]
fn test_api_logging() {
    let api = MockApi::default();

    // Test direct API logging
    api.error("API error");
    api.warn("API warning");
    api.info("API info");
    api.debug("API debug");
    api.trace("API trace");
}

#[test]
fn test_formatted_logging_macros() {
    let deps = MockDeps::default();
    let api = MockApi::default();

    let user = "alice";
    let amount = 1000u64;
    let tx_id = "abc123";

    // Test with deps
    error!(
        deps.as_ref(),
        "Transaction failed for user {} with amount {}", user, amount
    );
    warn!(deps.as_ref(), "Low balance warning for user {}", user);
    info!(deps.as_ref(), "User {} deposited {} tokens", user, amount);
    debug!(
        deps.as_ref(),
        "Processing transaction {} for {}", tx_id, user
    );
    trace!(
        deps.as_ref(),
        "Function entry: user={}, amount={}",
        user,
        amount
    );

    // Test with API
    error!(api, "API error: {}", "connection failed");
    info!(api, "API info: processed {} items", 42);
    debug!(api, "API debug: {:?}", vec![1, 2, 3]);
}

#[test]
fn test_boxed_api_logging() {
    let api: Box<dyn cosmwasm_std::Api> = Box::new(MockApi::default());

    // Test boxed API logging
    api.error("Boxed API error");
    api.info("Boxed API info");

    // Test with macros
    error!(api, "Boxed API formatted error: {}", "test");
    info!(api, "Boxed API formatted info: {}", 123);
}

#[test]
fn test_log_level_comparison() {
    // Test log level ordering
    assert!(LogLevel::Error < LogLevel::Warn);
    assert!(LogLevel::Warn < LogLevel::Info);
    assert!(LogLevel::Info < LogLevel::Debug);
    assert!(LogLevel::Debug < LogLevel::Trace);

    // Test specific comparisons
    assert_eq!(LogLevel::Debug <= LogLevel::Debug, true);
    assert_eq!(LogLevel::Debug <= LogLevel::Trace, true);
    assert_eq!(LogLevel::Trace <= LogLevel::Debug, false);
}

// Test that demonstrates the usage patterns
#[test]
fn test_realistic_contract_scenario() {
    let mut deps = MockDeps::default();

    // Simulate contract instantiation
    info!(
        deps.as_mut(),
        "Contract instantiated with admin: {}", "admin_addr"
    );

    // Simulate execute function
    let sender = "user123";
    let amount = 500u64;

    debug!(
        deps.as_ref(),
        "Execute called by {} with amount {}", sender, amount
    );

    // Simulate validation
    if amount == 0 {
        error!(deps.as_ref(), "Invalid amount: {}", amount);
        return;
    }

    // Simulate successful execution
    info!(
        deps.as_ref(),
        "Transfer completed: {} tokens from {}", amount, sender
    );

    // Simulate detailed tracing
    trace!(deps.as_ref(), "Function exit: success=true, gas_used=12345");
}

#[test]
fn test_mixed_logging_styles() {
    let deps = MockDeps::default();

    // Mix simple string logging with formatted macros
    deps.as_ref().info("Starting validation");
    debug!(deps.as_ref(), "Validating input: {}", "test_input");
    deps.as_ref().info("Validation complete");

    // This demonstrates that both styles work together seamlessly
}

// Note: Environment variable testing would require exposing the get_max_log_level function
// or testing it indirectly through the logging behavior. For now, we'll focus on
// testing the public API surface.
