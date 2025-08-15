use cosmwasm_logging::init_cosmwasm_logger;
use cosmwasm_std::testing::mock_dependencies;

// Re-export macros for testing - this tests both feature configurations
#[cfg(feature = "logging")]
use log::{debug, error, info, trace, warn};

#[cfg(not(feature = "logging"))]
use cosmwasm_logging::{debug, error, info, trace, warn};

#[test]
fn test_logger_initialization() {
    let deps = mock_dependencies();

    // Should not panic in either configuration
    init_cosmwasm_logger(&deps.api);

    // Multiple initializations should be safe
    init_cosmwasm_logger(&deps.api);
}

#[test]
fn test_all_log_levels() {
    let deps = mock_dependencies();
    init_cosmwasm_logger(&deps.api);

    // Test all log levels with formatting
    error!("This is an error: {}", "test error");
    warn!("This is a warning: {}", "test warning");
    info!("This is info: {}", "test info");
    debug!("This is debug: {}", "test debug");
    trace!("This is trace: {}", "test trace");
}

#[test]
fn test_complex_formatting() {
    let deps = mock_dependencies();
    init_cosmwasm_logger(&deps.api);

    let user = "alice";
    let amount = 1000u64;
    let balance = vec![1, 2, 3, 4];

    info!("User {} deposited {} tokens", user, amount);
    debug!("Current balances: {:?}", balance);
    error!(
        "Failed to process transaction for user {} with amount {}: {}",
        user, amount, "insufficient funds"
    );
}

#[test]
fn test_target_logging() {
    let deps = mock_dependencies();
    init_cosmwasm_logger(&deps.api);

    // Test log crate's target feature - these should show targets in output
    info!(target: "contract::babylon::instantiate", "Contract operation");
    debug!(target: "contract::babylon::execute", "Input validation passed");
    error!(target: "contract::babylon::query", "Execution failed: {}", "timeout");

    // Test with different target patterns
    info!(target: "ibc::packet", "IBC packet received");
    debug!(target: "state::config", "Config updated");
}

#[test]
fn test_realistic_contract_scenario() {
    let deps = mock_dependencies();
    init_cosmwasm_logger(&deps.api);

    // Simulate contract execution flow
    info!("Contract execution started");

    let sender = "cosmos1xyz...";
    let recipient = "cosmos1abc...";
    let amount = 500u64;

    debug!("Processing transfer from {} to {}", sender, recipient);

    // Simulate validation
    if amount > 0 {
        debug!("Amount validation passed: {}", amount);
    } else {
        error!("Invalid amount: {}", amount);
        return;
    }

    // Simulate execution
    info!(
        "Transfer executed successfully: {} tokens from {} to {}",
        amount, sender, recipient
    );
    trace!("Transfer completed at block height: {}", 12345);
}

// Test that compiles only when logging is enabled
#[cfg(feature = "logging")]
#[test]
fn test_log_crate_integration() {
    use log::Level;

    let deps = mock_dependencies();
    init_cosmwasm_logger(&deps.api);

    // Test direct log crate usage
    log::log!(Level::Info, "Direct log call: {}", "test");

    // Test that we can check if logging is enabled
    assert!(log::log_enabled!(Level::Debug));
}

// Test that our no-op macros work when logging is disabled
#[cfg(not(feature = "logging"))]
#[test]
fn test_no_op_macros() {
    let deps = mock_dependencies();
    init_cosmwasm_logger(&deps.api);

    // These should all be no-ops and compile without log crate
    error!("This should be a no-op");
    warn!("This should be a no-op");
    info!("This should be a no-op");
    debug!("This should be a no-op");
    trace!("This should be a no-op");

    // Test target variants too
    error!(target: "contract::babylon::test", "This should be a no-op");
    info!(target: "contract::babylon::test", "This should be a no-op");
    debug!(target: "ibc::test", "This should be a no-op");
}
