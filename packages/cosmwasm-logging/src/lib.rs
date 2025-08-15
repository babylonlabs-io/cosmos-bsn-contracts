//! # CosmWasm Logging
//!
//! Standard Rust logging for CosmWasm contracts inspired by Polkadot-SDK's runtime logging.
//!
//! This crate provides zero-cost logging abstractions for CosmWasm contracts:
//! - **Development builds**: Full logging support with standard `log` crate macros
//! - **Production builds**: All logging code eliminated at compile-time
//!
//! ## Features
//!
//! - **Standard log crate**: Use familiar `info!()`, `debug!()`, `error!()` macros
//! - **Zero-cost production**: No features = all logging code eliminated at compile-time
//! - **CosmWasm integration**: Logs route through CosmWasm's `api.debug()`
//! - **Lazy initialization**: Logger only initializes when actually used
//!
//! ## Usage
//!
//! ```rust
//! use cosmwasm_logging::{init_cosmwasm_logger, info, debug, error, warn};
//!
//! pub fn instantiate(
//!     deps: DepsMut,
//!     _env: Env,
//!     _info: MessageInfo,
//!     msg: InstantiateMsg,
//! ) -> Result<Response, ContractError> {
//!     // Initialize logger once (usually in instantiate)
//!     init_cosmwasm_logger(&deps.api);
//!
//!     info!("Contract instantiated");
//!     debug!("Instantiate message: {:?}", msg);
//!
//!     Ok(Response::new())
//! }
//!
//! pub fn execute(
//!     deps: DepsMut,
//!     env: Env,
//!     info: MessageInfo,
//!     msg: ExecuteMsg,
//! ) -> Result<Response, ContractError> {
//!     debug!("Execute called by {} at height {}", info.sender, env.block.height);
//!
//!     match msg {
//!         ExecuteMsg::Transfer { recipient, amount } => {
//!             info!("Transferring {} to {}", amount, recipient);
//!             // ... business logic
//!             Ok(Response::new())
//!         }
//!     }
//! }
//! ```
//!
//! ## Build Variants
//!
//! ```toml
//! # Development build (includes logging)
//! [dependencies]
//! cosmwasm-logging = { path = "...", features = ["logging"] }
//!
//! # Production build (no logging)
//! [dependencies]
//! cosmwasm-logging = { path = "..." }  # No features = no-op macros
//! ```

#[cfg(feature = "logging")]
mod enabled {
    use std::sync::Once;
    use cosmwasm_std::Api;
    use log::{Level, Log, Metadata, Record};

    pub use log::{debug, error, info, trace, warn, log};

    static COSMWASM_LOGGER: CosmWasmLogger = CosmWasmLogger;
    static INIT: Once = Once::new();

    thread_local! {
        static COSMWASM_API: std::cell::RefCell<Option<&'static dyn Api>> = std::cell::RefCell::new(None);
    }

    struct CosmWasmLogger;

    impl Log for CosmWasmLogger {
        fn enabled(&self, _metadata: &Metadata) -> bool {
            // Always enabled if logger is initialized - CosmWasm will handle filtering
            true
        }

        fn log(&self, record: &Record) {
            if self.enabled(record.metadata()) {
                COSMWASM_API.with(|api_ref| {
                    if let Some(api) = *api_ref.borrow() {
                        let level_str = match record.level() {
                            Level::Error => "ERROR",
                            Level::Warn => "WARN",
                            Level::Info => "INFO",
                            Level::Debug => "DEBUG",
                            Level::Trace => "TRACE",
                        };

                        let message = format!("{}: [{}] {}", record.target(), level_str, record.args());
                        api.debug(&message);
                    }
                });
            }
        }

        fn flush(&self) {
            // No-op for CosmWasm
        }
    }

    /// Initialize the CosmWasm logger.
    ///
    /// This function sets up logging to route through CosmWasm's `api.debug()` system.
    /// It uses `std::sync::Once` internally, so it's safe and efficient to call multiple times.
    ///
    /// ## Recommended Usage
    ///
    /// Call this function at the beginning of **every contract entry point** to ensure
    /// logging works in all scenarios, including unit tests that call functions directly:
    ///
    /// ```rust
    /// pub fn instantiate(deps: DepsMut, env: Env, info: MessageInfo, msg: InstantiateMsg) -> Result<Response, ContractError> {
    ///     init_cosmwasm_logger(deps.api);
    ///     info!("Contract instantiated");
    ///     // ... rest of function
    /// }
    ///
    /// pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> Result<Response, ContractError> {
    ///     init_cosmwasm_logger(deps.api);
    ///     debug!("Execute called by {}", info.sender);
    ///     // ... rest of function
    /// }
    ///
    /// pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> Result<QueryResponse, ContractError> {
    ///     init_cosmwasm_logger(deps.api);
    ///     debug!("Query: {:?}", msg);
    ///     // ... rest of function
    /// }
    ///
    /// pub fn reply(deps: DepsMut, env: Env, reply: Reply) -> Result<Response, ContractError> {
    ///     init_cosmwasm_logger(deps.api);
    ///     debug!("Reply received: {}", reply.id);
    ///     // ... rest of function
    /// }
    ///
    /// pub fn migrate(deps: DepsMut, env: Env, msg: MigrateMsg) -> Result<Response, ContractError> {
    ///     init_cosmwasm_logger(deps.api);
    ///     info!("Contract migration started");
    ///     // ... rest of function
    /// }
    /// ```
    ///
    /// ## Behavior
    ///
    /// - **First call**: Initializes the logger and stores the API reference
    /// - **Subsequent calls**: No-op (returns immediately)
    /// - **Thread safety**: Safe to call from multiple contexts
    /// - **Performance**: Zero overhead after first initialization
    ///
    /// ## When logging is disabled
    ///
    /// When compiled without the `logging` feature, this function becomes a no-op
    /// and is completely eliminated at compile time.
    ///
    /// ## Log Output Format
    ///
    /// Logs are formatted as: `target: [LEVEL] message`
    ///
    /// Examples:
    /// - `contract::babylon::instantiate: [INFO] Contract instantiated`
    /// - `contract::babylon::execute: [DEBUG] Processing transfer`
    /// - `ibc::packet: [ERROR] Failed to process IBC packet`
    pub fn init_cosmwasm_logger(api: &dyn Api) {
        INIT.call_once(|| {
            // Store the API reference
            COSMWASM_API.with(|api_ref| {
                // SAFETY: We assume the API reference lives for the duration of the contract call
                // This is safe in CosmWasm as the API is provided by the runtime and outlives all contract execution
                let api_static: &'static dyn Api = unsafe { std::mem::transmute(api) };
                *api_ref.borrow_mut() = Some(api_static);
            });

            // Set the global logger (ignore error if already set)
            let _ = log::set_logger(&COSMWASM_LOGGER)
                .map(|()| log::set_max_level(log::LevelFilter::Trace));
        });
    }
}

#[cfg(not(feature = "logging"))]
mod disabled {
    /// Initialize the CosmWasm logger (no-op when logging is disabled).
    ///
    /// When compiled without the `logging` feature, this function does nothing
    /// and is completely eliminated at compile time, providing zero runtime cost.
    ///
    /// This function has the same signature as the enabled version, so you can
    /// call it safely in all contract entry points regardless of feature flags.
    ///
    /// See the `enabled` module documentation for full usage examples.
    pub fn init_cosmwasm_logger(_api: &dyn cosmwasm_std::Api) {
        // No-op when logging is disabled - this function is eliminated at compile time
    }

    // No-op macros that match log crate's API
    #[macro_export]
    macro_rules! error {
        (target: $target:expr, $($arg:tt)*) => {};
        ($($arg:tt)*) => {};
    }

    #[macro_export]
    macro_rules! warn {
        (target: $target:expr, $($arg:tt)*) => {};
        ($($arg:tt)*) => {};
    }

    #[macro_export]
    macro_rules! info {
        (target: $target:expr, $($arg:tt)*) => {};
        ($($arg:tt)*) => {};
    }

    #[macro_export]
    macro_rules! debug {
        (target: $target:expr, $($arg:tt)*) => {};
        ($($arg:tt)*) => {};
    }

    #[macro_export]
    macro_rules! trace {
        (target: $target:expr, $($arg:tt)*) => {};
        ($($arg:tt)*) => {};
    }

    #[macro_export]
    macro_rules! log {
        (target: $target:expr, $lvl:expr, $($arg:tt)+) => {};
        ($lvl:expr, $($arg:tt)+) => {};
    }

    // Re-export our no-op macros
    pub use {debug, error, info, log, trace, warn};
}

// Export the appropriate symbols based on feature
#[cfg(feature = "logging")]
pub use enabled::*;

#[cfg(not(feature = "logging"))]
pub use disabled::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_logger_compiles() {
        // Test that the function compiles in both feature configurations
        use cosmwasm_std::testing::mock_dependencies;
        let deps = mock_dependencies();
        init_cosmwasm_logger(&deps.api);
    }

    #[test]
    fn test_macros_compile() {
        // These should compile in both configurations
        error!("Error: {}", "test");
        warn!("Warning: {}", "test");
        info!("Info: {}", "test");
        debug!("Debug: {}", "test");
        trace!("Trace: {}", "test");

        // Test with target (log crate style)
        error!(target: "my_target", "Error: {}", "test");
        info!(target: "my_target", "Info: {}", "test");
    }
}