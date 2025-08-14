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
//! - **Zero-cost production**: `disable-logging` feature eliminates all logging code
//! - **CosmWasm integration**: Logs route through CosmWasm's `api.debug()`
//! - **Lazy initialization**: Logger only initializes when actually used
//!
//! ## Usage
//!
//! ```rust
//! use log::{info, debug, error, warn};
//! use cosmwasm_logging::init_cosmwasm_logger;
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
//! cosmwasm-logging = { path = "...", features = ["disable-logging"] }
//! ```

#[cfg(feature = "logging")]
use std::sync::Once;

// Re-export the log crate when logging is enabled
#[cfg(feature = "logging")]
pub use log::{debug, error, info, trace, warn, log};

#[cfg(feature = "logging")]
use cosmwasm_std::Api;

#[cfg(feature = "logging")]
use log::{Level, Log, Metadata, Record};

#[cfg(feature = "logging")]
static COSMWASM_LOGGER: CosmWasmLogger = CosmWasmLogger;

#[cfg(feature = "logging")]
static INIT: Once = Once::new();

#[cfg(feature = "logging")]
thread_local! {
    static COSMWASM_API: std::cell::RefCell<Option<&'static dyn Api>> = std::cell::RefCell::new(None);
}

#[cfg(feature = "logging")]
struct CosmWasmLogger;

#[cfg(feature = "logging")]
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

                    let message = format!("[{level_str}] {}: {}", record.target(), record.args());
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
/// This should be called once, typically in your contract's `instantiate` function.
/// Subsequent calls are ignored (similar to Substrate's RuntimeLogger::init()).
///
/// # Example
/// ```rust
/// use cosmwasm_logging::init_cosmwasm_logger;
/// use log::info;
///
/// pub fn instantiate(deps: DepsMut, env: Env, info: MessageInfo, msg: InstantiateMsg) -> Result<Response, ContractError> {
///     init_cosmwasm_logger(&deps.api);
///     info!("Contract instantiated");
///     Ok(Response::new())
/// }
/// ```
#[cfg(feature = "logging")]
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

/// Initialize the CosmWasm logger (no-op when logging is disabled).
///
/// When the `disable-logging` feature is enabled, this function does nothing
/// and all logging macros become no-ops at compile time.
#[cfg(not(feature = "logging"))]
pub fn init_cosmwasm_logger(_api: &dyn cosmwasm_std::Api) {
    // No-op when logging is disabled
}

// When logging is disabled, provide no-op macros that match log crate's API
#[cfg(not(feature = "logging"))]
#[macro_export]
macro_rules! error {
    (target: $target:expr, $($arg:tt)*) => {};
    ($($arg:tt)*) => {};
}

#[cfg(not(feature = "logging"))]
#[macro_export]
macro_rules! warn {
    (target: $target:expr, $($arg:tt)*) => {};
    ($($arg:tt)*) => {};
}

#[cfg(not(feature = "logging"))]
#[macro_export]
macro_rules! info {
    (target: $target:expr, $($arg:tt)*) => {};
    ($($arg:tt)*) => {};
}

#[cfg(not(feature = "logging"))]
#[macro_export]
macro_rules! debug {
    (target: $target:expr, $($arg:tt)*) => {};
    ($($arg:tt)*) => {};
}

#[cfg(not(feature = "logging"))]
#[macro_export]
macro_rules! trace {
    (target: $target:expr, $($arg:tt)*) => {};
    ($($arg:tt)*) => {};
}

#[cfg(not(feature = "logging"))]
#[macro_export]
macro_rules! log {
    (target: $target:expr, $lvl:expr, $($arg:tt)+) => {};
    ($lvl:expr, $($arg:tt)+) => {};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_logger_compiles() {
        // Test that the function compiles in both feature configurations
        #[cfg(feature = "logging")]
        {
            use cosmwasm_std::testing::mock_dependencies;
            let deps = mock_dependencies();
            init_cosmwasm_logger(&deps.api);
        }

        #[cfg(not(feature = "logging"))]
        {
            use cosmwasm_std::testing::mock_dependencies;
            let deps = mock_dependencies();
            init_cosmwasm_logger(&deps.api);
        }
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
