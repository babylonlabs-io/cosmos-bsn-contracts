//! # CosmWasm Logging
//!
//! Conditional logging utilities for CosmWasm contracts with development and production variants.
//!
//! ## Features
//!
//! - **Zero-cost abstractions**: In production builds (without `logging` feature), all logging calls are completely eliminated
//! - **Log levels**: Support for ERROR, WARN, INFO, DEBUG, and TRACE levels
//! - **Environment configuration**: Control log levels via `CONTRACT_LOG_LEVEL` environment variable in development
//! - **Familiar API**: Consistent with standard Rust logging patterns
//!
//! ## Usage
//!
//! ```rust
//! use cosmwasm_logging::ContractLogger;
//! use cosmwasm_logging::{info, debug, error};
//!
//! pub fn execute(deps: DepsMut, env: Env, info: MessageInfo, msg: ExecuteMsg) -> Result<Response, ContractError> {
//!     // Simple string logging
//!     deps.info("Execute function called");
//!
//!     // Formatted logging
//!     info!(deps, "Sender: {}, block height: {}", info.sender, env.block.height);
//!     debug!(deps, "Processing message: {:?}", msg);
//!
//!     // Works with API directly too
//!     deps.api.debug("Direct API access");
//!
//!     Ok(Response::new())
//! }
//! ```
//!
//! ## Build Variants
//!
//! - **Development**: `cargo build` (includes logging)
//! - **Production**: `cargo build --no-default-features` (zero logging overhead)

use std::env;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum LogLevel {
    Error = 1,
    Warn = 2,
    Info = 3,
    Debug = 4,
    Trace = 5,
}

/// Extension trait that adds logging methods to CosmWasm types
pub trait ContractLogger {
    /// Log an error message
    fn error(&self, msg: &str);
    /// Log a warning message
    fn warn(&self, msg: &str);
    /// Log an info message
    fn info(&self, msg: &str);
    /// Log a debug message
    fn debug(&self, msg: &str);
    /// Log a trace message
    fn trace(&self, msg: &str);

    /// Log formatted error message (used by error! macro)
    fn error_f(&self, args: std::fmt::Arguments<'_>);
    /// Log formatted warning message (used by warn! macro)
    fn warn_f(&self, args: std::fmt::Arguments<'_>);
    /// Log formatted info message (used by info! macro)
    fn info_f(&self, args: std::fmt::Arguments<'_>);
    /// Log formatted debug message (used by debug! macro)
    fn debug_f(&self, args: std::fmt::Arguments<'_>);
    /// Log formatted trace message (used by trace! macro)
    fn trace_f(&self, args: std::fmt::Arguments<'_>);
}

// Implementation for Deps (read-only)
#[cfg(feature = "logging")]
impl ContractLogger for cosmwasm_std::Deps<'_> {
    fn error(&self, msg: &str) {
        self.api.log_at_level(LogLevel::Error, msg);
    }
    fn warn(&self, msg: &str) {
        self.api.log_at_level(LogLevel::Warn, msg);
    }
    fn info(&self, msg: &str) {
        self.api.log_at_level(LogLevel::Info, msg);
    }
    fn debug(&self, msg: &str) {
        self.api.log_at_level(LogLevel::Debug, msg);
    }
    fn trace(&self, msg: &str) {
        self.api.log_at_level(LogLevel::Trace, msg);
    }

    fn error_f(&self, args: std::fmt::Arguments<'_>) {
        self.api.log_at_level_f(LogLevel::Error, args);
    }
    fn warn_f(&self, args: std::fmt::Arguments<'_>) {
        self.api.log_at_level_f(LogLevel::Warn, args);
    }
    fn info_f(&self, args: std::fmt::Arguments<'_>) {
        self.api.log_at_level_f(LogLevel::Info, args);
    }
    fn debug_f(&self, args: std::fmt::Arguments<'_>) {
        self.api.log_at_level_f(LogLevel::Debug, args);
    }
    fn trace_f(&self, args: std::fmt::Arguments<'_>) {
        self.api.log_at_level_f(LogLevel::Trace, args);
    }
}

// Implementation for DepsMut (mutable)
#[cfg(feature = "logging")]
impl ContractLogger for cosmwasm_std::DepsMut<'_> {
    fn error(&self, msg: &str) {
        self.api.log_at_level(LogLevel::Error, msg);
    }
    fn warn(&self, msg: &str) {
        self.api.log_at_level(LogLevel::Warn, msg);
    }
    fn info(&self, msg: &str) {
        self.api.log_at_level(LogLevel::Info, msg);
    }
    fn debug(&self, msg: &str) {
        self.api.log_at_level(LogLevel::Debug, msg);
    }
    fn trace(&self, msg: &str) {
        self.api.log_at_level(LogLevel::Trace, msg);
    }

    fn error_f(&self, args: std::fmt::Arguments<'_>) {
        self.api.log_at_level_f(LogLevel::Error, args);
    }
    fn warn_f(&self, args: std::fmt::Arguments<'_>) {
        self.api.log_at_level_f(LogLevel::Warn, args);
    }
    fn info_f(&self, args: std::fmt::Arguments<'_>) {
        self.api.log_at_level_f(LogLevel::Info, args);
    }
    fn debug_f(&self, args: std::fmt::Arguments<'_>) {
        self.api.log_at_level_f(LogLevel::Debug, args);
    }
    fn trace_f(&self, args: std::fmt::Arguments<'_>) {
        self.api.log_at_level_f(LogLevel::Trace, args);
    }
}

// Implementation for Api trait object
#[cfg(feature = "logging")]
impl ContractLogger for dyn cosmwasm_std::Api + '_ {
    fn error(&self, msg: &str) {
        self.log_at_level(LogLevel::Error, msg);
    }
    fn warn(&self, msg: &str) {
        self.log_at_level(LogLevel::Warn, msg);
    }
    fn info(&self, msg: &str) {
        self.log_at_level(LogLevel::Info, msg);
    }
    fn debug(&self, msg: &str) {
        self.log_at_level(LogLevel::Debug, msg);
    }
    fn trace(&self, msg: &str) {
        self.log_at_level(LogLevel::Trace, msg);
    }

    fn error_f(&self, args: std::fmt::Arguments<'_>) {
        self.log_at_level_f(LogLevel::Error, args);
    }
    fn warn_f(&self, args: std::fmt::Arguments<'_>) {
        self.log_at_level_f(LogLevel::Warn, args);
    }
    fn info_f(&self, args: std::fmt::Arguments<'_>) {
        self.log_at_level_f(LogLevel::Info, args);
    }
    fn debug_f(&self, args: std::fmt::Arguments<'_>) {
        self.log_at_level_f(LogLevel::Debug, args);
    }
    fn trace_f(&self, args: std::fmt::Arguments<'_>) {
        self.log_at_level_f(LogLevel::Trace, args);
    }
}

// Implementation for boxed Api
#[cfg(feature = "logging")]
impl ContractLogger for Box<dyn cosmwasm_std::Api> {
    fn error(&self, msg: &str) {
        self.as_ref().log_at_level(LogLevel::Error, msg);
    }
    fn warn(&self, msg: &str) {
        self.as_ref().log_at_level(LogLevel::Warn, msg);
    }
    fn info(&self, msg: &str) {
        self.as_ref().log_at_level(LogLevel::Info, msg);
    }
    fn debug(&self, msg: &str) {
        self.as_ref().log_at_level(LogLevel::Debug, msg);
    }
    fn trace(&self, msg: &str) {
        self.as_ref().log_at_level(LogLevel::Trace, msg);
    }

    fn error_f(&self, args: std::fmt::Arguments<'_>) {
        self.as_ref().log_at_level_f(LogLevel::Error, args);
    }
    fn warn_f(&self, args: std::fmt::Arguments<'_>) {
        self.as_ref().log_at_level_f(LogLevel::Warn, args);
    }
    fn info_f(&self, args: std::fmt::Arguments<'_>) {
        self.as_ref().log_at_level_f(LogLevel::Info, args);
    }
    fn debug_f(&self, args: std::fmt::Arguments<'_>) {
        self.as_ref().log_at_level_f(LogLevel::Debug, args);
    }
    fn trace_f(&self, args: std::fmt::Arguments<'_>) {
        self.as_ref().log_at_level_f(LogLevel::Trace, args);
    }
}

// Helper trait for the actual logging implementation
#[cfg(feature = "logging")]
trait LogAtLevel {
    fn log_at_level(&self, level: LogLevel, msg: &str);
    fn log_at_level_f(&self, level: LogLevel, args: std::fmt::Arguments<'_>);
}

#[cfg(feature = "logging")]
impl LogAtLevel for dyn cosmwasm_std::Api + '_ {
    fn log_at_level(&self, level: LogLevel, msg: &str) {
        let max_level = get_max_log_level();
        if level <= max_level {
            let level_str = level_to_str(level);
            self.debug(&format!("[{}] {}", level_str, msg));
        }
    }

    fn log_at_level_f(&self, level: LogLevel, args: std::fmt::Arguments<'_>) {
        let max_level = get_max_log_level();
        if level <= max_level {
            let level_str = level_to_str(level);
            self.debug(&format!("[{}] {}", level_str, args));
        }
    }
}

#[cfg(feature = "logging")]
fn level_to_str(level: LogLevel) -> &'static str {
    match level {
        LogLevel::Error => "ERROR",
        LogLevel::Warn => "WARN",
        LogLevel::Info => "INFO",
        LogLevel::Debug => "DEBUG",
        LogLevel::Trace => "TRACE",
    }
}

#[cfg(feature = "logging")]
fn get_max_log_level() -> LogLevel {
    match env::var("CONTRACT_LOG_LEVEL").as_deref() {
        Ok("error") => LogLevel::Error,
        Ok("warn") => LogLevel::Warn,
        Ok("info") => LogLevel::Info,
        Ok("debug") => LogLevel::Debug,
        Ok("trace") => LogLevel::Trace,
        _ => LogLevel::Debug, // Default level
    }
}

// No-op implementations for production (zero overhead)
#[cfg(not(feature = "logging"))]
impl ContractLogger for cosmwasm_std::Deps<'_> {
    fn error(&self, _msg: &str) {}
    fn warn(&self, _msg: &str) {}
    fn info(&self, _msg: &str) {}
    fn debug(&self, _msg: &str) {}
    fn trace(&self, _msg: &str) {}
    fn error_f(&self, _args: std::fmt::Arguments<'_>) {}
    fn warn_f(&self, _args: std::fmt::Arguments<'_>) {}
    fn info_f(&self, _args: std::fmt::Arguments<'_>) {}
    fn debug_f(&self, _args: std::fmt::Arguments<'_>) {}
    fn trace_f(&self, _args: std::fmt::Arguments<'_>) {}
}

#[cfg(not(feature = "logging"))]
impl ContractLogger for cosmwasm_std::DepsMut<'_> {
    fn error(&self, _msg: &str) {}
    fn warn(&self, _msg: &str) {}
    fn info(&self, _msg: &str) {}
    fn debug(&self, _msg: &str) {}
    fn trace(&self, _msg: &str) {}
    fn error_f(&self, _args: std::fmt::Arguments<'_>) {}
    fn warn_f(&self, _args: std::fmt::Arguments<'_>) {}
    fn info_f(&self, _args: std::fmt::Arguments<'_>) {}
    fn debug_f(&self, _args: std::fmt::Arguments<'_>) {}
    fn trace_f(&self, _args: std::fmt::Arguments<'_>) {}
}

#[cfg(not(feature = "logging"))]
impl ContractLogger for dyn cosmwasm_std::Api + '_ {
    fn error(&self, _msg: &str) {}
    fn warn(&self, _msg: &str) {}
    fn info(&self, _msg: &str) {}
    fn debug(&self, _msg: &str) {}
    fn trace(&self, _msg: &str) {}
    fn error_f(&self, _args: std::fmt::Arguments<'_>) {}
    fn warn_f(&self, _args: std::fmt::Arguments<'_>) {}
    fn info_f(&self, _args: std::fmt::Arguments<'_>) {}
    fn debug_f(&self, _args: std::fmt::Arguments<'_>) {}
    fn trace_f(&self, _args: std::fmt::Arguments<'_>) {}
}

#[cfg(not(feature = "logging"))]
impl ContractLogger for Box<dyn cosmwasm_std::Api> {
    fn error(&self, _msg: &str) {}
    fn warn(&self, _msg: &str) {}
    fn info(&self, _msg: &str) {}
    fn debug(&self, _msg: &str) {}
    fn trace(&self, _msg: &str) {}
    fn error_f(&self, _args: std::fmt::Arguments<'_>) {}
    fn warn_f(&self, _args: std::fmt::Arguments<'_>) {}
    fn info_f(&self, _args: std::fmt::Arguments<'_>) {}
    fn debug_f(&self, _args: std::fmt::Arguments<'_>) {}
    fn trace_f(&self, _args: std::fmt::Arguments<'_>) {}
}

/// Log an error message with formatting
///
/// # Example
/// ```rust
/// use cosmwasm_logging::{ContractLogger, error};
///
/// error!(deps, "Transaction failed: {}", error_msg);
/// ```
#[macro_export]
macro_rules! error {
    ($logger:expr, $($arg:tt)*) => {
        $logger.error_f(format_args!($($arg)*))
    };
}

/// Log a warning message with formatting
///
/// # Example
/// ```rust
/// use cosmwasm_logging::{ContractLogger, warn};
///
/// warn!(deps, "Deprecated feature used: {}", feature_name);
/// ```
#[macro_export]
macro_rules! warn {
    ($logger:expr, $($arg:tt)*) => {
        $logger.warn_f(format_args!($($arg)*))
    };
}

/// Log an info message with formatting
///
/// # Example
/// ```rust
/// use cosmwasm_logging::{ContractLogger, info};
///
/// info!(deps, "User {} deposited {} tokens", user, amount);
/// ```
#[macro_export]
macro_rules! info {
    ($logger:expr, $($arg:tt)*) => {
        $logger.info_f(format_args!($($arg)*))
    };
}

/// Log a debug message with formatting
///
/// # Example
/// ```rust
/// use cosmwasm_logging::{ContractLogger, debug};
///
/// debug!(deps, "Processing transaction: {:?}", tx);
/// ```
#[macro_export]
macro_rules! debug {
    ($logger:expr, $($arg:tt)*) => {
        $logger.debug_f(format_args!($($arg)*))
    };
}

/// Log a trace message with formatting
///
/// # Example
/// ```rust
/// use cosmwasm_logging::{ContractLogger, trace};
///
/// trace!(deps, "Entering function with params: {:?}", params);
/// ```
#[macro_export]
macro_rules! trace {
    ($logger:expr, $($arg:tt)*) => {
        $logger.trace_f(format_args!($($arg)*))
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::MockApi;

    #[test]
    fn test_log_levels_ordering() {
        assert!(LogLevel::Error < LogLevel::Warn);
        assert!(LogLevel::Warn < LogLevel::Info);
        assert!(LogLevel::Info < LogLevel::Debug);
        assert!(LogLevel::Debug < LogLevel::Trace);
    }

    #[test]
    fn test_level_to_str() {
        #[cfg(feature = "logging")]
        {
            assert_eq!(level_to_str(LogLevel::Error), "ERROR");
            assert_eq!(level_to_str(LogLevel::Warn), "WARN");
            assert_eq!(level_to_str(LogLevel::Info), "INFO");
            assert_eq!(level_to_str(LogLevel::Debug), "DEBUG");
            assert_eq!(level_to_str(LogLevel::Trace), "TRACE");
        }
    }

    #[test]
    fn test_contract_logger_trait() {
        let api = MockApi::default();

        // These should compile without errors (no-op in test without logging feature)
        api.error("test error");
        api.warn("test warn");
        api.info("test info");
        api.debug("test debug");
        api.trace("test trace");
    }

    #[test]
    fn test_logging_macros() {
        let api = MockApi::default();

        // These should compile without errors
        error!(api, "Error: {}", "test");
        warn!(api, "Warning: {}", "test");
        info!(api, "Info: {}", "test");
        debug!(api, "Debug: {}", "test");
        trace!(api, "Trace: {}", "test");
    }
}
