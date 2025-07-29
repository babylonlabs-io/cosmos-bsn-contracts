#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{Binary, Deps, DepsMut, Empty, Env, MessageInfo, Response};

use babylon_bindings::BabylonMsg;

use crate::error::ContractError;
pub use crate::msg::ExecuteMsg;
use crate::msg::InstantiateMsg;
use crate::msg::QueryMsg;
pub use crate::state::BitcoinNetwork;

mod bitcoin;
pub mod contract;
pub mod error;
pub mod msg;
pub mod queries;
pub mod state;
#[cfg(test)]
mod tests;

#[macro_export]
macro_rules! contract_debug {
    // Generic version (contract_debug!("prefix", "..."))
    ($deps:expr, $prefix:expr, $msg:expr) => {
        $deps
            .api
            .debug(&format!("contracts::cosmos::{}: {}", $prefix, $msg))
    };
    // With error (contract_debug!("prefix", "error: {e:?}"))
    ($deps:expr, $prefix:expr, $msg:expr, $e:expr) => {
        $deps.api.debug(&format!(
            "contracts::cosmos::{}: {}: {:?}",
            $prefix, $msg, $e
        ))
    };
}

// Contract-specific shortcuts
#[macro_export]
macro_rules! lc {
    ($deps:expr, $($arg:tt)*) => {
        // Shortcut for babylon contract (babylon!("..."))
        crate::contract_debug!($deps, "lc", $($arg)*)
    };
}

pub struct ContractLogger<'a> {
    api: &'a dyn cosmwasm_std::Api,
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response<BabylonMsg>, ContractError> {
    contract::instantiate(deps, env, info, msg)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, env: Env, msg: QueryMsg) -> Result<Binary, ContractError> {
    contract::query(deps, env, msg)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(deps: DepsMut, env: Env, msg: Empty) -> Result<Response<BabylonMsg>, ContractError> {
    contract::migrate(deps, env, msg)
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response<BabylonMsg>, ContractError> {
    contract::execute(deps, env, info, msg)
}
