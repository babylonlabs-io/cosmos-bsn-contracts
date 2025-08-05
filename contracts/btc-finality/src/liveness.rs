use cosmwasm_std::{DepsMut, Env};

use crate::{
    error::ContractError,
    state::config::Config,
    state::finality::{get_last_signed_height, get_power_table_at_height, JAIL},
};

/// Check for inactive finality providers, and jail them.
///
/// The jailing mechanism is meant to be simple where an active finality provider
/// is jailed if it has not signed a block in the last `missed_blocks_window` blocks.
///
/// Note that this takes effect only after the next block is processed.
pub fn handle_liveness(deps: &mut DepsMut, env: &Env, cfg: &Config) -> Result<(), ContractError> {
    let fp_power_table = get_power_table_at_height(deps.storage, env.block.height)?;

    fp_power_table.iter().try_for_each(|(fp_btc_pk_hex, _)| {
        let last_sign_height = get_last_signed_height(deps.storage, fp_btc_pk_hex)?;
        match last_sign_height {
            Some(h) if h > env.block.height.saturating_sub(cfg.missed_blocks_window) => {
                Ok::<_, ContractError>(())
            }
            _ => {
                // FP is inactive for at least missed_blocks_window, jail! (if not already jailed)
                JAIL.update(
                    deps.storage,
                    fp_btc_pk_hex,
                    |jailed: Option<u64>| match jailed {
                        Some(jail_time) => Ok::<_, ContractError>(jail_time),
                        None => Ok(env.block.time.seconds() + cfg.jail_duration),
                    },
                )?;
                Ok(())
            }
        }
    })?;

    Ok(())
}
