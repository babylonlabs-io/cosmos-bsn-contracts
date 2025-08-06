use crate::{
    error::ContractError,
    events::{new_finality_provider_status_change_event, FinalityProviderStatus},
    state::config::Config,
    state::finality::{get_last_signed_height, get_power_table_at_height, JAIL},
};
use cosmwasm_std::{DepsMut, Env, Event};

/// Check for inactive finality providers, and jail them.
///
/// The jailing mechanism is meant to be simple where an active finality provider
/// is jailed if it has not signed a block in the last `missed_blocks_window` blocks.
///
/// Note that this takes effect only after the next block is processed.
/// Returns events for newly jailed finality providers.
pub fn handle_liveness(
    deps: &mut DepsMut,
    env: &Env,
    cfg: &Config,
) -> Result<Vec<Event>, ContractError> {
    let fp_power_table = get_power_table_at_height(deps.storage, env.block.height)?;
    let window_start_height = env.block.height.saturating_sub(cfg.missed_blocks_window);

    let mut events = Vec::new();

    for (fp_btc_pk_hex, _) in fp_power_table {
        let last_sign_height = get_last_signed_height(deps.storage, &fp_btc_pk_hex)?;
        let inactive = match last_sign_height {
            Some(h) if h > window_start_height => false,
            _ => true,
        };
        if inactive {
            // Check if FP is already jailed to avoid duplicate events and unnecessary updates
            let was_already_jailed = JAIL.may_load(deps.storage, &fp_btc_pk_hex)?.is_some();

            if was_already_jailed {
                // FP is already jailed, no action needed
                continue;
            }

            // Jail the FP (we know it's not already jailed)
            JAIL.save(
                deps.storage,
                &fp_btc_pk_hex,
                &(env.block.time.seconds() + cfg.jail_duration),
            )?;

            // Emit jailed event for the newly jailed FP
            let event = new_finality_provider_status_change_event(
                &fp_btc_pk_hex,
                FinalityProviderStatus::Jailed,
            );
            events.push(event);
        }
    }

    Ok(events)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::finality::{set_voting_power_table, FP_BLOCK_SIGNER, FP_START_HEIGHT};
    use cosmwasm_std::{
        testing::{mock_dependencies, mock_env},
        Timestamp,
    };
    use std::collections::HashMap;

    #[test]
    fn test_handle_liveness() {
        let mut deps = mock_dependencies();
        let mut env = mock_env();
        env.block.height = 100;
        env.block.time = Timestamp::from_seconds(1000);

        let babylon_addr = deps.api.addr_make("babylon");
        let staking_addr = deps.api.addr_make("staking");
        let mut cfg = Config::new_test(babylon_addr, staking_addr);
        cfg.missed_blocks_window = 20; // Use a smaller window for testing

        // Set up power table with 3 FPs
        let fp1 = "fp1";
        let fp2 = "fp2";
        let fp3 = "fp3";

        let mut power_table = HashMap::new();
        power_table.insert(fp1.to_string(), 1000u64);
        power_table.insert(fp2.to_string(), 2000u64);
        power_table.insert(fp3.to_string(), 3000u64);
        set_voting_power_table(&mut deps.storage, 100, power_table).unwrap();

        // FP1: Active (signed at block 95, within window)
        FP_BLOCK_SIGNER
            .save(&mut deps.storage, fp1, &95u64)
            .unwrap();

        // FP2: Inactive (signed at block 70, outside window)
        FP_BLOCK_SIGNER
            .save(&mut deps.storage, fp2, &70u64)
            .unwrap();

        // FP3: Never signed (no entry in FP_BLOCK_SIGNER)

        // Call handle_liveness
        let events = handle_liveness(&mut deps.as_mut(), &env, &cfg).unwrap();

        // Check results
        // FP1 should NOT be jailed (active)
        assert!(JAIL.may_load(&deps.storage, fp1).unwrap().is_none());

        // FP2 should be jailed (inactive)
        let fp2_jail = JAIL.may_load(&deps.storage, fp2).unwrap();
        assert!(fp2_jail.is_some(), "FP2 should be jailed but wasn't");
        assert_eq!(
            fp2_jail.unwrap(),
            env.block.time.seconds() + cfg.jail_duration
        );

        // FP3 should be jailed (never signed)
        let fp3_jail = JAIL.may_load(&deps.storage, fp3).unwrap();
        assert!(fp3_jail.is_some(), "FP3 should be jailed but wasn't");
        assert_eq!(
            fp3_jail.unwrap(),
            env.block.time.seconds() + cfg.jail_duration
        );

        // Check events - should have 2 jailing events (for FP2 and FP3)
        assert_eq!(events.len(), 2);

        // Events can be in any order since HashMap iteration is not deterministic
        let mut event_fps = Vec::new();
        for event in &events {
            assert_eq!(event.ty, "finality_provider_status_change");
            let btc_pk = event
                .attributes
                .iter()
                .find(|attr| attr.key == "btc_pk")
                .unwrap()
                .value
                .clone();
            let new_state = event
                .attributes
                .iter()
                .find(|attr| attr.key == "new_state")
                .unwrap()
                .value
                .clone();
            assert_eq!(new_state, "FINALITY_PROVIDER_STATUS_JAILED");
            event_fps.push(btc_pk);
        }

        // Sort to make assertion deterministic
        event_fps.sort();
        assert_eq!(event_fps, vec![fp2.to_string(), fp3.to_string()]);
    }

    #[test]
    fn test_handle_liveness_already_jailed() {
        let mut deps = mock_dependencies();
        let mut env = mock_env();
        env.block.height = 100;
        env.block.time = Timestamp::from_seconds(1000);

        let babylon_addr = deps.api.addr_make("babylon");
        let staking_addr = deps.api.addr_make("staking");
        let mut cfg = Config::new_test(babylon_addr, staking_addr);
        cfg.missed_blocks_window = 20; // Use a smaller window for testing

        let fp1 = "fp1";

        // Set up power table
        let mut power_table = HashMap::new();
        power_table.insert(fp1.to_string(), 1000u64);
        set_voting_power_table(&mut deps.storage, 100, power_table).unwrap();

        // FP1 is already jailed
        let existing_jail_time = 500u64;
        JAIL.save(&mut deps.storage, fp1, &existing_jail_time)
            .unwrap();

        // FP1 is inactive (no recent signing)
        // (no entry in FP_BLOCK_SIGNER means never signed)

        // Call handle_liveness
        let events = handle_liveness(&mut deps.as_mut(), &env, &cfg).unwrap();

        // Check that jail time remains unchanged (already jailed FPs are not re-jailed)
        let fp1_jail = JAIL.load(&deps.storage, fp1).unwrap();
        assert_eq!(fp1_jail, existing_jail_time);

        // Check events - should have no events since FP was already jailed
        assert_eq!(events.len(), 0);
    }

    #[test]
    fn test_handle_liveness_recent_start_height() {
        let mut deps = mock_dependencies();
        let mut env = mock_env();
        env.block.height = 100;
        env.block.time = Timestamp::from_seconds(1000);

        let babylon_addr = deps.api.addr_make("babylon");
        let staking_addr = deps.api.addr_make("staking");
        let mut cfg = Config::new_test(babylon_addr, staking_addr);
        cfg.missed_blocks_window = 20; // Use a smaller window for testing

        let fp1 = "fp1";

        // Set up power table
        let mut power_table = HashMap::new();
        power_table.insert(fp1.to_string(), 1000u64);
        set_voting_power_table(&mut deps.storage, 100, power_table).unwrap();

        // FP1 has never signed (no entry in FP_BLOCK_SIGNER)
        // but has a recent start height (within missed_blocks_window)
        let recent_start_height = env
            .block
            .height
            .saturating_sub(cfg.missed_blocks_window / 2); // Well within window
        FP_START_HEIGHT
            .save(&mut deps.storage, fp1, &recent_start_height)
            .unwrap();

        // Call handle_liveness
        let events = handle_liveness(&mut deps.as_mut(), &env, &cfg).unwrap();

        // Check that FP1 is NOT jailed (recent start height, hasn't had time to sign yet)
        assert!(JAIL.may_load(&deps.storage, fp1).unwrap().is_none());

        // Check events - should have no events since FP was not jailed
        assert_eq!(events.len(), 0);
    }
}
