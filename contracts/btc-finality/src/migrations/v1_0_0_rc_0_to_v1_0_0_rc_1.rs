use crate::error::ContractError;
use crate::state::config::{Config, CONFIG, DEFAULT_MAX_PUB_RAND_COMMIT_OFFSET};
use cosmwasm_schema::cw_serde;
use cosmwasm_std::{Addr, DepsMut};
use cw_storage_plus::Item;

/// Config struct for migration compatibility (v1.0.0-rc.0 format without max_pub_rand_commit_offset)
#[cw_serde]
pub struct ConfigV1 {
    pub denom: String,
    pub babylon: Addr,
    pub staking: Addr,
    pub max_active_finality_providers: u32,
    pub min_pub_rand: u64,
    pub reward_interval: u64,
    pub missed_blocks_window: u64,
    pub jail_duration: u64,
    pub finality_activation_height: u64,
}

/// Migrate config from v1.0.0-rc.0 to v1.0.0-rc.1
///
/// This migration adds the `max_pub_rand_commit_offset` field to the Config struct.
/// If the old config format is found, it will be migrated to the new format with
/// the default value for `max_pub_rand_commit_offset`.
pub fn migrate_config(deps: DepsMut) -> Result<(), ContractError> {
    // Try to load the current config, and if it fails (due to missing field),
    // load the old config format and migrate it
    match CONFIG.load(deps.storage) {
        Ok(_) => {
            // Config already in the new format, no migration needed
            Ok(())
        }
        Err(_) => {
            // Try to load the old config format
            let old_config_item: Item<ConfigV1> = Item::new("config");
            match old_config_item.load(deps.storage) {
                Ok(old_config) => {
                    // Migrate to new config format with default value for max_pub_rand_commit_offset
                    let new_config = Config {
                        denom: old_config.denom,
                        babylon: old_config.babylon,
                        staking: old_config.staking,
                        max_active_finality_providers: old_config.max_active_finality_providers,
                        min_pub_rand: old_config.min_pub_rand,
                        reward_interval: old_config.reward_interval,
                        missed_blocks_window: old_config.missed_blocks_window,
                        jail_duration: old_config.jail_duration,
                        finality_activation_height: old_config.finality_activation_height,
                        max_pub_rand_commit_offset: DEFAULT_MAX_PUB_RAND_COMMIT_OFFSET,
                    };

                    // Save the migrated config
                    CONFIG.save(deps.storage, &new_config)?;
                    Ok(())
                }
                Err(_) => {
                    // Neither old nor new config format could be loaded
                    // This is expected for contracts that were never initialized or in tests
                    // No migration is needed in this case
                    Ok(())
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::mock_dependencies;
    use cw_storage_plus::Item;

    #[test]
    fn test_migrate_config_from_v1() {
        let mut deps = mock_dependencies();

        // Create and save an old config (ConfigV1) without max_pub_rand_commit_offset
        let babylon_addr = deps.api.addr_make("babylon");
        let staking_addr = deps.api.addr_make("staking");
        let old_config = ConfigV1 {
            denom: "TOKEN".to_string(),
            babylon: babylon_addr.clone(),
            staking: staking_addr.clone(),
            max_active_finality_providers: 50,
            min_pub_rand: 10,
            reward_interval: 100,
            missed_blocks_window: 200,
            jail_duration: 3600,
            finality_activation_height: 5,
        };

        let old_config_item: Item<ConfigV1> = Item::new("config");
        old_config_item
            .save(deps.as_mut().storage, &old_config)
            .unwrap();

        // Verify the old config is saved and the new config cannot be loaded
        assert!(old_config_item.load(deps.as_ref().storage).is_ok());
        assert!(CONFIG.load(deps.as_ref().storage).is_err());

        // Run migration
        migrate_config(deps.as_mut()).unwrap();

        // Verify the new config can now be loaded and has the correct values
        let new_config = CONFIG.load(deps.as_ref().storage).unwrap();
        assert_eq!(new_config.denom, old_config.denom);
        assert_eq!(new_config.babylon, old_config.babylon);
        assert_eq!(new_config.staking, old_config.staking);
        assert_eq!(
            new_config.max_active_finality_providers,
            old_config.max_active_finality_providers
        );
        assert_eq!(new_config.min_pub_rand, old_config.min_pub_rand);
        assert_eq!(new_config.reward_interval, old_config.reward_interval);
        assert_eq!(
            new_config.missed_blocks_window,
            old_config.missed_blocks_window
        );
        assert_eq!(new_config.jail_duration, old_config.jail_duration);
        assert_eq!(
            new_config.finality_activation_height,
            old_config.finality_activation_height
        );
        // Verify the new field has the default value
        assert_eq!(
            new_config.max_pub_rand_commit_offset,
            DEFAULT_MAX_PUB_RAND_COMMIT_OFFSET
        );
    }

    #[test]
    fn test_migrate_config_already_new_format() {
        let mut deps = mock_dependencies();

        // Create and save a new config (already has max_pub_rand_commit_offset)
        let babylon_addr = deps.api.addr_make("babylon");
        let staking_addr = deps.api.addr_make("staking");
        let existing_config = Config {
            denom: "TOKEN".to_string(),
            babylon: babylon_addr.clone(),
            staking: staking_addr.clone(),
            max_active_finality_providers: 75,
            min_pub_rand: 15,
            reward_interval: 150,
            missed_blocks_window: 300,
            jail_duration: 7200,
            finality_activation_height: 10,
            max_pub_rand_commit_offset: 2_000_000,
        };

        CONFIG
            .save(deps.as_mut().storage, &existing_config)
            .unwrap();

        // Run migration
        migrate_config(deps.as_mut()).unwrap();

        // Verify the config remains unchanged (no migration needed)
        let config_after_migration = CONFIG.load(deps.as_ref().storage).unwrap();
        assert_eq!(config_after_migration.denom, existing_config.denom);
        assert_eq!(config_after_migration.babylon, existing_config.babylon);
        assert_eq!(config_after_migration.staking, existing_config.staking);
        assert_eq!(
            config_after_migration.max_active_finality_providers,
            existing_config.max_active_finality_providers
        );
        assert_eq!(
            config_after_migration.min_pub_rand,
            existing_config.min_pub_rand
        );
        assert_eq!(
            config_after_migration.reward_interval,
            existing_config.reward_interval
        );
        assert_eq!(
            config_after_migration.missed_blocks_window,
            existing_config.missed_blocks_window
        );
        assert_eq!(
            config_after_migration.jail_duration,
            existing_config.jail_duration
        );
        assert_eq!(
            config_after_migration.finality_activation_height,
            existing_config.finality_activation_height
        );
        // Verify the existing value is preserved
        assert_eq!(config_after_migration.max_pub_rand_commit_offset, 2_000_000);
    }

    #[test]
    fn test_migrate_config_no_config_exists() {
        let mut deps = mock_dependencies();

        // No config exists - this should not fail
        migrate_config(deps.as_mut()).unwrap();

        // Verify no config was created
        assert!(CONFIG.load(deps.as_ref().storage).is_err());
    }
}
