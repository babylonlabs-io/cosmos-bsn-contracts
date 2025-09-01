use crate::error::ContractError;
use crate::state::finality::{BLOCKS, NEXT_HEIGHT};
use cosmwasm_std::DepsMut;

/// Emergency migration to fix specific NEXT_HEIGHT corruption at block 342533
///
/// This fixes a critical bug where NEXT_HEIGHT points to already finalized block 342533,
/// causing all subsequent tallying operations to fail with FinalisedBlockWithFinalityProviderSet error.
///
/// The fix is very specific and conservative:
/// 1. ONLY fixes if NEXT_HEIGHT is exactly 342533
/// 2. ONLY fixes if block 342533 is actually finalized
/// 3. Sets NEXT_HEIGHT to 342534 to resume finalization
///
/// This targeted fix will immediately resume finalization for the 600,000+ blocks that have been stuck
/// since this specific corruption occurred.
pub fn fix_next_height_corruption(deps: DepsMut) -> Result<(), ContractError> {
    deps.api
        .debug("Starting NEXT_HEIGHT corruption fix migration...");

    // Get current NEXT_HEIGHT value
    let current_next_height = NEXT_HEIGHT.may_load(deps.storage)?.unwrap_or(0);

    deps.api
        .debug(&format!("Current NEXT_HEIGHT: {}", current_next_height));

    // Check ONLY for the specific known corruption: NEXT_HEIGHT == 342533
    if current_next_height == 342533 {
        deps.api.debug("Detected NEXT_HEIGHT pointing to block 342533 - checking if this is the known corruption...");

        // Verify that block 342533 is actually finalized (confirming the corruption)
        match BLOCKS.may_load(deps.storage, 342533)? {
            Some(block) if block.finalized => {
                deps.api.debug(
                    "CONFIRMED CORRUPTION: Block 342533 is finalized but NEXT_HEIGHT points to it!",
                );
                deps.api.debug("Applying emergency fix...");

                // Fix the corruption by setting NEXT_HEIGHT to 342534
                NEXT_HEIGHT.save(deps.storage, &342534)?;

                deps.api
                    .debug("EMERGENCY FIX APPLIED: Corrected NEXT_HEIGHT from 342533 to 342534");
                deps.api
                    .debug("This will resume finalization for 600,000+ stuck blocks");

                return Ok(());
            }
            Some(block) => {
                deps.api.debug(&format!(
                    "Block 342533 exists but is not finalized (finalized: {}). No corruption present - no fix needed.",
                    block.finalized
                ));
            }
            None => {
                deps.api
                    .debug("Block 342533 does not exist. No corruption present - no fix needed.");
            }
        }
    } else {
        deps.api.debug(&format!(
            "NEXT_HEIGHT ({}) is not 342533. This migration only fixes the specific 342533 corruption - no action needed.", 
            current_next_height
        ));
    }

    deps.api
        .debug("NEXT_HEIGHT corruption fix migration completed - no changes made");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::finality::BLOCKS;
    use babylon_apis::finality_api::IndexedBlock;
    use cosmwasm_std::testing::mock_dependencies;

    #[test]
    fn test_fix_next_height_corruption_342533() {
        let mut deps = mock_dependencies();

        // Set up the corrupted state: block 342533 is finalized but NEXT_HEIGHT points to it
        let finalized_block = IndexedBlock {
            height: 342533,
            app_hash: vec![1, 2, 3, 4],
            finalized: true,
        };
        BLOCKS
            .save(deps.as_mut().storage, 342533, &finalized_block)
            .unwrap();
        NEXT_HEIGHT.save(deps.as_mut().storage, &342533).unwrap();

        // Verify initial corrupted state
        let initial_next_height = NEXT_HEIGHT.load(deps.as_ref().storage).unwrap();
        assert_eq!(initial_next_height, 342533);

        // Run the fix
        fix_next_height_corruption(deps.as_mut()).unwrap();

        // Verify the fix worked
        let fixed_next_height = NEXT_HEIGHT.load(deps.as_ref().storage).unwrap();
        assert_eq!(fixed_next_height, 342534);
    }

    #[test]
    fn test_fix_next_height_no_corruption_needed() {
        let mut deps = mock_dependencies();

        // Set up a healthy state: NEXT_HEIGHT points to non-finalized block
        let non_finalized_block = IndexedBlock {
            height: 342534,
            app_hash: vec![1, 2, 3, 4],
            finalized: false,
        };
        BLOCKS
            .save(deps.as_mut().storage, 342534, &non_finalized_block)
            .unwrap();
        NEXT_HEIGHT.save(deps.as_mut().storage, &342534).unwrap();

        // Verify initial healthy state
        let initial_next_height = NEXT_HEIGHT.load(deps.as_ref().storage).unwrap();
        assert_eq!(initial_next_height, 342534);

        // Run the fix
        fix_next_height_corruption(deps.as_mut()).unwrap();

        // Verify nothing changed (no corruption to fix)
        let unchanged_next_height = NEXT_HEIGHT.load(deps.as_ref().storage).unwrap();
        assert_eq!(unchanged_next_height, 342534);
    }

    #[test]
    fn test_ignores_other_corruptions() {
        let mut deps = mock_dependencies();

        // Set up a different corruption: NEXT_HEIGHT points to a different finalized block
        // This migration should NOT fix this - only fixes the specific 342533 corruption
        let finalized_block = IndexedBlock {
            height: 100000,
            app_hash: vec![1, 2, 3, 4],
            finalized: true,
        };
        BLOCKS
            .save(deps.as_mut().storage, 100000, &finalized_block)
            .unwrap();
        NEXT_HEIGHT.save(deps.as_mut().storage, &100000).unwrap();

        // Verify initial state
        let initial_next_height = NEXT_HEIGHT.load(deps.as_ref().storage).unwrap();
        assert_eq!(initial_next_height, 100000);

        // Run the fix
        fix_next_height_corruption(deps.as_mut()).unwrap();

        // Verify the other corruption was NOT fixed (this is the correct behavior)
        let unchanged_next_height = NEXT_HEIGHT.load(deps.as_ref().storage).unwrap();
        assert_eq!(
            unchanged_next_height, 100000,
            "Migration should only fix 342533 corruption, not other corruptions"
        );
    }

    #[test]
    fn test_ignores_different_healthy_next_height() {
        let mut deps = mock_dependencies();

        // Set up a healthy state with NEXT_HEIGHT at a different value
        let non_finalized_block = IndexedBlock {
            height: 500000,
            app_hash: vec![1, 2, 3, 4],
            finalized: false,
        };
        BLOCKS
            .save(deps.as_mut().storage, 500000, &non_finalized_block)
            .unwrap();
        NEXT_HEIGHT.save(deps.as_mut().storage, &500000).unwrap();

        // Run the fix
        fix_next_height_corruption(deps.as_mut()).unwrap();

        // Verify nothing changed - migration only targets 342533
        let unchanged_next_height = NEXT_HEIGHT.load(deps.as_ref().storage).unwrap();
        assert_eq!(
            unchanged_next_height, 500000,
            "Migration should not affect NEXT_HEIGHT when it's not 342533"
        );
    }
}
