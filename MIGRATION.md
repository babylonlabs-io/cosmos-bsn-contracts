# CosmWasm Contract Migration Guide

This guide explains how to migrate the Babylon Consumer BSN contracts using
CosmWasm's built-in migration mechanism.

## Overview

CosmWasm provides a built-in migration mechanism that allows you to upgrade
contract logic while preserving the existing state and contract address. This is
essential for fixing bugs, adding features, or optimizing performance without
losing data or requiring users to interact with a new contract address.

## Migration Process

The migration process consists of three main stages:

1. **Build and Store New Contract Code**: Compile the updated contract and store
   it on the blockchain
2. **Execute Migration**: Use the admin account to migrate the existing contract
   to the new code
3. **Verify Migration**: Confirm the migration was successful and the contract
   is functioning correctly

## Migration Types

### Non-State-Breaking Migrations

Currently, our contracts support **non-state-breaking migrations**, which allow
you to:
- Update contract logic and business rules
- Fix bugs in existing functions
- Add new query functions
- Optimize performance
- Update dependencies

**Important**: The state structure (storage layout) must remain compatible
between versions.

### State-Breaking Migrations

State-breaking migrations that change the storage layout are not currently
supported but may be added in future versions.

## Prerequisites

- Admin privileges on the target contract
- Access to a CosmWasm-enabled blockchain node
- Updated contract code compiled and ready for deployment

## Step-by-Step Migration Process

### 1. Build and Store New Contract Code

First, build your updated contract:

```bash
# Build optimized contract
cargo wasm
cargo schema

# Optimize the wasm file (recommended)
docker run --rm -v "$(pwd)":/code \
  --mount type=volume,source="$(basename "$(pwd)")_cache",target=/code/target \
  --mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
  cosmwasm/rust-optimizer:0.12.13
```

Store the new contract code on the blockchain:

```bash
# Store the new contract code
TX_HASH=$(wasmd tx wasm store artifacts/contract.wasm \
  --from admin-key \
  --gas auto \
  --gas-adjustment 1.3 \
  --chain-id your-chain-id \
  --node https://your-node-endpoint \
  --yes \
  --output json | jq -r '.txhash')

# Wait for transaction to be included
sleep 6

# Get the new code ID
NEW_CODE_ID=$(wasmd query tx $TX_HASH \
  --node https://your-node-endpoint \
  --output json | jq -r '.logs[0].events[] | select(.type=="store_code") | .attributes[] | select(.key=="code_id") | .value')

echo "New code ID: $NEW_CODE_ID"
```

### 2. Execute Migration

Migrate the existing contract to use the new code:

```bash
# Define contract address and migration message
CONTRACT_ADDRESS="cosmos1..."
MIGRATE_MSG='{}' # Empty for non-state-breaking migrations

# Execute migration
wasmd tx wasm migrate $CONTRACT_ADDRESS $NEW_CODE_ID "$MIGRATE_MSG" \
  --from admin-key \
  --gas auto \
  --gas-adjustment 1.3 \
  --chain-id your-chain-id \
  --node https://your-node-endpoint \
  --yes
```

### 3. Verify Migration

Confirm the migration was successful:

```bash
# Check contract info to verify new code ID
wasmd query wasm contract $CONTRACT_ADDRESS \
  --node https://your-node-endpoint

# Query contract version to verify update
wasmd query wasm contract-state smart $CONTRACT_ADDRESS \
  '{"contract_info":{}}' \
  --node https://your-node-endpoint

# Test contract functionality
wasmd query wasm contract-state smart $CONTRACT_ADDRESS \
  '{"config":{}}' \
  --node https://your-node-endpoint
```

## Migration Message Structure

Our contracts use an empty migration message for non-state-breaking migrations:

```rust
#[cw_serde]
pub struct MigrateMsg {}
```

The migration handler performs these actions:
1. Validates the contract name matches the expected value
2. Updates the contract version using `cw2::set_contract_version`
3. Returns a response with migration attributes

## Version Tracking

All contracts use the `cw2` library for version tracking:

- **Contract Name**: Automatically set from `CARGO_PKG_NAME`
- **Version**: Automatically set from `CARGO_PKG_VERSION`
- **Migration Validation**: Ensures migrations only occur between compatible
  contracts

## Error Handling

Common migration errors and solutions:

### `InvalidContractName` Error
```
Cannot migrate from different contract. Expected: babylon-contract, found: other-contract
```
**Solution**: Ensure you're migrating the correct contract type.

### `Unauthorized` Error
```
Only admin can execute migrations
```
**Solution**: Use the admin account that was set during contract instantiation.

### `CodeNotFound` Error
```
Code ID not found
```
**Solution**: Verify the new code was stored successfully and use the correct
code ID.

## Best Practices

### Before Migration

1. **Test Thoroughly**: Always test migrations on a testnet first
2. **Backup State**: Document critical contract state before migration
3. **Review Changes**: Ensure the new code is compatible with existing state
4. **Coordinate Timing**: Plan migrations during low-activity periods

### During Migration

1. **Monitor Progress**: Watch for transaction confirmation
2. **Verify Execution**: Check that the migration transaction succeeded
3. **Test Immediately**: Run basic functionality tests after migration

### After Migration

1. **Health Check**: Monitor contract behavior for anomalies
2. **User Communication**: Notify users of any changes in functionality
3. **Documentation**: Update relevant documentation and changelogs
4. **Monitor Logs**: Watch for any unexpected behavior or errors

## Security Considerations

- **Admin Key Security**: Ensure admin private keys are securely stored
- **Code Verification**: Verify the integrity of new contract code before
  migration
- **Rollback Plan**: Have a plan for reverting if issues are discovered
- **Access Control**: Limit admin access to authorized personnel only

## Troubleshooting

### Migration Transaction Failed

Check the transaction details for specific error messages:

```bash
wasmd query tx $TX_HASH --node https://your-node-endpoint
```

### Contract Not Responding After Migration

1. Verify the migration completed successfully
2. Check if the new contract code has any initialization requirements
3. Test basic queries to isolate the issue

### State Inconsistencies

If you suspect state corruption:
1. Compare critical state before and after migration
2. Test all major contract functions
3. Consider rolling back if issues persist

## Contract-Specific Notes

### Babylon Contract
- Manages BTC light client, staking, and finality contract addresses
- Migration preserves all sub-contract references

### BTC Finality Contract
- Maintains finality provider states and voting power history
- Migration preserves all accumulated voting weights and jail states

### BTC Light Client Contract
- Preserves all stored BTC headers and tip information
- Migration maintains the header chain integrity

### BTC Staking Contract
- Maintains all delegation states and finality provider information
- Migration preserves active/inactive delegation status

## Support

For migration issues or questions:
1. Check the troubleshooting section above
2. Review contract-specific documentation
3. Consult the CosmWasm migration documentation
4. Reach out to the development team for complex issues

---

**Note**: Always test migrations on testnets before applying to production
environments. Migration is a powerful feature that should be used carefully and
with proper preparation.
