#!/bin/bash

# Script to check that schema binary names follow the format $crate-schema
# This script validates the naming convention defined in scripts/schema.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Checking schema binary naming convention..."
echo "Expected format: \$crate-schema (where \$crate is the contract directory name)"
echo

FAILED=0
TOTAL_CONTRACTS=0

# Check each contract directory
for CONTRACT_DIR in "$PROJECT_ROOT"/contracts/*/; do
    if [ ! -d "$CONTRACT_DIR" ]; then
        continue
    fi

    CRATE_NAME=$(basename "$CONTRACT_DIR")
    EXPECTED_SCHEMA_NAME="$CRATE_NAME-schema"
    CARGO_TOML="$CONTRACT_DIR/Cargo.toml"

    TOTAL_CONTRACTS=$((TOTAL_CONTRACTS + 1))

    echo "Checking contract: $CRATE_NAME"
    echo "  Expected schema binary name: $EXPECTED_SCHEMA_NAME"

    if [ ! -f "$CARGO_TOML" ]; then
        echo "  ❌ ERROR: Cargo.toml not found in $CONTRACT_DIR"
        FAILED=$((FAILED + 1))
        continue
    fi

    # Extract the schema binary name from Cargo.toml
    # Look for [[bin]] sections with name containing "schema"
    SCHEMA_BINARY=$(grep -A 10 '\[\[bin\]\]' "$CARGO_TOML" | grep -B 10 'schema\.rs' | grep '^name = ' | sed 's/name = "\(.*\)"/\1/' | tr -d '"')

    if [ -z "$SCHEMA_BINARY" ]; then
        echo "  ❌ ERROR: No schema binary found in $CARGO_TOML"
        FAILED=$((FAILED + 1))
        continue
    fi

    echo "  Found schema binary name: $SCHEMA_BINARY"

    if [ "$SCHEMA_BINARY" = "$EXPECTED_SCHEMA_NAME" ]; then
        echo "  ✅ PASS: Schema binary name matches expected format"
    else
        echo "  ❌ FAIL: Schema binary name does not match expected format"
        echo "    Expected: $EXPECTED_SCHEMA_NAME"
        echo "    Found: $SCHEMA_BINARY"
        FAILED=$((FAILED + 1))
    fi

    echo
done

echo "Summary:"
echo "  Total contracts checked: $TOTAL_CONTRACTS"
echo "  Failed checks: $FAILED"
echo "  Passed checks: $((TOTAL_CONTRACTS - FAILED))"

if [ $FAILED -eq 0 ]; then
    echo
    echo "🎉 All schema binary names follow the correct naming convention!"
    exit 0
else
    echo
    echo "💥 $FAILED contract(s) have incorrect schema binary names!"
    echo "Please ensure all schema binaries follow the format: \$crate-schema"
    echo "Where \$crate is the name of the contract directory."
    exit 1
fi
