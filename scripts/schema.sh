#!/bin/bash

for CONTRACT in ./contracts/*/; do
  CRATE_NAME=$(basename "$CONTRACT")
  echo "Generating schema for $CRATE_NAME..."
  (cd $CONTRACT && cargo run --bin "$CRATE_NAME-schema")
done
