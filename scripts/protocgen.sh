#!/usr/bin/env bash

# This script generates protobuf messages in Rust using a Buf workspace
# Use with: `cargo run-script gen-proto` in the root dir.

set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PROTO_ROOT="$SCRIPT_DIR/packages/proto"

# Initialize git submodules
git submodule update --init --recursive

# Run `buf dep update` in the submodule(s)
echo "🔄 Updating buf deps in submodules..."
(cd "$PROTO_ROOT/babylon/proto" && buf dep update)

# Run `buf generate` from the workspace root
echo "⚙️ Generating Rust protobuf bindings..."
(cd "$PROTO_ROOT" && buf generate --template buf.gen.rust.yaml)

echo "✅ Done generating protobuf bindings."
