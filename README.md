# Cosmos BSN Contracts

This repository contains the CosmWasm smart contracts that enable
the integration of Cosmos BSNs with the Babylon BTC Staking protocol.

## Architecture

The contracts are written in Rust, and use the CosmWasm framework to interact
with the BSN's Cosmos application layer.
There's a thin layer, which adds a `babylon` module, which provides the necessary
functionality to interact with the contracts through privileged calls (`sudo`
messages) and custom messages.
This thin layer is naturally written in Go, and uses the Cosmos SDK.
It is in the [`babylon-sdk`](https://github.com/babylonlabs-io/babylon-sdk)
repository.

An integrator can import the `babylon` module into their Cosmos SDK-based chain,
and use the provided functionality to interact with the Babylon contracts,
following the demo app's guidelines and layout, which is provided in
`babylon-sdk`.

The entire solution is designed to be modular and extensible, for ease of
integration and future upgrades.

A broad architecture diagram, along with the contracts' main interfaces, can be
found in the [`docs/Architecture.md`](docs/Architecture.md) documentation.

## Development

### Prerequisites

Make sure you have `cargo-run-script` installed and docker running.

```bash
cargo install cargo-run-script
```

### Clean the build

```bash
cargo clean
```

### Build the contract

```bash
cargo build
```

### Formatting and Linting

Check whether the code is formatted correctly.

```bash
cargo fmt --all -- --check
cargo check
cargo clippy --all-targets -- -D warnings
```

Alternatively, you can run the following command to run all the checks at once.

```bash
cargo run-script lint
```

### Test the contract

Note: Requires the optimized contract to be built (`cargo optimize`)

Runs all the CI checks locally (in your actual toolchain).

```bash
cargo test --lib
```

### Integration tests the contract

Note: Requires the optimized contract to be built (`cargo optimize`)

```bash
cargo test --test integration
```

Alternatively, you can run the following command, that makes sure to build the optimized contract before running
the integration tests.

```bash
cargo run-script integration
```

### Generate the schema

```bash
cargo run-script gen-schema
```

### Generate the protobuf files

```bash
cargo run-script gen-proto
```

### Generate test data

```bash
cargo run-script gen-data
```

### Build the optimized contract

```bash
cargo run-script optimize
```
