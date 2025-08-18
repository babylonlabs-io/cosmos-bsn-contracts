# IBC Connection Setup Guide for Babylon BSN Integration

## Table of Contents
1. [Overview](#1-overview)
2. [Prerequisites](#2-prerequisites)
3. [Relayer Configuration](#3-relayer-configuration)
   - [3.1 Initialize Relayer](#31-initialize-relayer)
   - [3.2 Create Configuration File](#32-create-configuration-file)
   - [3.3 Add Relayer Keys](#33-add-relayer-keys)
4. [Create IBC Infrastructure](#4-create-ibc-infrastructure)
   - [4.1 Create IBC Clients](#41-create-ibc-clients)
   - [4.2 Create IBC Connection](#42-create-ibc-connection)
   - [4.3 Create ICS20 Transfer Channel](#43-create-ics20-transfer-channel)
5. [Extract Consumer ID](#5-extract-consumer-id)
6. [Extract ICS20 Channel ID](#6-extract-ics20-channel-id)
7. [Verification](#7-verification)
   - [7.1 Verify IBC Clients](#71-verify-ibc-clients)
   - [7.2 Verify Connection](#72-verify-connection)
   - [7.3 Verify Transfer Channel](#73-verify-transfer-channel)
8. [Important Notes](#8-important-notes)

## 1. Overview

This guide provides detailed instructions for establishing IBC connections
between the Cosmos BSN chain and Babylon Genesis. This connection is essential
for BSN integration and must be completed before deploying BSN contracts.

> Critical The ICS20 transfer channel must be created before deploying BSN
> contracts. The Babylon contract requires the channel ID during instantiation.

## 2. Prerequisites

- Babylon Genesis node running and accessible
- Cosmos BSN chain running and accessible  
- IBC relayer installed ([cosmos/relayer](https://github.com/cosmos/relayer) recommended)
- Funded accounts on both chains for relayer operations

## 3. Relayer Configuration

### 3.1 Initialize Relayer
```bash
# Create relayer directory and initialize
mkdir -p ~/.relayer
rly --home ~/.relayer config init
```

### 3.2 Create Configuration File

Create a complete relayer configuration file at `~/.relayer/config/config.yaml`:

```yaml
global:
    api-listen-addr: :5183
    max-retries: 20
    timeout: 30s
    memo: ""
    light-cache-size: 10
chains:
    babylon:
        type: cosmos
        value:
            key: babylon-relayer-key
            chain-id: <babylon-chain-id>  # e.g., bbn-test-5 or bbn-1
            rpc-addr: <babylon-rpc-endpoint>  # e.g., http://babylon-node:26657
            account-prefix: bbn
            keyring-backend: test
            gas-adjustment: 1.5
            gas-prices: 0.002ubbn
            min-gas-amount: 1
            debug: true
            timeout: 30s
            output-format: json
            sign-mode: direct
            extra-codecs: []
            trusting-period: <babylon-trusting-period>  # e.g., 33h (2/3 of unbonding period)
    bsn-chain:
        type: cosmos
        value:
            key: bsn-relayer-key
            chain-id: <bsn-chain-id>  # e.g., bsn-1
            rpc-addr: <bsn-rpc-endpoint>  # e.g., http://bsn-node:26657
            account-prefix: <bsn-prefix>  # e.g., bsn
            keyring-backend: test
            gas-adjustment: 1.5
            gas-prices: <gas-price>  # e.g., 0.025ubsn
            min-gas-amount: 1
            debug: true
            timeout: 30s
            output-format: json
            sign-mode: direct
            extra-codecs: []
            trusting-period: <bsn-trusting-period>  # e.g., 336h (2/3 of unbonding period)
paths:
    <path-name>:
        src:
            chain-id: <babylon-chain-id>
        dst:
            chain-id: <bsn-chain-id>
```

**Configuration Notes:**
- `<babylon-chain-id>`: Babylon ChainId
- `<babylon-rpc-endpoint>`: Babylon Genesis RPC endpoint
- `<babylon-trusting-period>`: Calculate as 2/3 of Babylon's unbonding period
  (query with `babylond query epoching params`)
- `<bsn-chain-id>`: The Cosmos BSN chain's chain ID
- `<bsn-rpc-endpoint>`: The Cosmos BSN chain's RPC endpoint  
- `<bsn-prefix>`: The Cosmos BSN chain's address prefix
- `<gas-price>`: The Cosmos BSN chain's gas price and denomination
- `<bsn-trusting-period>`: Calculate as 2/3 of the Cosmos BSN chain's unbonding
  period

**Important:** The client-id and connection-id values are dynamically generated
during Steps 4.1 and 4.2. You'll need to update the configuration file with the
actual values after creating the IBC infrastructure.

### 3.3 Add Relayer Keys
```bash
# Add keys for both chains (use actual mnemonics)
rly keys add babylon babylon-relayer-key
rly keys add bsn-chain bsn-relayer-key

# Fund the relayer accounts
# Babylon: Send ubbn tokens to relayer address
# Cosmos BSN chain: Send tokens to relayer address
```

## 4. Create IBC Infrastructure

### 4.1 Create IBC Clients
```bash
# Create light clients for both chains
rly tx clients babylon-bsn
```

### 4.2 Create IBC Connection
```bash
# Create connection between the chains
rly tx connection babylon-bsn
```

### 4.3 Create ICS20 Transfer Channel
```bash
# Create the transfer channel (REQUIRED for BSN contracts)
rly tx channel babylon-bsn \
  --src-port transfer \
  --dst-port transfer \
  --order unordered \
  --version ics20-1
```

## 5. Extract Consumer ID

The Consumer ID (IBC client ID) is required for BSN registration:

```bash
# Get the client ID from Cosmos BSN chain's perspective of Babylon
CONSUMER_ID=$(bsnchaind query ibc client states -o json | \
  jq -r '.client_states[] | select(.client_state.chain_id=="<babylon-chain-id>") | .client_id')

echo "Consumer ID: $CONSUMER_ID"
# Example output: 07-tendermint-0
```

## 6. Extract ICS20 Channel ID

The ICS20 channel ID is required for contract instantiation:

```bash
# Get the transfer channel ID
ICS20_CHANNEL_ID=$(bsnchaind query ibc channel channels -o json | \
  jq -r '.channels[] | select(.port_id=="transfer") | .channel_id')

echo "ICS20 Channel ID: $ICS20_CHANNEL_ID"
# Example output: channel-0
```

## 7. Verification

### 7.1 Verify IBC Clients
```bash
# Check client status on Cosmos BSN chain
bsnchaind query ibc client state $CONSUMER_ID

# Check client status on Babylon (use the Babylon-side client id)
babylond query ibc client state $BABYLON_SIDE_CLIENT_ID
```

### 7.2 Verify Connection
```bash
# Check connection status
bsnchaind query ibc connection connections
babylond query ibc connection connections
```

### 7.3 Verify Transfer Channel
```bash
# Test transfer channel with small token transfer
bsnchaind tx ibc-transfer transfer \
  transfer $ICS20_CHANNEL_ID \
  <babylon-address> 1<bsn-token> \
  --from bsn-relayer-key
```

## 8. Important Notes

- **Save the Consumer ID**: Required for BSN registration step
- **Save the ICS20 Channel ID**: Required for contract instantiation
- **Trusting Period**: Calculate as 2/3 of unbonding period for each chain
- **Keep Relayer Running**: Required for ongoing IBC operations