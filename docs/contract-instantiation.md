# Contract Instantiation and Module Governance

This guide covers instantiating the Babylon contract on your Cosmos BSN chain
and registering the deployed contract addresses in the Babylon SDK module via
governance.

## Contents

- [1. Prerequisites](#1-prerequisites)
- [2. Instantiate the Babylon Contract](#2-instantiate-the-babylon-contract)
- [3. Read Deployed Contract Addresses](#3-read-deployed-contract-addresses)
- [4. Register Contracts in the Module (Governance)](#4-register-contracts-in-the-module-governance)

## 1. Prerequisites

- Babylon SDK module integrated into the chain binary ([x/babylon](https://github.com/babylonlabs-io/babylon-sdk/tree/v0.12.0/x/babylon))
- IBC connection with Babylon Genesis (ICS20 transfer channel established)
- [Cosmos BSN contracts](../contracts/) uploaded (code IDs recorded)

> Notice: To complete these prerequisites, see `cosmos-bsn-integration.md`:
> - [4.2 Adding the Babylon SDK Module](./cosmos-bsn-integration.md#42-adding-the-babylon-sdk-module)
> - [4.3 Establish IBC Connection with Babylon](./cosmos-bsn-integration.md#43-establish-ibc-connection-with-babylon)
> - [4.4 Upload BSN Contract Code](./cosmos-bsn-integration.md#44-upload-bsn-contract-code)

## 2. Instantiate the Babylon Contract

Instantiate the Babylon contract with the ICS20 channel ID and references to the
three dependent code IDs. The contract will orchestrate
deployment/initialization of the [BTC Light Client](../contracts/btc-light-client/), 
[BTC Staking](../contracts/btc-staking/), and [BTC Finality](../contracts/btc-finality/)
contracts.

Initialization message fields:
- `network`: Bitcoin network. Allowed values: `mainnet`, `signet`, `testnet`, `regtest`
- `btc_confirmation_depth`: Minimum Bitcoin confirmations required
- `checkpoint_finalization_timeout`: Timeout for checkpoint finalization
- `btc_light_client_code_id`: Code ID for the BTC Light Client contract
- `btc_light_client_msg` (optional): Opaque init message for the BTC Light Client contract
- `btc_staking_code_id`: Code ID for the BTC Staking contract
- `btc_staking_msg` (optional): Opaque init message for the BTC Staking contract
- `btc_finality_code_id`: Code ID for the BTC Finality contract
- `btc_finality_msg` (optional): Opaque init message for the BTC Finality contract
- `consumer_name`: Human-readable name for this BSN
- `consumer_description`: Short description of this BSN
- `ics20_channel_id`: ICS20 channel ID created during IBC setup
- `ibc_packet_timeout_days` (optional): IBC packet timeout in days (default 28)
- `destination_module`: Babylon module name for receiving ICS-20 transfers (e.g., `btcstaking`)
- `admin`: Address with admin rights over the contract

> Advanced (optional overrides): In most deployments you can leave the three `*_msg` fields unset.
> If you need to customize sub-contract initialization, provide the respective init message:
> - `btc_light_client_msg`: BTC Light Client init message. Defaults to the top-level `network`, `btc_confirmation_depth`, `checkpoint_finalization_timeout`, and `admin`. See definition: [`contracts/btc-light-client/src/msg/contract.rs`](../contracts/btc-light-client/src/msg/contract.rs).
> - `btc_staking_msg`: BTC Staking init message. Defaults to `{ admin }`. See definition: [`packages/apis/src/btc_staking_api.rs`](../packages/apis/src/btc_staking_api.rs).
> - `btc_finality_msg`: BTC Finality init message. Defaults to `{ admin }` and module defaults. See definition: [`packages/apis/src/finality_api.rs`](../packages/apis/src/finality_api.rs).
> - Encoding: All three `*_msg` values must be base64-encoded JSON strings (as required by CosmWasm instantiate schemas).

> Notes:
> - `network` must match the Bitcoin network used by your BTC Light Client headers source; mismatches will prevent header verification.
> - `admin` is applied to the Babylon contract and all three sub-contracts. Many deployments set this to a governance-controlled address; leave unset for no Wasm admin (immutable code state).
> - `destination_module` is typically `btcstaking` and must correspond to a valid module name on your Cosmos chain that receives rewards via ICS-20.

Example init JSON (adjust values to your environment):

```json
{
  "network": "regtest",
  "btc_confirmation_depth": 1,
  "checkpoint_finalization_timeout": 2,
  "btc_light_client_code_id": 12,
  "btc_staking_code_id": 13,
  "btc_finality_code_id": 14,
  "consumer_name": "my-bsn",
  "consumer_description": "my-bsn description",
  "ics20_channel_id": "channel-0",
  "destination_module": "btcstaking",
  "admin": "cosmos1..."
}
```

Instantiate command template:

```bash
<chain-binary> tx wasm instantiate <BABYLON_CODE_ID> '<INIT_JSON>' \
  --admin <admin-address> --label "babylon" \
  --from <key> --chain-id <chain-id> --gas auto --gas-adjustment 1.3 --gas-prices 0.01<denom> -y
```

Record the deployed Babylon contract address.

## 3. Read Deployed Contract Addresses

Query the Babylon contract to get the addresses of the auto-deployed contracts.

```bash
<chain-binary> query wasm contract-state smart <BABYLON_ADDR> '{"config":{}}' -o json
```

From the response, record:
- `btc_light_client`
- `btc_staking`
- `btc_finality`

## 4. Register Contracts in the Module (Governance)

Create a governance proposal to register the four contract addresses in the Babylon SDK module.

> Governance is needed because `MsgSetBSNContracts` updates module state and is
> restricted to the module authority (default x/gov), preventing arbitrary users
> from registering incorrect or malicious contract addresses.

Proposal JSON template:

```json
{
  "messages": [
    {
      "@type": "/babylonlabs.babylon.v1beta1.MsgSetBSNContracts",
      "authority": "<gov-authority>",
      "contracts": {
        "babylon_contract": "<BABYLON_ADDR>",
        "btc_light_client_contract": "<BTC_LC_ADDR>",
        "btc_staking_contract": "<BTC_STAKING_ADDR>",
        "btc_finality_contract": "<BTC_FINALITY_ADDR>"
      }
    }
  ],
  "metadata": "Set BSN Contracts",
  "title": "Set BSN Contracts",
  "summary": "Register BSN contract addresses",
  "deposit": "1000000<denom>"
}
```

Submit and vote:

```bash
<chain-binary> tx gov submit-proposal <proposal.json> --from <proposer> --chain-id <chain-id> --fees 100000<denom> -y
<chain-binary> tx gov vote <proposal-id> yes --from <validator> --chain-id <chain-id> --fees 50000<denom> -y
```

> **Governance Note:** On permissioned networks, proposals must be submitted and
> approved by designated governance participants. Only bonded validators' votes count
> toward passing thresholds. Ensure sufficient voting power votes "yes".