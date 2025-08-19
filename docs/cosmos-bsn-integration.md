# Cosmos BSN Integration

## Contents

- [1. Introduction](#1-introduction)
- [2. BSN Integration Overview](#2-bsn-integration-overview)
- [3. Governance Notes](#3-governance-notes)
  - [3.1 Babylon Genesis Governance](#31-babylon-genesis-governance)
  - [3.2 Cosmos BSN Governance](#32-cosmos-bsn-governance)
- [4. Compatibility and Version Requirements](#4-compatibility-and-version-requirements)
- [5. Integration Process](#5-integration-process)
  - [5.1 Adding the Babylon SDK Module](#51-adding-the-babylon-sdk-module)
  - [5.2 Establish IBC Connection with Babylon](#52-establish-ibc-connection-with-babylon)
  - [5.3 Upload BSN Contract Code](#53-upload-bsn-contract-code)
  - [5.4 Instantiate the Babylon Contract](#54-instantiate-the-babylon-contract)
  - [5.5 Register BSN Consumer on Babylon Genesis](#55-register-bsn-consumer-on-babylon-genesis)
  - [5.6 Create Zone Concierge Channel](#56-create-zone-concierge-channel)

## 1. Introduction

The Cosmos BSN (Bitcoin-Supercharged Network) is an integration model that
enables Cosmos SDK chains to inherit Bitcoin-backed security from Babylon
Genesis.  
It is implemented through a **native SDK module** combined with a suite of
CosmWasm contracts and an IBC connection to Babylon Genesis.

A Cosmos BSN chain must integrate the Babylon SDK module into its binary, deploy
the BSN contract suite on-chain, and establish an IBC channel with Babylon
Genesis.  
Once registered in Babylon Genesis as a BSN consumer, the chain can receive
finality secured by Bitcoin staking.

**Core components of a Cosmos BSN:**
- **Babylon SDK Module `x/babylon`** – Provides the necessary infrastructure
to collect venues and communicate with these contracts from Cosmos layer
- **BSN Contract Suite** – Four CosmWasm contracts deployed on the Cosmos chain:  
  - *Babylon Contract* – Coordinates BSN operations  
  - *BTC Light Client Contract* – Verifies Bitcoin state  
  - *BTC Staking Contract* – Manages BTC staking and delegation  
  - *BTC Finality Contract* – Collects and validates finality signatures
- **ICS20 IBC Channel** – Standard IBC transfer channel with Babylon Genesis
  required before BSN contract instantiation.
- **Zone Concierge IBC Channel** – Ordered channel used to connect the Cosmos
  chain to Babylon Genesis.  
- **Consumer Registration** – Each Cosmos BSN chain is registered on Babylon
  Genesis using its IBC client ID as the consumer identifier.  

## 2. BSN Integration Overview

> **Notice**  
> Before starting the lifecycle steps, ensure Cosmos BSN chain satisfies all
> [Compatibility and Version Requirements](#4-compatibility-and-version-requirements).

The following steps outline of integrating a Cosmos BSN:

1. **Module Integration:** Add the [Babylon SDK](https://github.com/babylonlabs-io/babylon-sdk) 
   module into Cosmos SDK chain binary.

2. **IBC Setup:** Establish IBC connection with Babylon:
   - Create IBC clients
   - Create an IBC connection
   - Create an **ICS20 transfer channel** (required before contract deployment)

3. **Contract Deployment:** Deploy the [BSN contract suite](https://github.com/babylonlabs-io/cosmos-bsn-contracts) 
   to Cosmos BSN chain and instantiate the Babylon contract, which requires the ICS20 
   channel ID and auto-deploys the Light Client, Staking, and Finality contracts.

4. **Governance Registration:** Register the deployed contract addresses with
   the Babylon SDK module via a governance proposal.

5. **BSN Consumer Registration:** Register cosmos BSN chain in the Babylon Genesis
   consumer registry using its IBC client ID.

6. **Zone Concierge Channel:** Establish an ordered Zone Concierge IBC channel
   between Cosmos BSN chain and Babylon Genesis.


## 3. Governance Notes

For Cosmos BSN integration, governance is required on **two chains**:  
- **Babylon Genesis** – where the BSN consumer must be registered  
- **The Cosmos BSN chain itself** – where BSN contracts are registered in the
  Babylon SDK module;  
  governance for contract deployment is only required if the Cosmos BSN chain
  uses permissioned CosmWasm  

Depending on whether you are integrating on **testnet** or **mainnet**, both
Babylon Genesis and the Cosmos BSN chain may operate in **permissioned** or
**permissionless** modes.  
The exact governance requirements vary, but the following apply in all cases.

### 3.1 Babylon Genesis Governance

Every Cosmos BSN must be registered in the Babylon Genesis consumer registry.  
This operation executes a `MsgRegisterConsumer` with the following metadata:

- IBC client ID of the Cosmos chain  
- Consumer name and description  
- Commission parameters  

The registration process depends on how the Babylon Genesis network is configured:

- **Permissionless** – No governance required. The Cosmos chain (or its operator
  account) can directly submit the MsgRegisterConsumer transaction.
- **Permissioned** – Governance required. The MsgRegisterConsumer message must
  be included in a governance proposal on Babylon Genesis and approved before
  registration.

> **Note**: For simplicity, the rest of this document assumes a **permissionless
> registration flow**.

### 3.2 Cosmos BSN Governance

On the Cosmos BSN chain itself, governance is required to integrate the BSN
contract suite with the Babylon SDK module:  

- **Register Contracts** – After deployment, the four BSN contracts must be
  registered with the Babylon SDK module using a `MsgSetBSNContracts` governance
  proposal. 

> **Notice**  
> Depending on the Cosmos BSN chain’s configuration:  
> - **Permissioned CosmWasm** – Governance may be required for uploading contract
>   code (`MsgStoreCode`) or allow-listing addresses for code upload
>   (`MsgAddCodeUploadParamsAddresses`).  
> - **Module Upgrades** – Adding the Babylon SDK `/x` module or performing
>   upgrades may also require governance approval.  

> **Note**: For simplicity, the rest of this document, we assume a **permissionless CosmWasm and
> governance flow** on the Cosmos BSN chain. 

## 4. Compatibility and Version Requirements

A Cosmos BSN must run on a Cosmos SDK stack with the following modules
enabled:  

- **IBC Module** – Provides cross-chain communication with Babylon Genesis  
- **CosmWasm Module** – Enables deployment and execution of the BSN smart
  contracts  
- **Governance Module** – Required for module configuration
  
**Supported Versions**  
- **Cosmos SDK**: v0.53  
- **IBC**: v10  
- **wasmd**: v0.55  

> **Notice:** We are actively testing backwards compatibility. 
> Once verified, all supported version combinations will be listed here.

## 5. Integration Process

### 5.1 Adding the Babylon SDK Module

> **Critical:** Before adding the Babylon SDK module, ensure you are using a 
> version that is compatible with your Cosmos SDK release. 
> See the [compatibility matrix]().

The [Babylon module (`x/babylon`)](https://github.com/babylonlabs-io/babylon-sdk/tree/main/x/babylon)
is the core integration point that enables a Cosmos SDK chain to function as a
BSN. It provides:

- **Contract Orchestration** — Manages the BSN contract suite (Babylon, BTC
  Light Client, BTC Staking, BTC Finality) deployed on the chain.
- **Block Information Bridge** — Sends block hash and app hash to contracts
  during BeginBlock/EndBlock for time-sensitive operations.
- **Fee Collector** — Intercepts a portion of transaction
fees collected by the network and sends them to the finality contract for distribution.

For design and functionality details, see the 
[module documentation](https://github.com/babylonlabs-io/babylon-sdk/tree/main/x/babylon/README.md).

> **Notice:** On some Cosmos SDK chains, adding a new module 
> (or upgrading the binary to include it) may require a governance proposal.

### 5.2 Establish IBC Connection with Babylon

> **Critical:** An **ICS20 transfer channel** must be established before 
> deploying BSN contracts. 
> The Babylon contract requires the channel ID during instantiation.

This step involves setting up an IBC relayer to create the necessary
communication between Cosmos BSN chain and Babylon Genesis. The
process includes:

- **IBC Client Creation** — Establish light clients for both chains
- **IBC Connection** — Create the connection between the chains  
- **ICS20 Transfer Channel** — Required for token transfers and contract
  instantiation
- **Consumer ID Extraction** — Save the IBC client ID for BSN registration

For detailed setup instructions, see the official 
[Babylon IBC Relayer Documentation](https://github.com/babylonlabs-io/babylon/blob/v3.0.0-rc.2/docs/ibc-relayer.md).

> **Important:** Save the **IBC client ID** from this step, it will 
> be used for BSN consumer registration.

### 5.3 Upload BSN Contract Code

Upload the four CosmWasm artifacts and record their code IDs. The command is the
same for each artifact; only `<WASM_PATH>` changes.

```bash
# Upload one artifact
<chain-binary> tx wasm store <WASM_PATH> --node <Cosmos BSN RPC> --from <key> --chain-id <chain-id> --gas 200000000 --gas-prices 0.01<denom> -y

# Retrieve the last uploaded code_id
<chain-binary> query wasm list-code -o json | jq -r '.code_infos[-1].code_id'
```

Repeat for:
- Babylon contract: `babylon_contract.wasm`
- BTC Light Client: `btc_light_client.wasm`
- BTC Staking: `btc_staking.wasm`
- BTC Finality: `btc_finality.wasm`

Record the four `code_id`s; you will use them in the next step.

> Note: These contracts must be compiled locally to obtain the `.wasm` artifacts.
> Refer to the official contract sources and build instructions at
> [cosmos-bsn-contracts/contracts](https://github.com/babylonlabs-io/cosmos-bsn-contracts/tree/main/contracts).

> **Notice:** This step uploads code only. Do not instantiate any contracts yet.

### 5.4 Instantiate the Babylon Contract

> **Critical:** You must have an ICS20 transfer channel established (from
> [5.2](#52-establish-ibc-connection-with-babylon)) and the four code IDs (from
> [5.3](#53-upload-bsn-contract-code)) before instantiating. The Babylon
> contract will orchestrate the initialization of the other three contracts.

For detailed instructions on instantiating the Babylon contract and registering
the instantiated Cosmos BSN contracts in the Babylon SDK module, refer to
[`docs/contract-instantiation.md`](./contract-instantiation.md).

On success, the Babylon contract will automatically:
- Instantiate the BTC Light Client, BTC Staking, and BTC Finality contracts
- Store IBC transfer details (ICS20 channel) for rewards distribution
- Set optional admin for controlled upgrades/migrations

> **Notice:** Most deployments can use default initialization for the three
> sub-contracts. Advanced users can override sub-contract init messages

### 5.5 Register BSN Consumer on Babylon Genesis

To register your Cosmos chain as a BSN on Babylon Genesis, you must submit its
BSN metadata.  

Use the following command: 

```bash
babylond tx btcstkconsumer register-consumer \
  <CONSUMER_ID> \
  <CONSUMER_NAME> \
  <CONSUMER_DESCRIPTION> \
  <BABYLON_REWARDS_COMMISSION> \
  --from <bbn-key> --chain-id <bbn-chain-id> --fees 100000ubbn -y
```

Required metadata for BSN registration:
- **consumer_id**: IBC client ID of your Cosmos BSN chain (saved during IBC
  setup)
- **consumer_name**: Human-readable name for your BSN (e.g., "DeFi Cosmos
  Chain")
- **consumer_description**: Brief description of the BSN's purpose
- **babylon_rewards_commission**: Decimal in [0,1], e.g., `0.1` for 10%

> **Governance Note:** On permissioned Babylon Genesis networks, this operation
> must be executed by governance.

### 5.6 Create Zone Concierge Channel

Establish an ordered IBC channel between the Cosmos BSN chain and Babylon
Genesis using the `zoneconcierge` port on the Cosmos side and the Babylon
contract port (`wasm.<babylon_contract_address>`) on the Babylon side.

Use your relayer to create the channel (example with Hermes):

```bash
rly tx channel <path-name> \
  --src-port zoneconcierge \
  --dst-port wasm.<babylon_contract_address> \
  --order ordered \
  --version zoneconcierge-1
```

Parameters:
- **path-name**: Pre-configured relayer path between Cosmos BSN chain and Babylon
- **src-port**: Must be `zoneconcierge` on the Cosmos BSN chain
- **dst-port**: Babylon contract port in the form `wasm.<babylon_contract_address>`
- **order**: Must be `ordered`
- **version**: Must be `zoneconcierge-1`

> **Notice:** For background and protocol details, see the Zone Concierge module
> docs: [x/zoneconcierge README](https://github.com/babylonlabs-io/babylon/blob/v3.0.0-rc.2/x/zoneconcierge/README.md).