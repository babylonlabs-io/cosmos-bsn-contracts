# Cosmos BSN Integration

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
- **Babylon SDK Module** – Provides native support for BSN logic and IBC
  interactions.  
- **BSN Contract Suite** – Four CosmWasm contracts deployed on the Cosmos chain:  
  - *Babylon Contract* – Coordinates BSN operations  
  - *BTC Light Client Contract* – Verifies Bitcoin state  
  - *BTC Staking Contract* – Manages BTC staking and delegation  
  - *BTC Finality Contract* – Collects and validates finality signatures
- **Zone Concierge IBC Channel** – Ordered channel used to connect the Cosmos
  chain to Babylon Genesis.  
- **Consumer Registration** – Each Cosmos BSN chain is registered on Babylon
  Genesis using its IBC client ID as the consumer identifier.  

## 2. BSN Lifecycle

<img width="3100" height="772" alt="governance" src="./images/lifecycle.png" />

> **Notice**  
> Before starting the lifecycle steps, ensure Cosmos BSN chain satisfies all
> [Compatibility and Version Requirements]().

The following steps outline the full lifecycle of a Cosmos BSN:

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

5. **Zone Concierge Channel:** Establish an ordered Zone Concierge IBC channel
   between Cosmos BSN chain and Babylon Genesis.

6. **BSN Consumer Registration:** Register cosmos BSN chain in the Babylon Genesis
   consumer registry using its IBC client ID.


## 3. Governance Notes

For Cosmos BSN integration, governance is required on **two chains**:  
- **Babylon Genesis** – where the BSN consumer must be registered  
- **The Cosmos BSN chain itself** – where BSN contracts are deployed and
  registered in the Babylon SDK module  

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

The governance flow depends on the mode of the Babylon Genesis network:  

- **Permissionless** – The Cosmos chain (or its operator account) can submit the
  `MsgRegisterConsumer` transaction directly.  
- **Permissioned** – A governance proposal must be submitted and approved on
  Babylon Genesis that executes the same `MsgRegisterConsumer` message.  

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

## 4. Integration Process

### 4.1 Compatibility and Version Requirements

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

### 4.2 Adding the Babylon SDK Module

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
- **Reward Distribution** — Mints and distributes staking rewards when requested
  by the finality contract.

For design and functionality details, see the 
[module documentation](https://github.com/babylonlabs-io/babylon-sdk/tree/main/x/babylon#readme).

> **Notice:** On some Cosmos SDK chains, adding a new module 
> (or upgrading the binary to include it) may require a governance proposal.

### 4.3 Establish IBC Connection with Babylon

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

For detailed setup instructions, see the [IBC Connection Setup
Guide](./ibc-connection-guide.md).

> **Important:** Save the **IBC client ID** from this step, it will 
> be used for BSN consumer registration.

### 4.4 Upload BSN Contract Code

Upload the four CosmWasm artifacts and record their code IDs. The command is the same for each artifact; only `<WASM_PATH>` changes.

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