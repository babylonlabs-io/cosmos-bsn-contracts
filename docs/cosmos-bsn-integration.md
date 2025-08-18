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
> Before starting the lifecycle steps, ensure your chain satisfies all
> [Compatibility and Version Requirements]().

The following steps outline the full lifecycle of a Cosmos BSN:

1. **Module Integration:** Add the [Babylon SDK](https://github.com/babylonlabs-io/babylon-sdk) 
   module into your Cosmos SDK chain binary.

2. **Contract Deployment:**  Deploy the [BSN contract](https://github.com/babylonlabs-io/cosmos-bsn-contracts) 
   suite to your chain and instantiate the Babylon contract, which auto-deploys
   the Light Client, Staking, and Finality contracts.

3. **Governance Registration:** Register the deployed contract addresses with
   the Babylon SDK module via a governance proposal.

4. **IBC Connection Setup:** Establish an ordered 
   [Zone Concierge IBC channel](https://github.com/babylonlabs-io/babylon/tree/v3.0.0-rc.2/x/zoneconcierge)
   between your chain and Babylon Genesis.

5. **BSN Consumer Registration:** Register your chain in the Babylon Genesis
   consumer registry using its IBC client ID.