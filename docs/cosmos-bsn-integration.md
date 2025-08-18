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
