# Cosmos BSN BTC Staking Integration Messages

These are the main messages used in the Cosmos BSN BTC Staking integration.

## Message Flow

The following diagram outlines the somewhat involved flow of messages between
the Babylon Genesis and BSN sides, as well as between the contracts and the
Babylon SDK's `babylon` module.

```mermaid

%%{init: {'theme': 'forest'}}%%
flowchart TD
    subgraph Babylon Genesis
        A(Zoneconcierge);
    end
    A -. <b>IBC</b>
        BtcStaking
        BtcTimestamp
        BtcHeaders .-> B;

    B -. <b>IBC</b>
        ConsumerSlashing .-> A;

    subgraph Cosmos BSN
        B(Babylon);
        C(BTC-Staking);
        D(BTC-Finality);
        E(BTC-Light-Client);
        I[Babylon SDK];
    end

    B -- <b>Execute</b>
        BtcStaking
        Slash
    --> C;

   B -- <b>Execute</b>
      BtcHeaders
   --> E;

    D -- <b>Execute</b>
        Slashing
    --> B;

    D -- <b>Execute</b>
        DistributeRewards
    --> C;

    D -- <b>Custom</b>
      MintRewards
    --> I;

    I -- <b>Sudo</b>
      BeginBlock
    --> C;

    I -- <b>Sudo</b>
      BeginBlock
      EndBlock
    --> D;

    subgraph Other Actors
        F[Staker];
        G(Finality Provider);
        H[Anyone];
    end

    F -- <b>Execute</b>
        Unjail
        WithdrawRewards
    --> C;

    G -- <b>Execute</b>
        CommitPublicRandomness
        SubmitFinalitySignature
    --> D;

   H -- <b>Execute</b>
      WithdrawRewards
   --> C;

   H -- <b>Execute</b>
        BtcHeaders
   --> E;
```

## Messages Overview

A brief overview of the messages involved in the flow can be found in the
README files of the respective contracts.

- [`babylon` contract](../contracts/babylon/README.md).
- [`btc-staking` contract](../contracts/btc-staking/README.md).
- [`btc-finality` contract](../contracts/btc-finality/README.md).
- [`btc-light-client` contract](../contracts/btc-light-client/README.md).