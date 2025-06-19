# Babylon Smart Contract

The `babylon` contract is the main entry point for Cosmos BSN Staking
integration.
It is responsible for handling the IBC messages and relaying them to the
appropriate contract on the BSN side.

## Interfaces

This section provides a detailed overview of the interfaces provided by the
contract.
It only describes the interfaces that are relevant for Cosmos BSN Staking
integration, and does not cover the full functionality of the contract.
It also does not cover the different queries.

### IBC Messages

`BtcStaking` Message:

This IBC packet is used to send the staking and unstaking requests from the
Babylon Genesis BTC staking module to the BSN.
It contains the necessary information about the amount of BTC to be staked or
unstaked, as well as the address of the delegator, the involved transactions on
the Bitcoin network, their validation information, etc.
It also sends information about finality providers entering the BSN network, and
finality providers leaving the network due to slashing on other chains.

`BtcTimestamp` Message:

This IBC packet is used to send the timestamping information from Babylon
Genesis BTC timestamping module to the BSN.
It contains the necessary information about Bitcoin headers and their
timestamps.
This information is forwarded to the `btc-light-client` contract, which
maintains the light client state of the Bitcoin network on the BSN.

`BtcHeaders` Message:

This IBC packet is used to send the Bitcoin headers from Babylon Genesis BTC
timestamping module to the BSN. It contains the necessary information about
the Bitcoin headers, their hashes, heights, and the associated proof of work.
It's also forwarded to the `btc-light-client` contract, which maintains the
light client state of the Bitcoin network on the BSN.

`ConsumerSlashing` Message:

This message is part of cascaded slashing, in which the slashing of a finality
provider on a BSN chain results in the undelegation of the involved BTC on
Babylon Genesis and on other BSN chains as well.
This is an **inbound** (from Babylon Genesis's point of view) IBC message.
It relates to the `Slashing` execution message, below.

### Execution Messages

`Slashing` Message:

This message handles the forwarding of slashing information and evidence
upstream, from the BSN to Babylon Genesis.
The `Slashing` execution handler handles the slashing information and evidence
originated on the BSN side (in the  `btc-finality` contract), and forwards it to
the Babylon Genesis `x/zonconcierge` module, through the `ConsumerSlashing`
IBC message.