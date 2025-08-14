# BTC Staking Smart Contract

The `btc-staking` contract is responsible for tracking the staking and
unstaking of BTC on the Cosmos BSN.

## Interfaces

### Execution Messages

`BtcStaking`: This is the message received by the `babylon` contract over IBC,
forwarded to the `btc-staking` contract. It contains the
necessary information about the staking and unstaking requests, as well as the
finality providers' information, and slashing events from other BSNs or from
Babylon Genesis.

```rust
/// BTC Staking operations
BtcStaking {
    new_fp: Vec<NewFinalityProvider>,
    active_del: Vec<ActiveBtcDelegation>,
    unbonded_del: Vec<UnbondedBtcDelegation>,
},
```

`Slash` Message:

This is a message sent by the `babylon` contract to the `btc-staking` contract,
to set the staking power of a finality provider to zero when it is found to be
malicious by the finality contract. This is used to handle slashing events
internally or locally to the BSN, and to ensure that the slashed finality
provider is no longer considered for voting and rewards distribution.

```rust
/// Slash finality provider staking power.
/// Used by the babylon-contract only.
/// The babylon contract will call this message to set the finality provider's staking power to
/// zero when the finality provider is found to be malicious by the finality contract.
Slash {
    fp_btc_pk_hex: String
},
```

`DistributeRewards` Message:

This is a message that is part of rewards distribution, sent by the
`btc-finality` contract to the `btc-staking` contract. It contains the rewards
information for the finality providers, which is used to distribute the rewards
to the delegators. The `btc-staking` contract will then handle the distribution
of the rewards to the delegators based on their staking power and the finality
providers' rewards.

```rust
/// `DistributeRewards` is a message sent by the finality contract, to distribute rewards to
/// delegators
DistributeRewards {
    /// `fp_distribution` is the list of finality providers and their rewards
    fp_distribution: Vec<RewardInfo>,
},
```

`WithdrawRewards` Message:

This is a message that can be sent by anyone on behalf of the staker, to claim
the rewards from the `btc-staking` contract. It contains the address of the
staker, which is a Babylon address, and the public key of the finality provider
to which the rewards are associated. The staker's address is used to compute the
equivalent address in the Cosmos BSN chain if the rewards are to be sent to a
BSN address. The `btc-staking` contract will then handle the withdrawal of
the rewards and send them to the staker's address.
If the rewards are to be sent to Babylon Genesis instead, the staker's address
will be used in the `to_address` field of a ICS20 transfer (`IbcMsg::Transfer`)
message, and the `btc-staking` contract will then send the rewards to the staker
address over IBC.

```rust
/// `WithdrawRewards` is a message sent by anyone on behalf of the
/// staker, to withdraw rewards from BTC staking via the given FP.
///
/// `staker_addr` is both the address to claim and receive the rewards.
/// It's a Babylon address. If rewards are to be sent to a BSN address, the
/// staker's equivalent address in that chain will be computed and used.
WithdrawRewards {
    staker_addr: String,
    fp_pubkey_hex: String,
},
```

### Sudo Messages

Sudo messages are used by the Babylon SDK `babylon` module to interact with the
Cosmos BSN contracts.

`BeginBlock` Sudo Message:

This message is called by the Babylon SDK to signal the beginning of a new
block.
It allows the staking contract to index the BTC height, and update the power
distribution of Finality Providers.

```rust
/// The SDK should call SudoMsg::BeginBlock{} once per block (in BeginBlock).
/// It allows the staking module to index the BTC height, and update the power
/// distribution of Finality Providers.
BeginBlock {
  hash_hex: String,
  app_hash_hex: String,
},
```
