# BTC Finality Smart Contract

## Interfaces

The `btc-finality` contract is responsible for handling the finality providers'
block signatures, as well as the public randomness commitments associated with
such signatures verification.
It provides the following interface:

### Execution Messages

`CommitPublicRandomness` Message:

This is a message that can be called by a finality provider to commit public
randomness to the BSN chain.
It contains the necessary information about the finality provider's public key,
the start height of the public randomness, the number of public randomness
values committed, the commitment itself, and the signature on the commitment.
The signature is used to prevent others from committing public randomness on
behalf of the finality provider.

```
CommitPublicRandomness {
    /// `fp_pubkey_hex` is the BTC PK of the finality provider that commits the public randomness
    fp_pubkey_hex: String,
    /// `start_height` is the start block height of the list of public randomness
    start_height: u64,
    /// `num_pub_rand` is the amount of public randomness committed
    num_pub_rand: u64,
    /// `commitment` is the commitment of these public randomness values.
    /// Currently, it's the root of the Merkle tree that includes the public randomness
    commitment: Binary,
    /// `signature` is the signature on (start_height || num_pub_rand || commitment) signed by
    /// the SK corresponding to `fp_pubkey_hex`.
    /// This prevents others committing public randomness on behalf of `fp_pubkey_hex`
    signature: Binary,
},
```

`SubmitFinalitySignature` Message:

This is the main message involved in the finality process. It is used to submit
the finality signature of a block on the BSN chain. It contains the necessary
information about the finality provider's public key, the height of the block
being signed, the public randomness value used, the signature's proof, the block
app hash, and the signature itself.

```
/// Submit Finality Signature.
///
/// This is a message that can be called by a finality provider to submit their finality
/// signature to the BSN chain.
/// The signature is verified by the BSN chain using the finality provider's public key
///
/// This message is equivalent to the `MsgAddFinalitySig` message in the Babylon finality protobuf
/// defs.
SubmitFinalitySignature {
    fp_pubkey_hex: String,
    height: u64,
    pub_rand: Binary,
    proof: Proof,
    // FIXME: Rename to block_app_hash for consistency / clarity
    block_hash: Binary,
    signature: Binary,
},
```

`Unjail` Message:

This message is used to unjail a finality provider that has been jailed due to
offline detection or other reasons. It allows the finality provider to return to
the active set of finality providers. The unjailing can be done by the admin at
any time, or by the finality provider themselves after the jail period has passed. The
`fp_pubkey_hex` field is used to identify the finality provider to be unjailed.

```rust
/// Unjails finality provider.
/// Admin can unjail anyone anytime, others can unjail only themselves, and only if the jail
/// period passed.
Unjail {
    /// FP to unjail
    fp_pubkey_hex: String,
},
```

### Sudo Messages

Sudo messages are used by the Babylon SDK `babylon` module to interact with the
Cosmos BSN contracts.

`BeginBlock` Sudo Message:

This message is called by the Babylon SDK to signal the beginning of a new
block.
It allows the finality module to distribute rewards to the finality providers,
and to compute the active finality provider set based on the current block
height and the finality provider's staking power.

```rust
BeginBlock {
  hash_hex: String,
  app_hash_hex: String,
},
```

`EndBlock` Sudo Message:

This message is called by the Babylon SDK to signal the end of a new block.
It allows the finality module to index blocks and tally the finality provider
votes.

```rust
/// The SDK should call SudoMsg::EndBlock{} once per block (in EndBlock).
/// It allows the finality module to index blocks and tally the finality provider votes
EndBlock {
  hash_hex: String,
  app_hash_hex: String,
},
```

### Custom Messages

Custom messages are used by the Cosmos BSN contracts to interact with the
Babylon SDK `babylon` module.

`MintRewards` Message:

This privileged message is used to mint the requested block rewards for the
finality providers.
It can only be sent from the finality contract.

```rust
/// MintRewards mints the requested block rewards for the finality providers.
/// It can only be sent from the finality contract.
/// The rewards are minted to the staking contract address, so that they
/// can be distributed across the active finality provider set
MintRewards { amount: Coin, recipient: String },
```
