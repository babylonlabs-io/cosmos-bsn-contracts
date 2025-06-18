# BTC Light Client Contract

The `btc-light-client` contract is responsible for maintaining the light client
state of the Bitcoin network on the BSN.

## Interfaces

### Execution Messages

`BtcHeaders` Message:

This is a message that can be called by the `babylon` contract to add or update
the Bitcoin headers in the light client.
It contains a list of Bitcoin headers, as well as temporary fields that are used
to initialize the light client with the first header's work and height.

Notably, this message can be called by anyone as well, who can provide valid
Bitcoin headers to extend or update the Bitcoin light client's state.

```rust
/// Add BTC headers to the light client. If not initialized, this will initialize
/// the light client with the provided headers. Otherwise, it will update the
/// existing chain with the new headers.
BtcHeaders {
   headers: Vec<BtcHeader>,
   first_work: Option<String>,
   first_height: Option<u32>,
},
```