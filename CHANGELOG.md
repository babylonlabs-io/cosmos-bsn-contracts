<!--
Guiding Principles:
Changelogs are for humans, not machines.
There should be an entry for every single version.
The same types of changes should be grouped.
Versions and sections should be linkable.
The latest version comes first.
The release date of each version is displayed.
Mention whether you follow Semantic Versioning.
Usage:
Change log entries are to be added to the Unreleased section under the
appropriate stanza (see below). Each entry should have following format:
* [#PullRequestNumber](PullRequestLink) message
Types of changes (Stanzas):
"Features" for new features.
"Improvements" for changes in existing functionality.
"Deprecated" for soon-to-be removed features.
"Bug Fixes" for any bug fixes.
"Client Breaking" for breaking CLI commands and REST routes used by end-users.
"API Breaking" for breaking exported APIs used by developers building on SDK.
"State Machine Breaking" for any changes that result in a different AppState
given same genesisState and txList.
Ref: https://keepachangelog.com/en/1.0.0/
-->

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)

## [Unreleased](https://github.com/babylonlabs-io/cosmos-bsn-contracts/tree/HEAD)

[Full Changelog](https://github.com/babylonlabs-io/cosmos-bsn-contracts/compare/v0.14.0...HEAD)

### Features

- [#274](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/274) Send rewards to Babylon for distribution

### Improvements

- [#270](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/270) fix: fix Babylon SDK e2e
- [#265](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/265) finality: handle public randomness misalignment
- [#260](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/260) chore: manual changelog setup

## [v0.14.0](https://github.com/babylonlabs-io/cosmos-bsn-contracts/tree/v0.14.0) (2025-05-14)

[Full Changelog](https://github.com/babylonlabs-io/cosmos-bsn-contracts/compare/v0.13.0-rc.0...v0.14.0)

**Implemented enhancements:**

- refactor: split BTC light client contract and Babylon contract
  [\#53](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/53)

**Closed issues:**

- Impact of Contract Address Changes on Token Holdings
  [\#144](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/144)
- Refactor: Rename outdated `CZ` terminology
  [\#132](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/132)
- filter out non-timestamped FPs from active FP list
  [\#130](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/130)
- Online FPs verification
  [\#121](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/121)
- Go over TODOs and create issues
  [\#116](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/116)
- move BTC timestamping utility functions to `packages/`
  [\#105](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/105)
- Implement efficient voting power rotation algorithm
  [\#91](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/91)
- timestamping public randomness support
  [\#83](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/83)
- Jailing of inactive finality providers
  [\#82](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/82)
- Allowing contract to choose its own w
  [\#4](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/4)

**Merged pull requests:**

- F/rename old cz
  [\#141](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/141) ([maurolacy](https://github.com/maurolacy))
- F/filter non timestamped
  [\#140](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/140) ([maurolacy](https://github.com/maurolacy))
- F/jailing inactive
  [\#138](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/138) ([maurolacy](https://github.com/maurolacy))
- f/TODOs annotation
  [\#135](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/135) ([maurolacy](https://github.com/maurolacy))
- fix: handle empty btc headers in timestamp packet
  [\#133](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/133) ([gusin13](https://github.com/gusin13))
- Feat/btc light client refactor
  [\#129](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/129) ([SebastianElvis](https://github.com/SebastianElvis))
- F/public randomness ts
  [\#128](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/128) ([maurolacy](https://github.com/maurolacy))
- feat: consumer delegation expiry
  [\#126](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/126) ([gusin13](https://github.com/gusin13))
- F/ibc timeout [\#117](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/117) ([maurolacy](https://github.com/maurolacy))
- refactor: move ics23\_commitment to a new package
  [\#113](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/113) ([SebastianElvis](https://github.com/SebastianElvis))
- feat: Update consumer BTC light client
  [\#112](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/112) ([gusin13](https://github.com/gusin13))

## [v0.13.0](https://github.com/babylonlabs-io/cosmos-bsn-contracts/tree/v0.13.0) (2025-02-11)

[Full Changelog](https://github.com/babylonlabs-io/cosmos-bsn-contracts/compare/v0.12.0-rc.0...v0.13.0)

**Merged pull requests:**

- feat: improve IBC packet structure
  [\#110](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/110) ([gusin13](https://github.com/gusin13))

## [v0.12.0](https://github.com/babylonlabs-io/cosmos-bsn-contracts/tree/v0.12.0) (2025-02-07)

[Full Changelog](https://github.com/babylonlabs-io/cosmos-bsn-contracts/compare/v0.11.0-rc.1...v0.12.0)

**Closed issues:**

- Native rewards distribution protocol
  [\#102](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/102)
- Fix borken protobuf generation
  [\#101](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/101)

**Merged pull requests:**

- F/sync protos [\#108](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/108) ([maurolacy](https://github.com/maurolacy))
- F/rewards claiming babylon
  [\#106](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/106) ([maurolacy](https://github.com/maurolacy))
- F/rewards distribution consumer
  [\#104](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/104) ([maurolacy](https://github.com/maurolacy))
- feat: op consumer chain slashing \(2/2\)
  [\#98](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/98) ([parketh](https://github.com/parketh))
- F/rewards distribution 2
  [\#97](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/97) ([maurolacy](https://github.com/maurolacy))
- F/rewards distribution send
  [\#96](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/96) ([maurolacy](https://github.com/maurolacy))
- chore: use query\_grpc from cosmwasm\_std
  [\#93](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/93) ([lesterli](https://github.com/lesterli))
- feat: op consumer chain slashing \(1/2\)
  [\#92](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/92) ([parketh](https://github.com/parketh))
- Rm auto register 2
  [\#89](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/89) ([maurolacy](https://github.com/maurolacy))
- fix: bump contract and permissioned integration
  [\#87](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/87) ([SebastianElvis](https://github.com/SebastianElvis))

## [v0.11.0](https://github.com/babylonlabs-io/cosmos-bsn-contracts/tree/v0.11.0) (2024-11-19)

[Full Changelog](https://github.com/babylonlabs-io/cosmos-bsn-contracts/compare/v0.10.0-rc.0...v0.11.0)


**Closed issues:**

- sdk: instantiate all Babylon contracts using Babylon SDK (dup)
  [\#67](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/67)
- OP: integration test vs. unit test
  [\#18](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/18)

**Merged pull requests:**

- F/rewards generation 2
  [\#81](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/81) ([maurolacy](https://github.com/maurolacy))

## [v0.10.0](https://github.com/babylonlabs-io/cosmos-bsn-contracts/tree/v0.10.0) (2024-10-08)

[Full Changelog](https://github.com/babylonlabs-io/cosmos-bsn-contracts/compare/v0.9.0-rc.1...v0.10.0)

**Merged pull requests:**

- \[OP\] chore: remove unused activated\_height
  [\#77](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/77) ([bap2pecs](https://github.com/bap2pecs))
- F/stock optimizer
  [\#76](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/76) ([maurolacy](https://github.com/maurolacy))
- Fix: proper name for the full wasm checks job
  [\#75](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/75) ([maurolacy](https://github.com/maurolacy))
- F/optimizer ci [\#73](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/73) ([maurolacy](https://github.com/maurolacy))
- Fix/optimizer [\#72](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/72) ([maurolacy](https://github.com/maurolacy))
- fix: Fp info query should return err for non existent Fp's
  [\#71](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/71) ([gusin13](https://github.com/gusin13))
- R/test utils [\#70](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/70) ([maurolacy](https://github.com/maurolacy))
- R/finality contract
  [\#65](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/65) ([maurolacy](https://github.com/maurolacy))
- R/index btc height
  [\#64](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/64) ([maurolacy](https://github.com/maurolacy))
- Disable recovered\_fp\_btc\_sk validation in SlashedBtcDelegation
  [\#63](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/63) ([gusin13](https://github.com/gusin13))
- btcstaking: verify covenant signatures and undelegation data
  [\#62](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/62) ([SebastianElvis](https://github.com/SebastianElvis))
- btcstaking: full validation of unbonding/slashing BTC delegation
  [\#60](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/60) ([SebastianElvis](https://github.com/SebastianElvis))
- Fix/lints [\#59](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/59) ([maurolacy](https://github.com/maurolacy))
- chore: move validation functions to a new mod
  [\#58](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/58) ([SebastianElvis](https://github.com/SebastianElvis))
- pop: verify PoP in FP registration request
  [\#57](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/57) ([SebastianElvis](https://github.com/SebastianElvis))
- staking: verifying staker's signature over slashing tx
  [\#56](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/56) ([SebastianElvis](https://github.com/SebastianElvis))
- test: refactor test data generation
  [\#51](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/51) ([SebastianElvis](https://github.com/SebastianElvis))
- Change license to BSL
  [\#50](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/50) ([maurolacy](https://github.com/maurolacy))
- staking: verify staking/slashing tx relationship in staking requests
  [\#46](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/46) ([SebastianElvis](https://github.com/SebastianElvis))

## [v0.9.0](https://github.com/babylonlabs-io/cosmos-bsn-contracts/tree/v0.9.0) (2024-08-29)

[Full Changelog](https://github.com/babylonlabs-io/cosmos-bsn-contracts/compare/v0.8.0-rc.1...v0.9.0)

**Fixed bugs:**

- crypto: implement adaptor signature using k256
  [\#13](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/13)

**Merged pull requests:**

- Try and enable CI release jobs
  [\#48](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/48) ([maurolacy](https://github.com/maurolacy))
- Fix: Wasm size limit
  [\#47](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/47) ([maurolacy](https://github.com/maurolacy))
- F/slashing propagation 2
  [\#45](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/45) ([maurolacy](https://github.com/maurolacy))
- btcstaking: fix error types for BTC staking package
  [\#44](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/44) ([SebastianElvis](https://github.com/SebastianElvis))
- crypto: use k256 to implement adaptor sig
  [\#43](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/43) ([SebastianElvis](https://github.com/SebastianElvis))
- Fix/cross contract query
  [\#40](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/40) ([SebastianElvis](https://github.com/SebastianElvis))
- F/btc delegations
  [\#39](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/39) ([maurolacy](https://github.com/maurolacy))
- Try and enable wasm tests
  [\#38](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/38) ([maurolacy](https://github.com/maurolacy))
- 0.8.x integ [\#37](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/37) ([maurolacy](https://github.com/maurolacy))
- F/slashing undelegations
  [\#35](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/35) ([maurolacy](https://github.com/maurolacy))
- feat: Automatic consumer registration
  [\#34](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/34) ([gusin13](https://github.com/gusin13))
- Eots refactor 2 [\#33](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/33) ([maurolacy](https://github.com/maurolacy))
- eots: fix tests for verifying EOTS signatures from Go
  [\#32](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/32) ([SebastianElvis](https://github.com/SebastianElvis))
- Add GH actions workflow
  [\#30](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/30) ([maurolacy](https://github.com/maurolacy))
- f/FP SK extract [\#29](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/29) ([maurolacy](https://github.com/maurolacy))
- Eots refactor [\#27](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/27) ([maurolacy](https://github.com/maurolacy))
- Migrate repo [\#26](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/26) ([maurolacy](https://github.com/maurolacy))

## [v0.8.0](https://github.com/babylonlabs-io/cosmos-bsn-contracts/tree/v0.8.0) (2024-07-09)

[Full Changelog](https://github.com/babylonlabs-io/cosmos-bsn-contracts/compare/v0.7.0...v0.8.0)

**Closed issues:**

- Update babylon-private to latest base/consumer-chain-support (2024-08-09)

**Merged pull requests:**

- F/babylon private rebase (#211)
- fix: allow query_block_voters() to return `None` if the block doesn't exist (#204)
- chore: refactor pub rand commit (#200)
- feat: add the query msg `FirstPubRandCommit ` and `Event` (#198)
- feat: add query msg `HasPubRandCommit` (#196)
- fix: decode hex hash (#195)
- feat: set `isEnabled` at instantiation (#193)
- feat: update admin (#192)
- fix: cannot compare babylon chain height with consumer chain height (#190)
- test: add finality gadget tests (#188)
- chore: clean up scripts/optimizer.sh (#187)

## [v0.7.0](https://github.com/babylonlabs-io/cosmos-bsn-contracts/tree/v0.7.0) (2024-06-24)

[Full Changelog](https://github.com/babylonlabs-io/cosmos-bsn-contracts/compare/v0.6.0...v0.7.0)

**Closed issues:**

- add a killswitch to disable finality gadget
  [\#181](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/181)
- Simplify packages/apis/src/queries.rs
  [\#172](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/172)
- Set an activated height when deploying the op-finality-gadget contract
  [\#167](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/167)
- Store block hash in the op-finality-gadget contract
  [\#159](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/159)
- Finality round [\#153](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/153)
- Upgrade to CosmWasm 2.x
  [\#140](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/140)
- Refactor btc-staking contract into modules
  [\#130](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/130)
- Active finality provider set
  [\#118](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/118)
- Finality signatures submission
  [\#109](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/109)

**Merged pull requests:**

- fix: build-optimizer.sh to properly generate code for arm64
  [\#185](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/185) ([bap2pecs](https://github.com/bap2pecs))
- fix: init pr empty issue
  [\#184](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/184) ([bap2pecs](https://github.com/bap2pecs))
- fix: pub rand and finality sig query
  [\#183](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/183) ([gusin13](https://github.com/gusin13))
- feat: implement killswitch
  [\#182](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/182) ([parketh](https://github.com/parketh))
- fix: comment out unused code
  [\#146](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/146) ([bap2pecs](https://github.com/bap2pecs))
- Fix: Set initial FP power to zero
  [\#180](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/180) ([maurolacy](https://github.com/maurolacy))
- chore: change to query block votes
  [\#178](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/178) ([lesterli](https://github.com/lesterli))
- feat: query last pub rand commit
  [\#177](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/177) ([lesterli](https://github.com/lesterli))
- \[op finality gadget\] feat: add QueryMsg::QueryBlockFinalized \(part 2\)
  [\#174](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/174) ([bap2pecs](https://github.com/bap2pecs))
- chore: move queries
  [\#173](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/173) ([lesterli](https://github.com/lesterli))
- chore: simplify the naming
  [\#171](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/171) ([lesterli](https://github.com/lesterli))
- \[op finality gadget\] feat: add QueryMsg::QueryBlockFinalized \(part 1\)
  [\#170](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/170) ([bap2pecs](https://github.com/bap2pecs))
- fix: typo [\#169](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/169) ([lesterli](https://github.com/lesterli))
- feat: set activated height
  [\#168](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/168) ([lesterli](https://github.com/lesterli))
- feat: Use gRPC to query the Babylon Chain
  [\#158](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/158) ([lesterli](https://github.com/lesterli))
- Active finality provider set
  [\#163](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/163) ([maurolacy](https://github.com/maurolacy))
- R/sudo msgs [\#162](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/162) ([maurolacy](https://github.com/maurolacy))
- F/finality queries tests
  [\#161](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/161) ([maurolacy](https://github.com/maurolacy))
- Add last pub rand commit by FP query
  [\#160](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/160) ([maurolacy](https://github.com/maurolacy))
- Update protocgen.sh
  [\#156](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/156) ([lesterli](https://github.com/lesterli))
- F/finality round [\#155](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/155) ([maurolacy](https://github.com/maurolacy))
- sudo: EndBlock sudo message
  [\#154](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/154) ([SebastianElvis](https://github.com/SebastianElvis))
- U/cosmwasm 2.x [\#151](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/151) ([maurolacy](https://github.com/maurolacy))
- \[op finality gadget\] feat: 5/x - add CommitPublicRandomness and
  SubmitFinalitySignature
  [\#150](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/150) ([bap2pecs](https://github.com/bap2pecs))
- \[op finality gadget\] feat: 2/x - set admin and consumer chain while
  instantiating [\#147](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/147) ([bap2pecs](https://github.com/bap2pecs))
- \[op finality gadget\] feat: 1/x - set up crate skeleton
  [\#144](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/144) ([bap2pecs](https://github.com/bap2pecs))
- docs: add missing instruction before running test
  [\#143](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/143) ([bap2pecs](https://github.com/bap2pecs))
- Fix build-optimizer.sh to properly generate code for arm64
  [\#142](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/142) ([bap2pecs](https://github.com/bap2pecs))
- crypto: error/option handling in EOTS implementation
  [\#139](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/139) ([SebastianElvis](https://github.com/SebastianElvis))
- R/btc staking modules
  [\#138](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/138) ([maurolacy](https://github.com/maurolacy))

## [v0.6.0](https://github.com/babylonlabs-io/cosmos-bsn-contracts/tree/v0.6.0) (2024-06-07)

[Full Changelog](https://github.com/babylonlabs-io/cosmos-bsn-contracts/compare/v0.5.3...v0.6.0)

**Closed issues:**

- crypto: implement EOTS using `k256`
  [\#134](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/134)
- fix contract size
  [\#126](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/126)
- replace `Vec<u8>` with `Binary` for exec messages
  [\#125](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/125)
- Finality signatures verification
  [\#117](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/117)
- Benchmarking ci job failing
  [\#112](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/112)
- admin commands for contracts
  [\#107](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/107)
- Voting table [\#103](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/103)
- Implement BTC undelegation
  [\#99](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/99)
- crypto: EOTS in rust
  [\#93](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/93)
- Add `validate` methods
  [\#83](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/83)

**Merged pull requests:**

- crypto: use k256 instead of secp256kfun for implementing EOTS
  [\#136](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/136) ([SebastianElvis](https://github.com/SebastianElvis))
- F/finality sig verification
  [\#128](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/128) ([maurolacy](https://github.com/maurolacy))
- chore: fix size of BTC staking contract
  [\#127](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/127) ([SebastianElvis](https://github.com/SebastianElvis))
- F/merkle rs [\#124](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/124) ([maurolacy](https://github.com/maurolacy))
- finality: vanilla sudo message
  [\#123](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/123) ([SebastianElvis](https://github.com/SebastianElvis))
- F/public randomness
  [\#122](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/122) ([maurolacy](https://github.com/maurolacy))
- chore: fixing inconsistency of protobuf objects
  [\#121](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/121) ([SebastianElvis](https://github.com/SebastianElvis))
- F/voting table height 2
  [\#119](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/119) ([maurolacy](https://github.com/maurolacy))
- F/ibc proto improvements
  [\#116](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/116) ([maurolacy](https://github.com/maurolacy))
- C/babylon update sync
  [\#115](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/115) ([maurolacy](https://github.com/maurolacy))
- F/submit finality sigs
  [\#114](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/114) ([maurolacy](https://github.com/maurolacy))
- F/voting table height
  [\#113](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/113) ([maurolacy](https://github.com/maurolacy))
- Fix/main ci 2 [\#111](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/111) ([maurolacy](https://github.com/maurolacy))
- Update schemas [\#110](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/110) ([maurolacy](https://github.com/maurolacy))
- feat: Add admin commands
  [\#108](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/108) ([gusin13](https://github.com/gusin13))
- F/voting table [\#106](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/106) ([maurolacy](https://github.com/maurolacy))
- F/config params [\#105](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/105) ([maurolacy](https://github.com/maurolacy))
- F/begin block handler
  [\#104](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/104) ([maurolacy](https://github.com/maurolacy))
- F/active delegations queries
  [\#102](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/102) ([maurolacy](https://github.com/maurolacy))
- F/validate methods
  [\#101](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/101) ([maurolacy](https://github.com/maurolacy))
- BTC undelegate basic impl
  [\#98](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/98) ([maurolacy](https://github.com/maurolacy))
- crypto: EOTS implementation
  [\#95](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/95) ([SebastianElvis](https://github.com/SebastianElvis))

## [v0.5.3](https://github.com/babylonlabs-io/cosmos-bsn-contracts/tree/v0.5.3) (2024-05-13)

[Full Changelog](https://github.com/babylonlabs-io/cosmos-bsn-contracts/compare/v0.5.2...v0.5.3)

**Closed issues:**

- Staking Tx Hash mismatch causing issues in `finality_provider` and
  `delegations_by_f_p` queries
  [\#94](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/94)

**Merged pull requests:**

- Fix/reverse hash [\#96](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/96) ([maurolacy](https://github.com/maurolacy))

## [v0.5.2](https://github.com/babylonlabs-io/cosmos-bsn-contracts/tree/v0.5.2) (2024-05-07)

[Full Changelog](https://github.com/babylonlabs-io/cosmos-bsn-contracts/compare/v0.5.1...v0.5.2)

**Merged pull requests:**

- Fix/protos [\#91](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/91) ([maurolacy](https://github.com/maurolacy))
- Fix: publish schemas on release
  [\#90](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/90) ([maurolacy](https://github.com/maurolacy))

## [v0.5.1](https://github.com/babylonlabs-io/cosmos-bsn-contracts/tree/v0.5.1) (2024-05-06)

[Full Changelog](https://github.com/babylonlabs-io/cosmos-bsn-contracts/compare/v0.5.0...v0.5.1)

**Closed issues:**

- test: formalise datagen library
  [\#76](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/76)

**Merged pull requests:**

- Fix/query responses
  [\#88](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/88) ([maurolacy](https://github.com/maurolacy))
- Release 0.5 follow up
  [\#87](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/87) ([maurolacy](https://github.com/maurolacy))
- datagen: refactor datagen and test utilities
  [\#86](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/86) ([SebastianElvis](https://github.com/SebastianElvis))

## [v0.5.0](https://github.com/babylonlabs-io/cosmos-bsn-contracts/tree/v0.5.0) (2024-05-03)

[Full Changelog](https://github.com/babylonlabs-io/cosmos-bsn-contracts/compare/v0.4.0...v0.5.0)

**Closed issues:**

- btcstaking: verification of {Schnorr, adaptor} signatures in BTC staking
  library [\#77](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/77)
- compiling IBC packets from protobuf to Rust
  [\#69](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/69)
- btcstaking: BTC staking library
  [\#64](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/64)

**Merged pull requests:**

- F/staking validation
  [\#82](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/82) ([maurolacy](https://github.com/maurolacy))
- F/staking queries [\#81](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/81) ([maurolacy](https://github.com/maurolacy))
- Support Mac's ugly non-standard sed
  [\#80](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/80) ([maurolacy](https://github.com/maurolacy))
- multi-tests follow-up
  [\#79](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/79) ([maurolacy](https://github.com/maurolacy))
- btcstaking: verify Schnorr/adaptor sig over txs
  [\#78](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/78) ([SebastianElvis](https://github.com/SebastianElvis))
- Add multi-test support
  [\#75](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/75) ([maurolacy](https://github.com/maurolacy))
- Update proto / apis defs
  [\#74](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/74) ([maurolacy](https://github.com/maurolacy))
- F/staking handling
  [\#73](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/73) ([maurolacy](https://github.com/maurolacy))
- BTC staking msgs [\#68](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/68) ([maurolacy](https://github.com/maurolacy))
- Fix/btc lc datagen
  [\#67](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/67) ([maurolacy](https://github.com/maurolacy))
- btcstaking: btcstaking library in Rust
  [\#65](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/65) ([SebastianElvis](https://github.com/SebastianElvis))
- BTC staking contract
  [\#63](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/63) ([maurolacy](https://github.com/maurolacy))
- Benchmark fixes / follow-up
  [\#62](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/62) ([maurolacy](https://github.com/maurolacy))
- Babylon contract benchmarks
  [\#61](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/61) ([maurolacy](https://github.com/maurolacy))
- Upgrade to latest rust-bitcoin 0.31.x
  [\#60](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/60) ([maurolacy](https://github.com/maurolacy))

## [v0.4.0](https://github.com/babylonlabs-io/cosmos-bsn-contracts/tree/v0.4.0) (2024-02-14)

[Full Changelog](https://github.com/babylonlabs-io/cosmos-bsn-contracts/compare/v0.3.0...v0.4.0)

**Merged pull requests:**

- Refactor: BTC light client header storage
  [\#57](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/57) ([maurolacy](https://github.com/maurolacy))
- More queries [\#56](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/56) ([maurolacy](https://github.com/maurolacy))
- Add queries [\#55](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/55) ([maurolacy](https://github.com/maurolacy))
- Update CI rust image to a more recent version \(1.75.0\)
  [\#54](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/54) ([maurolacy](https://github.com/maurolacy))
- Remove Makefile [\#53](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/53) ([maurolacy](https://github.com/maurolacy))
- BtcHeaders message handler
  [\#52](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/52) ([maurolacy](https://github.com/maurolacy))
- Fork choice tests [\#51](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/51) ([maurolacy](https://github.com/maurolacy))
- Fork choice rule impl
  [\#50](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/50) ([maurolacy](https://github.com/maurolacy))
- Point to public repo
  [\#47](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/47) ([maurolacy](https://github.com/maurolacy))
- Update cosmwasm [\#46](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/46) ([maurolacy](https://github.com/maurolacy))
- Upgrade comswasm to v1.5.1
  [\#44](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/44) ([maurolacy](https://github.com/maurolacy))
- chore: bump Babylon with ABCI++
  [\#41](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/41) ([SebastianElvis](https://github.com/SebastianElvis))
- Babylon tag format
  [\#40](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/40) ([maurolacy](https://github.com/maurolacy))

## [v0.3.0](https://github.com/babylonlabs-io/cosmos-bsn-contracts/tree/v0.3.0) (2024-02-09)

[Full Changelog](https://github.com/babylonlabs-io/cosmos-bsn-contracts/compare/v0.2.0...v0.3.0)

**Closed issues:**

- Get rid of Makefile
  [\#48](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/48)

## [v0.2.0](https://github.com/babylonlabs-io/cosmos-bsn-contracts/tree/v0.2.0) (2023-12-22)

[Full Changelog](https://github.com/babylonlabs-io/cosmos-bsn-contracts/compare/v0.1.0...v0.2.0)

**Merged pull requests:**

- API adjustments / serialisation support
  [\#37](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/37) ([maurolacy](https://github.com/maurolacy))

## [v0.1.0](https://github.com/babylonlabs-io/cosmos-bsn-contracts/tree/v0.1.0) (2023-12-22)

[Full Changelog](https://github.com/babylonlabs-io/cosmos-bsn-contracts/compare/975426f4cef50ce47610b51a55c576c5ddd1d39b...v0.1.0)

**Closed issues:**

- test: tests for Go \<-\> Rust serialisation
  [\#4](https://github.com/babylonlabs-io/cosmos-bsn-contracts/issues/4)

**Merged pull requests:**

- bump Babylon proto files and verification rules
  [\#33](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/33) ([SebastianElvis](https://github.com/SebastianElvis))
- chore: bump dependencies to {Babylon, optimiser, blst, cosmwasm}
  [\#32](https://github.com/babylonlabs-ibabylonlabs-io/cosmos-bsn-contracts/pull/32) ([SebastianElvis](https://github.com/SebastianElvis))
- CI: Push optimized smart contract to S3
  [\#31](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/31) ([filippos47](https://github.com/filippos47))
- bump to Babylon v0.7.0
  [\#29](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/29) ([SebastianElvis](https://github.com/SebastianElvis))
- chore: apply fmt/clippy and solidify CI
  [\#28](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/28) ([SebastianElvis](https://github.com/SebastianElvis))
- feat: handler for BTC timestamps
  [\#26](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/26) ([SebastianElvis](https://github.com/SebastianElvis))
- chore: improve error handling
  [\#24](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/24) ([SebastianElvis](https://github.com/SebastianElvis))
- CZ header chain: KVStore and handlers
  [\#23](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/23) ([SebastianElvis](https://github.com/SebastianElvis))
- epoch chain: reenable test for `ProofEpochSealed`
  [\#22](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/22) ([SebastianElvis](https://github.com/SebastianElvis))
- epoch chain: verifying a checkpoint is submitted to Bitcoin
  [\#21](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/21) ([SebastianElvis](https://github.com/SebastianElvis))
- epoch chain: verifying a sealed epoch
  [\#18](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/18) ([SebastianElvis](https://github.com/SebastianElvis))
- KVStore and basic logic for Babylon epoch chain
  [\#17](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/17) ([SebastianElvis](https://github.com/SebastianElvis))
- test: preliminary test for BTC light client
  [\#16](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/16) ([SebastianElvis](https://github.com/SebastianElvis))
- wasmbinding: functionalities for sending custom messages to Cosmos zone
  [\#15](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/15) ([SebastianElvis](https://github.com/SebastianElvis))
- btclightclient: DB schema for BTC light client, and basic logics
  [\#13](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/13) ([SebastianElvis](https://github.com/SebastianElvis))
- chore: CI steup [\#11](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/11) ([SebastianElvis](https://github.com/SebastianElvis))
- chore: Enable contract to be used as a dependency and add error module
  [\#10](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/10) ([vitsalis](https://github.com/vitsalis))
- bitcoin: importing `rust-bitcoin`
  [\#8](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/8) ([SebastianElvis](https://github.com/SebastianElvis))
- test: unit test for Go\<-\>Rust protobuf deserialisation
  [\#6](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/6) ([SebastianElvis](https://github.com/SebastianElvis))
- proto: protobuf messages for Babylon smart contract
  [\#5](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/5) ([SebastianElvis](https://github.com/SebastianElvis))
- vanilla contract [\#1](https://github.com/babylonlabs-io/cosmos-bsn-contracts/pull/1) ([SebastianElvis](https://github.com/SebastianElvis))



\* *This Changelog was automatically generated by [github_changelog_generator](https://github.com/github-changelog-generator/github-changelog-generator)*
