use crate::error::ContractError;
use babylon_proto::babylon::btclightclient::v1::BtcHeaderInfo;
use bitcoin::params::Params;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::Order::{Ascending, Descending};
use cosmwasm_std::{StdError, StdResult, Storage};
use cw_storage_plus::{Bound, Item, Map};
use hex::ToHex;
use prost::Message;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub const CONFIG: Item<Config> = Item::new("config");

pub const BTC_BASE_HEADER_HEIGHT: Item<u32> = Item::new("btc_lc_base_header_height");
pub const BTC_HEADERS: Map<u32, Vec<u8>> = Map::new("btc_lc_headers");
pub const BTC_HEIGHTS: Map<&[u8], u32> = Map::new("btc_lc_heights");
pub const BTC_TIP: Item<Vec<u8>> = Item::new("btc_lc_tip");

/// Error type for the state store.
#[derive(thiserror::Error, Debug, PartialEq)]
pub enum StoreError {
    #[error("The bytes cannot be decoded")]
    Decode(#[from] prost::DecodeError),
    #[error(transparent)]
    CosmwasmStd(#[from] StdError),
    #[error("The BTC height {height} is not found in the storage")]
    HeightNotFound { height: u32 },
    #[error("The BTC header with hash {hash} is not found in the storage")]
    HeaderNotFound { hash: String },
}

#[cw_serde]
pub struct Config {
    pub network: BitcoinNetwork,
    pub btc_confirmation_depth: u32,
    pub checkpoint_finalization_timeout: u32,
}

// we re-implement the enum here since `rust-bitcoin`'s enum implementation
// does not implement the trait `JsonSchema`.
#[derive(Serialize, Deserialize, Copy, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum BitcoinNetwork {
    Mainnet,
    Testnet,
    Signet,
    Regtest,
}

impl BitcoinNetwork {
    pub fn bitcoin_network(&self) -> bitcoin::Network {
        match self {
            Self::Mainnet => bitcoin::Network::Bitcoin,
            Self::Testnet => bitcoin::Network::Testnet,
            Self::Signet => bitcoin::Network::Signet,
            Self::Regtest => bitcoin::Network::Regtest,
        }
    }

    pub fn chain_params(&self) -> Params {
        match self {
            Self::Mainnet => Params::new(bitcoin::Network::Bitcoin),
            Self::Testnet => Params::new(bitcoin::Network::Testnet),
            Self::Signet => Params::new(bitcoin::Network::Signet),
            Self::Regtest => Params::new(bitcoin::Network::Regtest),
        }
    }
}

// getters for storages

// Checks if the BTC light client has been initialised or not.
// The check is done by checking the existence of the base header height
pub fn is_initialized(storage: &mut dyn Storage) -> bool {
    BTC_BASE_HEADER_HEIGHT.load(storage).is_ok()
}

// getter/setter for base header
pub fn get_base_header(storage: &dyn Storage) -> Result<BtcHeaderInfo, StoreError> {
    // NOTE: if init is successful, then base header is guaranteed to be in storage and decodable
    let base_header_height = BTC_BASE_HEADER_HEIGHT.load(storage)?;
    get_header(storage, base_header_height)
}

pub fn set_base_header(storage: &mut dyn Storage, base_header: &BtcHeaderInfo) -> StdResult<()> {
    BTC_BASE_HEADER_HEIGHT.save(storage, &base_header.height)?;
    insert_header(storage, base_header)
}

// getter/setter for chain tip
pub fn get_tip(storage: &dyn Storage) -> Result<BtcHeaderInfo, StoreError> {
    let tip_bytes = BTC_TIP.load(storage)?;
    //  NOTE: if init is successful, then tip header is guaranteed to be correct
    BtcHeaderInfo::decode(tip_bytes.as_slice()).map_err(Into::into)
}

pub fn set_tip(storage: &mut dyn Storage, tip: &BtcHeaderInfo) -> StdResult<()> {
    let tip_bytes = &tip.encode_to_vec();
    BTC_TIP.save(storage, tip_bytes)
}

// Inserts BTC headers that have passed the verification to the header chain
// storages, including
// - insert all headers
// - insert all hash-to-height indices
pub fn insert_headers(storage: &mut dyn Storage, new_headers: &[BtcHeaderInfo]) -> StdResult<()> {
    // Add all the headers by height
    for new_header in new_headers.iter() {
        insert_header(storage, new_header)?;
    }
    Ok(())
}

fn insert_header(storage: &mut dyn Storage, new_header: &BtcHeaderInfo) -> StdResult<()> {
    let hash_bytes: &[u8] = new_header.hash.as_ref();
    let header_bytes = new_header.encode_to_vec();
    BTC_HEADERS.save(storage, new_header.height, &header_bytes)?;
    BTC_HEIGHTS.save(storage, hash_bytes, &new_header.height)?;
    Ok(())
}

// Removes BTC headers from the header chain storages, including
// - remove all hash-to-height indices
pub fn remove_headers(
    storage: &mut dyn Storage,
    tip_header: &BtcHeaderInfo,
    parent_header: &BtcHeaderInfo,
) -> Result<(), ContractError> {
    // Remove all the headers by hash starting from the tip, until hitting the parent header
    let mut rem_header = tip_header.clone();
    while rem_header.hash != parent_header.hash {
        // Remove header from storage
        BTC_HEIGHTS.remove(storage, rem_header.hash.as_ref());
        // Obtain the previous header
        rem_header = get_header(storage, rem_header.height - 1)?;
    }
    Ok(())
}

// Retrieves the BTC header of a given height.
pub fn get_header(storage: &dyn Storage, height: u32) -> Result<BtcHeaderInfo, StoreError> {
    // Try to find the header with the given hash
    let header_bytes = BTC_HEADERS
        .load(storage, height)
        .map_err(|_| StoreError::HeightNotFound { height })?;

    BtcHeaderInfo::decode(header_bytes.as_slice()).map_err(Into::into)
}

/// Retrieves the BTC header associated with the given block hash.
///
/// This function assumes the header **must exist**, and will return an error if it is not found.
pub fn expect_header_by_hash(
    storage: &dyn Storage,
    hash: &[u8],
) -> Result<BtcHeaderInfo, StoreError> {
    let height = BTC_HEIGHTS
        .load(storage, hash)
        .map_err(|_| StoreError::HeaderNotFound {
            hash: hash.encode_hex::<String>(),
        })?;

    get_header(storage, height)
}

/// Attempts to retrieve the BTC header associated with the given block hash.
///
/// Unlike [`expect_header_by_hash`], this version returns `Ok(None)` if the header does not exist,
/// allowing for optional handling instead of an error.
pub fn get_header_by_hash(
    storage: &dyn Storage,
    hash: &[u8],
) -> Result<Option<BtcHeaderInfo>, StoreError> {
    let maybe_height = BTC_HEIGHTS.may_load(storage, hash)?;

    match maybe_height {
        Some(height) => Ok(Some(get_header(storage, height)?)),
        None => Ok(None),
    }
}

// Retrieves the BTC header height of a given BTC hash
pub fn get_header_height(storage: &dyn Storage, hash: &[u8]) -> Result<u32, StoreError> {
    BTC_HEIGHTS
        .load(storage, hash)
        .map_err(|_| StoreError::HeaderNotFound {
            hash: hash.encode_hex(),
        })
}

// Retrieves BTC headers in a given range.
pub fn get_headers(
    storage: &dyn Storage,
    start_after: Option<u32>,
    limit: Option<u32>,
    reverse: Option<bool>,
) -> Result<Vec<BtcHeaderInfo>, StoreError> {
    let limit = limit.unwrap_or(10) as usize;
    let reverse = reverse.unwrap_or(false);

    let (start, end, order) = match (start_after, reverse) {
        (Some(start), true) => (None, Some(Bound::exclusive(start)), Descending),
        (Some(start), false) => (Some(Bound::exclusive(start)), None, Ascending),
        (None, true) => (None, None, Descending),
        (None, false) => (None, None, Ascending),
    };

    let headers = BTC_HEADERS
        .range(storage, start, end, order)
        .take(limit)
        .map(|item| {
            let (_, header_bytes) = item?;
            BtcHeaderInfo::decode(header_bytes.as_slice()).map_err(StoreError::Decode)
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(headers)
}

pub mod test_utils {
    use crate::msg::contract::BaseHeader;
    use babylon_proto::babylon::btclightclient::v1::BtcHeaderInfo;
    use bitcoin::block::Header as BlockHeader;

    /// Helper function to get the appropriate base header
    pub fn get_btc_base_header() -> Option<BaseHeader> {
        None
    }

    pub fn test_headers() -> Vec<BtcHeaderInfo> {
        let headers = vec![
        // Initial base header on Babylon Genesis mainnet, https://www.blockchain.com/explorer/blocks/btc/854784.
        ("0000c020f382af1f6d228721b49f3da2f5b831587803b16597b301000000000000000000e4f76aae64d8316d195a92424871b74168b58d1c3c6988548e0e9890b15fc2fc3c00aa66be1a0317082e4bc7", 854784),
        ("0000003acbfbbb0a8d32aa0e739dc4f910a58299a8015b1cd48902000000000000000000a32c4a6ca3d399cc5146c28af944b807f298c6de063c161c13a1b3ca6fd2632e6500aa66be1a031783eb001c", 854785)
    ];

        headers
            .into_iter()
            .map(|(header, height)| {
                let header: BlockHeader = bitcoin::consensus::encode::deserialize_hex(header)
                    .expect("Static value must be correct");
                BtcHeaderInfo {
                    header: bitcoin::consensus::serialize(&header).into(),
                    hash: bitcoin::consensus::serialize(&header.block_hash()).into(),
                    height,
                    work: header.work().to_be_bytes().to_vec().into(),
                }
            })
            .collect()
    }
}
