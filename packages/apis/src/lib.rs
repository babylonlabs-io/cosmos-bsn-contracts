pub mod btc_staking_api;
pub mod error;
pub mod finality_api;
pub mod signing_context;
mod validate;

use bech32::Variant::Bech32;
use bech32::{FromBase32, ToBase32, Variant};
use cosmwasm_std::{Addr, CanonicalAddr};
use error::StakingApiError;
use sha2::Digest;
pub use validate::Validate;

pub type Bytes = Vec<u8>;

/// Converts a bech32 address to a canonical address
/// ported from cosmwasm-std/testing/mock.rs
pub fn to_canonical_addr(addr: &str, prefix: &str) -> Result<CanonicalAddr, StakingApiError> {
    // decode bech32 address
    let decode_result = bech32::decode(addr);
    if let Err(e) = decode_result {
        return Err(StakingApiError::InvalidAddressString(e.to_string()));
    }
    let (decoded_prefix, decoded_data, variant) = decode_result.unwrap();
    // check bech32 prefix
    if decoded_prefix != prefix {
        return Err(StakingApiError::InvalidAddressString(
            "wrong bech32 prefix".to_string(),
        ));
    }
    // check bech32 variant
    if variant == Variant::Bech32m {
        return Err(StakingApiError::InvalidAddressString(
            "wrong bech32 variant".to_string(),
        ));
    }
    // check bech32 data
    let bytes = Vec::<u8>::from_base32(&decoded_data)
        .map_err(|_| StakingApiError::InvalidAddressString("invalid bech32 data".to_string()))?;
    if bytes.is_empty() || bytes.len() > 255 {
        return Err(StakingApiError::InvalidAddressString(
            "Invalid canonical address length".to_string(),
        ));
    }
    // return canonical address
    Ok(bytes.into())
}

// Hash function to replace Cosmos SDK crypto.AddressHash and Hash.
fn hash(namespace: &str, input: &[u8]) -> Vec<u8> {
    let mut hasher = sha2::Sha256::new();
    sha2::digest::Update::update(&mut hasher, namespace.as_bytes());
    sha2::digest::Update::update(&mut hasher, input);
    hasher.finalize().to_vec()
}

/// Generates a Cosmos SDK compatible module address from a module name
pub fn to_module_canonical_addr(module_name: &str) -> CanonicalAddr {
    CanonicalAddr::from(hash("", module_name.as_bytes()))
}

/// Converts a CanonicalAddr to a Cosmos SDK compatible Bech32 encoded Addr with
/// the given prefix
pub fn to_bech32_addr(prefix: &str, addr: &CanonicalAddr) -> Result<Addr, StakingApiError> {
    let bech32_addr = bech32::encode(prefix, &addr.as_slice().to_base32()[..32], Bech32)
        .map_err(|e| StakingApiError::InvalidAddressString(e.to_string()))?;
    Ok(Addr::unchecked(bech32_addr))
}
