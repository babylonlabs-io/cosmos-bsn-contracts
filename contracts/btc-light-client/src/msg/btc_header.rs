use std::str::{from_utf8, FromStr};

use cosmwasm_schema::cw_serde;

use babylon_bitcoin::hash_types::TxMerkleNode;
use babylon_bitcoin::{BlockHash, BlockHeader};
use babylon_proto::babylon::btclightclient::v1::{BtcHeaderInfo, BtcHeaderInfoResponse};

use crate::error::ContractError;

/// Bitcoin header.
///
/// Contains all the block's information except the actual transactions, but
/// including a root of a [merkle tree] committing to all transactions in the block.
///
/// This struct is for use in RPC requests and responses. It has convenience trait impls to convert
/// to the internal representation (`BlockHeader`), and to the Babylon extended representation
/// (`BtcHeaderInfo`).
/// Adapted from `BlockHeader`.
#[cw_serde]
pub struct BtcHeader {
    /// Originally protocol version, but repurposed for soft-fork signaling.
    ///
    /// ### Relevant BIPs
    ///
    /// * [BIP9 - Version bits with timeout and delay](https://github.com/bitcoin/bips/blob/master/bip-0009.mediawiki) (current usage)
    /// * [BIP34 - Block v2, Height in Coinbase](https://github.com/bitcoin/bips/blob/master/bip-0034.mediawiki)
    pub version: i32,
    /// Reference to the previous block in the chain.
    /// Encoded as a (byte-reversed) hex string.
    pub prev_blockhash: String,
    /// The root hash of the merkle tree of transactions in the block.
    /// Encoded as a (byte-reversed) hex string.
    pub merkle_root: String,
    pub time: u32,
    /// The target value below which the blockhash must lie, encoded as a
    /// a float (with well-defined rounding, of course).
    pub bits: u32,
    /// The nonce, selected to obtain a low enough blockhash.
    pub nonce: u32,
}

impl BtcHeader {
    pub fn to_btc_header_info(
        &self,
        height: u32,
        work: babylon_bitcoin::Work,
    ) -> Result<BtcHeaderInfo, ContractError> {
        let block_header: BlockHeader = self.try_into()?;
        Ok(BtcHeaderInfo {
            header: ::prost::bytes::Bytes::from(babylon_bitcoin::serialize(&block_header)),
            hash: ::prost::bytes::Bytes::from(babylon_bitcoin::serialize(
                &block_header.block_hash(),
            )),
            height,
            work: work.to_be_bytes().to_vec().into(),
        })
    }

    pub fn to_btc_header_info_from_prev(
        &self,
        prev_height: u32,
        prev_work: babylon_bitcoin::Work,
    ) -> Result<BtcHeaderInfo, ContractError> {
        let block_header: BlockHeader = self.try_into()?;
        let total_work = prev_work + block_header.work();

        Ok(BtcHeaderInfo {
            header: ::prost::bytes::Bytes::from(babylon_bitcoin::serialize(&block_header)),
            hash: ::prost::bytes::Bytes::from(babylon_bitcoin::serialize(
                &block_header.block_hash(),
            )),
            height: prev_height + 1,
            work: total_work.to_be_bytes().to_vec().into(),
        })
    }
}

/// Try to convert &BtcHeaderInfo to/into BtcHeader
impl TryFrom<&BtcHeaderInfo> for BtcHeader {
    type Error = ContractError;
    fn try_from(btc_header_info: &BtcHeaderInfo) -> Result<Self, Self::Error> {
        let block_header: BlockHeader = babylon_bitcoin::deserialize(&btc_header_info.header)?;
        Ok(Self {
            version: block_header.version.to_consensus(),
            prev_blockhash: block_header.prev_blockhash.to_string(),
            merkle_root: block_header.merkle_root.to_string(),
            time: block_header.time,
            bits: block_header.bits.to_consensus(),
            nonce: block_header.nonce,
        })
    }
}

/// Try to convert BtcHeaderInfo to/into BtcHeader
impl TryFrom<BtcHeaderInfo> for BtcHeader {
    type Error = ContractError;
    fn try_from(btc_header_info: BtcHeaderInfo) -> Result<Self, Self::Error> {
        Self::try_from(&btc_header_info)
    }
}

/// Try to convert &BtcHeaderInfoResponse to/into BtcHeader
impl TryFrom<&BtcHeaderInfoResponse> for BtcHeader {
    type Error = ContractError;
    fn try_from(btc_header_info_response: &BtcHeaderInfoResponse) -> Result<Self, Self::Error> {
        let block_header: BlockHeader =
            babylon_bitcoin::deserialize(&hex::decode(&btc_header_info_response.header_hex)?)?;
        Ok(Self {
            version: block_header.version.to_consensus(),
            prev_blockhash: block_header.prev_blockhash.to_string(),
            merkle_root: block_header.merkle_root.to_string(),
            time: block_header.time,
            bits: block_header.bits.to_consensus(),
            nonce: block_header.nonce,
        })
    }
}

/// Try to convert BtcHeaderResponse to/into BlockHeader
impl TryFrom<&BtcHeaderResponse> for BlockHeader {
    type Error = ContractError;
    fn try_from(header_response: &BtcHeaderResponse) -> Result<Self, Self::Error> {
        BlockHeader::try_from(&header_response.header)
    }
}

/// Try to convert BtcHeaderInfoResponse to/into BtcHeader
impl TryFrom<BtcHeaderInfoResponse> for BtcHeader {
    type Error = ContractError;
    fn try_from(btc_header_info_response: BtcHeaderInfoResponse) -> Result<Self, Self::Error> {
        Self::try_from(&btc_header_info_response)
    }
}

/// Try to convert &BtcHeader to/into BlockHeader
impl TryFrom<&BtcHeader> for BlockHeader {
    type Error = ContractError;

    fn try_from(header: &BtcHeader) -> Result<Self, Self::Error> {
        Ok(Self {
            version: babylon_bitcoin::Version::from_consensus(header.version),
            prev_blockhash: BlockHash::from_str(&header.prev_blockhash)?,
            merkle_root: TxMerkleNode::from_str(&header.merkle_root)?,
            time: header.time,
            bits: babylon_bitcoin::CompactTarget::from_consensus(header.bits),
            nonce: header.nonce,
        })
    }
}

/// Try to convert BtcHeader to/into BlockHeader
impl TryFrom<BtcHeader> for BlockHeader {
    type Error = ContractError;

    fn try_from(header: BtcHeader) -> Result<Self, Self::Error> {
        Self::try_from(&header)
    }
}

/// Convert &BlockHeader to/into BtcHeader
impl From<&BlockHeader> for BtcHeader {
    fn from(header: &BlockHeader) -> Self {
        Self {
            version: header.version.to_consensus(),
            prev_blockhash: header.prev_blockhash.to_string(),
            merkle_root: header.merkle_root.to_string(),
            time: header.time,
            bits: header.bits.to_consensus(),
            nonce: header.nonce,
        }
    }
}

/// Convert BlockHeader to/into BtcHeader
impl From<BlockHeader> for BtcHeader {
    fn from(header: BlockHeader) -> Self {
        Self::from(&header)
    }
}

/// Bitcoin header response.
///
/// This struct is for use in RPC requests and responses. It has convenience helpers to convert
/// from the internal representation (`BtcHeaderInfo`), and to the Babylon extended representation
///
/// Adapted from `BtcHeaderInfo`.
#[cw_serde]
pub struct BtcHeaderResponse {
    /// The Bitcoin header.
    pub header: BtcHeader,
    /// Hash of the BTC header.
    /// Encoded as a (byte-reversed) hex string.
    pub hash: String,
    /// The height of the block in the BTC blockchain.
    pub height: u32,
    /// The cumulative total work of this block and all of its ancestors.
    pub cum_work: cosmwasm_std::Uint256,
}

/// Bitcoin header responses.
///
/// Vector of `BtcHeaderResponse`.
#[cw_serde]
pub struct BtcHeadersResponse {
    /// The Bitcoin headers.
    pub headers: Vec<BtcHeaderResponse>,
}

impl TryFrom<Vec<BtcHeaderInfo>> for BtcHeadersResponse {
    type Error = ContractError;

    fn try_from(headers: Vec<BtcHeaderInfo>) -> Result<Self, Self::Error> {
        Ok(Self {
            headers: headers
                .iter()
                .map(TryFrom::try_from)
                .collect::<Result<Vec<_>, ContractError>>()?,
        })
    }
}
/// Try to convert from Vec<BtcHeaderInfo> to Vec<BtcHeader>
pub fn btc_headers_from_info(headers: &[BtcHeaderInfo]) -> Result<Vec<BtcHeader>, ContractError> {
    headers
        .iter()
        .map(BtcHeader::try_from)
        .collect::<Result<Vec<_>, ContractError>>()
}

/// Try to convert from `&BtcHeaderInfo` to/into `BtcHeaderResponse`
impl TryFrom<&BtcHeaderInfo> for BtcHeaderResponse {
    type Error = ContractError;

    fn try_from(btc_header_info: &BtcHeaderInfo) -> Result<Self, Self::Error> {
        let header = BtcHeader::try_from(btc_header_info)?;
        let total_work = from_utf8(btc_header_info.work.as_ref())?;
        let total_work = cosmwasm_std::Uint256::from_str(total_work)?;
        // FIXME: Use BlockHash / Hash helper / encapsulation to reverse the hash under the hood
        let hash_repr = hex::encode(
            btc_header_info
                .hash
                .iter()
                .rev()
                .cloned()
                .collect::<Vec<_>>(),
        );
        Ok(Self {
            header,
            hash: hash_repr,
            height: btc_header_info.height,
            cum_work: total_work,
        })
    }
}

/// Try to convert from `BtcHeaderInfo` to/into `BtcHeaderResponse`
impl TryFrom<BtcHeaderInfo> for BtcHeaderResponse {
    type Error = ContractError;
    fn try_from(header: BtcHeaderInfo) -> Result<Self, Self::Error> {
        Self::try_from(&header)
    }
}

impl From<&BtcHeaderResponse> for BtcHeader {
    fn from(btc_header_response: &BtcHeaderResponse) -> Self {
        btc_header_response.header.clone()
    }
}

impl From<BtcHeaderResponse> for BtcHeader {
    fn from(btc_header_response: BtcHeaderResponse) -> Self {
        Self::from(&btc_header_response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use babylon_bitcoin::{CompactTarget, Version, Work};

    #[test]
    fn btc_header_to_block_header_works() {
        let btc_header = BtcHeader {
            version: 1,
            prev_blockhash: "deaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead"
                .to_string(),
            merkle_root: "beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef"
                .to_string(),
            time: 123,
            bits: 456,
            nonce: 789,
        };
        let block_header: BlockHeader = btc_header.try_into().unwrap();
        assert_eq!(block_header.version.to_consensus(), 1);
        assert_eq!(
            block_header.prev_blockhash.to_string(),
            "deaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead"
        );
        assert_eq!(
            block_header.merkle_root.to_string(),
            "beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef"
        );
        assert_eq!(block_header.time, 123);
        assert_eq!(block_header.bits.to_consensus(), 456);
        assert_eq!(block_header.nonce, 789);
    }

    #[test]
    fn btc_header_into_block_header_works() {
        let btc_header = BtcHeader {
            version: 1,
            prev_blockhash: "deaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead"
                .to_string(),
            merkle_root: "beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef"
                .to_string(),
            time: 123,
            bits: 456,
            nonce: 789,
        };
        let block_header: BlockHeader = btc_header.try_into().unwrap();
        assert_eq!(block_header.version.to_consensus(), 1);
        assert_eq!(
            block_header.prev_blockhash.to_string(),
            "deaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead"
        );
        assert_eq!(
            block_header.merkle_root.to_string(),
            "beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef"
        );
        assert_eq!(block_header.time, 123);
        assert_eq!(block_header.bits.to_consensus(), 456);
        assert_eq!(block_header.nonce, 789);
    }

    #[test]
    fn btc_header_to_btc_header_info_works() {
        let btc_header = BtcHeader {
            version: 4,
            prev_blockhash: "683e86bd5c6d110d91b94b97137ba6bfe02dbbdb8e3dff722a669b5d69d77af6"
                .to_string(),
            merkle_root: "1f39321c9b4b78d6727a3e5a193eb7632ffc981bb2bcd52319ae23d7ea6457aa"
                .to_string(),
            time: 1401292937,
            bits: 545259519,
            nonce: 3865470564,
        };
        let block_header = BlockHeader::try_from(&btc_header).unwrap();
        let btc_header_info = btc_header.to_btc_header_info_from_prev(
            10,
            Work::from_be_bytes(cosmwasm_std::Uint256::from(23456u64).to_be_bytes()),
        );
        assert_eq!(
            btc_header_info,
            Ok(BtcHeaderInfo {
                header: ::prost::bytes::Bytes::from(babylon_bitcoin::serialize(&block_header)),
                hash: ::prost::bytes::Bytes::from(babylon_bitcoin::serialize(
                    &block_header.block_hash()
                )),
                height: 10 + 1,
                work: ::prost::bytes::Bytes::from("23458".as_bytes()), // header work is two
            })
        );
    }

    #[test]
    fn btc_header_from_block_header_works() {
        let block_header = BlockHeader {
            version: Version::from_consensus(1),
            prev_blockhash: BlockHash::from_str(
                "beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef",
            )
            .unwrap(),
            merkle_root: TxMerkleNode::from_str(
                "deaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead",
            )
            .unwrap(),
            time: 123,
            bits: CompactTarget::from_consensus(456),
            nonce: 789,
        };
        let btc_header = BtcHeader::from(block_header);
        assert_eq!(btc_header.version, 1);
        assert_eq!(
            block_header.prev_blockhash.to_string(),
            "beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef"
        );
        assert_eq!(
            block_header.merkle_root.to_string(),
            "deaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead"
        );
        assert_eq!(btc_header.time, 123);
        assert_eq!(btc_header.bits, 456);
        assert_eq!(btc_header.nonce, 789);
    }

    #[test]
    fn btc_header_from_btc_header_info_works() {
        let block_header = BlockHeader {
            version: Version::from_consensus(1),
            prev_blockhash: BlockHash::from_str(
                "beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef",
            )
            .unwrap(),
            merkle_root: TxMerkleNode::from_str(
                "deaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead",
            )
            .unwrap(),
            time: 123,
            bits: CompactTarget::from_consensus(456),
            nonce: 789,
        };
        let btc_header_info = BtcHeaderInfo {
            header: ::prost::bytes::Bytes::from(babylon_bitcoin::serialize(&block_header)),
            hash: ::prost::bytes::Bytes::from(babylon_bitcoin::serialize(
                &block_header.block_hash(),
            )),
            height: 1234,
            work: ::prost::bytes::Bytes::from("5678".as_bytes().to_vec()),
        };
        let btc_header = BtcHeader::try_from(&btc_header_info).unwrap();
        assert_eq!(btc_header.version, 1);
        assert_eq!(
            btc_header.prev_blockhash,
            block_header.prev_blockhash.to_string()
        );
        assert_eq!(btc_header.merkle_root, block_header.merkle_root.to_string());
        assert_eq!(btc_header.time, 123);
        assert_eq!(btc_header.bits, 456);
        assert_eq!(btc_header.nonce, 789);
    }

    #[test]
    fn btc_header_reponse_from_btc_header_info_works() {
        let block_header = BlockHeader {
            version: Version::from_consensus(1),
            prev_blockhash: BlockHash::from_str(
                "beefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeefbeef",
            )
            .unwrap(),
            merkle_root: TxMerkleNode::from_str(
                "deaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddeaddead",
            )
            .unwrap(),
            time: 123,
            bits: CompactTarget::from_consensus(456),
            nonce: 789,
        };
        let btc_header_info = BtcHeaderInfo {
            header: ::prost::bytes::Bytes::from(babylon_bitcoin::serialize(&block_header)),
            hash: ::prost::bytes::Bytes::from(block_header.block_hash().to_string()),
            height: 1234,
            work: ::prost::bytes::Bytes::from("5678".as_bytes().to_vec()),
        };
        let btc_header = BtcHeaderResponse::try_from(btc_header_info).unwrap();
        assert_eq!(btc_header.header.version, 1);
        assert_eq!(
            btc_header.header.prev_blockhash,
            block_header.prev_blockhash.to_string()
        );
        assert_eq!(
            btc_header.header.merkle_root,
            block_header.merkle_root.to_string()
        );
        assert_eq!(btc_header.header.time, 123);
        assert_eq!(btc_header.header.bits, 456);
        assert_eq!(btc_header.header.nonce, 789);

        assert_eq!(btc_header.height, 1234);
        assert_eq!(
            btc_header.cum_work,
            cosmwasm_std::Uint256::from_str("5678").unwrap()
        );
    }
}
