use babylon_proto::babylon::zoneconcierge::v1::IndexedHeader;
use cosmwasm_schema::cw_serde;
use cosmwasm_std::Timestamp;
use hex::ToHex;

/// Metadata of a Consumer header.
///
/// This struct is for use in RPC requests and responses. It has convenience helpers to convert
/// from the internal representation (`IndexedHeader`).
///
/// Adapted from `IndexedHeader`.
#[cw_serde]
pub struct ConsumerHeaderResponse {
    /// Unique ID of the consumer
    pub consumer_id: String,
    /// Hash of this header.
    /// Hex-encoded string of 32 bytes
    pub hash: String,
    /// Height of this header in the Consumer's ledger.
    /// (hash, height) jointly provides the position of the header on the Consumer ledger
    pub height: u64,
    /// Timestamp of this header in the Consumer's ledger.
    /// It's necessary for the Consumer to unbond all mature validators/delegations before this
    /// timestamp when this header is BTC-finalised
    pub time: Option<Timestamp>,
    /// Hash of the babylon block that includes this Consumer header.
    /// Hex-encoded string of 32 bytes
    pub babylon_header_hash: String,
    /// Height of the babylon block that includes this Consumer header
    pub babylon_header_height: u64,
    /// Epoch number of this header in the Babylon ledger
    pub babylon_epoch: u64,
    /// Hash of the tx that includes this header.
    /// (babylon_block_height, babylon_tx_hash) jointly provides the position of
    /// Header in the Babylon ledger.
    /// Hex-encoded string of 32 bytes
    pub babylon_tx_hash: String,
}

/// Metadata of a Consumer height.
///
/// This struct is for use in RPC requests and responses. It is a convenience, efficient way to
/// return the height of the last finalised Consumer header.
///
/// Adapted from `ConsumerHeaderResponse`.
#[cw_serde]
pub struct ConsumerHeightResponse {
    pub height: u64,
}

/// Convert from `&IndexedHeader` to `ConsumerHeaderResponse`.
impl From<&IndexedHeader> for ConsumerHeaderResponse {
    fn from(header: &IndexedHeader) -> Self {
        ConsumerHeaderResponse {
            consumer_id: header.consumer_id.clone(),
            hash: header.hash.encode_hex(),
            height: header.height,
            time: header
                .time
                .as_ref()
                .map(|t| Timestamp::from_seconds(t.seconds as u64).plus_nanos(t.nanos as u64)),
            babylon_header_hash: header.babylon_header_hash.encode_hex(),
            babylon_header_height: header.babylon_header_height,
            babylon_epoch: header.babylon_epoch,
            babylon_tx_hash: header.babylon_tx_hash.encode_hex(),
        }
    }
}

/// Convert from `IndexedHeader` to `ConsumerHeaderResponse`.
impl From<IndexedHeader> for ConsumerHeaderResponse {
    fn from(header: IndexedHeader) -> Self {
        Self::from(&header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexed_header_to_indexed_header_response_works() {
        let indexed_header = IndexedHeader {
            consumer_id: "consumer_id".to_string(),
            hash: prost::bytes::Bytes::from("hash"),
            height: 1,
            time: Some(::pbjson_types::Timestamp {
                seconds: 2,
                nanos: 3,
            }),
            babylon_header_hash: prost::bytes::Bytes::from("babylon_header_hash"),
            babylon_header_height: 4,
            babylon_epoch: 5,
            babylon_tx_hash: prost::bytes::Bytes::from("babylon_tx_hash"),
        };

        let indexed_header_response = ConsumerHeaderResponse::from(&indexed_header);

        assert_eq!(indexed_header_response.consumer_id, "consumer_id");
        assert_eq!(indexed_header_response.hash, hex::encode("hash"));
        assert_eq!(indexed_header_response.height, 1);
        assert_eq!(
            indexed_header_response.time.unwrap(),
            Timestamp::from_seconds(2).plus_nanos(3)
        );
        assert_eq!(
            indexed_header_response.babylon_header_hash,
            hex::encode("babylon_header_hash")
        );
        assert_eq!(indexed_header_response.babylon_header_height, 4);
        assert_eq!(indexed_header_response.babylon_epoch, 5);
        assert_eq!(
            indexed_header_response.babylon_tx_hash,
            hex::encode("babylon_tx_hash")
        );
    }
}
