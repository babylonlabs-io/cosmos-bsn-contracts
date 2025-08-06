use cosmwasm_schema::cw_serde;
use cosmwasm_std::Decimal;
use ibc_proto::ibc::core::channel::v1::{acknowledgement::Response, Acknowledgement};

pub type TransferInfoResponse = Option<String>;

pub fn new_ack_res() -> Acknowledgement {
    let resp = Response::Result(vec![]);

    Acknowledgement {
        response: Some(resp),
    }
}

pub fn new_ack_err(emsg: String) -> Acknowledgement {
    let resp = Response::Error(emsg);

    Acknowledgement {
        response: Some(resp),
    }
}

#[cw_serde]
pub struct BtcTimestampResponse {
    pub placeholder: String,
}

/// IBC callback structure for Babylon protocol integration
///
/// This module defines the callback structures used for IBC transfers to Babylon,
/// specifically for reward distribution and staking operations.
///
/// Reference: https://github.com/babylonlabs-io/babylon/blob/fa63f5eadc697dc17773de2ef4fc6d972a5e1618/x/btcstaking/types/ibc_callbacks.go

/// Action for adding BSN rewards
const ADD_BSN_REWARDS_ACTION: &str = "add_bsn_rewards";

// Callback memo structures for IBC transfers
#[cw_serde]
pub struct CallbackMemo {
    pub action: String,
    pub dest_callback: CallbackInfo,
}

impl CallbackMemo {
    /// Creates a new callback memo for adding Cosmos BSN rewards
    ///
    /// # Arguments
    ///
    /// * `address` - Address that calls the callback
    /// * `fp_ratios` - The FP ratios for the rewards
    pub fn new_add_cosmos_bsn_rewards(address: String, fp_ratios: Vec<FpRatio>) -> Self {
        Self {
            action: ADD_BSN_REWARDS_ACTION.to_string(),
            dest_callback: CallbackInfo {
                address,
                add_bsn_rewards: BsnRewards::new_cosmos(fp_ratios),
            },
        }
    }
}

#[cw_serde]
pub struct CallbackInfo {
    pub address: String,
    pub add_bsn_rewards: BsnRewards,
}

#[cw_serde]
pub struct BsnRewards {
    /// If set, this stores the address of the Babylon consumer contract on the Consumer.
    /// Cosmos BSN should always use `None`
    pub bsn_consumer_id: Option<String>,
    /// The FP ratios for the rewards
    pub fp_ratios: Vec<FpRatio>,
}

impl BsnRewards {
    /// Creates a new BSN rewards struct for Cosmos BSN
    ///
    /// # Arguments
    ///
    /// * `fp_ratios` - The FP ratios for the rewards
    pub fn new_cosmos(fp_ratios: Vec<FpRatio>) -> Self {
        Self {
            // Cosmos BSN should always use `None` for `bsn_consumer_id`
            // because Babylon Genesis will use IBC modules to determine
            // the consumer ID
            bsn_consumer_id: None,
            fp_ratios,
        }
    }
}

#[cw_serde]
pub struct FpRatio {
    // FP BTC public key, encoded in hex
    pub btc_pk: String,
    pub ratio: Decimal,
}
