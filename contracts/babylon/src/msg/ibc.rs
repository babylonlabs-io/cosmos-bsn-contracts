use ibc_proto::ibc::core::channel::v1::{acknowledgement::Response, Acknowledgement};

use cosmwasm_schema::cw_serde;
use cosmwasm_std::Binary;
use cosmwasm_std::Decimal;

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

// Callback memo structures for IBC transfers
#[cw_serde]
pub struct CallbackMemo {
    pub action: String,
    pub dest_callback: CallbackInfo,
}

#[cw_serde]
pub struct CallbackInfo {
    pub address: String,
    pub add_bsn_rewards: BsnRewards,
}

#[cw_serde]
pub struct BsnRewards {
    pub bsn_consumer_id: String,
    pub fp_ratios: Vec<FpRatio>,
}

#[cw_serde]
pub struct FpRatio {
    pub btc_pk: Binary,
    pub ratio: Decimal,
}
