use ibc_proto::ibc::core::channel::v1::{acknowledgement::Response, Acknowledgement};

use cosmwasm_schema::cw_serde;

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
