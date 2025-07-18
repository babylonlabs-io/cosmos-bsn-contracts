use btc_staking::msg::{ExecuteMsg, InstantiateMsg, QueryMsg};
use cosmwasm_schema::write_api;
use cosmwasm_std::Empty;

fn main() {
    // Clear & write standard API
    write_api! {
        instantiate: InstantiateMsg,
        query: QueryMsg,
        migrate: Empty,
        execute: ExecuteMsg,
    }

    // Schemas for inter-contract communication
    // let mut out_dir = current_dir().unwrap();
    // out_dir.push("schema");
    // export_schema(&schema_for!(PacketMsg), &out_dir); // TODO: find a way to export schema for IBC packet
    // export_schema_with_title(
    //     &schema_for!(AcknowledgementMsg<BtcTimestampResponse>),
    //     &out_dir,
    //     "AcknowledgementMsgBtcTimestamp",
    // );
}
