use btc_light_client::msg::contract::{ExecuteMsg, InstantiateMsg, QueryMsg};
use cosmwasm_schema::write_api;
use cosmwasm_std::Empty;

fn main() {
    write_api! {
        instantiate: InstantiateMsg,
        execute: ExecuteMsg,
        query: QueryMsg,
        migrate: Empty,
    }
}
