use btc_finality::msg::{ExecuteMsg, InstantiateMsg, MigrateMsg, QueryMsg};
use cosmwasm_schema::write_api;

fn main() {
    write_api! {
        instantiate: InstantiateMsg,
        query: QueryMsg,
        migrate: MigrateMsg,
        execute: ExecuteMsg,
    }
}
