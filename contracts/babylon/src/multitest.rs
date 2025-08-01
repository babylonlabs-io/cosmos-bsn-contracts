mod suite;

use babylon_bindings_test::{
    BABYLON_CONTRACT_ADDR, BTC_FINALITY_CONTRACT_ADDR, BTC_LIGHT_CLIENT_CONTRACT_ADDR,
    BTC_STAKING_CONTRACT_ADDR,
};
use cosmwasm_std::Addr;
use suite::SuiteBuilder;

#[test]
fn initialization() {
    let suite = SuiteBuilder::new()
        .with_checkpoint_finalization_timeout(1)
        .build();

    // Check that the contracts were initialized correctly
    let config = suite.get_config();
    assert_eq!(config.network, btc_light_client::BitcoinNetwork::Testnet);
    assert_eq!(config.babylon_tag, [1, 2, 3, 4]);
    assert_eq!(config.btc_confirmation_depth, 1);
    assert_eq!(config.checkpoint_finalization_timeout, 1);
    assert!(!config.notify_cosmos_zone);
    assert_eq!(
        config.btc_light_client.unwrap().as_str(),
        BTC_LIGHT_CLIENT_CONTRACT_ADDR
    );
    assert_eq!(
        config.btc_staking,
        Some(Addr::unchecked(BTC_STAKING_CONTRACT_ADDR))
    );
    assert_eq!(
        config.btc_finality,
        Some(Addr::unchecked(BTC_FINALITY_CONTRACT_ADDR))
    );

    // Check that the btc-staking contract was initialized correctly
    let btc_staking_config = suite.get_btc_staking_config();
    assert_eq!(
        btc_staking_config.babylon,
        Addr::unchecked(BABYLON_CONTRACT_ADDR)
    );

    // Check that the btc-finality contract was initialized correctly
    let btc_finality_config = suite.get_btc_finality_config();
    assert_eq!(
        btc_finality_config.babylon,
        Addr::unchecked(BABYLON_CONTRACT_ADDR)
    );
}

mod instantiation {
    use super::*;
    use crate::state::config::Config;

    use cosmwasm_std::to_json_string;

    fn contract_should_be_instantiated(config: Config) {
        // Confirm the btc-light-client contract has been instantiated and set
        assert_eq!(
            config.btc_light_client.unwrap().as_str(),
            BTC_LIGHT_CLIENT_CONTRACT_ADDR
        );
        // Confirm the btc-staking contract has been instantiated and set
        assert_eq!(
            config.btc_staking,
            Some(Addr::unchecked(BTC_STAKING_CONTRACT_ADDR))
        );
        // Confirm the btc-finality contract has been instantiated and set
        assert_eq!(
            config.btc_finality,
            Some(Addr::unchecked(BTC_FINALITY_CONTRACT_ADDR))
        );
    }

    #[test]
    fn instantiate_works() {
        let suite = SuiteBuilder::new().build();
        contract_should_be_instantiated(suite.get_config());
    }

    #[test]
    fn instantiate_light_client_msg_works() {
        let params = btc_light_client::msg::InstantiateMsg {
            network: btc_light_client::BitcoinNetwork::Regtest,
            btc_confirmation_depth: 1,
            checkpoint_finalization_timeout: 1,
            admin: None,
        };
        let suite = SuiteBuilder::new()
            .with_light_client_msg(&to_json_string(&params).unwrap())
            .build();

        let config = suite.get_config();
        contract_should_be_instantiated(config);

        // Check that the btc-light-client contract was initialized correctly
        let btc_light_client_config = suite.get_btc_light_client_config();
        assert_eq!(btc_light_client_config.network, params.network);
        assert_eq!(
            btc_light_client_config.btc_confirmation_depth,
            params.btc_confirmation_depth
        );
        assert_eq!(
            btc_light_client_config.checkpoint_finalization_timeout,
            params.checkpoint_finalization_timeout
        );
    }

    #[test]
    fn instantiate_staking_msg_works() {
        let staking_instantiation_msg = btc_staking::msg::InstantiateMsg { admin: None };
        let suite = SuiteBuilder::new()
            .with_staking_msg(&to_json_string(&staking_instantiation_msg).unwrap())
            .build();

        contract_should_be_instantiated(suite.get_config());
    }

    #[test]
    fn instantiate_finality_msg_works() {
        let finality_instantiation_msg = btc_finality::msg::InstantiateMsg::default();
        let suite = SuiteBuilder::new()
            .with_finality_msg(&to_json_string(&finality_instantiation_msg).unwrap())
            .build();

        contract_should_be_instantiated(suite.get_config());
    }

    #[test]
    fn instantiate_ibc_ics20_works() {
        let suite = SuiteBuilder::new().with_ics20_channel("channel-10").build();

        // Confirm the transfer info has been set
        let channel_id = suite.get_transfer_info().unwrap();
        assert_eq!(channel_id, "channel-10");
    }
}

mod migration {
    use super::*;
    use cosmwasm_std::Empty;

    #[test]
    fn migrate_works() {
        let mut suite = SuiteBuilder::new().build();
        let admin = suite.admin().to_string();

        suite.migrate(&admin, Empty {}).unwrap();
    }
}
