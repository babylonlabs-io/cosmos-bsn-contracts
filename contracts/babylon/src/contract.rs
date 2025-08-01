use crate::error::ContractError;
use crate::ibc::{get_ibc_packet_timeout, ibc_packet, IBC_TRANSFER_CHANNEL, IBC_ZC_CHANNEL};
use crate::msg::contract::{ExecuteMsg, InstantiateMsg, QueryMsg};
use crate::msg::ibc::{BsnRewards, CallbackInfo, CallbackMemo, FpRatio};
use crate::queries;
use crate::state::config::{Config, CONFIG, DEFAULT_IBC_PACKET_TIMEOUT_DAYS};
use crate::state::consumer_header_chain::CONSUMER_HEIGHT_LAST;
use babylon_apis::{btc_staking_api, finality_api, to_bech32_addr, to_module_canonical_addr};
use cosmwasm_std::{
    to_json_binary, to_json_string, Addr, Binary, Decimal, Deps, DepsMut, Empty, Env, MessageInfo,
    QueryResponse, Reply, Response, SubMsg, SubMsgResponse, WasmMsg,
};
use cw2::set_contract_version;
use cw_utils::{must_pay, ParseReplyError};

pub const CONTRACT_NAME: &str = env!("CARGO_PKG_NAME");
pub const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

const REPLY_ID_INSTANTIATE_LIGHT_CLIENT: u64 = 2;
const REPLY_ID_INSTANTIATE_STAKING: u64 = 3;
const REPLY_ID_INSTANTIATE_FINALITY: u64 = 4;

/// When we instantiate the Babylon contract, it will optionally instantiate a BTC light client
/// contract first – if its code id is provided – followed by BTC staking and finality contracts
/// if their code ids are provided.
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    msg.validate()?;

    // Initialize config with None values for consumer fields
    let denom = deps.querier.query_bonded_denom()?;
    let mut cfg = Config {
        network: msg.network,
        btc_confirmation_depth: msg.btc_confirmation_depth,
        checkpoint_finalization_timeout: msg.checkpoint_finalization_timeout,
        btc_light_client: None, // Will be set in `reply` if `btc_light_client_code_id` is provided
        btc_staking: None,      // Will be set in `reply` if `btc_staking_code_id` is provided
        btc_finality: None,     // Will be set in `reply` if `btc_finality_code_id` is provided
        consumer_name: None,
        consumer_description: None,
        denom,
        ibc_packet_timeout_days: msg
            .ibc_packet_timeout_days
            .unwrap_or(DEFAULT_IBC_PACKET_TIMEOUT_DAYS),
        destination_module: msg.destination_module,
    };

    let mut res = Response::new().add_attribute("action", "instantiate");

    // instantiate btc light client contract first
    // It has to be before btc staking and finality contracts which depend on it
    if let Some(btc_light_client_code_id) = msg.btc_light_client_code_id {
        let init_msg = msg
            .btc_light_client_msg
            .ok_or(ContractError::MissingBtcLightClientInitMsg)?;
        let init_msg = WasmMsg::Instantiate {
            admin: msg.admin.clone(),
            code_id: btc_light_client_code_id,
            msg: init_msg,
            funds: vec![],
            label: "BTC Light Client".into(),
        };
        let init_msg = SubMsg::reply_on_success(init_msg, REPLY_ID_INSTANTIATE_LIGHT_CLIENT);
        res = res.add_submessage(init_msg);
    }

    if let Some(btc_staking_code_id) = msg.btc_staking_code_id {
        // Update config with consumer information
        cfg.consumer_name = msg.consumer_name;
        cfg.consumer_description = msg.consumer_description;

        // Instantiate BTC staking contract
        let init_msg = WasmMsg::Instantiate {
            admin: msg.admin.clone(),
            code_id: btc_staking_code_id,
            msg: msg.btc_staking_msg.unwrap_or(Binary::from(b"{}")),
            funds: vec![],
            label: "BTC Staking".into(),
        };
        let init_msg = SubMsg::reply_on_success(init_msg, REPLY_ID_INSTANTIATE_STAKING);

        // Test code sets a channel, so that we can better approximate IBC in test code
        #[cfg(any(test, all(feature = "library", not(target_arch = "wasm32"))))]
        {
            IBC_ZC_CHANNEL.save(deps.storage, &"channel-123".to_string())?;
        }
        res = res.add_submessage(init_msg);
    }

    if let Some(btc_finality_code_id) = msg.btc_finality_code_id {
        // Instantiate BTC finality contract
        let init_msg = WasmMsg::Instantiate {
            admin: msg.admin,
            code_id: btc_finality_code_id,
            msg: msg.btc_finality_msg.unwrap_or(Binary::from(b"{}")),
            funds: vec![],
            label: "BTC Finality".into(),
        };
        let init_msg = SubMsg::reply_on_success(init_msg, REPLY_ID_INSTANTIATE_FINALITY);

        res = res.add_submessage(init_msg);
    }

    // Save the config after potentially updating it
    CONFIG.save(deps.storage, &cfg)?;

    // Save the IBC transfer info
    IBC_TRANSFER_CHANNEL.save(deps.storage, &msg.ics20_channel_id)?;

    // Initialize the last Consumer height to 0 to avoid not found error
    CONSUMER_HEIGHT_LAST.save(deps.storage, &0)?;
    // Mock the last Consumer height for multi-test
    #[cfg(any(test, all(feature = "library", not(target_arch = "wasm32"))))]
    {
        let last_consumer_height = 100;
        CONSUMER_HEIGHT_LAST.save(deps.storage, &last_consumer_height)?;
    }

    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    Ok(res)
}

pub fn reply(deps: DepsMut, _env: Env, reply: Reply) -> Result<Response, ContractError> {
    let response = || {
        reply
            .result
            .into_result()
            .expect("TODO: why it's okay to not handle error here")
    };

    match reply.id {
        REPLY_ID_INSTANTIATE_LIGHT_CLIENT => reply_init_callback_light_client(deps, response()),
        REPLY_ID_INSTANTIATE_STAKING => reply_init_callback_staking(deps, response()),
        REPLY_ID_INSTANTIATE_FINALITY => reply_init_callback_finality(deps, response()),
        _ => Err(ContractError::InvalidReplyId(reply.id)),
    }
}

/// Tries to get contract address from events in reply
fn reply_init_get_contract_address(reply: &SubMsgResponse) -> Result<Addr, ContractError> {
    for event in &reply.events {
        if event.ty == "instantiate" {
            for attr in &event.attributes {
                if attr.key == "_contract_address" {
                    return Ok(Addr::unchecked(attr.value.clone()));
                }
            }
        }
    }
    Err(ContractError::ParseReply(ParseReplyError::ParseFailure(
        "Cannot parse contract address".to_string(),
    )))
}

/// Store BTC light client address
fn reply_init_callback_light_client(
    deps: DepsMut,
    reply: SubMsgResponse,
) -> Result<Response, ContractError> {
    // Try to get contract address from events in reply
    let addr = reply_init_get_contract_address(&reply)?;

    CONFIG.update(deps.storage, |mut cfg| {
        cfg.btc_light_client = Some(addr);
        Ok::<_, ContractError>(cfg)
    })?;

    Ok(Response::new())
}

/// Store BTC staking address
fn reply_init_callback_staking(
    deps: DepsMut,
    reply: SubMsgResponse,
) -> Result<Response, ContractError> {
    // Try to get contract address from events in reply
    let addr = reply_init_get_contract_address(&reply)?;
    CONFIG.update(deps.storage, |mut cfg| {
        cfg.btc_staking = Some(addr);
        Ok::<_, ContractError>(cfg)
    })?;
    Ok(Response::new())
}

/// Store BTC finality address
fn reply_init_callback_finality(
    deps: DepsMut,
    reply: SubMsgResponse,
) -> Result<Response, ContractError> {
    // Try to get contract address from events in reply
    let finality_addr = reply_init_get_contract_address(&reply)?;
    CONFIG.update(deps.storage, |mut cfg| {
        cfg.btc_finality = Some(finality_addr.clone());
        Ok::<_, ContractError>(cfg)
    })?;
    // Set the BTC finality contract address to the BTC staking contract
    let cfg = CONFIG.load(deps.storage)?;
    let msg = btc_staking_api::ExecuteMsg::UpdateContractAddresses {
        btc_light_client: cfg
            .btc_light_client
            .ok_or(ContractError::BtcLightClientNotSet {})?
            .to_string(),
        finality: cfg
            .btc_finality
            .ok_or(ContractError::BtcFinalityNotSet {})?
            .to_string(),
    };
    let staking_addr = cfg.btc_staking.ok_or(ContractError::BtcStakingNotSet {})?;
    let wasm_msg_1 = WasmMsg::Execute {
        contract_addr: staking_addr.to_string(),
        msg: to_json_binary(&msg)?,
        funds: vec![],
    };

    // Set the BTC staking contract address to the BTC finality contract
    let msg = finality_api::ExecuteMsg::UpdateStaking {
        staking: staking_addr.to_string(),
    };
    let wasm_msg_2 = WasmMsg::Execute {
        contract_addr: finality_addr.to_string(),
        msg: to_json_binary(&msg)?,
        funds: vec![],
    };
    Ok(Response::new()
        .add_message(wasm_msg_1)
        .add_message(wasm_msg_2))
}

pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> Result<QueryResponse, ContractError> {
    match msg {
        QueryMsg::Config {} => Ok(to_json_binary(&queries::config(deps)?)?),
        QueryMsg::BabylonBaseEpoch {} => Ok(to_json_binary(&queries::babylon_base_epoch(deps)?)?),
        QueryMsg::BabylonLastEpoch {} => Ok(to_json_binary(&queries::babylon_last_epoch(deps)?)?),
        QueryMsg::BabylonEpoch { epoch_number } => Ok(to_json_binary(&queries::babylon_epoch(
            deps,
            epoch_number,
        )?)?),
        QueryMsg::BabylonCheckpoint { epoch_number } => Ok(to_json_binary(
            &queries::babylon_checkpoint(deps, epoch_number)?,
        )?),
        QueryMsg::LastConsumerHeader {} => {
            Ok(to_json_binary(&queries::last_consumer_header(deps)?)?)
        }
        QueryMsg::LastConsumerHeight {} => {
            Ok(to_json_binary(&queries::last_consumer_height(deps)?)?)
        }
        QueryMsg::ConsumerHeader { height } => {
            Ok(to_json_binary(&queries::consumer_header(deps, height)?)?)
        }
        QueryMsg::TransferInfo {} => Ok(to_json_binary(&queries::transfer_info(deps)?)?),
    }
}

/// this is a no-op just to test how this integrates with wasmd
pub fn migrate(_deps: DepsMut, _env: Env, _msg: Empty) -> Result<Response, ContractError> {
    Ok(Response::default())
}

pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::Slashing { evidence } => {
            // This is an internal routing message from the `btc_finality` contract
            let cfg = CONFIG.load(deps.storage)?;
            // Check sender
            let btc_finality = cfg
                .btc_finality
                .ok_or(ContractError::BtcFinalityNotSet {})?;
            if info.sender != btc_finality {
                return Err(ContractError::Unauthorized {});
            }
            // Send to the staking contract for processing
            let mut res = Response::new();
            let btc_staking = cfg.btc_staking.ok_or(ContractError::BtcStakingNotSet {})?;
            // Slashes this finality provider, i.e., sets its slashing height to the block height
            // and its power to zero
            let msg = btc_staking_api::ExecuteMsg::Slash {
                fp_btc_pk_hex: hex::encode(evidence.fp_btc_pk.clone()),
            };
            let wasm_msg = WasmMsg::Execute {
                contract_addr: btc_staking.to_string(),
                msg: to_json_binary(&msg)?,
                funds: vec![],
            };
            res = res.add_message(wasm_msg);

            // Send over IBC to the Provider (Babylon)
            let channel_id = IBC_ZC_CHANNEL.load(deps.storage)?;
            let ibc_msg = ibc_packet::slashing_msg(&deps.as_ref(), &env, &channel_id, &evidence)?;
            // Send packet only if we are IBC enabled
            // TODO: send in test code when multi-test can handle it
            #[cfg(not(any(test, feature = "library")))]
            {
                res = res.add_message(ibc_msg);
            }
            #[cfg(any(test, feature = "library"))]
            {
                let _ = ibc_msg;
            }

            // TODO: Add events (#124)
            Ok(res)
        }
        ExecuteMsg::RewardsDistribution { fp_distribution } => {
            // Check that the sender is the finality contract
            let cfg = CONFIG.load(deps.storage)?;
            let finality_addr = cfg
                .btc_finality
                .ok_or(ContractError::BtcFinalityNotSet {})?;
            if info.sender != finality_addr {
                return Err(ContractError::Unauthorized {});
            }

            // Check that the funds are there
            let funds_sent_total = must_pay(&info, &cfg.denom)?;

            // Calculate total rewards to send
            let total_rewards = fp_distribution
                .iter()
                .map(|reward_info| reward_info.reward)
                .sum();

            // Check that the total rewards  to distribute match the funds sent
            if funds_sent_total != total_rewards {
                return Err(ContractError::InvalidRewards(
                    total_rewards,
                    funds_sent_total,
                ));
            }

            // Get consumer name for bsn_consumer_id
            let bsn_consumer_id = cfg
                .consumer_name
                .ok_or(ContractError::ConsumerNameNotSet {})?;

            // Get the ICS20 transfer channel ID
            let channel_id = IBC_TRANSFER_CHANNEL.load(deps.storage)?;

            // Calculate ratios from absolute amounts
            let fp_ratios: Vec<FpRatio> = fp_distribution
                .iter()
                .map(|reward_info| {
                    // Convert to Decimal for proper ratio calculation
                    let reward_decimal = Decimal::from_ratio(reward_info.reward, total_rewards);

                    let btc_pk_bytes = hex::decode(&reward_info.fp_pubkey_hex)?;
                    Ok(FpRatio {
                        btc_pk: Binary::new(btc_pk_bytes),
                        ratio: reward_decimal,
                    })
                })
                .collect::<Result<Vec<_>, ContractError>>()?;

            // Create memo with the proper Babylon structure using typed structs
            let callback_memo = CallbackMemo {
                action: "add_bsn_rewards".to_string(),
                dest_callback: CallbackInfo {
                    address: cfg.destination_module.clone(),
                    add_bsn_rewards: BsnRewards {
                        bsn_consumer_id,
                        fp_ratios,
                    },
                },
            };

            let memo = to_json_string(&callback_memo)?;

            // Define destination address using the rewards module name from config
            let rcpt_addr =
                to_bech32_addr("bbn", &to_module_canonical_addr(&cfg.destination_module))?;

            // Create ICS20 transfer message
            let transfer_msg = cosmwasm_std::IbcMsg::Transfer {
                channel_id,
                to_address: rcpt_addr.into(),
                amount: cosmwasm_std::Coin {
                    denom: cfg.denom.clone(),
                    amount: funds_sent_total,
                },
                timeout: get_ibc_packet_timeout(&env, &deps.as_ref())?,
                memo: Some(memo),
            };

            let mut response = Response::new()
                .add_attribute("action", "distribute_rewards")
                .add_attribute("total_rewards", total_rewards.to_string())
                .add_attribute("fp_count", fp_distribution.len().to_string());

            // Send IBC transfer message
            response = response.add_message(transfer_msg);

            Ok(response)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bitcoin::block::Header as BlockHeader;
    use btc_light_client::msg::InstantiateMsg as BtcLightClientInstantiateMsg;

    use cosmwasm_std::testing::message_info;
    use cosmwasm_std::testing::{mock_dependencies, mock_env};
    use cosmwasm_std::Uint128;

    use crate::msg::contract::RewardInfo;

    const CREATOR: &str = "creator";

    #[test]
    fn test_deserialize_btc_header() {
        // https://babylon.explorers.guru/transaction/8CEC6D605A39378F560C2134ABC931AE7DED0D055A6655B82CC5A31D5DA0BE26
        let btc_header_hex = "00400720b2559c9eb13821d6df53ffab9ddf3a645c559f030cac050000000000000000001ff22ffaa13c41df6aebc4b9b09faf328748c3a45772b6a4c4da319119fd5be3b53a1964817606174cc4c4b0";
        let btc_header_bytes = hex::decode(btc_header_hex).unwrap();
        let _btc_header: BlockHeader = bitcoin::consensus::deserialize(&btc_header_bytes).unwrap();
    }

    #[test]
    fn instantiate_works() {
        let mut deps = mock_dependencies();
        let msg = InstantiateMsg::new_test();
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(0, res.messages.len());
    }

    #[test]
    fn instantiate_light_client_works() {
        let mut deps = mock_dependencies();
        let mut msg = InstantiateMsg::new_test();

        msg.btc_light_client_code_id.replace(1);

        let btc_light_client_msg = BtcLightClientInstantiateMsg {
            network: btc_light_client::BitcoinNetwork::Regtest,
            btc_confirmation_depth: msg.btc_confirmation_depth,
            checkpoint_finalization_timeout: msg.checkpoint_finalization_timeout,
            admin: None,
        };

        msg.btc_light_client_msg
            .replace(to_json_binary(&btc_light_client_msg).unwrap());

        let info = message_info(&deps.api.addr_make(CREATOR), &[]);
        let res = instantiate(deps.as_mut(), mock_env(), info, msg.clone()).unwrap();
        assert_eq!(1, res.messages.len());
        assert_eq!(REPLY_ID_INSTANTIATE_LIGHT_CLIENT, res.messages[0].id);
        assert_eq!(
            res.messages[0].msg,
            WasmMsg::Instantiate {
                admin: None,
                code_id: 1,
                msg: to_json_binary(&btc_light_client_msg).unwrap(),
                funds: vec![],
                label: "BTC Light Client".into(),
            }
            .into()
        );
    }

    #[test]
    fn instantiate_light_client_params_works() {
        let mut deps = mock_dependencies();
        let params = r#"{"network":"testnet","btc_confirmation_depth":6,"checkpoint_finalization_timeout":100}"#;
        let mut msg = InstantiateMsg::new_test();
        msg.btc_light_client_code_id.replace(1);
        msg.btc_light_client_msg
            .replace(Binary::from(params.as_bytes()));
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(1, res.messages.len());
        assert_eq!(REPLY_ID_INSTANTIATE_LIGHT_CLIENT, res.messages[0].id);
        assert_eq!(
            res.messages[0].msg,
            WasmMsg::Instantiate {
                admin: None,
                code_id: 1,
                msg: Binary::from(params.as_bytes()),
                funds: vec![],
                label: "BTC Light Client".into(),
            }
            .into()
        );
    }

    #[test]
    fn instantiate_finality_works() {
        let mut deps = mock_dependencies();
        let mut msg = InstantiateMsg::new_test();
        msg.btc_finality_code_id.replace(2);
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(1, res.messages.len());
        assert_eq!(REPLY_ID_INSTANTIATE_FINALITY, res.messages[0].id);
        assert_eq!(
            res.messages[0].msg,
            WasmMsg::Instantiate {
                admin: None,
                code_id: 2,
                msg: Binary::from(b"{}"),
                funds: vec![],
                label: "BTC Finality".into(),
            }
            .into()
        );
    }

    #[test]
    fn instantiate_finality_params_works() {
        let mut deps = mock_dependencies();
        let params = r#"{"params": {"reward_interval": 10}}"#;
        let mut msg = InstantiateMsg::new_test();
        msg.btc_finality_code_id.replace(2);
        msg.btc_finality_msg
            .replace(Binary::from(params.as_bytes()));
        let info = message_info(&deps.api.addr_make(CREATOR), &[]);
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(1, res.messages.len());
        assert_eq!(REPLY_ID_INSTANTIATE_FINALITY, res.messages[0].id);
        assert_eq!(
            res.messages[0].msg,
            WasmMsg::Instantiate {
                admin: None,
                code_id: 2,
                msg: Binary::from(params.as_bytes()),
                funds: vec![],
                label: "BTC Finality".into(),
            }
            .into()
        );
    }

    #[test]
    fn test_distribute_rewards_unauthorized() {
        let mut deps = mock_dependencies();

        // Set up config with finality contract address
        let finality_addr = deps.api.addr_make("finality_contract");
        let cfg = Config {
            network: btc_light_client::BitcoinNetwork::Regtest,
            btc_confirmation_depth: 1,
            checkpoint_finalization_timeout: 1,
            btc_light_client: None,
            btc_staking: None,
            btc_finality: Some(finality_addr.clone()),
            consumer_name: Some("TestConsumer".to_string()),
            consumer_description: Some("Test Consumer Description".to_string()),
            denom: "stake".to_string(),
            ibc_packet_timeout_days: 1,
            destination_module: "btcstaking".to_string(),
        };
        CONFIG.save(&mut deps.storage, &cfg).unwrap();

        // Set up IBC transfer channel
        IBC_TRANSFER_CHANNEL
            .save(&mut deps.storage, &"channel-0".to_string())
            .unwrap();

        // Try to call with wrong sender
        let wrong_sender = deps.api.addr_make("wrong_sender");
        let fp_distribution = vec![RewardInfo {
            fp_pubkey_hex: "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619"
                .to_string(),
            reward: Uint128::new(1000),
        }];

        let msg = ExecuteMsg::RewardsDistribution { fp_distribution };
        let info = message_info(&wrong_sender, &[]);

        let err = execute(deps.as_mut(), mock_env(), info, msg).unwrap_err();
        match err {
            ContractError::Unauthorized {} => {}
            _ => panic!("Expected Unauthorized error"),
        }
    }

    #[test]
    fn test_distribute_rewards_invalid_amount() {
        let mut deps = mock_dependencies();

        // Set up config with finality contract address
        let finality_addr = deps.api.addr_make("finality_contract");
        let cfg = Config {
            network: btc_light_client::BitcoinNetwork::Regtest,
            btc_confirmation_depth: 1,
            checkpoint_finalization_timeout: 1,
            btc_light_client: None,
            btc_staking: None,
            btc_finality: Some(finality_addr.clone()),
            consumer_name: Some("TestConsumer".to_string()),
            consumer_description: Some("Test Consumer Description".to_string()),
            denom: "stake".to_string(),
            ibc_packet_timeout_days: 1,
            destination_module: "btcstaking".to_string(),
        };
        CONFIG.save(&mut deps.storage, &cfg).unwrap();

        // Set up IBC transfer channel
        IBC_TRANSFER_CHANNEL
            .save(&mut deps.storage, &"channel-0".to_string())
            .unwrap();

        // Test with no funds sent
        let fp_distribution = vec![RewardInfo {
            fp_pubkey_hex: "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619"
                .to_string(),
            reward: Uint128::new(1000),
        }];

        let funds = vec![];
        let msg = ExecuteMsg::RewardsDistribution { fp_distribution };
        let info = message_info(&finality_addr, &funds);

        let err = execute(deps.as_mut(), mock_env(), info, msg).unwrap_err();
        match err {
            ContractError::Payment(payment_err) => {
                assert!(matches!(
                    payment_err,
                    cw_utils::PaymentError::NoFunds { .. }
                ));
            }
            _ => panic!("Expected Payment error, got: {:?}", err),
        }

        // Test with wrong amount sent
        let fp_distribution = vec![
            RewardInfo {
                fp_pubkey_hex: "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619"
                    .to_string(),
                reward: Uint128::new(1000),
            },
            RewardInfo {
                fp_pubkey_hex: "03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7"
                    .to_string(),
                reward: Uint128::new(500),
            },
        ];

        // Send 1000 instead of 1500 (total rewards)
        let funds = vec![cosmwasm_std::coin(1000, "stake")];
        let msg = ExecuteMsg::RewardsDistribution { fp_distribution };
        let info = message_info(&finality_addr, &funds);

        let err = execute(deps.as_mut(), mock_env(), info, msg).unwrap_err();
        match err {
            ContractError::InvalidRewards(expected, sent) => {
                assert_eq!(expected, Uint128::new(1500));
                assert_eq!(sent, Uint128::new(1000));
            }
            _ => panic!("Expected InvalidRewards, got: {:?}", err),
        }
    }

    #[test]
    fn test_distribute_rewards_memo_structure() {
        let mut deps = mock_dependencies();

        // Set up config with finality contract address
        let finality_addr = deps.api.addr_make("finality_contract");
        let cfg = Config {
            network: btc_light_client::BitcoinNetwork::Regtest,
            btc_confirmation_depth: 1,
            checkpoint_finalization_timeout: 1,
            btc_light_client: None,
            btc_staking: None,
            btc_finality: Some(finality_addr.clone()),
            consumer_name: Some("TestConsumer".to_string()),
            consumer_description: Some("Test Consumer Description".to_string()),
            denom: "stake".to_string(),
            ibc_packet_timeout_days: 1,
            destination_module: "btcstaking".to_string(),
        };
        CONFIG.save(&mut deps.storage, &cfg).unwrap();

        // Set up IBC transfer channel
        IBC_TRANSFER_CHANNEL
            .save(&mut deps.storage, &"channel-0".to_string())
            .unwrap();

        // Test with valid distribution using proper hex strings for BIP340 public keys
        let fp_distribution = vec![
            RewardInfo {
                fp_pubkey_hex: "02eec7245d6b7d2ccb30380bfbe2a3648cd7a942653f5aa340edcea1f283686619"
                    .to_string(),
                reward: Uint128::new(600),
            },
            RewardInfo {
                fp_pubkey_hex: "03a0434d9e47f3c86235477c7b1ae6ae5d3442d49b1943c2b752a68e2a47e247c7"
                    .to_string(),
                reward: Uint128::new(400),
            },
        ];

        let funds = vec![cosmwasm_std::Coin {
            denom: "stake".to_string(),
            amount: Uint128::new(1000),
        }];
        let msg = ExecuteMsg::RewardsDistribution { fp_distribution };
        let info = message_info(&finality_addr, &funds);

        let response = execute(deps.as_mut(), mock_env(), info, msg).unwrap();

        // Verify that the response contains an IBC transfer message
        assert_eq!(response.messages.len(), 1);

        // The memo should be properly structured for Babylon
        // We can't easily test the exact memo content here, but we can verify
        // that the execution succeeds and produces the expected response structure
        assert_eq!(response.attributes.len(), 3);
        assert_eq!(response.attributes[0].key, "action");
        assert_eq!(response.attributes[0].value, "distribute_rewards");
        assert_eq!(response.attributes[1].key, "total_rewards");
        assert_eq!(response.attributes[1].value, "1000");
        assert_eq!(response.attributes[2].key, "fp_count");
        assert_eq!(response.attributes[2].value, "2");
    }
}
