use crate::error::ContractError;
use crate::state::config::CONFIG;
use babylon_apis::btc_staking_api::{
    ActiveBtcDelegation, NewFinalityProvider, UnbondedBtcDelegation,
};
use babylon_apis::finality_api::Evidence;
use babylon_proto::babylon::{
    btcstaking::v1::BtcStakingIbcPacket,
    zoneconcierge::v1::{
        inbound_packet::Packet as InboundPacketType, outbound_packet::Packet as OutboundPacketType,
        BsnSlashingIbcPacket, BtcHeaders, BtcTimestamp, InboundPacket, OutboundPacket,
    },
};
use cosmwasm_std::{
    to_json_binary, Binary, Deps, DepsMut, Env, Event, Ibc3ChannelOpenResponse, IbcBasicResponse,
    IbcChannelCloseMsg, IbcChannelConnectMsg, IbcChannelOpenMsg, IbcChannelOpenResponse, IbcMsg,
    IbcOrder, IbcPacketAckMsg, IbcPacketReceiveMsg, IbcPacketTimeoutMsg, IbcReceiveResponse,
    IbcTimeout, Never, StdAck, StdError, StdResult, WasmMsg,
};
use cw_storage_plus::Item;
use prost::Message;

/// Zone Concierge IBC channel settings
pub const IBC_VERSION: &str = "zoneconcierge-1";
pub const IBC_ORDERING: IbcOrder = IbcOrder::Ordered;

/// IBC Zone Concierge channel ID
pub const IBC_ZC_CHANNEL: Item<String> = Item::new("ibc_zc");
/// IBC transfer (ICS-020) channel ID
pub const IBC_TRANSFER_CHANNEL: Item<String> = Item::new("ibc_ics20");

/// Get IBC packet timeout based on configuration
pub fn get_ibc_packet_timeout(env: &Env, deps: &Deps) -> StdResult<IbcTimeout> {
    let cfg = CONFIG.load(deps.storage)?;
    let timeout = env.block.time.plus_days(cfg.ibc_packet_timeout_days);
    Ok(IbcTimeout::with_timestamp(timeout))
}

/// This is executed during the ChannelOpenInit and ChannelOpenTry
/// of the IBC 4-step channel protocol
/// (see https://github.com/cosmos/ibc/tree/main/spec/core/ics-004-channel-and-packet-semantics#channel-lifecycle-management)
/// In the case of ChannelOpenTry there's a counterparty_version attribute in the message.
/// Here we ensure the ordering and version constraints.
pub fn ibc_channel_open(
    deps: DepsMut,
    _env: Env,
    msg: IbcChannelOpenMsg,
) -> Result<IbcChannelOpenResponse, ContractError> {
    // Ensure we have no channel yet
    if IBC_ZC_CHANNEL.may_load(deps.storage)?.is_some() {
        return Err(ContractError::IbcChannelAlreadyOpen {});
    }
    // The IBC channel has to be ordered
    let channel = msg.channel();
    if channel.order != IBC_ORDERING {
        return Err(ContractError::IbcUnorderedChannel {});
    }

    // In IBCv3 we don't check the version string passed in the message
    // and only check the counterparty version
    if let Some(counter_version) = msg.counterparty_version() {
        if counter_version != IBC_VERSION {
            return Err(ContractError::IbcInvalidCounterPartyVersion {
                version: IBC_VERSION.to_string(),
            });
        }
    }

    // We return the version we need (which could be different from the counterparty version)
    Ok(Some(Ibc3ChannelOpenResponse {
        version: IBC_VERSION.to_string(),
    }))
}

/// Second part of the 4-step handshake, i.e. ChannelOpenAck and ChannelOpenConfirm.
pub fn ibc_channel_connect(
    deps: DepsMut,
    _env: Env,
    msg: IbcChannelConnectMsg,
) -> Result<IbcBasicResponse, ContractError> {
    // Ensure we have no channel yet
    if IBC_ZC_CHANNEL.may_load(deps.storage)?.is_some() {
        return Err(ContractError::IbcChannelAlreadyOpen {});
    }
    let channel = msg.channel();

    // Store the channel
    IBC_ZC_CHANNEL.save(deps.storage, &channel.endpoint.channel_id)?;

    let channel_id = &channel.endpoint.channel_id;
    let response = IbcBasicResponse::new()
        .add_attribute("action", "ibc_connect")
        .add_attribute("channel_id", channel_id)
        .add_event(Event::new("ibc").add_attribute("channel", "connect"));

    Ok(response)
}

/// This is invoked on the IBC Channel Close message
/// We perform any cleanup related to the channel
pub fn ibc_channel_close(
    _deps: DepsMut,
    _env: Env,
    msg: IbcChannelCloseMsg,
) -> StdResult<IbcBasicResponse> {
    let channel = msg.channel();
    // Get contract address and remove lookup
    let channel_id = channel.endpoint.channel_id.as_str();

    Ok(IbcBasicResponse::new()
        .add_attribute("action", "ibc_close")
        .add_attribute("channel_id", channel_id))
}

/// Invoked when an IBC packet is received.
/// We decode the contents of the packet and if it matches one of the packets we support, execute
/// the relevant function, otherwise return an IBC Ack error.
pub fn ibc_packet_receive(
    deps: &mut DepsMut,
    _env: Env,
    msg: IbcPacketReceiveMsg,
) -> Result<IbcReceiveResponse, Never> {
    (|| {
        let packet = msg.packet;
        let packet_data = OutboundPacket::decode(packet.data.as_slice())
            .map_err(|e| StdError::generic_err(format!("failed to decode OutboundPacket: {e}")))?;
        let outbound_packet = packet_data
            .packet
            .ok_or(StdError::generic_err("empty IBC packet"))?;
        match outbound_packet {
            OutboundPacketType::BtcTimestamp(btc_ts) => {
                ibc_packet::handle_btc_timestamp(deps, &btc_ts)
            }
            OutboundPacketType::BtcStaking(btc_staking) => {
                ibc_packet::handle_btc_staking(deps, &btc_staking)
            }
            OutboundPacketType::BtcHeaders(btc_headers) => {
                ibc_packet::handle_btc_headers(deps, &btc_headers)
            }
        }
    })()
    .or_else(|e| {
        Ok(
            IbcReceiveResponse::new(StdAck::error(format!("invalid packet: {e}")))
                .add_event(Event::new("ibc").add_attribute("packet", "receive")),
        )
    })
}

// Methods to handle PacketMsg variants
pub(crate) mod ibc_packet {
    use super::*;
    use cosmwasm_std::Deps;

    pub fn handle_btc_timestamp(
        deps: &mut DepsMut,
        btc_ts: &BtcTimestamp,
    ) -> StdResult<IbcReceiveResponse> {
        // handle the BTC timestamp, i.e., verify the BTC timestamp and update the contract state
        let wasm_msg = crate::state::handle_btc_timestamp(deps, btc_ts)?;

        // construct response
        let mut resp: IbcReceiveResponse = IbcReceiveResponse::new(StdAck::success(vec![]))
            .add_attribute("action", "receive_btc_timestamp");

        // add wasm message for BTC headers to response if it exists
        if let Some(wasm_msg) = wasm_msg {
            resp = resp.add_message(wasm_msg);
        }

        Ok(resp)
    }

    pub fn handle_btc_staking(
        deps: &mut DepsMut,
        btc_staking: &BtcStakingIbcPacket,
    ) -> StdResult<IbcReceiveResponse> {
        let cfg = CONFIG.load(deps.storage)?;

        // Route the packet to the btc-staking contract
        let btc_staking_addr = cfg
            .btc_staking
            .ok_or(StdError::generic_err("btc_staking contract not set"))?;

        // Build the message to send to the BTC staking contract
        let msg = babylon_apis::btc_staking_api::ExecuteMsg::BtcStaking {
            new_fp: btc_staking
                .new_fp
                .iter()
                .map(|fp| NewFinalityProvider::try_from(fp).map_err(StdError::generic_err))
                .collect::<StdResult<_>>()?,
            active_del: btc_staking
                .active_del
                .iter()
                .map(|d| ActiveBtcDelegation::try_from(d).map_err(StdError::generic_err))
                .collect::<StdResult<_>>()?,
            unbonded_del: btc_staking
                .unbonded_del
                .iter()
                .map(|u| UnbondedBtcDelegation {
                    staking_tx_hash: u.staking_tx_hash.clone(),
                    unbonding_tx_sig: u.unbonding_tx_sig.to_vec().into(),
                })
                .collect(),
        };

        let wasm_msg = WasmMsg::Execute {
            contract_addr: btc_staking_addr.to_string(),
            msg: to_json_binary(&msg)?,
            funds: vec![],
        };

        // construct response
        let resp: IbcReceiveResponse = IbcReceiveResponse::new(StdAck::success(vec![]))
            .add_message(wasm_msg)
            .add_attribute("action", "receive_btc_staking");

        Ok(resp)
    }

    pub fn handle_btc_headers(
        deps: &mut DepsMut,
        btc_headers: &BtcHeaders,
    ) -> StdResult<IbcReceiveResponse> {
        // Submit headers to BTC light client
        let msg = crate::utils::btc_light_client_executor::new_btc_headers_msg(
            deps,
            &btc_headers.headers,
        )
        .map_err(|e| {
            let err = format!("CONTRACT: handle_btc_headers, failed to submit BTC headers: {e}");
            deps.api.debug(&err);
            StdError::generic_err(err)
        })?;

        let resp: IbcReceiveResponse = IbcReceiveResponse::new(StdAck::success(vec![]))
            .add_message(msg)
            .add_attribute("action", "receive_btc_headers");

        Ok(resp)
    }

    pub(crate) fn get_slashing_msg(
        deps: &Deps,
        env: &Env,
        channel_id: &str,
        evidence: &Evidence,
    ) -> Result<IbcMsg, ContractError> {
        let packet = InboundPacket {
            packet: Some(InboundPacketType::BsnSlashing(BsnSlashingIbcPacket {
                evidence: Some(babylon_proto::babylon::finality::v1::Evidence {
                    fp_btc_pk: evidence.fp_btc_pk.to_vec().into(),
                    block_height: evidence.block_height,
                    pub_rand: evidence.pub_rand.to_vec().into(),
                    canonical_app_hash: evidence.canonical_app_hash.to_vec().into(),
                    fork_app_hash: evidence.fork_app_hash.to_vec().into(),
                    canonical_finality_sig: evidence.canonical_finality_sig.to_vec().into(),
                    fork_finality_sig: evidence.fork_finality_sig.to_vec().into(),
                    signing_context: evidence.signing_context.clone(),
                }),
            })),
        };
        let msg = IbcMsg::SendPacket {
            channel_id: channel_id.to_string(),
            data: Binary::new(packet.encode_to_vec()),
            timeout: get_ibc_packet_timeout(env, deps)?,
        };
        Ok(msg)
    }
}

pub fn ibc_packet_ack(
    _deps: DepsMut,
    _env: Env,
    _msg: IbcPacketAckMsg,
) -> Result<IbcBasicResponse, ContractError> {
    Ok(IbcBasicResponse::default())
}

pub fn ibc_packet_timeout(
    deps: DepsMut,
    _env: Env,
    msg: IbcPacketTimeoutMsg,
) -> Result<IbcBasicResponse, ContractError> {
    deps.api.debug(&format!(
        "Cosmos BSN contracts: ibc_packet_timeout: packet timed out on channel {} port {}",
        msg.packet.src.channel_id, msg.packet.src.port_id
    ));

    let response = IbcBasicResponse::new()
        .add_attribute("action", "ibc_packet_timeout")
        .add_attribute("channel_id", &msg.packet.src.channel_id)
        .add_attribute("port_id", &msg.packet.src.port_id);

    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_ibc_channel_open_try};

    #[test]
    fn enforce_version_in_handshake() {
        let mut deps = mock_dependencies();

        let wrong_order = mock_ibc_channel_open_try("channel-12", IbcOrder::Unordered, IBC_VERSION);
        ibc_channel_open(deps.as_mut(), mock_env(), wrong_order).unwrap_err();

        let wrong_version = mock_ibc_channel_open_try("channel-12", IbcOrder::Ordered, "reflect");
        ibc_channel_open(deps.as_mut(), mock_env(), wrong_version).unwrap_err();

        let valid_handshake = mock_ibc_channel_open_try("channel-12", IBC_ORDERING, IBC_VERSION);
        ibc_channel_open(deps.as_mut(), mock_env(), valid_handshake).unwrap();
    }
}
