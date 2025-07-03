use babylon_bitcoin::Network;
use babylon_test_utils::get_params;

use crate::state::config::Params;

pub fn staking_params() -> Params {
    let proto_params = get_params();
    Params {
        covenant_pks: proto_params.covenant_pks.iter().map(hex::encode).collect(),
        covenant_quorum: proto_params.covenant_quorum,
        btc_network: Network::Regtest, // TODO: fix this
        slashing_pk_script: hex::encode(proto_params.slashing_pk_script),
        min_slashing_tx_fee_sat: proto_params.min_slashing_tx_fee_sat as u64,
        slashing_rate: "0.01".to_string(), // TODO: fix this
    }
}
