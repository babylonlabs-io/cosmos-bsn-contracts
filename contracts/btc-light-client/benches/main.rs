//! This benchmark tries to run and call the generated wasm.
//! It depends on a Wasm build being available, which you can create by running `cargo optimize` in
//! the workspace root.
//! Then running `cargo bench` will validate we can properly call into that generated Wasm.

use criterion::{criterion_group, criterion_main, Criterion, PlottingBackend};

use std::time::Duration;
use thousands::Separable;

use cosmwasm_std::{Env, MessageInfo, Response};
use cosmwasm_vm::testing::{
    execute, instantiate, mock_env, mock_info, mock_instance_with_gas_limit, MockApi, MockQuerier,
    MockStorage,
};
use cosmwasm_vm::Instance;

use babylon_bindings::BabylonMsg;
use babylon_test_utils::get_btc_lc_mainchain_resp;
use btc_light_client::msg::btc_header::BtcHeader;
use btc_light_client::msg::contract::{ExecuteMsg, InstantiateMsg};

#[cfg(clippy)]
static WASM: &[u8] = &[];

// Output of `cargo optimize`
#[cfg(not(clippy))]
static WASM: &[u8] = include_bytes!("../../../artifacts/btc_light_client.wasm");

// From https://github.com/CosmWasm/wasmd/blob/7ea00e2ea858ed599141e322bd68171998a3259a/x/wasm/types/gas_register.go#L33
const GAS_MULTIPLIER: u64 = 140_000_000;

const CREATOR: &str = "creator";

#[track_caller]
pub fn get_main_msg_test_headers() -> Vec<BtcHeader> {
    let res = get_btc_lc_mainchain_resp();
    res.headers
        .iter()
        .map(TryInto::try_into)
        .collect::<Result<_, _>>()
        .unwrap()
}

#[track_caller]
pub fn setup_instance() -> Instance<MockApi, MockStorage, MockQuerier> {
    let mut deps = mock_instance_with_gas_limit(WASM, 10_000_000_000_000);
    let msg = InstantiateMsg {
        network: babylon_bitcoin::Network::Regtest,
        btc_confirmation_depth: 10,
        checkpoint_finalization_timeout: 2,
    };
    let info = mock_info(CREATOR, &[]);
    let res: Response = instantiate(&mut deps, mock_env(), info, msg).unwrap();
    assert_eq!(0, res.messages.len());
    deps
}

#[track_caller]
fn setup_benchmark() -> (
    Instance<MockApi, MockStorage, MockQuerier>,
    MessageInfo,
    Env,
    Vec<BtcHeader>,
) {
    let mut deps = setup_instance();
    let info = mock_info(CREATOR, &[]);
    let env = mock_env();

    let test_headers = get_main_msg_test_headers();

    let benchmark_msg = ExecuteMsg::BtcHeaders {
        headers: test_headers[0..=1].to_owned(),
        first_work: None,
        first_height: None,
    };

    // init call
    execute::<_, _, _, _, BabylonMsg>(&mut deps, env.clone(), info.clone(), benchmark_msg.clone())
        .unwrap();
    (deps, info, env, test_headers)
}

fn bench_btc_light_client(c: &mut Criterion) {
    let mut group = c.benchmark_group("BTC Light Client");

    group.bench_function("btc_headers_verify cpu", |b| {
        let (mut deps, info, env, test_headers) = setup_benchmark();

        let headers_len = test_headers.len();
        let mut i = 1;
        b.iter(|| {
            let benchmark_msg = ExecuteMsg::BtcHeaders {
                headers: test_headers[i..=i + 1].to_owned(),
                first_work: None,
                first_height: None,
            };
            execute::<_, _, _, _, BabylonMsg>(&mut deps, env.clone(), info.clone(), benchmark_msg)
                .unwrap();
            i = (i + 1) % (headers_len - 1);
        });
    });

    group.bench_function("btc_headers_verify gas", |b| {
        let (mut deps, info, env, test_headers) = setup_benchmark();

        let headers_len = test_headers.len();
        let mut i = 1;
        b.iter_custom(|iter| {
            let mut gas_used = 0;
            for _ in 0..iter {
                let benchmark_msg = ExecuteMsg::BtcHeaders {
                    headers: test_headers[i..=i + 1].to_owned(),
                    first_work: None,
                    first_height: None,
                };
                let gas_before = deps.get_gas_left();
                execute::<_, _, _, _, BabylonMsg>(
                    &mut deps,
                    env.clone(),
                    info.clone(),
                    benchmark_msg,
                )
                .unwrap();
                gas_used += gas_before - deps.get_gas_left();
                i = (i + 1) % (headers_len - 1);
            }
            println!(
                "BTC header avg call gas: {}",
                (gas_used / (2 * iter)).separate_with_underscores()
            );
            Duration::new(0, gas_used as u32 / 2)
        });
    });

    group.bench_function("btc_headers_verify SDK gas", |b| {
        let (mut deps, info, env, test_headers) = setup_benchmark();

        let headers_len = test_headers.len();
        let mut i = 1;
        b.iter_custom(|iter| {
            let mut gas_used = 0;
            for _ in 0..iter {
                let benchmark_msg = ExecuteMsg::BtcHeaders {
                    headers: test_headers[i..=i + 1].to_owned(),
                    first_work: None,
                    first_height: None,
                };
                let gas_before = deps.get_gas_left();
                execute::<_, _, _, _, BabylonMsg>(
                    &mut deps,
                    env.clone(),
                    info.clone(),
                    benchmark_msg,
                )
                .unwrap();
                gas_used += (gas_before - deps.get_gas_left()) / GAS_MULTIPLIER;
                i = (i + 1) % (headers_len - 1);
            }
            println!("BTC header avg call SDK gas: {}", gas_used / (2 * iter));
            Duration::new(0, gas_used as u32 / 2)
        });
    });

    group.finish();
}

fn make_config() -> Criterion {
    Criterion::default()
        .plotting_backend(PlottingBackend::Plotters)
        .without_plots()
        .warm_up_time(Duration::new(0, 1_000_000))
        .measurement_time(Duration::new(0, 10_000_000))
        .sample_size(10)
}

criterion_group!(
    name = btc_light_client;
    config = make_config();
    targets = bench_btc_light_client
);
criterion_main!(btc_light_client);
