//! `verify_new_checkpoint` against local stub endpoints serving recorded
//! mainnet responses, and `stall_status` at period boundaries.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;

use eth_lc_core::{profile, BeaconBlockHeader, ChainConfig, Store};
use eth_lc_host::chain_dir::parse_root;
use eth_lc_host::checkpoint::{
    stall_status, verify_new_checkpoint, CheckpointError, CheckpointPolicy, StallStatus,
};
use serde_json::Value;

const ROOT: &str = "0xe7c0ae95dd6a82d9eca7d9dc4e1b42a4c8197fbb0e4cd880bc5f9631de2b992b";
const SLOT: u64 = 15_581_184;

fn recorded(name: &str) -> Value {
    let path = format!("{}/../vectors/mainnet/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

/// Responses of one endpoint, by path.
#[derive(Clone)]
struct Responses {
    genesis: Value,
    header: Value,
    bootstrap: Value,
}

impl Responses {
    fn recorded() -> Self {
        Self {
            genesis: recorded("genesis.json"),
            header: recorded("checkpoint/header.json"),
            bootstrap: recorded("checkpoint/bootstrap.json"),
        }
    }
}

/// Serves `r` on a local port; returns the base URL.
fn serve(r: Responses) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let routes: HashMap<String, String> = [
        ("/eth/v1/beacon/genesis".to_string(), r.genesis.to_string()),
        (
            format!("/eth/v1/beacon/headers/{ROOT}"),
            r.header.to_string(),
        ),
        (
            format!("/eth/v1/beacon/light_client/bootstrap/{ROOT}"),
            r.bootstrap.to_string(),
        ),
    ]
    .into_iter()
    .collect();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            loop {
                let mut h = String::new();
                if reader.read_line(&mut h).unwrap() == 0 || h == "\r\n" {
                    break;
                }
            }
            let path = line.split_whitespace().nth(1).unwrap_or_default();
            let (status, body) = match routes.get(path) {
                Some(b) => ("200 OK", b.clone()),
                None => ("404 Not Found", "{}".to_string()),
            };
            let _ = write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
        }
    });
    url
}

fn cfg() -> ChainConfig {
    profile::mainnet()
}

/// One hour after the checkpoint slot.
fn now() -> u64 {
    cfg().slot_start_ms(SLOT) + 3_600_000
}

fn run(
    endpoints: Vec<Responses>,
    now_ms: u64,
) -> Result<eth_lc_core::BootstrapInput, CheckpointError> {
    let urls: Vec<String> = endpoints.into_iter().map(serve).collect();
    verify_new_checkpoint(
        &cfg(),
        &urls,
        parse_root(ROOT).unwrap(),
        now_ms,
        &CheckpointPolicy::default(),
    )
}

#[test]
fn three_agreeing_endpoints_pass() {
    let r = Responses::recorded();
    let input = run(vec![r.clone(), r.clone(), r], now()).unwrap();
    assert_eq!(input.bootstrap.header.beacon().slot, SLOT);
}

#[test]
fn two_endpoints_fail() {
    let r = Responses::recorded();
    assert!(matches!(
        run(vec![r.clone(), r], now()),
        Err(CheckpointError::TooFewEndpoints {
            answered: 2,
            required: 3
        })
    ));
}

#[test]
fn disagreeing_bootstrap_fails() {
    let r = Responses::recorded();
    let mut other = r.clone();
    other.bootstrap["data"]["header"]["beacon"]["proposer_index"] = Value::String("1".into());
    assert!(matches!(
        run(vec![r.clone(), r, other], now()),
        Err(CheckpointError::BootstrapMismatch { .. })
    ));
}

#[test]
fn non_finalized_root_fails() {
    let r = Responses::recorded();
    let mut other = r.clone();
    other.header["finalized"] = Value::Bool(false);
    assert!(matches!(
        run(vec![r.clone(), other, r], now()),
        Err(CheckpointError::NotFinalized { .. })
    ));
}

#[test]
fn wrong_genesis_root_fails() {
    let r = Responses::recorded();
    let mut other = r.clone();
    other.genesis["data"]["genesis_validators_root"] =
        Value::String(format!("0x{}", "11".repeat(32)));
    assert!(matches!(
        run(vec![other, r.clone(), r], now()),
        Err(CheckpointError::GenesisMismatch { .. })
    ));
}

#[test]
fn bad_committee_branch_fails() {
    let mut r = Responses::recorded();
    r.bootstrap["data"]["current_sync_committee_branch"][2] =
        Value::String(format!("0x{}", "22".repeat(32)));
    assert!(matches!(
        run(vec![r.clone(), r.clone(), r], now()),
        Err(CheckpointError::Initialize(
            eth_lc_core::Error::InvalidCurrentCommitteeBranch
        ))
    ));
}

#[test]
fn age_of_257_epochs_fails() {
    let r = Responses::recorded();
    let epoch_ms = 32 * 12 * 1000;
    let at = |epochs: u64| cfg().slot_start_ms(SLOT) + epochs * epoch_ms;
    assert!(run(vec![r.clone(), r.clone(), r.clone()], at(256)).is_ok());
    assert!(matches!(
        run(vec![r.clone(), r.clone(), r], at(257)),
        Err(CheckpointError::TooOld { .. })
    ));
}

#[test]
fn stall_status_at_period_boundaries() {
    let cfg = cfg();
    let store = |slot| Store {
        finalized: BeaconBlockHeader {
            slot,
            ..Default::default()
        },
        execution: Default::default(),
        current_committee_root: [0; 32],
        next_committee_root: None,
    };
    let period = 8192;
    let s = store(1902 * period);
    let stale = cfg.slot_start_ms(1904 * period);
    assert_eq!(
        stall_status(&cfg, &s, stale - 1),
        StallStatus::Live { remaining_ms: 1 }
    );
    assert_eq!(stall_status(&cfg, &s, stale), StallStatus::Stalled);
    // The last slot of the period has the same bound as the first.
    assert_eq!(
        stall_status(&cfg, &store(1903 * period - 1), stale),
        StallStatus::Stalled
    );
    assert_eq!(
        stall_status(&cfg, &store(1903 * period), stale),
        StallStatus::Live {
            remaining_ms: 8192 * 12 * 1000
        }
    );
}
