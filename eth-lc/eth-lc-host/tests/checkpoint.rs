//! `verify_instance_config` and `verify_new_checkpoint` against local stub
//! endpoints serving recorded responses (a Fulu mainnet checkpoint and a
//! Gloas Sepolia checkpoint), and `stall_status` at period boundaries.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;

use eth_lc_core::{BeaconBlockHeader, ChainConfig, ForkName, LightClientHeader, Store};
use eth_lc_host::chain_dir::parse_root;
use eth_lc_host::checkpoint::{
    stall_status, verify_instance_config, verify_new_checkpoint, CheckpointError, CheckpointPolicy,
    StallStatus,
};
use serde_json::{json, Value};

/// A recorded checkpoint of one chain.
#[derive(Clone)]
struct Chain {
    dir: &'static str,
    root: &'static str,
    slot: u64,
    cfg: fn() -> ChainConfig,
}

const MAINNET: Chain = Chain {
    dir: "mainnet",
    root: "0xe7c0ae95dd6a82d9eca7d9dc4e1b42a4c8197fbb0e4cd880bc5f9631de2b992b",
    slot: 15_581_184,
    cfg: ChainConfig::mainnet,
};

const SEPOLIA: Chain = Chain {
    dir: "sepolia",
    root: "0xbc075dc6a21938f799abeafa88759bfd56336e6917dc53c100f7b451f218e6de",
    slot: 11_544_512,
    cfg: ChainConfig::sepolia,
};

fn recorded(chain: &Chain, name: &str) -> Value {
    let path = format!(
        "{}/../vectors/{}/{name}",
        env!("CARGO_MANIFEST_DIR"),
        chain.dir
    );
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

/// Responses of one Beacon API endpoint, by path.
#[derive(Clone)]
struct Responses {
    root: String,
    genesis: Value,
    spec: Value,
    header: Value,
    bootstrap: Value,
    /// `/eth/v1/beacon/states/head/finality_checkpoints`, when served.
    finality: Option<Value>,
}

impl Responses {
    fn recorded(chain: &Chain) -> Self {
        Self {
            root: chain.root.into(),
            genesis: recorded(chain, "genesis.json"),
            spec: recorded(chain, "config-spec.json"),
            header: recorded(chain, "checkpoint/header.json"),
            bootstrap: recorded(chain, "checkpoint/bootstrap.json"),
            finality: None,
        }
    }
}

/// Serves `route(method, path, body)` on a local port; returns the base URL.
fn serve_with(route: impl Fn(&str, &str, &str) -> Option<String> + Send + 'static) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let mut len = 0;
            loop {
                let mut h = String::new();
                if reader.read_line(&mut h).unwrap() == 0 || h == "\r\n" {
                    break;
                }
                if let Some(v) = h.to_ascii_lowercase().strip_prefix("content-length:") {
                    len = v.trim().parse().unwrap();
                }
            }
            let mut body = vec![0; len];
            reader.read_exact(&mut body).unwrap();
            let mut parts = line.split_whitespace();
            let method = parts.next().unwrap_or_default().to_string();
            let path = parts.next().unwrap_or_default().to_string();
            let (status, body) = match route(&method, &path, &String::from_utf8_lossy(&body)) {
                Some(b) => ("200 OK", b),
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

fn serve(r: Responses) -> String {
    let finality = r.finality.map(|f| {
        (
            "/eth/v1/beacon/states/head/finality_checkpoints".to_string(),
            f.to_string(),
        )
    });
    let routes: HashMap<String, String> = [
        ("/eth/v1/beacon/genesis".to_string(), r.genesis.to_string()),
        ("/eth/v1/config/spec".to_string(), r.spec.to_string()),
        (
            format!("/eth/v1/beacon/headers/{}", r.root),
            r.header.to_string(),
        ),
        (
            format!("/eth/v1/beacon/light_client/bootstrap/{}", r.root),
            r.bootstrap.to_string(),
        ),
    ]
    .into_iter()
    .chain(finality)
    .collect();
    serve_with(move |_, path, _| routes.get(path).cloned())
}

/// A JSON-RPC stub: `eth_chainId` answers `chain_id`; `eth_getBlockByHash`
/// answers `block` (an RPC block object) for its own hash.
fn serve_rpc(chain_id: u64, block: Option<Value>) -> String {
    serve_with(move |method, _, body| {
        if method != "POST" {
            return None;
        }
        let req: Value = serde_json::from_str(body).ok()?;
        let result = match req["method"].as_str()? {
            "eth_chainId" => json!(format!("0x{chain_id:x}")),
            "eth_getBlockByHash" => match &block {
                Some(b) if b["hash"] == req["params"][0] => b.clone(),
                _ => Value::Null,
            },
            _ => return None,
        };
        Some(json!({"jsonrpc": "2.0", "id": req["id"], "result": result}).to_string())
    })
}

fn rpc_for(chain: &Chain) -> String {
    let block = (chain.dir == "sepolia")
        .then(|| recorded(chain, "checkpoint/block.json")["result"].clone());
    serve_rpc((chain.cfg)().chain_id, block)
}

/// One hour after the checkpoint slot.
fn now(chain: &Chain) -> u64 {
    (chain.cfg)().slot_start_ms(chain.slot) + 3_600_000
}

fn run_on(
    chain: &Chain,
    cfg: &ChainConfig,
    endpoints: Vec<Responses>,
    rpcs: Vec<String>,
    now_ms: u64,
) -> Result<eth_lc_core::BootstrapInput, CheckpointError> {
    let urls: Vec<String> = endpoints.into_iter().map(serve).collect();
    verify_new_checkpoint(
        cfg,
        &urls,
        &rpcs,
        parse_root(chain.root).unwrap(),
        now_ms,
        &CheckpointPolicy::default(),
    )
}

fn run(
    endpoints: Vec<Responses>,
    now_ms: u64,
) -> Result<eth_lc_core::BootstrapInput, CheckpointError> {
    run_on(
        &MAINNET,
        &ChainConfig::mainnet(),
        endpoints,
        vec![rpc_for(&MAINNET)],
        now_ms,
    )
}

fn three(chain: &Chain) -> Vec<Responses> {
    vec![Responses::recorded(chain); 3]
}

#[test]
fn three_agreeing_endpoints_pass() {
    let input = run(three(&MAINNET), now(&MAINNET)).unwrap();
    assert_eq!(input.bootstrap.header.beacon().slot, MAINNET.slot);
    assert_eq!(input.execution_header_rlp, None);
}

#[test]
fn gloas_bootstrap_gets_its_execution_header() {
    let cfg = ChainConfig::sepolia();
    let input = run_on(
        &SEPOLIA,
        &cfg,
        three(&SEPOLIA),
        vec![rpc_for(&SEPOLIA)],
        now(&SEPOLIA),
    )
    .unwrap();
    assert_eq!(
        cfg.fork_at_slot(input.bootstrap.header.beacon().slot),
        ForkName::Gloas
    );
    let LightClientHeader::Gloas {
        execution_block_hash,
        ..
    } = &input.bootstrap.header
    else {
        panic!("Gloas bootstrap")
    };
    let rlp = input.execution_header_rlp.as_ref().unwrap();
    assert_eq!(eth_lc_core::crypto::keccak256(rlp), *execution_block_hash);
    let store = eth_lc_core::initialize_store(&cfg, &input).unwrap();
    assert_eq!(store.execution.block_hash, *execution_block_hash);
    assert_eq!(store.execution.number, 0xb8a4f8);

    // An execution endpoint that knows another block: refused.
    let wrong = serve_rpc(
        cfg.chain_id,
        Some(recorded(&MAINNET, "../mainnet/evidence/block.json")),
    );
    assert!(matches!(
        run_on(&SEPOLIA, &cfg, three(&SEPOLIA), vec![wrong], now(&SEPOLIA)),
        Err(CheckpointError::MissingExecutionHeader { .. })
    ));
    // A block object altered in one field: its RLP hashes to another value.
    let mut block = recorded(&SEPOLIA, "checkpoint/block.json")["result"].clone();
    block["gasUsed"] = json!("0x1");
    let altered = serve_rpc(cfg.chain_id, Some(block));
    assert!(matches!(
        run_on(
            &SEPOLIA,
            &cfg,
            three(&SEPOLIA),
            vec![altered],
            now(&SEPOLIA)
        ),
        Err(CheckpointError::MissingExecutionHeader { .. })
    ));
}

#[test]
fn instance_config_matches_each_recorded_chain() {
    for chain in [MAINNET, SEPOLIA] {
        let urls: Vec<String> = three(&chain).into_iter().map(serve).collect();
        verify_instance_config(
            &(chain.cfg)(),
            &urls,
            &[rpc_for(&chain)],
            &CheckpointPolicy::default(),
        )
        .unwrap();
    }
}

#[test]
fn instance_config_refuses_any_field_mismatch() {
    let base = ChainConfig::sepolia();
    let alter: Vec<(&str, fn(&mut ChainConfig))> = vec![
        ("chain_id", |c| c.chain_id += 1),
        ("genesis_validators_root", |c| {
            c.genesis_validators_root[0] ^= 1
        }),
        ("genesis_time", |c| c.genesis_time += 1),
        ("SECONDS_PER_SLOT", |c| c.seconds_per_slot = 6),
        ("SLOTS_PER_EPOCH", |c| c.slots_per_epoch = 8),
        ("EPOCHS_PER_SYNC_COMMITTEE_PERIOD", |c| {
            c.epochs_per_sync_committee_period = 8
        }),
        ("SYNC_COMMITTEE_SIZE", |c| c.sync_committee_size = 32),
        ("GENESIS_FORK_VERSION", |c| c.forks[0].version[0] ^= 1),
        ("CAPELLA_FORK_VERSION", |c| c.forks[3].version[3] ^= 1),
        ("ELECTRA_FORK_EPOCH", |c| c.forks[5].epoch += 1),
        ("GLOAS_FORK_EPOCH", |c| c.forks[7].epoch = u64::MAX),
    ];
    let urls: Vec<String> = three(&SEPOLIA).into_iter().map(serve).collect();
    let rpc = vec![rpc_for(&SEPOLIA)];
    for (name, f) in alter {
        let mut cfg = base.clone();
        f(&mut cfg);
        let err = verify_instance_config(&cfg, &urls, &rpc, &CheckpointPolicy::default())
            .expect_err(name);
        assert!(
            matches!(
                err,
                CheckpointError::ConfigMismatch { .. } | CheckpointError::GenesisMismatch { .. }
            ),
            "{name}: {err}"
        );
    }
    // One endpoint that disagrees on one key is enough to refuse.
    let mut other = Responses::recorded(&SEPOLIA);
    other.spec["data"]["FULU_FORK_EPOCH"] = json!("272641");
    let urls: Vec<String> = vec![
        Responses::recorded(&SEPOLIA),
        Responses::recorded(&SEPOLIA),
        other,
    ]
    .into_iter()
    .map(serve)
    .collect();
    assert!(matches!(
        verify_instance_config(&base, &urls, &rpc, &CheckpointPolicy::default()),
        Err(CheckpointError::ConfigMismatch { field, .. }) if field == "FULU_FORK_EPOCH"
    ));
    // No execution endpoint answers.
    let urls: Vec<String> = three(&SEPOLIA).into_iter().map(serve).collect();
    assert!(matches!(
        verify_instance_config(
            &base,
            &urls,
            &["http://127.0.0.1:9".into()],
            &CheckpointPolicy::default()
        ),
        Err(CheckpointError::TooFewEndpoints { .. })
    ));
}

#[test]
fn one_endpoint_fails() {
    let r = Responses::recorded(&MAINNET);
    assert!(run(vec![r.clone(), r.clone()], now(&MAINNET)).is_ok());
    assert!(matches!(
        run(vec![r], now(&MAINNET)),
        Err(CheckpointError::TooFewEndpoints {
            answered: 1,
            required: 2
        })
    ));
}

#[test]
fn disagreeing_bootstrap_fails() {
    let r = Responses::recorded(&MAINNET);
    let mut other = r.clone();
    other.bootstrap["data"]["header"]["beacon"]["proposer_index"] = Value::String("1".into());
    assert!(matches!(
        run(vec![r.clone(), r, other], now(&MAINNET)),
        Err(CheckpointError::BootstrapMismatch { .. })
    ));
}

#[test]
fn non_finalized_root_fails() {
    let r = Responses::recorded(&MAINNET);
    let mut other = r.clone();
    other.header["finalized"] = Value::Bool(false);
    assert!(matches!(
        run(vec![r.clone(), other, r], now(&MAINNET)),
        Err(CheckpointError::NotFinalized { .. })
    ));
}

/// Lodestar's form: `finalized: false` on the header, the root named by the
/// endpoint's finalized checkpoint.
#[test]
fn root_named_by_finality_checkpoints_passes() {
    let r = Responses::recorded(&MAINNET);
    let mut lodestar = r.clone();
    lodestar.header["finalized"] = Value::Bool(false);
    lodestar.finality = Some(json!({"data": {"finalized": {"epoch": "1", "root": MAINNET.root}}}));
    assert!(run(vec![r.clone(), lodestar.clone()], now(&MAINNET)).is_ok());
    let mut other = lodestar;
    other.finality = Some(
        json!({"data": {"finalized": {"epoch": "1", "root": format!("0x{}", "11".repeat(32))}}}),
    );
    assert!(matches!(
        run(vec![r, other], now(&MAINNET)),
        Err(CheckpointError::NotFinalized { .. })
    ));
}

#[test]
fn wrong_genesis_root_fails() {
    let r = Responses::recorded(&MAINNET);
    let mut other = r.clone();
    other.genesis["data"]["genesis_validators_root"] =
        Value::String(format!("0x{}", "11".repeat(32)));
    assert!(matches!(
        run(vec![other, r.clone(), r], now(&MAINNET)),
        Err(CheckpointError::GenesisMismatch { .. })
    ));
}

#[test]
fn bad_committee_branch_fails() {
    let mut r = Responses::recorded(&MAINNET);
    r.bootstrap["data"]["current_sync_committee_branch"][2] =
        Value::String(format!("0x{}", "22".repeat(32)));
    assert!(matches!(
        run(vec![r.clone(), r.clone(), r], now(&MAINNET)),
        Err(CheckpointError::Initialize(
            eth_lc_core::Error::InvalidCurrentCommitteeBranch
        ))
    ));
}

#[test]
fn age_of_257_epochs_fails() {
    let epoch_ms = 32 * 12 * 1000;
    let at = |epochs: u64| ChainConfig::mainnet().slot_start_ms(MAINNET.slot) + epochs * epoch_ms;
    assert!(run(three(&MAINNET), at(256)).is_ok());
    assert!(matches!(
        run(three(&MAINNET), at(257)),
        Err(CheckpointError::TooOld { .. })
    ));
}

/// One live run against public Sepolia endpoints (network access): config,
/// Gloas checkpoint and execution header. `cargo test -- --ignored`.
#[test]
#[ignore = "network: public Sepolia endpoints"]
fn sepolia_live() {
    let cfg = ChainConfig::sepolia();
    let endpoints = vec!["https://lodestar-sepolia.chainsafe.io".to_string()];
    let rpcs = vec!["https://ethereum-sepolia-rpc.publicnode.com".to_string()];
    let root = eth_lc_host::http::get_json(&endpoints[0], "/eth/v1/beacon/headers/finalized")
        .unwrap()["data"]["root"]
        .as_str()
        .map(|r| parse_root(r).unwrap())
        .unwrap();
    let policy = CheckpointPolicy {
        min_endpoints: 1,
        ..Default::default()
    };
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let input = verify_new_checkpoint(&cfg, &endpoints, &rpcs, root, now_ms, &policy).unwrap();
    let slot = input.bootstrap.header.beacon().slot;
    assert_eq!(cfg.fork_at_slot(slot), ForkName::Gloas);
    assert!(input.execution_header_rlp.is_some());
    let store = eth_lc_core::initialize_store(&cfg, &input).unwrap();
    println!(
        "sepolia live: root=0x{} slot={slot} execution_block={}",
        hex::encode(root),
        store.execution.number
    );
}

#[test]
fn stall_status_at_the_ws_period() {
    let cfg = ChainConfig::mainnet();
    let store = |slot| Store {
        finalized: BeaconBlockHeader {
            slot,
            ..Default::default()
        },
        execution: Default::default(),
        current_committee_root: [0; 32],
        next_committee_root: None,
    };
    let slot = 1902 * 8192 + 100;
    let s = store(slot);
    let stale = cfg.slot_start_ms(slot) + cfg.weak_subjectivity_period * 1000;
    assert_eq!(
        stall_status(&cfg, &s, stale - 1),
        StallStatus::Live { remaining_ms: 1 }
    );
    assert_eq!(stall_status(&cfg, &s, stale), StallStatus::Stalled);
    // A later finalized slot moves the bound by the same amount.
    assert_eq!(
        stall_status(&cfg, &store(slot + 1), stale),
        StallStatus::Live {
            remaining_ms: 12_000
        }
    );
}
