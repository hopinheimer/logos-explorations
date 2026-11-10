# eth-lc

Ethereum light-client crates for RISC Zero guests, written from the specs:

| Crate | Role |
|---|---|
| [`eth-lc-core`](eth-lc-core/README.md) | Guest code: sync protocol (Capella through Gloas), execution anchor, MPT claims. `no_std` + `alloc`. |
| [`eth-lc-host`](eth-lc-host/README.md) | Host code: Beacon API and SSZ decoding per fork, chain directories, key hints, checkpoint checks, evidence, synthetic test data. |

Spec sources: consensus-specs tag `v1.7.0-beta.4`; Yellow Paper (App. B, App. D,
4.3, 4.4.1); EIP-1186, EIP-2718, EIP-2930, EIP-1559, EIP-4844, EIP-7702.

## Versioning

Releases are git tags `eth-lc-vX.Y.Z` on this repository. While at 0.x, a
change of a borsh layout (`eth-lc-core/tests/borsh_golden.rs`) or of the
pinned preset bumps the minor version. The chain identity (chain id, genesis,
fork schedule) comes from each instance's `Init`, so one program serves
mainnet, Sepolia, Hoodi and any other chain of the mainnet preset. A new fork
schedule for a chain (for example a real Gloas epoch on mainnet) is a new
instance with an `Init` that carries it. A fork after Gloas needs a new crate
version and a new program.

## Using the crates

In-repo consumers use path dependencies. Other projects use a git dependency
on a tag:

```toml
[dependencies]
eth-lc-core = { git = "ssh://git@github.com/hu55a1n1/logos-explorations", tag = "eth-lc-v0.1.0", default-features = false }
```

```console
export CARGO_NET_GIT_FETCH_WITH_CLI=true   # private repository: cargo uses your git credentials
```

Cargo finds the crate inside the nested `eth-lc/` workspace by its package name.

### Accelerated crypto

`eth-lc-core` depends on the RISC Zero forks of `blst`
(`v0.3.16-risczero.0`), `sha2` (`sha2-v0.10.8-risczero.0`) and `tiny-keccak`
(`tiny-keccak/v2.0.2-risczero.0`) by git tag. The forks take their accelerated
paths on `target_os = "zkvm"`, so the core's own hashing and BLS accelerate
with a patch-free consumer manifest.

- Other crates in your graph that use crates.io `sha2` or `tiny-keccak` still
  need your own `[patch.crates-io]` entry to accelerate. Check with
  `cargo tree -i sha2 --target all`.
- `blst` declares `links = "blst"`: one `blst` source per graph. If your graph
  also uses crates.io `blst`, patch it to the same tag so both resolve to one
  package:

```toml
[patch.crates-io]
blst = { git = "https://github.com/risc0/blst", tag = "v0.3.16-risczero.0" }
```

### Building a guest

Toolchain build (rzup): see `rfp-021/e1/justfile`, recipe `e1b-elf`, for the
flags and the RISC-V C toolchain that `blst` needs.

Docker build (`cargo risczero build`, builder `r0.1.91.1`): the container sees
only the guest's directory tree and ignores paths named `target`, `tmp`,
`Dockerfile`, `.git` and `node_modules`. Vendor the dependencies and adjust
three things:

```console
cd guest
cargo update -p cc --precise 1.1.31          # newer cc ships src/target/, which the builder ignores
cargo vendor --versioned-dirs vendor > vendor-config.toml
mkdir -p .cargo && sed 's|directory = ".*vendor"|directory = "vendor"|' vendor-config.toml > .cargo/config.toml
# Drop ignored non-source files from the vendor checksums (for example num_cpus' ci Dockerfile).
python3 - <<'PY'
import glob, json
ignored = {"Dockerfile", ".git", "node_modules", "target", "tmp"}
for f in glob.glob("vendor/*/.cargo-checksum.json"):
    d = json.load(open(f))
    d["files"] = {k: v for k, v in d["files"].items() if not set(k.split("/")) & ignored}
    json.dump(d, open(f, "w"))
PY
# The git package of blst builds its C sources from the repository root; vendor holds the crate only.
blst_repo=$(ls -d ~/.cargo/git/checkouts/blst-*/7d1fc3e)   # risc0/blst at v0.3.16-risczero.0
mkdir -p vendor/blst-0.3.16/blst && cp -R "$blst_repo"/{src,build,bindings} vendor/blst-0.3.16/blst/
RISC0_DOCKER_CONTAINER_TAG=r0.1.91.1 cargo risczero build --manifest-path Cargo.toml
```

This recipe produced a working ELF for the README guest example. Its update
cycles were 2.9% above the toolchain build.

The `eth-lc-core` README holds a complete guest example (LEZ v0.4 actor with
`Init`, `Update` and `Attest`).

### Host example

```rust
use eth_lc_core::{apply_update, initialize_store};
use eth_lc_host::ChainDir;

let dir = ChainDir::load("eth-lc/vectors/mainnet")?;
let mut store = initialize_store(&dir.cfg, &dir.bootstrap)?;
for update in dir.all_updates() {
    let input = dir.update_input(&store, update)?; // committee + key hints
    store = apply_update(&dir.cfg, &store, &input)?;
}
```

## Trust anchor: config and checkpoint

An instance's `Init` carries two trust inputs: the chain config and the
checkpoint. The core pins the preset and checks the chain identity for
structure only, so the operator verifies the identity values against the
chain:

- `verify_instance_config(cfg, beacon_endpoints, rpc_endpoints, policy)`
  compares the genesis validators root, the genesis time, the preset fields
  and every fork version and epoch (phase0 through Gloas) with each Beacon
  API endpoint's `/eth/v1/beacon/genesis` and `/eth/v1/config/spec`, and the
  chain id with each execution endpoint's `eth_chainId`. Every answering
  endpoint must agree.
- `verify_new_checkpoint` runs `verify_instance_config` first, then checks the
  checkpoint (below).

## Stalls and migration

An instance stalls when a full sync committee period passes with zero
qualifying updates. A stalled instance stays readable: claims against the
headers it recorded keep working. Updates on it are refused.

Detect:

- Call `eth_lc_host::checkpoint::stall_status(cfg, &store, now_ms)` on the instance store.
- Alert when `remaining_ms` falls under 6 hours. At `Stalled`, LEZ refuses further updates to the instance.

When to switch: at `Stalled`, or earlier if you expect the period to end
before a qualifying update arrives.

Migrate:

1. Take the current finalized root from one endpoint.
2. Run `verify_new_checkpoint` against at least three independent endpoints
   (`just verify-checkpoint`, or `fetch_chain verify-checkpoint --endpoint URL ... --rpc URL`).
   It verifies the chain config and the checkpoint together.
   Choose endpoints run by independent parties: the check confirms agreement;
   independence is your responsibility.
3. Deploy a new instance and send `Init` with the returned `BootstrapInput`.
4. Point consumers at the new instance id. Keep the old id for claims against
   headers the old instance recorded.

`verify_new_checkpoint` accepts a root only when `verify_instance_config`
accepts the config; every answering endpoint reports the root as canonical
and finalized and serves the same bootstrap; for a Gloas-variant bootstrap
header, an execution endpoint serves the RLP header of its
`execution_block_hash` (checked by Keccak-256); `initialize_store` succeeds
locally; and the checkpoint is at most 256 epochs old (the floor of the
weak-subjectivity period). Default mainnet endpoints:
`https://ethereum-beacon-api.publicnode.com`,
`https://lodestar-mainnet.chainsafe.io`,
`http://unstable.mainnet.beacon-api.nimbus.team`, and
`https://ethereum-rpc.publicnode.com` for execution. Sepolia
(`--network sepolia --min 2`): `https://lodestar-sepolia.chainsafe.io`,
`http://unstable.sepolia.beacon-api.nimbus.team`, and
`https://ethereum-sepolia-rpc.publicnode.com`. The Nimbus endpoints answer
over plain http only, so a network path can alter their answers. They are
weaker independent sources than the https ones. Add your own node to the set.

## Tests

```console
cd eth-lc
just test            # unit tests, cross-checks, recorded mainnet and Sepolia chains, synthetic cases
just spec-tests      # consensus-specs light-client vectors (downloads about 1.4 GB once)
just eth-tests       # ethereum/tests TrieTests
just lc-test         # integration tests with output
just live-test       # a live Sepolia Gloas checkpoint (network)
just consumer-check  # README guest example as a git dependency, built and run under the LEZ executor
just vectors         # re-record the mainnet and Sepolia chain-dirs and the evidence
```

Conformance at consensus-specs `v1.7.0-beta.4` (`just spec-tests`):

- `sync`: all 33 minimal-preset cases from Capella through Gloas (129 steps;
  the pin ships sync vectors for the minimal preset only). The test-only spec store
  passes every step. The strict store runs on every case, Gloas bootstraps
  included: 56 accepted steps, each equal to the spec store (finalized header,
  both committee roots, execution anchor); 10 accept-rule refusals, each
  justified by an independent check; 15 steps after the spec force updates
  of the 5 `light_client_sync` cases, checked against the strict model.
  Gloas anchors use execution preimages that the test derives (from payload
  headers in the vectors, or from the genesis payload of the pyspec test
  helper) and checks by Keccak-256.
- `single_merkle_proof`: 52 proofs; every leaf index equals the core gindex.
- ethereum/tests `TrieTests` (`just eth-tests`): 5 files.

Recorded data:

- `vectors/mainnet/`: chain-dir for periods 1902 to 1905, a finality update,
  claim evidence, a checkpoint, the Beacon API config and genesis.
- `vectors/sepolia/`: chain-dir for periods 1376 to 1380 across the Gloas fork
  (epoch 353,024, the first slot of period 1379) with the RLP execution header
  of every finalized header, a Gloas checkpoint, the Beacon API config and
  genesis. `tests/sepolia.rs` replays it with real BLS, and replays its Fulu
  objects again after the Gloas upgrade (`fork.md`) to the same stores.
- `vectors/hoodi/`: the Beacon API config and genesis (Gloas unscheduled).
