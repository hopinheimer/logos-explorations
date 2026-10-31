//! E1b: write each real mainnet update step as the borsh input the E1b guest
//! decodes: (cfg, store, update, committee, witness).
use sextant_core::lc::AggMode;
use sextant_host::{mainnet, mainnet_steps, witness};

fn main() {
    let out = std::env::args().nth(1).expect("output dir");
    std::fs::create_dir_all(&out).unwrap();
    let m = mainnet();
    for (i, (store, u, committee)) in mainnet_steps(&m).into_iter().enumerate() {
        let w = witness(&committee, &u.bits, AggMode::Subtract);
        let handoff = u.next_committee.is_some();
        std::fs::write(format!("{out}/store-{i}.bin"), borsh::to_vec(&store).unwrap()).unwrap();
        let bytes = borsh::to_vec(&(m.cfg.clone(), store, u, committee, w)).unwrap();
        let path = format!("{out}/step-{i}.bin");
        std::fs::write(&path, &bytes).unwrap();
        println!("{path} bytes={} handoff={handoff}", bytes.len());
    }
}
