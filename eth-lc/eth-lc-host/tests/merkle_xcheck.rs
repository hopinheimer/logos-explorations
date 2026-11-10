//! Cross-check of core SSZ roots against `tree_hash` on the host containers.

use alloy_primitives::{Address, B256, U256};
use eth_lc_core::{ChainConfig, LightClientHeader};
use eth_lc_host::forks::{
    self, Bootstrap, ExecutionPayloadHeaderCapella, HeaderDeneb, Preset, Wire,
};
use ssz::Decode;
use ssz_types::typenum::{U512, U6};
use ssz_types::{FixedVector, VariableList};
use tree_hash::TreeHash;

fn bootstrap_bytes() -> Vec<u8> {
    std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../vectors/mainnet/bootstrap.ssz"
    ))
    .unwrap()
}

#[test]
fn mainnet_bootstrap_roots() {
    let bytes = bootstrap_bytes();
    let host = Bootstrap::<HeaderDeneb, U512, U6>::from_ssz_bytes(&bytes).unwrap();
    let cfg = ChainConfig::mainnet();
    let raw = forks::decode_bootstrap(
        eth_lc_core::ForkName::Fulu,
        Preset::Mainnet,
        Wire::Ssz(&bytes),
    )
    .unwrap();
    let core = forks::to_core_bootstrap(&cfg, &raw).unwrap();
    assert_eq!(
        core.header.beacon().hash_tree_root(),
        host.header.beacon.tree_hash_root().0
    );
    assert_eq!(
        core.current_sync_committee.hash_tree_root(),
        host.current_sync_committee.tree_hash_root().0
    );
    let LightClientHeader::Deneb { execution, .. } = &core.header else {
        panic!("Fulu bootstrap is Deneb-shaped")
    };
    assert_eq!(
        execution.hash_tree_root().unwrap(),
        host.header.execution.tree_hash_root().0
    );
    assert_eq!(
        eth_lc_core::get_lc_execution_root(&cfg, &core.header),
        host.header.execution.tree_hash_root().0
    );
}

#[test]
fn capella_payload_root_with_varied_fields() {
    for (extra, fee) in [
        (vec![], 0u64),
        (vec![1u8; 31], 7),
        (vec![0xab; 32], u64::MAX),
    ] {
        let host = ExecutionPayloadHeaderCapella {
            parent_hash: B256::repeat_byte(1),
            fee_recipient: Address::repeat_byte(2),
            state_root: B256::repeat_byte(3),
            receipts_root: B256::repeat_byte(4),
            logs_bloom: FixedVector::new(vec![5u8; 256]).unwrap(),
            prev_randao: B256::repeat_byte(6),
            block_number: 7,
            gas_limit: 8,
            gas_used: 9,
            timestamp: 10,
            extra_data: VariableList::new(extra.clone()).unwrap(),
            base_fee_per_gas: U256::from(fee) << 100usize,
            block_hash: B256::repeat_byte(11),
            transactions_root: B256::repeat_byte(12),
            withdrawals_root: B256::repeat_byte(13),
        };
        let core = eth_lc_core::ExecutionPayloadHeaderCapella {
            parent_hash: [1; 32],
            fee_recipient: [2; 20],
            state_root: [3; 32],
            receipts_root: [4; 32],
            logs_bloom: [5; 256],
            prev_randao: [6; 32],
            block_number: 7,
            gas_limit: 8,
            gas_used: 9,
            timestamp: 10,
            extra_data: extra,
            base_fee_per_gas: (U256::from(fee) << 100usize).to_le_bytes::<32>(),
            block_hash: [11; 32],
            transactions_root: [12; 32],
            withdrawals_root: [13; 32],
        };
        assert_eq!(core.hash_tree_root().unwrap(), host.tree_hash_root().0);
    }
}
