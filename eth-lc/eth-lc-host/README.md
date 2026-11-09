# eth-lc-host

Host-side support for `eth-lc-core`.

| Module or binary | Use |
|---|---|
| `forks` | Light-client containers per fork layout (Capella, Deneb, Electra and Fulu, Gloas), from Beacon API JSON or SSZ, converted to core types. Each header becomes the core variant of the fork at its own slot. |
| `chain_dir` | `ChainDir::load(dir)`: a recorded bootstrap, period updates and a finality update; `update_input` builds the guest input. |
| `hints` | `key_hints(committee, bits)`: the uncompressed aggregate and non-signer keys. |
| `checkpoint` | `stall_status` and `verify_new_checkpoint` for new instances. |
| `evidence` | `eth_getProof` results and receipt trie proofs as `Evidence`. |
| `synthetic` | Test-key committees, consistent branches and signed updates for any supported fork. |
| `fetch_chain` | Records a mainnet chain-dir; `verify-checkpoint` checks a checkpoint against three endpoints. |
| `fetch_evidence` | Records claim evidence at the finalized block of the latest finality update. |

`forks::to_core_header` refuses a Gloas-layout header at a pre-Gloas slot:
the Gloas layout drops the payload header that the older variants carry. Updates whose attested and finalized
headers sit on both sides of the Gloas fork therefore fail to convert.
