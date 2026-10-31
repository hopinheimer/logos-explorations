# RFP-021 context load (2026-11-01)

Status: context only. Discussion, plan and experiments come next.
Sources are cloned in the session scratchpad (`src/rfp`, `src/lez`, `src/sextant`, `src/cs`).

## 1. Hard facts

### Deadline and process
- RFP-021 is open. README deadline: `10/11/26`. Proposals arrived on Oct 16, 25 and 29, so this reads as **10 Nov 2026**. About 9 days remain.
- Reviewers: `jzaki`, `hackyguru` (Logos). They review weekly and answer in about 14 days.
- Tier M. Expected effort: 8 to 12 weeks. Audit lead time sits outside that.
- The RFP author drafts with Claude (commit trailers). The text is precise and every FURPS item is testable.

### RFP history that matters (git log of the RFP file)
- `8b8086a8` (2026-08-27): "verify the light client on-chain, drop the off-chain prover".
  Their reason: "LEZ execution is already proven, so a second proof layer over the same check would add a translation step and its own audit surface without strengthening the guarantee."
  F.1 now ends with: "The module checks the sync-committee aggregate itself."
- `3a15912a` (2026-10-12): delivery target moved to **LEZ testnet 0.4**.
- `25a94809`: design decision log is a hard requirement (S.11).
- Last edits (Oct 13 to 14) are legal wording only.

### LEZ facts (read from `logos-execution-zone` at `952bd6dd`, 2026-10-30)
- `v0.4.0-rc1` was tagged on 2026-10-29. It contains PR #935 "transactional actors with side-effects" and PR #985 "pptx fees with in-proof reserve and refund, tx dry-runs".
- Testnet 0.4 is expected at the end of November (per the Tessera proposal, citing the roadmap).
- **v0.4 is an actor model.** A program handles one message for one actor `(account_id, program_account_id)`. It sees only its own `pre_state`. It reads another actor by sending `ReadState` and gets a `StateReply` back as a new sync message. Multi-step logic keeps "pending" continuations in its own state (`flash_swap_initiator.rs`). v0.3 plan/apply programs do not port by a thin shell swap.
- **Gas caps are per block.** `MAX_GAS_EXEC = 10,000,000` and `TARGET_GAS_EXEC = 5,000,000` (`lez/programs/fee/core/src/market.rs`). `accumulate_exec_gas` sums every transaction in the block against `MAX_GAS_EXEC` (`lez/chain_state/src/apply.rs`). Storage gas: `MAX_GAS_STOR = 1,000,000` bytes per block.
- **A private transaction costs a flat verification charge.** `PRIVATE_VERIFY_GAS = 409,764` exec gas and `PRIVATE_GAS_STOR = 224,063` bytes (succinct receipt plus 512-byte padded payload), whatever the private part computed.
- Private program executions are proven by `prove_session` with no session limit. The privacy circuit calls `env::verify(image_id, transition)` on each one. The sequencer verifies only the circuit receipt and the image claims (`circuit/mod.rs`, `privacy_preserving_circuit/src/main.rs`).
- A private transaction publishes: the boundary steps (messages between private and public actors), sealed async messages, nullifiers and commitments, program image claims, validity windows, fee data. A private root call stays hidden (`public_root: None`).
- A private sender can be presented `Canonical` or `Blinded`. Program images can be `Disclosed`, `Undisclosed` (membership in the set of immutable headers) or `Shadow`.
- Public actors touched by a private transaction are listed in `PublicExecutionContext.actors`. So a private consumer that reads a header record reveals which record it read.
- `risc0-zkvm 3.0.5`. Tessera reports private proving at 19.2 s on an NVIDIA L4 against 626 s on a 16-thread CPU.
- SPEL (latest `v0.7.0-rc.3`) supports neither LEZ v0.3 nor v0.4 (spel#291 open). Every serious proposal ships a SPEL-format IDL by hand with a drift check.

### Ethereum facts
- Gloas (ePBS, EIP-7732) is live on Sepolia (2026-10-06) and Hoodi (2026-10-26). Mainnet has no date.
- Gloas `LightClientHeader` drops `execution` and carries `execution_block_hash`, proven at gindex 2856 = `signed_execution_payload_bid.message.parent_block_hash`. State gindices move (EIP-7688): finalized root 735, current committee 2945, next committee 2946.
- A light-client store needs at least one update per sync-committee period (27.3 h) to follow handoffs.
- The "Logos Ethereum core module" is `logos-co/logos-verified-proxy-module` (Nimbus `libverifproxy`). It does not expose light-client objects or raw `eth_getProof` nodes. Its C ABI accepts host-supplied beacon and execution transports, which is the upstream extension point (Sextant's analysis, `docs/ETH-CORE-MODULE.md`).

## 2. What reviewers reward (evidence from RFP-020 and RFP-003)

- RFP-020 winner: Kanon by Equilibrium (#117). Traits:
  - An established organisation with linked, audited delivery history.
  - "We checked each dependency against the live runtime" table.
  - One verification core behind a swap trait, so a precompile is a local change.
  - M0 = a 1-week cost baseline reviewed with Logos before the build.
  - Full traceability matrix.
  - Took the servicing SLA in full (operate feeds to March 2028) inside the budget.
  - Budget "to be agreed".
- Rejections cite "strong proposals from several teams", "insufficient details", unverifiable history (#114).
- Logos added a servicing SLA to RFP-020 mid-review (PR #107). Expect the same pressure here: someone runs the update operator for a defined period.
- RFP-003 winner (#112): a re-iteration of an earlier proposal after feedback.

## 3. The three open proposals

### #224 Sextant (Antumbra, 2 people) - the one to beat
- Prototype `edenbd1/lez-sextant` (Rust, about 6.5k lines). v0.3 plan/apply program, deployed on the public v0.3 testnet, real mainnet, Sepolia and Hoodi vectors, Gloas handled, CI-reproducible builds, an on-chain verifier script, demo video, frequent updates.
- Measurements (RISC0 cycles, mainnet period 1882):
  - pairing check: blst accelerated 7.85M; zkcrypto accelerated 19.7M.
  - signing key: aggregate minus non-signers 0.45M; full decompression 234M.
  - whole update with handoff: 12.6M (blst). Finality only: 11.2M.
  - consumer log attestation: 56k cycles, 48 s proof on an M4 Pro CPU; storage slot: 188k cycles.
- Design: 3 public transactions per update (`Begin` 5.3M, `Miller` 4.2M, `Finish` 3.8M) joined by a job account; immutable 120-byte header records per verified slot; consumer calls `Attest` as a chained call.
- Price: $40k build (7 weeks) plus a $40k audit allowance paid by Logos. Post-delivery: 12 months, runs one instance.

Weak points:
1. **Wrong runtime generation.** Everything runs on v0.3 plan/apply. RFP S.1 targets 0.4 (actor model). Their plan budgets the port inside M4 as "a 320-line shell". The consumer pattern changes too (message and reply continuations in place of chained calls with return).
2. **Per-block cost.** They compare each step with "the 10M cap" as if it were per transaction. In LEZ the cap is per block. One update consumes about 126% of one block's total execution capacity, spread over 3 blocks. Hourly freshness costs about 28 full blocks a day. Under load the 1559-style base fee rises, and updates compete with all user traffic.
3. **Job state machine.** A 3-transaction protocol with a job account adds audit surface and new states (abandoned jobs, step races).
4. **Private consumer path under v0.4.** If a private consumer sends the `Attest` query to a public actor, the query crosses the boundary and is published. Their D5 ("chained call vs inspect guard") predates the actor model.
5. **Native ETH consumer via the transaction trie** plus secp256k1 sender recovery. A transfer that arrives as an internal call (Safe, ERC-4337, EIP-7702 delegations, any contract caller) has no top-level transaction to that contract. Typed-transaction parsing also adds audit surface.
6. **Capacity.** Two people. The same team has an RFP-005 proposal (#222, Accord); if both win, this one starts about 5 weeks later.
7. **Audit allowance** of $40k for about 2 auditor-weeks may be thin for BLS, SSZ, MPT and the program.

Do not publish anything from this list that reads as a vulnerability in their code. Compete on our design, stated positively.

### #238 Fable Systems (1 person)
- No prototype, no numbers, no Gloas, no LEZ code. Generic requirement restatement. Founder background is commodity quant work. $48k. Did not consent to public use. Weak.

### #239 le-sync (Nani Plus, 1.25 FTE)
- Pipeline names copy Sextant (`begin_update`, `miller_update`, `finish_update`). Repo `cenwadike/LE-sync` was created recently (pushed 2026-10-30). No measurements. Electra and Fulu only (testnets run Gloas). Plans to store whole 512-key committees on chain. Replaces the audit with a $10k bug bounty. Says ownership passes to the Logos core team (the T&C say Logos maintains nothing). $60k. Weak.

## 4. What a winning proposal needs

Must-haves (table stakes, Sextant already has most):
- Prototype evidence with reproducible numbers, on real chain data.
- Full FURPS and VS traceability, every item mapped to a test or artifact.
- An honest answer to the central feasibility question (BLS in-program).
- Gloas-aware light client (testnets already run it).
- Reuse assessment of r0vm-helios, SP1 Helios, Helios (R.6), with audit-surface consequences.
- Audit plan with named firms and a budget line.
- Operator commitment for a period (expect a servicing ask like RFP-020 PR #107).
- Dependency check against the live runtime (v0.4, SPEL, the core module gaps).
- A credible team with linked history.

Where we can win (differentiators):
- **Native on LEZ 0.4** from day one, with the actor-model consumer pattern specified.
- **A better update path** (section 5, idea A): one transaction per update, about 20x cheaper, and no multi-step job machine.
- **A correct private consumer path** for 0.4 (idea B), measured on a laptop.
- **Sharper consumer semantics**: statement-id classes that say which facts are nullifier-safe (idea D); native ETH that works for every sender type (idea C).
- **Quantified sync-committee attack cost** and a concrete consumer defence (idea F).

## 5. Novel ideas (validation status in brackets)

### A. Prove-don't-execute: run the update in LEZ's own proven mode [validated by E1, see `e1/README.md`; node-level run pending]
Bisociation: LEZ's privacy machinery is also a compute-offload channel. The sequencer pays a flat fee to verify a private part, whatever it computed.

Mechanism:
1. The submitter sends a private root call to `Actor(own private account, LC program)` with the update material.
2. The LC program runs the full update check (BLS, branches, handoff) in that private execution. The submitter's machine proves it.
3. That private actor sends one sync message `Advance { prev_store_digest, new_store }` to the public instance actor.
4. The public instance actor accepts it only if `from_own_program()` holds and `prev_store_digest` equals its current state. Then it writes the new store and the header record.

Why it holds:
- The same deployed program bytecode checks the aggregate. The privacy circuit verifies its image (`Disclosed` claim checked by the sequencer). No separate proving system, no translation step. This matches the RFP's own reasoning in `8b8086a8`: "LEZ execution is already proven".
- `from_own_program()` is the same guarantee the native token relies on for private-to-public credits.
- The update material stays off chain. Only the proof (224 KB) and a small boundary message are posted.

Expected numbers (to measure):
| | Public 3-step (Sextant) | Proven, 1 transaction |
|---|---|---|
| Exec gas | about 12.6M + fee overhead | 409,764 + a few thousand for the public apply |
| Storage gas | update material (tens of KB) | 224,063 |
| Share of one block | about 126% exec (3 blocks) | about 4% exec, 22% storage |
| Transactions per update | 3, joined by a job account | 1 |
| Submitter hardware | none beyond LEZ gas | a prover: about 30 min CPU (estimate), minutes on a GPU |

Open risks:
- Permissionless submission now needs proving hardware. Mitigations: proving is liveness-only and delegable (no secret inputs); keep the public multi-step path available as a fallback that shares the same core. Decision for us.
- Latency: proving time adds to freshness latency (P.5).
- Must confirm in v0.4 that a private actor can message a public actor of its own program, and that `from.program_account_id` survives sender blinding.
- Reviewer framing: the RFP text says tracking "belongs on the public path". We answer the feasibility question with the public measurement (P.2, P.8 still delivered) and then show the proven path removes the need for a precompile.

### B. Private consumer path designed for the 0.4 boundary [validated by code reading; needs experiment E2]
- Run `Attest` on a private actor of the LC program: `Actor(consumer's private account, LC program)`. The query stays inside the proof. Only one `ReadState` to the public header record crosses the boundary.
- That read reveals which header record was used. Mitigation: always read the newest record and reach older blocks with historical proofs. The leak becomes "proved after time T", which the submission time already shows.
- Header records are immutable, so a private transaction computes its result before inclusion (R.11).

### C. Native ETH consumer that works for every sender [design choice]
- The reference vault records deposits in a write-once storage mapping or emits a `Deposit(sender, amount, nonce)` log from `receive()`.
- `msg.sender` inside the contract is the real sender, also for Safe, 4337 and 7702 accounts.
- No transaction-trie parsing and no secp256k1 recovery in the trusted path.

### D. Statement identifier with explicit nullifier-safety classes [design choice]
- Log statements: id over `(chain_id, block_hash, tx_index, log_index, log content)`. One id per occurrence, so it is nullifier-safe.
- State statements: id over `(chain_id, address, slot, value)`. Identical state gives identical id (F.6), so the same value at two times collides. The docs mark state ids "unsafe as a one-shot nullifier unless the slot is write-once" and show the write-once mapping pattern.

### E. Historical proofs through EIP-2935 [needs check]
- Since Prague, the history contract stores the last 8191 block hashes in its state. A storage proof under a newer verified state root gives an older block hash. An RLP header then gives its receipts root.
- This uses only keccak and MPT, works before and after Gloas, and covers about 27 h. Older blocks fall back to beacon `historical_summaries`.

### F. Quantify the sync-committee attack cost [needs computation]
- Sync-committee signatures are not slashable. The relevant attack is bribery of 342 known members, chosen about 27 h ahead.
- Produce: binomial tail for an attacker holding stake share f; bribe-cost model; consumer defence of "act only after a header signed by the next committee" (two independent committees) for high value, plus caps.

### G. Demand-driven freshness [follows from A]
- With idea A an update costs about 0.63M gas units. The consumer or its relayer can submit the update it needs. The daemon only has to guarantee one update per period. This weakens the operator-incentive problem (soft #5).

### H. Catch-up in one transaction [follows from A]
- One private execution can verify several consecutive period updates. A stalled instance resumes in one transaction (R.7).

## 6. Experiments to propose

- **E1** (decisive): on `v0.4.0-rc1`, a minimal LC program whose private actor runs a heavy check and sends `Advance` to its public instance actor. Measure exec gas and storage gas charged, then real proving time (CPU, GPU) for a real 12.6M-cycle update.
- **E2**: private consumer attest with the query on a private LC actor. Enumerate every boundary crossing and what it reveals (F.8 evidence).
- **E3**: port Sextant-equivalent BLS numbers to v0.4 (cycles for the public path, P.8 delta).
- **E4**: EIP-2935 historical proof on Sepolia post-Gloas.

## 7. Questions to settle with you
1. Team, capacity and track record we can claim.
2. Compete head-on on a build (we need a prototype on 0.4 in about 9 days), or position differently.
3. Primary update path: proven only, or proven plus a public fallback.
4. Budget posture against Sextant's $40k + $40k.
