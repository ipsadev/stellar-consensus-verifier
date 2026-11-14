# Security model

This crate verifies, from untrusted bytes, that a quorum of the validators you trust externalized a particular Stellar ledger, and that a particular router state root belongs to that ledger. This document states what is trusted, what is not, the order the pieces must be called in, and exactly what each step does and does not establish. It is the reference an auditor should read first.

A passing verification is only as strong as two things you supply and this crate cannot check for you: the trust root you chose, and the assumption that the validators in it are intertwined with the network under quorum intersection. Everything below is relative to those.

## Trusted inputs

These are the values you must obtain out of band and are trusting by assumption. The crate treats them as ground truth.

- The network identifier (`network_id`), which fixes the network and is folded into every signature check so a message from one network cannot be replayed on another.
- Your local quorum set (the `local: &QuorumSet` passed to the commit checks). This is your trust root: the validators you trust and the thresholds among them. The crate never derives this from the archive, because that would let whoever writes the archive decide who counts.
- An anchor ledger hash you already trust, when using `chain::walk_back` to reach an older ledger.
- The router contract identifier and the root event topic (`router_contract_id`, `root_event_topic` in `results::Inputs`), which say whose published state root you are willing to believe.

## Untrusted inputs

Everything else is attacker-controlled and is checked before it is believed: all SCP envelopes, all quorum-set preimages, all ledger-header bytes, all transaction sets, all transaction-result pairs, and anything read from a history archive. No count or hash read from these is trusted until a step below authenticates it.

## Required call order

The `verify` module is the front door and the recommended way to use this crate. It carries trust in the types: each step takes the value the previous step produced and returns a new one whose fields are private, so holding a value is proof the earlier checks ran. The pipeline is `authenticate` → `AuthenticatedBatch`, `confirmed_value` → `ConfirmedValue`, `bind_header` → `ValueBoundHeader`, then either `bind_successor` or `walk_back` → `AuthenticatedHeader`, then `verify_router_root` → `VerifiedRouterRoot`. `verify_consensus` and `verify_header` are convenience wrappers for the first steps, and `confirmed_value` enforces the strict trust-root check (`local.check_sane(true)`).

The two header types encode the `bind_header` rule. A `ValueBoundHeader` has its transaction set, close time and upgrades authenticated, but not its `tx_set_result_hash` or `bucket_list_hash`, because validators sign the scpValue, not the whole header. Only an `AuthenticatedHeader` — whose `ledger_hash` is pinned by the next slot (`bind_successor`) or by the chain (`walk_back`) — has every field authenticated, and only an `AuthenticatedHeader` can be passed to `verify_router_root`. A caller therefore cannot extract a router state root from a header whose results field was never authenticated; the code will not compile.

The individual steps below are what these functions do internally. They wrap the primitives under `primitives`, grouped by what each guarantees: `primitives::scp` (envelope, authentication, commit, quorum acceptance), `primitives::stellar` (header, txset, chain), `primitives::execution` (results, router_event), and `primitives::analysis` (quorum-split checks that do not affect acceptance). These are available for advanced callers who assemble the pipeline themselves and take on the responsibilities under "Known gaps".

The steps must run in this order. Each one is sound only if the steps before it succeeded, and each establishes strictly less than it may appear to.

1. `envelope::authenticate(network_id, slot_index, envelopes_xdr, quorum_sets_xdr) -> Vec<Authenticated>`.
   - Establishes: every returned statement carries a valid ed25519 signature over the right network and slot, and each supplied quorum-set preimage genuinely hashes to the value its validator named. A validator whose quorum set cannot be matched is dropped, not trusted.
   - Does not establish: that any value won consensus, or that the evidence is complete. It is the only constructor of `Authenticated`; nothing downstream should accept hand-built evidence.

2. `commit::confirmed_value(local, &[Authenticated]) -> Vec<u8>`.
   - Establishes: a quorum of your trust root confirmed-committed exactly one value, and returns that value's bytes (the externalized `scpValue`). If two different values both reach confirm-commit it returns fork evidence instead.
   - Does not establish: any connection to a `LedgerHeader`. The return is a bare value, not a verified ledger.

3. Bind the value to a header. Decode the header with `ledger::LedgerHeader::decode`, then require `header.scp_value_bytes == confirmed_value(...)`.
   - Establishes: this specific header carries the exact value consensus agreed on, so `header.ledger_hash` is the hash of the ledger the quorum externalized.
   - Does not establish: that the header's other fields are authentic. `tx_set_result_hash` and `bucket_list_hash` are inside the signed value only indirectly; binding the value authenticates the header's identity, not every field. To trust those fields you additionally need the next ledger's `previous_ledger_hash` to equal `sha256(header)` (the next-slot binding), or you must reach this header by walking back from a recent anchor you trust (step 4).
   - This binding step currently lives only in the test suite (`tests/ledger_mainnet.rs`), not in `src/`. Until it is a function here, it is the caller's responsibility, and it is the single easiest step to forget. See "Known gaps".

4. `chain::walk_back(anchor_seq, anchor_previous_ledger_hash, headers_descending, target_seq) -> ChainedLedger`, optional.
   - Establishes: the target ledger is a genuine ancestor of the anchor, by following the `previous_ledger_hash` links down from a ledger you already trust. Because of hash chaining, one recent trusted ledger certifies its whole history.
   - Does not establish: anything about the anchor itself. You must have trusted the anchor by some other means (typically steps 1 through 3 on a recent ledger).

5. `results::verify_state_root(&Inputs) -> [u8; 32]`, optional.
   - Establishes: the supplied result pairs hash to the header's `tx_set_result_hash`, the named transaction succeeded, and the router contract you named emitted exactly one state-root event, whose 32-byte payload is returned.
   - Does not establish: that `tx_set_result_hash` itself is authentic. This step trusts the hash you pass in, so it is only as sound as the header field feeding it, which must have been authenticated per the caveat in step 3.

## What a full run proves, and what it does not

A full run proves: a quorum of the validators you chose externalized this ledger, this header is that ledger, it descends from an anchor you trust, and this router state root was published by it.

It does not prove: that your trust root is the right one, that quorum intersection holds, or that the network has not partitioned beneath your chosen validators. Those are assumptions, not results, and no light client can check them for itself.

## Known gaps and caller responsibilities

These are current, deliberate limitations. Treat each as a thing the caller must handle until it is addressed in `src/`.

The following are addressed when you use the `verify` module, and remain the caller's responsibility only when reaching for the raw primitives:

- The value-to-header binding is done by `verify::bind_header`, which returns a `ValueBoundHeader`. Callers using the raw `envelope::authenticate`/`commit::confirmed_value` primitives must perform the `scp_value_bytes` comparison themselves.
- `verify::verify_router_root` takes an `AuthenticatedHeader`, not a raw hash, so trust is carried in the type. The raw `results::verify_state_root` and `chain::walk_back` still take plain `&[u8; 32]` hashes with no evidence of origin; a caller using them directly must feed only authenticated hashes.
- `LedgerHeader` has all-public fields, so a bare header can be constructed or edited. The `verify` types wrap it behind private fields, and `verify_router_root` refuses anything but an `AuthenticatedHeader`; the bare type is only safe through that layer.
- `verify::confirmed_value` runs the strict `local.check_sane(true)` and refuses an unsound trust root. The raw `commit::confirmed_value` primitive does not.
- `AuthenticatedBatch` and `ConfirmedValue` carry their network identifier and slot, so the typed pipeline cannot combine evidence from different networks or slots. The raw `Authenticated` does not carry this context, so callers mixing raw batches must check it themselves.

These remain open regardless of which layer you use:

- `verify_signature` uses ed25519-dalek's strict, cofactorless verification, which rejects non-canonical encodings and small-order public keys. stellar-core verifies through libsodium, which uses the cofactored equation, so for an adversarial signature the two can disagree: this crate may reject a cofactored or small-order signature that stellar-core accepts, but it never accepts one stellar-core rejects. That is conservative (a liveness, not a safety, difference) and only arises for malformed signatures no honest validator produces; edge cases are covered in `tests/signature.rs`. A live differential against a compiled stellar-core, like the quorum oracle, is the complete check and is still to be built.

## The one assumption behind all of it

Safety rests on quorum intersection among well-behaved nodes, and on your being intertwined with the network under the trust root you chose. This crate cannot verify either. A passing run says the validators you trusted signed this ledger; it does not say you trusted the right validators.
