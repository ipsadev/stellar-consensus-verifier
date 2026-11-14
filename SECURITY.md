# Security model

This crate verifies, from untrusted bytes, that a quorum of the validators you trust externalized a particular Stellar ledger, and that a particular router state root belongs to that ledger. This document states what is trusted, what is not, the order the pieces must be called in, and exactly what each step does and does not establish. It is the reference an auditor should read first.

A passing verification is only as strong as two things you supply and this crate cannot check for you: the trust root you chose, and the assumption that the validators in it are intertwined with the network under quorum intersection. Everything below is relative to those.

## Trusted inputs

These are the values you must obtain out of band and are trusting by assumption. The crate treats them as ground truth.

- The network identifier (`network_id`), which fixes the network and is folded into every signature check so a message from one network cannot be replayed on another.
- Your trust root, built with `TrustRoot::from_pinned(quorum_set_xdr, expected_fingerprint)`: the validators you trust and the thresholds among them. You pin its fingerprint out of band, so a quorum set read from the archive — pledged by the very validators being checked — cannot be passed in by mistake. `from_pinned` also checks the set is BFT-sound.
- An anchor ledger hash you already trust, when using `chain::walk_back` to reach an older ledger.
- The router contract identifier and the root event topic (`router_contract_id`, `root_event_topic` in `results::Inputs`), which say whose published state root you are willing to believe.

## Untrusted inputs

Everything else is attacker-controlled and is checked before it is believed: all SCP envelopes, all quorum-set preimages, all ledger-header bytes, all transaction sets, all transaction-result pairs, and anything read from a history archive. No count or hash read from these is trusted until a step below authenticates it.

Each of these is also bounded, so a verifier running under a gas or cycle budget cannot be forced into unbounded work: the number of envelopes (`MAX_ENVELOPES`), quorum-set preimages (`MAX_QUORUM_SETS`), transaction-result pairs (`MAX_RESULT_PAIRS`) and their total bytes (`MAX_RESULT_SET_BYTES`), transaction-set bytes (`MAX_TRANSACTION_SET_BYTES`), success-preimage bytes (`MAX_SUCCESS_PREIMAGE_BYTES`, checked before the preimage is hashed), and walk-back steps (`MAX_WALK_BACK_STEPS`) are capped, and over-limit input is refused with `InputTooLarge`. Quorum-set depth and size are already bounded by `QuorumSet::check_sane`, and the XDR decoder caps nesting. These are resource bounds, not soundness: an over-limit input could never have verified, so refusing it only avoids wasted work.

## Required call order

The `verify` module is the front door and the recommended way to use this crate. It carries trust in the types: each step takes the value the previous step produced and returns a new one whose fields are private, so holding a value is proof the earlier checks ran. The pipeline is `authenticate` → `AuthenticatedBatch`, `confirmed_value` → `ConfirmedValue`, `bind_header` → `ValueBoundHeader`, then either `bind_successor` or `walk_back` → `AuthenticatedHeader`, then `verify_router_root` → `VerifiedRouterRoot`. `verify_consensus` and `verify_header` are convenience wrappers for the first steps, and `verify_update` runs the whole update in one call. The trust root is checked for BFT-soundness once, when you build it with `TrustRoot::from_pinned`.

The two header types encode the `bind_header` rule. A `ValueBoundHeader` has its transaction set, close time and upgrades authenticated, but not its `tx_set_result_hash` or `bucket_list_hash`, because validators sign the scpValue, not the whole header. Only an `AuthenticatedHeader` — whose whole-bytes hash is pinned by the next slot's transaction set (`bind_successor`) or by the chain (`walk_back`) — has every field authenticated, and only an `AuthenticatedHeader` can be passed to `verify_router_root`. A caller therefore cannot extract a router state root from a header whose results field was never authenticated; the code will not compile.

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
   - Does not establish: that the header's other fields are authentic. `tx_set_result_hash` and `bucket_list_hash` are not covered by the signed value, so this step cannot vouch for them. A header's own `previous_ledger_hash` cannot be used to pin it either, because it too is unsigned and attacker-editable. They become trustworthy only once the header's whole-bytes hash is pinned, by `bind_successor` (step 4a) or `walk_back` (step 4b).

4a. `verify::bind_successor(header, successor_value, successor_tx_set_xdr) -> AuthenticatedHeader`.
   - Establishes: this header is ledger N in full. The successor's confirmed value fixes the next slot's `txSetHash`; the supplied transaction set must hash to it; that set's `previousLedgerHash` is the real hash of ledger N; and this header is authenticated only if its bytes hash to that. Pinning the whole-bytes hash makes `tx_set_result_hash` and `bucket_list_hash` trustworthy.
   - A successor that closed with an empty transaction set (CAP-83) carries an all-zero `txSetHash` that no transaction set hashes to, so it is rejected with `SuccessorTxSetMismatch`; authenticate a different ledger N instead.
   - Assumption: it relies on the stellar-core Herder rule that a validator only votes for a transaction set built on its own last closed ledger, so the set's `previousLedgerHash` is the hash of the ledger consensus actually extended. That is an assumption about honest validators, not a check.

4b. `verify::walk_back(anchor, headers_descending, target_seq) -> AuthenticatedHeader`, optional.
   - Establishes: the target ledger is a genuine ancestor of the anchor, by following the `previous_ledger_hash` links down from a header already pinned (step 4a). Because of hash chaining, one recent pinned ledger certifies its whole history.
   - Does not establish: anything about the anchor itself. The anchor must already be an `AuthenticatedHeader`, which only steps 4a or 4b produce.

5. `verify::verify_router_root(authenticated_header, …) -> VerifiedRouterRoot`, optional.
   - Establishes: the supplied result pairs hash to the header's `tx_set_result_hash`, the named transaction succeeded, and the router contract you named emitted exactly one contract event whose single topic is the agreed symbol, whose 32-byte payload is returned.
   - Takes only an `AuthenticatedHeader`, so the `tx_set_result_hash` it reads has been pinned by step 4a or 4b; it cannot be called on a merely value-bound header.

## What a full run proves, and what it does not

A full run proves: a quorum of the validators you chose externalized this ledger, this header is that ledger, it descends from an anchor you trust, and this router state root was published by it.

It does not prove: that your trust root is the right one, that quorum intersection holds, or that the network has not partitioned beneath your chosen validators. Those are assumptions, not results, and no light client can check them for itself.

It also does not judge freshness. A full run proves a ledger was agreed and is authentic, not that it is recent; an old but validly agreed ledger passes every check. Rejecting a stale ledger is the consuming light client's job, using the authenticated header's ledger sequence and close time.

## Known gaps and caller responsibilities

These are current, deliberate limitations. Treat each as a thing the caller must handle until it is addressed in `src/`.

The following are addressed when you use the `verify` module, and remain the caller's responsibility only when reaching for the raw primitives:

- The value-to-header binding is done by `verify::bind_header`, which returns a `ValueBoundHeader`. Callers using the raw `envelope::authenticate`/`commit::confirmed_value` primitives must perform the `scp_value_bytes` comparison themselves.
- `verify::verify_router_root` takes an `AuthenticatedHeader`, not a raw hash, so trust is carried in the type. The raw `results::verify_state_root` and `chain::walk_back` still take plain `&[u8; 32]` hashes with no evidence of origin; a caller using them directly must feed only authenticated hashes.
- `LedgerHeader` has all-public fields, so a bare header can be constructed or edited. The `verify` types wrap it behind private fields, and `verify_router_root` refuses anything but an `AuthenticatedHeader`; the bare type is only safe through that layer.
- `TrustRoot::from_pinned` checks the trust root is BFT-sound and matches the pinned fingerprint when it is built, so every `verify` entry point already holds a sound, pinned root. The raw `commit::confirmed_value` primitive takes a bare `QuorumSet` and checks neither.
- The typed values carry their network and slot end to end: `AuthenticatedBatch`, `ConfirmedValue`, `ValueBoundHeader` and `AuthenticatedHeader` all record the network, and `bind_successor` refuses a header and successor from different networks, so the pipeline cannot mix networks or slots. The raw `Authenticated` does not carry this context, so callers mixing raw batches must check it themselves.

These remain open regardless of which layer you use:

- `verify_signature` uses ed25519-dalek's strict, cofactorless verification, which rejects non-canonical encodings and small-order public keys. stellar-core verifies through libsodium, which uses the cofactored equation, so for an adversarial signature the two can disagree: this crate may reject a cofactored or small-order signature that stellar-core accepts. The converse — that it never accepts one stellar-core rejects — is expected from strict verification being the tighter check, but is not claimed here until a differential test against stellar-core's libsodium check exists. Either way the difference only arises for malformed signatures no honest validator produces; edge cases are covered in `tests/signature.rs`. A live differential against a compiled stellar-core, like the quorum oracle, is the complete check and is still to be built.

## The one assumption behind all of it

Safety rests on quorum intersection among well-behaved nodes, and on your being intertwined with the network under the trust root you chose. This crate cannot verify either. A passing run says the validators you trusted signed this ledger; it does not say you trusted the right validators.
