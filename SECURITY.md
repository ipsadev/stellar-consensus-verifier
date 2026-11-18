# Security model

This crate verifies, from untrusted bytes, that a quorum of the validators you trust externalized a particular Stellar ledger, and that a particular router state root belongs to that ledger. This document states what is trusted, what is not, the order the pieces must be called in, and exactly what each step does and does not establish. It is the reference an auditor should read first.

A passing verification is only as strong as two things you supply and this crate cannot check for you: the trust root you chose, and the assumption that the validators in it are intertwined with the network under quorum intersection. Everything below is relative to those.

## Trusted inputs

These are the values you must obtain out of band and are trusting by assumption. The crate treats them as ground truth.

- The network identifier (`network_id`), which fixes the network and is folded into every signature check so a message from one network cannot be replayed on another.
- Your trust root, built with `TrustRoot::from_pinned(quorum_set_xdr, expected_fingerprint, min_orgs)`: the validators you trust and the thresholds among them. You pin its fingerprint out of band, so a quorum set read from the archive — pledged by the very validators being checked — cannot be passed in by mistake. `from_pinned` also holds a floor on the root: stellar-core's strict-majority sanity, plus a top-level threshold of at least two thirds and at least `min_orgs` top-level orgs (see below for what that does and does not give you).
- An anchor ledger hash you already trust, when using `chain::walk_back` to reach an older ledger.
- The router contract identifier and the root event topic (`router_contract_id`, `root_event_topic` in `results::Inputs`), which say whose published state root you are willing to believe.

## Untrusted inputs

Everything else is attacker-controlled and is checked before it is believed: all SCP envelopes, all quorum-set preimages, all ledger-header bytes, all transaction sets, all transaction-result pairs, and anything read from a history archive. No count or hash read from these is trusted until a step below authenticates it.

Each of these is also bounded, so a verifier running under a gas or cycle budget cannot be forced into unbounded work: the number of envelopes (`MAX_ENVELOPES`), quorum-set preimages (`MAX_QUORUM_SETS`), transaction-result pairs (`MAX_RESULT_PAIRS`) and their total bytes (`MAX_RESULT_SET_BYTES`), transaction-set bytes (`MAX_TRANSACTION_SET_BYTES`), success-preimage bytes (`MAX_SUCCESS_PREIMAGE_BYTES`, checked before the preimage is hashed), and walk-back steps (`MAX_WALK_BACK_STEPS`) are capped, and over-limit input is refused with `InputTooLarge`. Quorum-set depth and size are already bounded by `QuorumSet::check_sane`, and the XDR decoder caps nesting. These are resource bounds, not soundness: an over-limit input could never have verified, so refusing it only avoids wasted work.

## Required call order

The `verify` module is the front door and the recommended way to use this crate. It carries trust in the types: each step takes the value the previous step produced and returns a new one whose fields are private, so holding a value is proof the earlier checks ran. The pipeline is `authenticate` → `AuthenticatedBatch`, `confirmed_value` → `ConfirmedValue`, `bind_header` → `ValueBoundHeader`, then either `bind_successor` or `walk_back` → `AuthenticatedHeader`, then `verify_router_root` → `VerifiedRouterRoot`. `verify_consensus` and `verify_header` are convenience wrappers for the first steps, and `verify_update` runs the whole update in one call. The trust root is checked once, when you build it with `TrustRoot::from_pinned`.

The two header types encode the `bind_header` rule. A `ValueBoundHeader` has its transaction set, close time and upgrades authenticated, but not its `tx_set_result_hash` or `bucket_list_hash`, because validators sign the scpValue, not the whole header. Only an `AuthenticatedHeader` — whose whole-bytes hash is pinned by the next slot's transaction set (`bind_successor`) or by the chain (`walk_back`) — has every field authenticated, and only an `AuthenticatedHeader` can be passed to `verify_router_root`. A caller therefore cannot extract a router state root from a header whose results field was never authenticated; the code will not compile.

The individual steps below are what these functions do internally. They wrap the primitives under `primitives`, grouped by what each guarantees: `primitives::scp` (envelope, authentication, commit, quorum acceptance), `primitives::stellar` (header, txset, chain), `primitives::execution` (results, router_event), and `primitives::analysis` (quorum-split checks that do not affect acceptance). These are available for advanced callers who assemble the pipeline themselves and take on the responsibilities under "Known gaps".

The steps must run in this order. Each one is sound only if the steps before it succeeded, and each establishes strictly less than it may appear to.

1. `envelope::authenticate(network_id, slot_index, envelopes_xdr, quorum_sets_xdr) -> Vec<Authenticated>`.
   - Establishes: every returned statement carries a valid ed25519 signature over the right network and slot, and each supplied quorum-set preimage genuinely hashes to the value its validator named. A validator whose quorum set cannot be matched is dropped, not trusted.
   - Does not establish: that any value won consensus, or that the evidence is complete. It is the only constructor of `Authenticated`; nothing downstream should accept hand-built evidence.

2. `commit::confirmed_value(local, &[Authenticated]) -> Vec<u8>`.
   - Establishes: a quorum of your trust root confirmed-committed exactly one value, and returns that value's bytes (the externalized `scpValue`). If two different values both reach confirm-commit it returns fork evidence instead.
   - Does not establish: any connection to a `LedgerHeader`. The return is a bare value, not a verified ledger.

3. `verify::bind_header(value, ledger_header_xdr) -> ValueBoundHeader`. It decodes the header with `primitives::stellar::header::LedgerHeader::decode`, then requires `header.scp_value_bytes == confirmed_value(...)` and `header.ledger_seq` to equal the slot.
   - Establishes: only that the `scpValue` span inside the supplied bytes equals the value consensus agreed on, so the transaction-set hash, close time and upgrades it carries are authentic.
   - Does not establish: that the header is the ledger the quorum externalized. `header.ledger_hash` is SHA-256 over bytes the caller supplied, and every byte outside the `scpValue` span is unsigned and attacker-editable: `tx_set_result_hash`, `bucket_list_hash` and `previous_ledger_hash` among them. Two headers can carry the same `scpValue` and differ everywhere else, so at this point `ledger_hash` is not yet the real ledger hash. `tests/verify/forgery.rs` shows a header with a forged `tx_set_result_hash` passing this step and being rejected by step 4a. The header's own `previous_ledger_hash` cannot pin it either, for the same reason. The whole header becomes trustworthy only once its whole-bytes hash is pinned, by `bind_successor` (step 4a) or `walk_back` (step 4b).

4a. `verify::bind_successor(header, successor_value, successor_tx_set_xdr) -> AuthenticatedHeader`.
   - Establishes: this header is ledger N in full. The successor's confirmed value fixes the next slot's `txSetHash`; the supplied transaction set must hash to it; that set's `previousLedgerHash` is the real hash of ledger N; and this header is authenticated only if its bytes hash to that. Pinning the whole-bytes hash makes `tx_set_result_hash` and `bucket_list_hash` trustworthy.
   - A successor that closed with an empty transaction set (CAP-83) carries an all-zero `txSetHash` that no transaction set hashes to, so it is rejected with `SuccessorTxSetMismatch`; authenticate a different ledger N instead.
   - Assumption: it relies on the stellar-core Herder rule that a validator only votes for a transaction set built on its own last closed ledger, so the set's `previousLedgerHash` is the hash of the ledger consensus actually extended. That is an assumption about honest validators, not a check.

4b. `verify::walk_back(anchor, headers_descending, target_seq) -> AuthenticatedHeader`, optional.
   - Establishes: the target ledger is a genuine ancestor of the anchor, by following the `previous_ledger_hash` links down from a header already pinned (step 4a). Because of hash chaining, one recent pinned ledger certifies its whole history.
   - Does not establish: anything about the anchor itself. The anchor must already be an `AuthenticatedHeader`, which only steps 4a or 4b produce.

5. `verify::verify_router_root(authenticated_header, …) -> VerifiedRouterRoot`, optional.
   - Establishes: the supplied result pairs hash to the header's `tx_set_result_hash`, the named transaction succeeded, directly or as the inner transaction of a fee-bump, and the router contract you named emitted at least one contract event whose single topic is the agreed symbol. The 32-byte payload of the last such event is returned: the success preimage holds only events from calls that succeeded, in the order they were emitted, so the last root is the router's state when the invocation ended.
   - The caller chooses which result pair is the router's transaction (`result_index`). A fee-bump is one pair whose result nests the inner transaction's result, and the crate reads through it. This is safe because every pair is first checked to hash, as an ordered set, to `tx_set_result_hash`, so no index can select a pair the ledger did not commit.
   - Takes only an `AuthenticatedHeader`, so the `tx_set_result_hash` it reads has been pinned by step 4a or 4b; it cannot be called on a merely value-bound header.

## What a full run proves, and what it does not

A full run proves: a quorum of the validators you chose externalized this ledger, this header is that ledger, it descends from an anchor you trust, and this router state root was published by it.

### What `from_pinned` checks about your trust root

`from_pinned` runs stellar-core's `isQuorumSetSane` with its extra checks on: at every level of the quorum set the threshold must be a strict majority of its entries (`threshold >= entries - threshold + 1`). That guarantees any two slices of your trust root share at least one member, but not that they share an *honest* one, so on its own it is not a Byzantine fault tolerance check: a strict-majority set still lets two slices intersect in a single node, which a compromised validator can equivocate across.

On top of that sanity, `from_pinned` holds a floor the audit asked for (c3, d3: a 1-of-1 root passed before). It is checked once, where you build the root:

- The top-level threshold must be at least two thirds of its entries (`threshold * 3 >= entries * 2`). Two thirds is the Byzantine bound: above it any two quorums overlap in enough orgs that at least one is honest, so a single equivocating org cannot get two values confirmed. stellar-core defaults `THRESHOLD_PERCENT` to 67 for the same reason; this crate now enforces it for a pinned root rather than leaving it to the operator.
- The top level must name at least `min_orgs` entries, so the trust is actually distributed. A 1-of-1 or a too-thin root is refused however high its threshold: concentration, not just threshold, is what a trust root has to avoid.

The floor is **top-level only**. The entries of the top set are the orgs you trust, and an org is the unit of Byzantine fault: all of an org's nodes are run by one operator, so if that operator is honest the org does not equivocate, and if it is compromised the whole org is Byzantine whatever its internal threshold. Real tier-1 roots run orgs below two thirds internally (mainnet has `3-of-5` orgs inside a `5-of-7` root), so enforcing two thirds on inner sets would reject legitimate roots for no safety the client can rely on. `min_orgs` is yours to set because the right minimum differs by network: mainnet is a seven-org root, testnet a three-org one.

What acceptance actually rests on: a ledger is accepted only if every member of at least one slice of your trust root signed for it. stellar-core gives a signer of an EXTERNALIZE statement the singleton quorum set of itself, so in practice, where the evidence is EXTERNALIZE statements, acceptance reduces to one slice of your trust root having signed EXTERNALIZE for the value, and the quorum-set preimages you pass are not consulted. The assumption is therefore that no slice of your trust root is fully compromised. For a 2-of-3 trust root, that means any two keys.

It does not prove: that your trust root is the right one, that quorum intersection holds, or that the network has not partitioned beneath your chosen validators. Those are assumptions, not results, and no light client can check them for itself.

It also does not judge freshness. A full run proves a ledger was agreed and is authentic, not that it is recent; an old but validly agreed ledger passes every check. Rejecting a stale ledger is the consuming light client's job, using the authenticated header's ledger sequence and close time.

## Known gaps and caller responsibilities

These are current, deliberate limitations. Treat each as a thing the caller must handle until it is addressed in `src/`.

The following are addressed when you use the `verify` module, and remain the caller's responsibility only when reaching for the raw primitives:

- The value-to-header binding is done by `verify::bind_header`, which returns a `ValueBoundHeader`. Callers using the raw `envelope::authenticate`/`commit::confirmed_value` primitives must perform the `scp_value_bytes` comparison themselves.
- `verify::verify_router_root` takes an `AuthenticatedHeader`, not a raw hash, so trust is carried in the type. The raw `results::verify_state_root` and `chain::walk_back` still take plain `&[u8; 32]` hashes with no evidence of origin; a caller using them directly must feed only authenticated hashes.
- `LedgerHeader` has all-public fields, so a bare header can be constructed or edited. The `verify` types wrap it behind private fields, and `verify_router_root` refuses anything but an `AuthenticatedHeader`; the bare type is only safe through that layer.
- `TrustRoot::from_pinned` checks the trust root is strict-majority, clears the two-thirds and `min_orgs` floor, and matches the pinned fingerprint when it is built, so every `verify` entry point already holds a well-formed, pinned root. The raw `commit::confirmed_value` primitive takes a bare `QuorumSet` and checks none of these.
- The typed values carry their network and slot end to end: `AuthenticatedBatch`, `ConfirmedValue`, `ValueBoundHeader` and `AuthenticatedHeader` all record the network, and `bind_successor` refuses a header and successor from different networks, so the pipeline cannot mix networks or slots. The raw `Authenticated` does not carry this context, so callers mixing raw batches must check it themselves.

These remain open regardless of which layer you use:

- `verify_signature` calls ed25519-dalek's `VerifyingKey::from_bytes` and then `verify_strict`, which rejects non-canonical encodings and small-order points. From protocol 25 onward stellar-core verifies with exactly the same two calls, through its rust bridge function `verify_ed25519_signature_dalek` (`src/rust/src/ed25519_verify.rs`), and both lockfiles pin the same versions, ed25519-dalek 2.2.0 and curve25519-dalek 4.1.3. For any ledger at protocol 25 or later the signature check is therefore identical to stellar-core's. Keeping those versions in step with stellar-core's `Cargo.lock` is a release check, not yet automated.
- Before protocol 25, stellar-core verified with libsodium's `crypto_sign_verify_detached`, which is also cofactorless but rejects malformed inputs by its own rules, so for an adversarial signature in a pre-protocol-25 archive the two checks could disagree on an edge case. This only matters when verifying ledgers older than protocol 25, and only for malformed signatures no honest validator produces. Edge cases are covered in `tests/envelope/signature.rs`.

## The one assumption behind all of it

Safety rests on quorum intersection among well-behaved nodes, and on your being intertwined with the network under the trust root you chose. This crate cannot verify either. A passing run says the validators you trusted signed this ledger; it does not say you trusted the right validators.
