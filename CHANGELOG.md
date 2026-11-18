# Changelog

All notable changes to this crate are recorded here. It follows semantic versioning: a major bump signals breaking API changes.

## 3.0.0

### Changed

- `TrustRoot::from_pinned` takes a third argument, `min_orgs`, and enforces a trust-root floor on top of stellar-core's strict-majority sanity: the top-level threshold must be at least two thirds of its entries, and the top level must name at least `min_orgs` orgs. A 1-of-1 root, or any root below two thirds or below the org count, is refused (ibc-contracts audit c3, d3: a 1-of-1 root passed before). The floor is top-level only, since an org is the unit of Byzantine fault and real tier-1 roots run orgs below two thirds internally (mainnet has `3-of-5` orgs inside its `5-of-7` root). `check_sane`, which mirrors stellar-core's `isQuorumSetSane`, is unchanged. New errors `TrustRootThresholdBelowTwoThirds` and `TrustRootTooFewOrgs`.

### Documentation

- `SECURITY.md` describes the floor and why: two thirds is the Byzantine bound that makes quorums intersect in an honest org, `min_orgs` forces the trust to be distributed, and the floor is top-level because an org's internal threshold is its own business.

## 2.3.0

### Changed

- `verify_state_root` accepts a fee-bumped router transaction: a result pair with code `txFEE_BUMP_INNER_SUCCESS` is read through to its inner result, which must be `txSUCCESS` with one successful `INVOKE_HOST_FUNCTION` operation, and the inner success hash binds the preimage. Before, a fee-bumped router transaction could not prove its root.
- When one invocation emits several root events from the router, the last one is returned instead of `AmbiguousRouterEvent`. The success preimage holds only events from calls that succeeded, in emission order, and each root covers every commitment before it, so the last root is the router's state when the invocation ended. `AmbiguousRouterEvent` is no longer returned; the variant stays so matching code keeps compiling.

### Documentation

- `SECURITY.md` step 5 describes the fee-bump path and the last-root rule, and no longer suggests a fee-bump's inner result is a separate pair in the result set.

## 2.2.1

### Added

- Coverage-guided fuzz targets under `fuzz/` (a cargo-fuzz crate, excluded from the published package): `LedgerHeader::decode`, `Envelope::decode`, `QuorumSet::decode`, the transaction-set reader, and `verify_update` run against the committed `testnet-router-chain` fixture. See `fuzz/README.md` for how to run them.

### Changed

- The router-event reader now rejects a claimable-balance `SCAddress` whose `ClaimableBalanceIDType` is not the only defined variant, `V0` (0), instead of accepting any discriminant. This is a skip-only path that cannot cause a false accept; the change makes it fail fast on undefined input.
- `just fmt-check` (and the CI fmt step) now runs on nightly, so the nightly-only `imports_granularity` and `group_imports` options in `rustfmt.toml` are actually enforced rather than silently skipped on stable.

### Documentation

- `SECURITY.md` step 5 now documents that the caller chooses which result pair is the router's transaction (for example the inner pair of a fee-bump), and that this is safe because every pair is first bound, as an ordered set, to `tx_set_result_hash`.

## 2.2.0

### Changed

- The crate is now genuinely `no_std`: `#![no_std]` with `extern crate alloc`, and `thiserror` 2 with default features off. It builds for a bare-metal target (`thumbv7em-none-eabi`), so the `no-std` category is now accurate (1.x and 2.0/2.1 carried the label but still pulled in the standard library through `thiserror`).

### Added

- The router-event reader understands every Protocol 30 `SCAddress` type — muxed account, claimable balance, liquidity pool and muxed contract — alongside account and contract, and it skips the `SCV_EXECUTABLE_TAG` value and the `ExternalRef` contract executable. Before this, an event anywhere in the router's transaction that carried one of these made `verify_router_root` refuse a genuine state root (safe, but it could stall updates).

## 2.1.0

### Added

- `MAX_RESULT_SET_BYTES` caps the total bytes of all result pairs, checked before hashing, so a few very large pairs cannot make a verifier hash an unbounded amount before the set-hash check fails.
- `MAX_SUCCESS_PREIMAGE_BYTES` caps the success preimage, checked before it is hashed (Soroban's `txMaxContractEventsSizeBytes` keeps a real preimage far below it).

Both are resource bounds, not soundness fixes: an over-limit input could never have verified. Over-limit input is refused with `InputTooLarge`.

## 2.0.0

A hardening and restructuring release from the audit. Every consumer must update import paths and move to the `verify` front door; see the migration notes at the end.

### Security

- Fixed a predecessor-authentication forgery in the next-slot binding. `bind_successor` previously compared `successor.previous_ledger_hash` against the header hash, both of which are header fields outside the signed `scpValue` and so attacker-editable; a forged ledger could be bound to a forged successor. It now authenticates the hash of ledger N from N+1's transaction set: the successor's confirmed value fixes the next slot's `txSetHash`, the supplied transaction set must hash to it, and that set's `previousLedgerHash` is the real hash of N. This relies on the stellar-core Herder rule, stated in `SECURITY.md`. Regression coverage is in `tests/verify/forgery.rs`.

### Changed (breaking)

- Modules are regrouped under `primitives/` by what each guarantees. Notable moves: `ledger` to `primitives::stellar::header`, `txset` to `primitives::stellar::txset`, `chain` to `primitives::stellar::chain`, `quorum` to `primitives::scp::quorum`, `results` to `primitives::execution::results`, `router_event` to `primitives::execution::router_event`, and the authentication entry point from `ballot`/`envelope` to `primitives::scp::envelope::authenticate`. Signature-only quorum-split checks live in `primitives::analysis`.
- The `verify` module is the front door and carries trust in the types: `AuthenticatedBatch`, `ConfirmedValue`, `ValueBoundHeader`, `AuthenticatedHeader`, `VerifiedRouterRoot`. Each step consumes the previous value and returns one with private fields, so `verify_router_root` accepts only a fully authenticated header and the unsound call orders no longer compile.
- `verify_update` runs a whole update (ledger N and its successor) in one call over an `UpdateEvidence` struct.
- `TrustRoot::from_pinned(quorum_set_xdr, expected_fingerprint)` is the only way to build a trust root. It checks the pinned fingerprint and BFT-soundness once, at construction, so `check_sane` no longer runs inside `confirmed_value`.
- Every typed value records the network, and `bind_successor` refuses a header and successor from different networks.

### Added

- Bounds on every untrusted input so a verifier under a gas or cycle budget cannot be driven into unbounded work: `MAX_ENVELOPES`, `MAX_QUORUM_SETS`, `MAX_RESULT_PAIRS`, `MAX_TRANSACTION_SET_BYTES`, and `MAX_WALK_BACK_STEPS`, each refused with `InputTooLarge`.
- New error variants: `SuccessorTxSetMismatch`, `NetworkMismatch`, `TrustRootFingerprintMismatch`, `InputTooLarge`, `HeaderValueMismatch`, `HeaderSlotMismatch`, `SuccessorNotNext`, and `NoBallotEvidence`.
- Real mainnet and testnet fixtures and regression suites covering the typed pipeline, `verify_update` and its negatives, the forgery, trust-root pinning, cross-network rejection, router-root extraction, signature edge cases, and each input limit.

### Migration from 1.x

- Update imports to the new `primitives::*` paths and drive the crate through `verify`.
- Replace bare `QuorumSet` construction with `TrustRoot::from_pinned`, supplying the pinned `sha256(xdr)` fingerprint.
- Replace hand-assembled verification with `verify_update`, then `verify_router_root` for the router state root; use `walk_back` to reach an older ledger from an authenticated anchor.
- A single-ledger run with no successor evidence is value-bound only: `tx_set_result_hash` and `bucket_list_hash` are not authenticated until a successor or the chain pins the header.

## 1.1.1

- Fixed the zero-start commit edge case in confirm-commit detection.
