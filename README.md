# Stellar SCP Verification Core

Answers whether the Stellar network agreed on a ledger.

Given the messages Stellar's validators signed, it checks the signatures, works
out whether enough validators agreed, and reports the value they settled on. It
reads bytes and returns answers. No network, no storage, no clock.

## What it does

`verify` is the front door: a typed pipeline that carries trust in its types, so holding a value proves the earlier checks ran. It wraps the primitives under `primitives`, grouped by what each guarantees.

| Module | What it answers |
|---|---|
| `verify` | the whole proof, step by step, as types that cannot be skipped |
| `primitives::scp::envelope` | what did this validator say, did it really sign it, and is it genuine evidence |
| `primitives::scp::statement` | which SCP statement is this, and is it newer than another |
| `primitives::scp::ballot` | a proposed value and the round that proposed it |
| `primitives::scp::commit` | did enough validators commit to one value for it to be settled |
| `primitives::scp::quorum` | who does a validator listen to, and do these signers add up to enough |
| `primitives::stellar::header` | what is in this closed ledger, and what is its true hash |
| `primitives::stellar::chain` | is this older ledger really an ancestor of one already trusted |
| `primitives::stellar::txset` | the SHA-256 of a transaction set, and the previous-ledger hash it names |
| `primitives::execution::results` | did this transaction succeed, and does its result set match the header |
| `primitives::execution::router_event` | which state root did the router publish in the success preimage |
| `primitives::analysis` | could the network split, and would that split threaten you (never affects acceptance) |
| `xdr` | reading Stellar's binary format without trusting it |
| `error` | every reason a proof can be rejected |

Signatures are verified inside the crate. `primitives::scp::envelope::authenticate` is the only way to turn raw messages into something the rest of the crate will accept, and `verify` is the recommended way to drive it. Build a trust root with `TrustRoot::from_pinned`, pinning its fingerprint out of band, then call `verify_update` to authenticate a ledger and its successor in one step and `verify_router_root` for the router state root, or drive the pipeline stage by stage. See [SECURITY.md](SECURITY.md) for the trusted inputs, the required call order, and what each step does and does not establish.

`primitives::stellar::header` reads every kind of agreed value up to Protocol 30: plain, signed, empty-transaction-set (CAP-83), and the two that also record the close time in milliseconds (CAP-88). It refuses a millisecond close time before Protocol 30, or one whose seconds differ from the header's `closeTime`, and exposes it as `close_time_ms`.

It does not tell you whether the validators you trust are a sensible choice.
That stays the caller's decision.

## Dependencies

`ed25519-dalek`, `sha2` and `thiserror`. Nothing else. It builds for
`wasm32-unknown-unknown`.

## License

Copyright 2026 Amanda Gonsalves. Licensed under the
[Apache License 2.0](https://github.com/ipsadev/stellar-consensus-verifier/blob/main/LICENSE).
