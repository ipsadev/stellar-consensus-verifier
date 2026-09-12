# Stellar SCP Verification Core

Answers whether the Stellar network agreed on a ledger.

Given the messages Stellar's validators signed, it checks the signatures, works
out whether enough validators agreed, and reports the value they settled on. It
reads bytes and returns answers. No network, no storage, no clock.

## What it does

| Module | What it answers |
|---|---|
| `envelope` | what did this validator say, and did it really sign it |
| `ballot` | did enough validators commit to this value for it to be settled |
| `quorum` | who does a validator listen to, and do these signers add up to enough |
| `ledger` | what is in this closed ledger, and what is its true hash |
| `chain` | is this older ledger really an ancestor of one already trusted |
| `txset` | which transactions did this ledger apply |
| `results` | did this transaction succeed, and what state did it publish |
| `xdr` | reading Stellar's binary format without trusting it |
| `error` | every reason a proof can be rejected |

Signatures are verified inside the crate. `ballot::authenticate` is the only way
to turn raw messages into something the rest of the crate will accept.

It does not tell you whether the validators you trust are a sensible choice.
That stays the caller's decision.

## Dependencies

`ed25519-dalek`, `sha2` and `thiserror`. Nothing else. It builds for
`wasm32-unknown-unknown`.

## License

Licensed under the
[Apache License 2.0](https://github.com/ipsadev/stellar-consensus-verifier/blob/main/LICENSE).
