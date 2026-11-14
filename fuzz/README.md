# Fuzzing

Coverage-guided fuzzers for the crate's decoders and the end-to-end update path, built on [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) and libFuzzer. This directory is a separate crate and is excluded from the published package.

## Targets

- `ledger_header_decode` — `LedgerHeader::decode`
- `envelope_decode` — `Envelope::decode`
- `quorum_set_decode` — `QuorumSet::decode`
- `tx_set_reader` — `txset::previous_ledger_hash` and `txset::hash`
- `verify_update` — `verify_update` against the committed `tests/fixtures/testnet-router-chain.json`, with the fuzz input substituted for the ledger header

## Running

Requires a nightly toolchain and `cargo-fuzz` (`cargo install cargo-fuzz`). From the crate root:

```
cargo +nightly fuzz build                       # build every target
cargo +nightly fuzz run envelope_decode         # fuzz one target
cargo +nightly fuzz run verify_update -- -max_total_time=10   # time-boxed run
```

`cargo +nightly fuzz list` prints the target names. Corpus and crash artifacts land under `fuzz/corpus/` and `fuzz/artifacts/` and are not committed.
