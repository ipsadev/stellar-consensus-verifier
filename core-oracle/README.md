# core-oracle

a differential oracle: stellar-core's own quorum predicates, wrapped in a line protocol so
`tests/quorum/quorum_differential.rs` can check our port against them case for case.

## what it exposes

three functions, straight out of a real stellar-core tree, no reimplementation:

- `LocalNode::isQuorum`
- `LocalNode::isQuorumSlice`
- `isQuorumSetSane`

the test writes cases on stdin and reads verdicts off stdout. if our fixed point and stellar-core
ever disagree on the same input, the test fails.

## build and run

```sh
just oracle                                         # docker build, then copies the binary to core-oracle/oracle
just differential                                   # linux: runs core-oracle/oracle natively
just differential core-oracle/oracle-docker 2000    # macos: runs the image through docker
```

`just differential` runs `cargo test --release --test quorum_differential -- --include-ignored` with `CORE_ORACLE` and `CORE_DIFF_CASES` set. `oracle-docker` is a one-line wrapper around `docker run --rm -i scp-core-oracle`. point `CORE_ORACLE` at any executable that speaks the protocol if you'd rather build it another way.

the three differential tests are `#[ignore]`d, so a plain `cargo test` reports them as ignored rather than passed. run with `--include-ignored` and they need `CORE_ORACLE`: if it is unset, they fail instead of passing quietly.

## in ci

`.github/workflows/differential.yml` runs the differential on pull requests that touch `src/primitives/scp/`, `tests/quorum/` or `core-oracle/`, every monday, and on demand. the oracle binary is cached under a key hashed from `core-oracle/**`, so stellar-core is only rebuilt when the tag, the oracle source or the build script changes. pull requests run 20,000 cases per predicate, the weekly run 200,000, and a manual run takes the count as an input.

## what's in the build

`Dockerfile` clones stellar-core at `CORE_TAG` (currently `v30.0.0`, pinned to its commit by `CORE_COMMIT`), runs `./autogen.sh` and
`./configure --disable-tests`, then hands off to `build-oracle.sh`.

`build-oracle.sh` compiles `oracle.cpp` and `stubs.cpp` and links them against stellar-core's own
object files: `src/scp/*.o`, `src/crypto/*.o`, `src/util/*.o`, plus asio, jsoncpp, crc16, siphash and
spdlog. the quorum code is the real thing, compiled from the tree.

## what's stubbed, and why it aborts

`stubs.cpp` stands in for the rust bridge and the bits of stellar-core the quorum predicates never
touch. it does not fake them. `verify_ed25519_signature_dalek` prints a message and calls `abort()`:

> core-oracle: verify_ed25519_signature_dalek was called. This oracle links only the quorum
> predicates and stubs the rust bridge, so any answer would be meaningless.

that's deliberate. an oracle that quietly returned `true` for a stubbed signature check would turn a
missing dependency into a passing test, which is the worst possible failure for a tool whose whole job
is telling you when two implementations disagree.

from v30, stellar-core computes SHA-256 through the rust bridge too (`compute_sha256` and the incremental `RustSha256`), and `src/crypto/SHA.o` will not link without them. `stubs.cpp` implements those on libsodium's `crypto_hash_sha256`, which is already linked, calling `sodium_init()` once before the first hash and keeping the rust side's behaviour that `finalize` resets the state. this is a real SHA-256, not a stand-in: the quorum predicates look quorum sets up by node and never hash at runtime, but in case a future oracle does, a known-answer test on `"abc"` (one-shot and streamed) runs when the binary starts and aborts on a mismatch. `build-oracle.sh` runs the binary once after linking, so a broken hash fails the build.

## what agreement proves, and what it doesn't

**proves:** our port of the quorum predicates and stellar-core's originals reach the same answer on the
same input, over the generated cases (2,000 by default, 20,000 on a pull request, 200,000 weekly) of up to 8 nodes with nested quorum sets.

**does not prove:** anything about signature verification, which is stubbed out here. and it does not
prove either implementation matches the whitepaper. `tests/quorum/quorum_whitepaper.rs` covers that separately, on
small federations built by hand.
