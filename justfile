# Stellar SCP verification core

lints := "-D warnings -A clippy::manual_is_multiple_of -A clippy::too_many_arguments -A clippy::result_large_err"

default:
    @just --list

# everything CI runs, in CI's order
ci: fmt-check lint test doc-check wasm audit

fmt:
    cargo +nightly fmt --all

fmt-check:
    cargo fmt --all -- --check

lint:
    cargo clippy --locked --all-targets -- {{lints}}

# every public item must be documented, and every doc link must resolve
doc-check:
    RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps

test:
    cargo test --locked

# the crate must stay buildable for the contract target
wasm:
    cargo build --locked --target wasm32-unknown-unknown

audit:
    cargo audit --file Cargo.lock

# build stellar-core's quorum predicates into core-oracle/oracle, a linux binary
oracle:
    #!/bin/sh
    set -eu
    docker build -t scp-core-oracle core-oracle/
    id=$(docker create scp-core-oracle)
    trap 'docker rm "$id" >/dev/null' EXIT
    docker cp "$id":/usr/local/bin/oracle core-oracle/oracle

# check the quorum predicates against stellar-core; off linux, pass oracle=core-oracle/oracle-docker
differential oracle="core-oracle/oracle" cases="2000":
    CORE_ORACLE={{oracle}} CORE_DIFF_CASES={{cases}} cargo test --locked --release --test quorum_differential -- --include-ignored --nocapture

# the rendered API docs, as docs.rs will build them
doc:
    cargo doc --no-deps --open

# what crates.io would receive, without sending it
package:
    cargo package --locked

# a publish that talks to crates.io but changes nothing
publish-dry:
    cargo publish --locked --dry-run

clean:
    cargo clean
