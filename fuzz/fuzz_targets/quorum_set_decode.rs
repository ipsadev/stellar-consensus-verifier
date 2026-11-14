#![no_main]

use libfuzzer_sys::fuzz_target;
use stellar_consensus_verifier::primitives::scp::quorum::QuorumSet;

fuzz_target!(|data: &[u8]| {
    let _ = QuorumSet::decode(data);
});
