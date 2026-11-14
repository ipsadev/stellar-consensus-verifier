#![no_main]

use libfuzzer_sys::fuzz_target;
use stellar_consensus_verifier::primitives::stellar::header::LedgerHeader;

fuzz_target!(|data: &[u8]| {
    let _ = LedgerHeader::decode(data);
});
