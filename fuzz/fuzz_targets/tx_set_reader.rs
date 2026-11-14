#![no_main]

use libfuzzer_sys::fuzz_target;
use stellar_consensus_verifier::primitives::stellar::txset;

fuzz_target!(|data: &[u8]| {
    let _ = txset::previous_ledger_hash(data);
    let _ = txset::hash(data);
});
