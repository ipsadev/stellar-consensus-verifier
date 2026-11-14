#![no_main]

use libfuzzer_sys::fuzz_target;
use stellar_consensus_verifier::primitives::scp::envelope::Envelope;

fuzz_target!(|data: &[u8]| {
    let _ = Envelope::decode(data);
});
