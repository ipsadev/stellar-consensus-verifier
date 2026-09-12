use sha2::{Digest, Sha256};

use super::xdr::{Decoder, Result};
use crate::error::ScpError;

/// The only transaction-set format this crate reads.
pub const GENERALIZED_TX_SET_V1: i32 = 1;

/// Reads which ledger a transaction set was built on.
///
/// Used to prove a set belongs to the ledger that follows the one being
/// verified, rather than to some other ledger.
pub fn previous_ledger_hash(bytes: &[u8]) -> Result<[u8; 32]> {
    let mut d = Decoder::new(bytes);

    match d.i32()? {
        GENERALIZED_TX_SET_V1 => d.fixed32(),
        other => Err(ScpError::InvalidWire(alloc::format!(
            "unsupported GeneralizedTransactionSet version {other}"
        ))),
    }
}

/// Hashes a transaction set, so it can be matched against the hash the
/// network agreed on.
pub fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

extern crate alloc;
