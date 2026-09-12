use super::xdr::Result;
use crate::{error::ScpError, ledger::LedgerHeader};

#[derive(Clone, Debug)]
/// A ledger reached by walking back from one you already trust.
///
/// `links` is how many ledgers were stepped through to get there.
pub struct ChainedLedger {
    pub ledger_seq: u32,
    pub ledger_hash: [u8; 32],
    pub previous_ledger_hash: [u8; 32],
    pub close_time: u64,
    pub tx_set_result_hash: [u8; 32],
    pub bucket_list_hash: [u8; 32],
    pub links: usize,
}

/// Follows a chain of ledgers backwards from a trusted one to an older one.
///
/// Verifying a single old ledger only proves that whoever you trusted *then*
/// agreed on it. Instead, verify one recent ledger against validators you
/// trust today, then walk back: each ledger names its predecessor's hash, so
/// following that trail proves the older ledger is really an ancestor.
///
/// Fails if a ledger is missing, out of order, altered, or does not lead back
/// to the one you started from.
pub fn walk_back(
    anchor_seq: u32,
    anchor_previous_ledger_hash: &[u8; 32],
    headers_descending: &[&[u8]],
    target_seq: u32,
) -> Result<ChainedLedger> {
    if anchor_seq <= target_seq {
        return Err(ScpError::ChainNotDescending {
            anchor: anchor_seq,
            target: target_seq,
        });
    }

    let expected = (anchor_seq - target_seq) as usize;

    if headers_descending.len() != expected {
        return Err(ScpError::ChainLengthMismatch {
            anchor: anchor_seq,
            target: target_seq,
            expected,
            found: headers_descending.len(),
        });
    }

    let mut expected_hash = *anchor_previous_ledger_hash;
    let mut expected_seq = anchor_seq - 1;
    let mut child = anchor_seq;
    let mut last = None;

    for raw in headers_descending {
        let header = LedgerHeader::decode(raw)?;

        if header.ledger_seq != expected_seq {
            return Err(ScpError::ChainGap {
                expected: expected_seq,
                found: header.ledger_seq,
            });
        }

        if header.ledger_hash != expected_hash {
            return Err(ScpError::ChainBroken {
                seq: header.ledger_seq,
                child,
            });
        }

        expected_hash = header.previous_ledger_hash;
        child = header.ledger_seq;
        expected_seq = expected_seq.saturating_sub(1);
        last = Some(header);
    }

    let target = last.ok_or(ScpError::ChainLengthMismatch {
        anchor: anchor_seq,
        target: target_seq,
        expected,
        found: 0,
    })?;

    Ok(ChainedLedger {
        ledger_seq: target.ledger_seq,
        ledger_hash: target.ledger_hash,
        previous_ledger_hash: target.previous_ledger_hash,
        close_time: target.close_time,
        tx_set_result_hash: target.tx_set_result_hash,
        bucket_list_hash: target.bucket_list_hash,
        links: expected,
    })
}
