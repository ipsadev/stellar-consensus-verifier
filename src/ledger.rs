use alloc::vec::Vec;

use sha2::{Digest, Sha256};

use super::xdr::{Decoder, Result};
use crate::error::ScpError;

/// A closed ledger with nothing extra attached.
pub const STELLAR_VALUE_BASIC: i32 = 0;
/// A closed ledger naming the validator that proposed it.
pub const STELLAR_VALUE_SIGNED: i32 = 1;
/// A ledger the network agreed to close empty because its transactions could
/// not be fetched in time.
pub const STELLAR_VALUE_EMPTY_TX_SET: i32 = 2;

const MAX_UPGRADES: usize = 6;
const MAX_UPGRADE_LEN: usize = 128;
/// Headers carry four back-pointers for jumping through history. This crate
/// walks link by link instead, which is simpler to audit.
pub const SKIP_LIST_LEN: usize = 4;

const EMPTY_TX_SET_PROTOCOL_VERSION: u32 = 28;
const EMPTY_TX_SET_HASH: [u8; 32] = [0u8; 32];
const GENESIS_LEDGER_SEQ: u32 = 1;

fn bad(what: &str) -> ScpError {
    ScpError::InvalidWire(what.into())
}

#[derive(Clone, Debug)]
/// The transaction set that was dropped, and the ledger it was meant for.
pub struct EmptyTxSet {
    pub proposed_tx_set_hash: [u8; 32],
    pub proposed_previous_ledger_hash: [u8; 32],
    pub proposed_previous_ledger_version: u32,
}

#[derive(Clone, Debug)]
/// A closed Stellar ledger.
///
/// `ledger_hash` is computed from the bytes, so it is the ledger's real
/// identity rather than a claim. `scp_value_bytes` is the exact slice the
/// validators agreed on, ready to compare against their signed messages.
pub struct LedgerHeader {
    pub ledger_version: u32,
    pub previous_ledger_hash: [u8; 32],
    pub tx_set_hash: [u8; 32],
    pub empty_tx_set: Option<EmptyTxSet>,
    pub scp_value_bytes: Vec<u8>,
    pub close_time: u64,
    pub tx_set_result_hash: [u8; 32],
    pub bucket_list_hash: [u8; 32],
    pub ledger_seq: u32,
    pub ledger_hash: [u8; 32],
}

impl LedgerHeader {
    /// Reads a ledger header and computes its hash.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoded = Decoder::new(bytes);

        let ledger_version = decoded.u32()?;
        let previous_ledger_hash = decoded.fixed32()?;
        let value_start = decoded.position();
        let tx_set_hash = decoded.fixed32()?;
        let close_time = decoded.u64()?;
        let upgrades = decoded.vec_len(MAX_UPGRADES)?;

        for _ in 0..upgrades {
            let upgrade = decoded.var_bytes()?;

            if upgrade.len() > MAX_UPGRADE_LEN {
                return Err(bad("upgrade entry longer than the 128 bytes XDR permits"));
            }
        }

        let mut empty_tx_set = None;

        match decoded.i32()? {
            STELLAR_VALUE_BASIC => {}
            STELLAR_VALUE_SIGNED => {
                let _node_id = decoded.node_id()?;
                let _signature = decoded.signature()?;
            }
            STELLAR_VALUE_EMPTY_TX_SET => {
                let proposed_tx_set_hash = decoded.fixed32()?;
                let proposed_previous_ledger_hash = decoded.fixed32()?;
                let proposed_previous_ledger_version = decoded.u32()?;
                let _node_id = decoded.node_id()?;
                let _signature = decoded.signature()?;

                empty_tx_set = Some(EmptyTxSet {
                    proposed_tx_set_hash,
                    proposed_previous_ledger_hash,
                    proposed_previous_ledger_version,
                });
            }
            other => return Err(bad(&alloc::format!("unsupported StellarValue ext {other}"))),
        }

        let scp_value_bytes = decoded.slice_from(value_start).to_vec();
        let tx_set_result_hash = decoded.fixed32()?;
        let bucket_list_hash = decoded.fixed32()?;
        let ledger_seq = decoded.u32()?;
        let _total_coins = decoded.u64()?;
        let _fee_pool = decoded.u64()?;
        let _inflation_seq = decoded.u32()?;
        let _id_pool = decoded.u64()?;
        let _base_fee = decoded.u32()?;
        let _base_reserve = decoded.u32()?;
        let _max_tx_set_size = decoded.u32()?;

        for _ in 0..SKIP_LIST_LEN {
            let _skip = decoded.fixed32()?;
        }

        match decoded.i32()? {
            0 => {}
            1 => {
                let _flags = decoded.u32()?;

                match decoded.i32()? {
                    0 => {}
                    other => {
                        return Err(bad(&alloc::format!(
                            "unsupported LedgerHeaderExtensionV1 ext {other}"
                        )))
                    }
                }
            }
            other => return Err(bad(&alloc::format!("unsupported LedgerHeader ext {other}"))),
        }

        decoded.finish()?;

        check_empty_tx_set(
            &empty_tx_set,
            &tx_set_hash,
            &previous_ledger_hash,
            ledger_version,
            ledger_seq,
        )?;

        Ok(Self {
            ledger_version,
            previous_ledger_hash,
            tx_set_hash,
            empty_tx_set,
            scp_value_bytes,
            close_time,
            tx_set_result_hash,
            bucket_list_hash,
            ledger_seq,
            ledger_hash: Sha256::digest(bytes).into(),
        })
    }
}

extern crate alloc;

fn check_empty_tx_set(
    empty_tx_set: &Option<EmptyTxSet>,
    tx_set_hash: &[u8; 32],
    previous_ledger_hash: &[u8; 32],
    ledger_version: u32,
    ledger_seq: u32,
) -> Result<()> {
    let is_empty_value = *tx_set_hash == EMPTY_TX_SET_HASH;
    let Some(info) = empty_tx_set else {
        if is_empty_value && ledger_seq != GENESIS_LEDGER_SEQ {
            return Err(bad(
                "empty tx set hash on a header without the empty-tx-set ext arm",
            ));
        }

        return Ok(());
    };

    if !is_empty_value {
        return Err(bad("empty-tx-set header carries a non-empty tx set hash"));
    }

    if ledger_version < EMPTY_TX_SET_PROTOCOL_VERSION {
        return Err(bad(
            "empty-tx-set ext arm before the protocol version that permits it",
        ));
    }

    if info.proposed_previous_ledger_version < EMPTY_TX_SET_PROTOCOL_VERSION {
        return Err(bad(
            "empty-tx-set proposed on a predecessor before the permitting protocol version",
        ));
    }

    if info.proposed_previous_ledger_hash != *previous_ledger_hash {
        return Err(bad(
            "empty-tx-set proposed previousLedgerHash differs from the header's own",
        ));
    }

    Ok(())
}

/// Reads which transaction set a ledger agreed to apply.
pub fn tx_set_hash_of_value(value: &[u8]) -> Result<[u8; 32]> {
    let mut d = Decoder::new(value);

    d.fixed32()
}
