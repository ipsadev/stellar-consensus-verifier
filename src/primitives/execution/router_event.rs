use alloc::vec::Vec;

use crate::error::ScpError;
use crate::xdr::{Decoder, Result};

const SCV_BOOL: i32 = 0;
const SCV_VOID: i32 = 1;
const SCV_ERROR: i32 = 2;
const SCV_U32: i32 = 3;
const SCV_I32: i32 = 4;
const SCV_U64: i32 = 5;
const SCV_I64: i32 = 6;
const SCV_TIMEPOINT: i32 = 7;
const SCV_DURATION: i32 = 8;
const SCV_U128: i32 = 9;
const SCV_I128: i32 = 10;
const SCV_U256: i32 = 11;
const SCV_I256: i32 = 12;
const SCV_BYTES: i32 = 13;
const SCV_STRING: i32 = 14;
const SCV_SYMBOL: i32 = 15;
const SCV_VEC: i32 = 16;
const SCV_MAP: i32 = 17;
const SCV_ADDRESS: i32 = 18;
const SCV_CONTRACT_INSTANCE: i32 = 19;
const SCV_LEDGER_KEY_CONTRACT_INSTANCE: i32 = 20;
const SCV_LEDGER_KEY_NONCE: i32 = 21;

const CONTRACT_EVENT_CONTRACT: i32 = 1;

const SC_ADDRESS_TYPE_ACCOUNT: i32 = 0;
const SC_ADDRESS_TYPE_CONTRACT: i32 = 1;

const CONTRACT_EXECUTABLE_WASM: i32 = 0;
const CONTRACT_EXECUTABLE_STELLAR_ASSET: i32 = 1;

const MAX_TOPICS: usize = 4;
const MAX_EVENTS: usize = 4096;
const MAX_SCVAL_ELEMENTS: usize = 4096;
const MAX_SCVAL_DEPTH: u32 = 16;

fn bad(what: &str) -> ScpError {
    ScpError::InvalidWire(what.into())
}

/// Finds the single state root the router published in a success preimage.
///
/// Walks the contract events, keeps only those from the router contract whose
/// topic matches, and returns the one 32-byte root they carry. Ambiguity or
/// absence is an error, not a guess.
pub(crate) fn root_from_preimage(
    preimage: &[u8],
    router_contract_id: &[u8; 32],
    root_event_topic: &[u8],
) -> Result<[u8; 32]> {
    let mut d = Decoder::new(preimage);

    skip_scval(&mut d, 0)?;
    let n_events = d.vec_len(MAX_EVENTS)?;
    let mut found: Option<[u8; 32]> = None;

    for _ in 0..n_events {
        if let Some(root) = read_event(&mut d, router_contract_id, root_event_topic)? {
            if found.is_some() {
                return Err(ScpError::AmbiguousRouterEvent);
            }

            found = Some(root);
        }
    }

    d.finish()?;
    found.ok_or(ScpError::RouterEventMissing)
}

fn read_event(
    d: &mut Decoder<'_>,
    router_contract_id: &[u8; 32],
    root_event_topic: &[u8],
) -> Result<Option<[u8; 32]>> {
    match d.i32()? {
        0 => {}
        other => {
            return Err(bad(&alloc::format!(
                "unsupported ContractEvent ext {other}"
            )))
        }
    }

    let contract_id = match d.u32()? {
        0 => None,
        1 => Some(d.fixed32()?),
        other => return Err(bad(&alloc::format!("bad optional discriminant {other}"))),
    };

    let event_type = d.i32()?;

    match d.i32()? {
        0 => {}
        other => {
            return Err(bad(&alloc::format!(
                "unsupported ContractEvent body {other}"
            )))
        }
    }

    let n_topics = d.vec_len(MAX_TOPICS)?;
    let mut topics = Vec::with_capacity(n_topics);

    for _ in 0..n_topics {
        topics.push(scval_slice(d)?);
    }

    let data = scval_slice(d)?;

    // A router state root is a contract event from the router whose single topic
    // is the agreed symbol: a fixed layout, not a symbol found anywhere among
    // several topics or carried by a system or diagnostic event.
    let is_root_event = event_type == CONTRACT_EVENT_CONTRACT
        && contract_id.as_ref() == Some(router_contract_id)
        && topics.len() == 1
        && scval_symbol(topics[0]) == Some(root_event_topic);

    if !is_root_event {
        return Ok(None);
    }

    let root = scval_bytes32(data).ok_or(ScpError::StateRootMalformed)?;

    Ok(Some(root))
}

fn scval_slice<'a>(d: &mut Decoder<'a>) -> Result<&'a [u8]> {
    let start = d.position();

    skip_scval(d, 0)?;

    Ok(d.slice_from(start))
}

fn scval_symbol(bytes: &[u8]) -> Option<&[u8]> {
    let mut d = Decoder::new(bytes);

    if d.i32().ok()? != SCV_SYMBOL {
        return None;
    }

    let out = d.var_bytes().ok()?;

    d.finish().ok()?;

    Some(out)
}

fn scval_bytes32(bytes: &[u8]) -> Option<[u8; 32]> {
    let mut d = Decoder::new(bytes);

    if d.i32().ok()? != SCV_BYTES {
        return None;
    }

    let out = d.var_bytes().ok()?;

    d.finish().ok()?;
    out.try_into().ok()
}

fn skip_scval(d: &mut Decoder<'_>, depth: u32) -> Result<()> {
    if depth > MAX_SCVAL_DEPTH {
        return Err(bad("SCVal nested too deeply"));
    }

    match d.i32()? {
        SCV_VOID | SCV_LEDGER_KEY_CONTRACT_INSTANCE => {}
        SCV_BOOL | SCV_U32 | SCV_I32 => {
            d.u32()?;
        }
        SCV_ERROR => {
            d.i32()?;
            d.i32()?;
        }
        SCV_U64 | SCV_I64 | SCV_TIMEPOINT | SCV_DURATION | SCV_LEDGER_KEY_NONCE => {
            d.u64()?;
        }
        SCV_U128 | SCV_I128 => {
            d.u64()?;
            d.u64()?;
        }
        SCV_U256 | SCV_I256 => {
            for _ in 0..4 {
                d.u64()?;
            }
        }
        SCV_BYTES | SCV_STRING | SCV_SYMBOL => {
            d.var_bytes()?;
        }
        SCV_VEC => {
            if optional_present(d)? {
                let n = d.vec_len(MAX_SCVAL_ELEMENTS)?;

                for _ in 0..n {
                    skip_scval(d, depth + 1)?;
                }
            }
        }
        SCV_MAP => {
            if optional_present(d)? {
                let n = d.vec_len(MAX_SCVAL_ELEMENTS)?;

                for _ in 0..n {
                    skip_scval(d, depth + 1)?;
                    skip_scval(d, depth + 1)?;
                }
            }
        }
        SCV_ADDRESS => skip_address(d)?,
        SCV_CONTRACT_INSTANCE => {
            match d.i32()? {
                CONTRACT_EXECUTABLE_WASM => {
                    d.fixed32()?;
                }
                CONTRACT_EXECUTABLE_STELLAR_ASSET => {}
                other => {
                    return Err(bad(&alloc::format!(
                        "unsupported ContractExecutable {other}"
                    )))
                }
            }

            if optional_present(d)? {
                let n = d.vec_len(MAX_SCVAL_ELEMENTS)?;

                for _ in 0..n {
                    skip_scval(d, depth + 1)?;
                    skip_scval(d, depth + 1)?;
                }
            }
        }
        other => return Err(bad(&alloc::format!("unsupported SCValType {other}"))),
    }

    Ok(())
}

fn skip_address(d: &mut Decoder<'_>) -> Result<()> {
    match d.i32()? {
        SC_ADDRESS_TYPE_ACCOUNT => {
            d.node_id()?;
        }
        SC_ADDRESS_TYPE_CONTRACT => {
            d.fixed32()?;
        }
        other => return Err(bad(&alloc::format!("unsupported SCAddressType {other}"))),
    }

    Ok(())
}

fn optional_present(d: &mut Decoder<'_>) -> Result<bool> {
    match d.u32()? {
        0 => Ok(false),
        1 => Ok(true),
        other => Err(bad(&alloc::format!("bad optional discriminant {other}"))),
    }
}

extern crate alloc;
