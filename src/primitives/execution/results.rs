use alloc::vec::Vec;

use sha2::{Digest, Sha256};

use crate::error::ScpError;
use crate::primitives::execution::router_event::root_from_preimage;
use crate::xdr::{Decoder, Result};

const TX_SUCCESS: i32 = 0;
const OP_INNER: i32 = 0;
const OP_TYPE_INVOKE_HOST_FUNCTION: i32 = 24;
const INVOKE_HOST_FUNCTION_SUCCESS: i32 = 0;

fn bad(what: &str) -> ScpError {
    ScpError::InvalidWire(what.into())
}

/// Everything needed to prove what a transaction produced.
pub struct Inputs<'a> {
    pub tx_set_result_hash: &'a [u8; 32],
    pub result_pairs: &'a [Vec<u8>],
    pub result_index: u32,
    pub success_preimage_xdr: &'a [u8],
    pub router_contract_id: &'a [u8; 32],
    pub root_event_topic: &'a [u8],
}

/// Checks that a set of transaction results is the one the ledger committed to.
///
/// A ledger header records a single hash covering every result in it, so this
/// proves none were added, removed or altered.
pub fn verify_result_set_hash(
    result_pairs: &[Vec<u8>],
    tx_set_result_hash: &[u8; 32],
) -> Result<()> {
    let mut hasher = Sha256::new();

    hasher.update((result_pairs.len() as u32).to_be_bytes());

    for pair in result_pairs {
        hasher.update(pair);
    }

    let computed: [u8; 32] = hasher.finalize().into();

    if &computed != tx_set_result_hash {
        return Err(ScpError::TxResultSetMismatch);
    }

    Ok(())
}

/// Proves a transaction succeeded and returns the state root it published.
///
/// Checks the results belong to the ledger, that the named transaction
/// succeeded, that it was a contract call, and that the contract announced a
/// new state root. That root is what a bridge relies on to trust Stellar's
/// state.
pub fn verify_state_root(input: &Inputs<'_>) -> Result<[u8; 32]> {
    verify_result_set_hash(input.result_pairs, input.tx_set_result_hash)?;
    let pair = input.result_pairs.get(input.result_index as usize).ok_or(
        ScpError::ResultIndexOutOfRange {
            index: input.result_index,
            len: input.result_pairs.len(),
        },
    )?;
    let success_hash = invoke_success_hash(pair)?;
    let preimage_hash: [u8; 32] = Sha256::digest(input.success_preimage_xdr).into();

    if preimage_hash != success_hash {
        return Err(ScpError::SuccessPreimageMismatch);
    }

    root_from_preimage(
        input.success_preimage_xdr,
        input.router_contract_id,
        input.root_event_topic,
    )
}

fn invoke_success_hash(pair: &[u8]) -> Result<[u8; 32]> {
    let mut d = Decoder::new(pair);
    let _transaction_hash = d.fixed32()?;
    let _fee_charged = d.u64()?;

    match d.i32()? {
        TX_SUCCESS => {}
        other => return Err(ScpError::TransactionNotSuccessful { code: other }),
    }

    let n_ops = d.vec_len(1)?;

    if n_ops != 1 {
        return Err(ScpError::NotASorobanInvocation);
    }

    if d.i32()? != OP_INNER {
        return Err(ScpError::NotASorobanInvocation);
    }

    if d.i32()? != OP_TYPE_INVOKE_HOST_FUNCTION {
        return Err(ScpError::NotASorobanInvocation);
    }

    match d.i32()? {
        INVOKE_HOST_FUNCTION_SUCCESS => {}
        other => return Err(ScpError::InvokeHostFunctionFailed { code: other }),
    }

    let success = d.fixed32()?;

    match d.i32()? {
        0 => {}
        other => {
            return Err(bad(&alloc::format!(
                "unsupported TransactionResult ext {other}"
            )))
        }
    }

    d.finish()?;

    Ok(success)
}

extern crate alloc;
