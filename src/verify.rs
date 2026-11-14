use alloc::vec::Vec;

use crate::{
    error::ScpError,
    primitives::execution::results::{verify_state_root, Inputs},
    primitives::scp::commit::confirmed_value as commit_confirmed_value,
    primitives::scp::envelope::{authenticate as envelope_authenticate, Authenticated},
    primitives::scp::quorum::QuorumSet,
    primitives::stellar::chain::walk_back as chain_walk_back,
    primitives::stellar::header::LedgerHeader,
    xdr::Result,
};

// The types in this module carry trust in their shape. Each has private fields
// and can only be built by the function above it in the pipeline, so holding one
// is proof the earlier steps ran. The module-level functions in `envelope`,
// `commit`, `chain`, and `results` are the primitives these wrap; a
// caller reaching for those takes on the responsibilities listed in SECURITY.md.

/// Signed statements for one slot of one network, every signature already checked.
#[derive(Clone, Debug)]
pub struct AuthenticatedBatch {
    network_id: [u8; 32],
    slot: u64,
    statements: Vec<Authenticated>,
}

impl AuthenticatedBatch {
    pub fn network_id(&self) -> &[u8; 32] {
        &self.network_id
    }

    pub fn slot(&self) -> u64 {
        self.slot
    }

    pub fn statements(&self) -> &[Authenticated] {
        &self.statements
    }
}

/// The one value a quorum of your trust root externalized for a slot.
#[derive(Clone, Debug)]
pub struct ConfirmedValue {
    network_id: [u8; 32],
    slot: u64,
    value_bytes: Vec<u8>,
}

impl ConfirmedValue {
    pub fn network_id(&self) -> &[u8; 32] {
        &self.network_id
    }

    pub fn slot(&self) -> u64 {
        self.slot
    }

    pub fn value_bytes(&self) -> &[u8] {
        &self.value_bytes
    }
}

/// A header proven to carry the value consensus agreed on.
///
/// This authenticates the ledger's identity: its transaction set, close time and
/// upgrades. It does not authenticate `tx_set_result_hash` or `bucket_list_hash`,
/// because validators sign the scpValue, not the whole header. Promote it with
/// [`bind_successor`] or reach it with [`walk_back`] before trusting those fields.
#[derive(Clone, Debug)]
pub struct ValueBoundHeader {
    header: LedgerHeader,
}

impl ValueBoundHeader {
    pub fn header(&self) -> &LedgerHeader {
        &self.header
    }
}

/// A header whose every field is authenticated.
///
/// Its `ledger_hash` is pinned either by the next slot naming it as predecessor
/// ([`bind_successor`]) or by the trusted chain ([`walk_back`]), so the result
/// and bucket-list hashes can be relied on. Only this can produce a
/// [`VerifiedRouterRoot`].
#[derive(Clone, Debug)]
pub struct AuthenticatedHeader {
    header: LedgerHeader,
}

impl AuthenticatedHeader {
    pub fn header(&self) -> &LedgerHeader {
        &self.header
    }
}

/// A router state root proven to belong to an authenticated ledger.
#[derive(Clone, Debug)]
pub struct VerifiedRouterRoot {
    ledger_seq: u32,
    router_id: [u8; 32],
    root: [u8; 32],
}

impl VerifiedRouterRoot {
    pub fn ledger_seq(&self) -> u32 {
        self.ledger_seq
    }

    pub fn router_id(&self) -> &[u8; 32] {
        &self.router_id
    }

    pub fn root(&self) -> &[u8; 32] {
        &self.root
    }
}

/// Check every signature, slot and quorum-set preimage, and keep the context.
pub fn authenticate(
    network_id: &[u8; 32],
    slot: u64,
    envelopes_xdr: &[Vec<u8>],
    quorum_sets_xdr: &[Vec<u8>],
) -> Result<AuthenticatedBatch> {
    let statements = envelope_authenticate(network_id, slot, envelopes_xdr, quorum_sets_xdr)?;

    Ok(AuthenticatedBatch {
        network_id: *network_id,
        slot,
        statements,
    })
}

/// Confirm a single value reached confirm-commit for a BFT-sound trust root.
pub fn confirmed_value(local: &QuorumSet, batch: &AuthenticatedBatch) -> Result<ConfirmedValue> {
    local.check_sane(true)?;

    let value_bytes = commit_confirmed_value(local, &batch.statements)?;

    Ok(ConfirmedValue {
        network_id: batch.network_id,
        slot: batch.slot,
        value_bytes,
    })
}

/// Bind the externalized value to a ledger header.
pub fn bind_header(value: &ConfirmedValue, ledger_header_xdr: &[u8]) -> Result<ValueBoundHeader> {
    let header = LedgerHeader::decode(ledger_header_xdr)?;

    if u64::from(header.ledger_seq) != value.slot {
        return Err(ScpError::HeaderSlotMismatch {
            expected: value.slot,
            found: u64::from(header.ledger_seq),
        });
    }

    if header.scp_value_bytes != value.value_bytes {
        return Err(ScpError::HeaderValueMismatch);
    }

    Ok(ValueBoundHeader { header })
}

/// Promote a value-bound header to fully authenticated using the next slot.
///
/// `successor` must be the value-bound header for the following ledger, and it
/// must name this header's `ledger_hash` as its predecessor. That link pins this
/// header's whole content, so its result and bucket-list hashes become trusted.
pub fn bind_successor(
    header: &ValueBoundHeader,
    successor: &ValueBoundHeader,
) -> Result<AuthenticatedHeader> {
    let expected = header.header.ledger_seq + 1;

    if successor.header.ledger_seq != expected {
        return Err(ScpError::SuccessorNotNext {
            expected,
            found: successor.header.ledger_seq,
        });
    }

    if successor.header.previous_ledger_hash != header.header.ledger_hash {
        return Err(ScpError::ChainBroken {
            seq: header.header.ledger_seq,
            child: successor.header.ledger_seq,
        });
    }

    Ok(AuthenticatedHeader {
        header: header.header.clone(),
    })
}

/// Extend trust backward from an authenticated anchor to an older ledger.
///
/// `headers_descending` is every header from the anchor's predecessor down to
/// the target. On success the target is a genuine ancestor of the anchor, so its
/// whole content is trusted.
pub fn walk_back(
    anchor: &AuthenticatedHeader,
    headers_descending: &[&[u8]],
    target_seq: u32,
) -> Result<AuthenticatedHeader> {
    chain_walk_back(
        anchor.header.ledger_seq,
        &anchor.header.previous_ledger_hash,
        headers_descending,
        target_seq,
    )?;

    let target_bytes = headers_descending
        .last()
        .copied()
        .ok_or(ScpError::ChainLengthMismatch {
            anchor: anchor.header.ledger_seq,
            target: target_seq,
            expected: (anchor.header.ledger_seq - target_seq) as usize,
            found: 0,
        })?;

    let header = LedgerHeader::decode(target_bytes)?;

    Ok(AuthenticatedHeader { header })
}

/// Verify the router state root an authenticated ledger published.
///
/// Takes only an [`AuthenticatedHeader`], so a header whose `tx_set_result_hash`
/// has not been pinned cannot be used here.
pub fn verify_router_root(
    header: &AuthenticatedHeader,
    result_pairs: &[Vec<u8>],
    result_index: u32,
    success_preimage_xdr: &[u8],
    router_contract_id: &[u8; 32],
    root_event_topic: &[u8],
) -> Result<VerifiedRouterRoot> {
    let inputs = Inputs {
        tx_set_result_hash: &header.header.tx_set_result_hash,
        result_pairs,
        result_index,
        success_preimage_xdr,
        router_contract_id,
        root_event_topic,
    };

    let root = verify_state_root(&inputs)?;

    Ok(VerifiedRouterRoot {
        ledger_seq: header.header.ledger_seq,
        router_id: *router_contract_id,
        root,
    })
}

/// Authenticate the evidence for a slot and confirm its externalized value.
pub fn verify_consensus(
    network_id: &[u8; 32],
    local: &QuorumSet,
    slot: u64,
    envelopes_xdr: &[Vec<u8>],
    quorum_sets_xdr: &[Vec<u8>],
) -> Result<ConfirmedValue> {
    let batch = authenticate(network_id, slot, envelopes_xdr, quorum_sets_xdr)?;

    confirmed_value(local, &batch)
}

/// Verify consensus and bind the value to a header in one step.
pub fn verify_header(
    network_id: &[u8; 32],
    local: &QuorumSet,
    slot: u64,
    envelopes_xdr: &[Vec<u8>],
    quorum_sets_xdr: &[Vec<u8>],
    ledger_header_xdr: &[u8],
) -> Result<ValueBoundHeader> {
    let value = verify_consensus(network_id, local, slot, envelopes_xdr, quorum_sets_xdr)?;

    bind_header(&value, ledger_header_xdr)
}

extern crate alloc;
