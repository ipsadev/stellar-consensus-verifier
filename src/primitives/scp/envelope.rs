use alloc::{format, string::String, vec::Vec};

use ed25519_dalek::{Signature, VerifyingKey};

use crate::xdr::{Decoder, Result};
use crate::{
    error::{bad, ScpError},
    primitives::scp::{
        quorum::{singleton_quorum_set, NodeId, QuorumSet},
        statement::{read_confirm, read_externalize, read_prepare, Externalize, Statement},
    },
};

/// Marks a signature as covering a consensus message, so it cannot be reused
/// as any other kind of Stellar signature.
pub const ENVELOPE_TYPE_SCP: [u8; 4] = [0, 0, 0, 1];

/// A validator still weighing a value.
pub const SCP_ST_PREPARE: i32 = 0;
/// A validator that has accepted a value and is waiting for others.
pub const SCP_ST_CONFIRM: i32 = 1;
/// A validator declaring a value final.
pub const SCP_ST_EXTERNALIZE: i32 = 2;
/// Part of choosing what to vote on, which this crate does not need.
pub const SCP_ST_NOMINATE: i32 = 3;

#[derive(Clone, Debug)]
/// A signed statement from one validator.
///
/// `statement_bytes` is the exact slice the signature covers, kept as-is so
/// nothing is lost or reshaped before the signature is checked.
pub struct Envelope {
    pub node_id: [u8; 32],
    pub slot_index: u64,
    pub statement: Statement,
    pub signature: [u8; 64],
    pub statement_bytes: Vec<u8>,
}

impl Envelope {
    /// Reads a signed statement, rejecting one that is malformed or that no
    /// honest validator would have sent.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut decoded = Decoder::new(bytes);

        let statement_start = decoded.position();
        let node_id = decoded.node_id()?;
        let slot_index = decoded.u64()?;
        let kind = decoded.i32()?;

        let statement = match kind {
            SCP_ST_PREPARE => Statement::Prepare(read_prepare(&mut decoded)?),
            SCP_ST_CONFIRM => Statement::Confirm(read_confirm(&mut decoded)?),
            SCP_ST_EXTERNALIZE => Statement::Externalize(read_externalize(&mut decoded)?),
            SCP_ST_NOMINATE => return Err(ScpError::NominationStatement),
            other => return Err(bad(&alloc::format!("unknown statement type {other}"))),
        };

        statement.check_sane()?;

        let statement_bytes = decoded.slice_from(statement_start).to_vec();
        let signature = decoded.signature()?;

        decoded.finish()?;

        Ok(Self {
            node_id,
            slot_index,
            statement,
            signature,
            statement_bytes,
        })
    }

    /// The statement as a final declaration, or an error if it is not one.
    pub fn externalize(&self) -> Result<&Externalize> {
        self.statement
            .as_externalize()
            .ok_or(ScpError::NotExternalize)
    }

    /// Rebuilds exactly what the validator signed.
    ///
    /// Includes the network it was signing for, so a message from testnet cannot
    /// be replayed on the public network.
    pub fn signing_payload(&self, network_id: &[u8; 32]) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 4 + self.statement_bytes.len());

        out.extend_from_slice(network_id);
        out.extend_from_slice(&ENVELOPE_TYPE_SCP);
        out.extend_from_slice(&self.statement_bytes);

        out
    }
}

#[derive(Clone, Debug)]
/// A statement that has been proven genuine.
///
/// Only [`authenticate`] can produce one, so anything reasoning over these has
/// already had signatures checked and quorum sets matched to their hashes.
/// There is no way to skip that step.
pub struct Authenticated {
    node_id: NodeId,
    statement: Statement,
    quorum_set: Option<QuorumSet>,
}

impl Authenticated {
    /// Which validator signed it.
    pub fn node_id(&self) -> NodeId {
        self.node_id
    }

    /// What it said.
    pub fn statement(&self) -> &Statement {
        &self.statement
    }

    /// The quorum set used when counting this validator, if one is known.
    pub fn quorum_set(&self) -> Option<&QuorumSet> {
        self.quorum_set.as_ref()
    }

    /// The quorum set this validator actually published, if it did.
    ///
    /// A validator declaring a value final does not republish its quorum set, so
    /// this is empty for those. Use it when you need a validator's real
    /// configuration rather than a stand-in.
    pub fn declared_quorum_set(&self) -> Option<&QuorumSet> {
        if self.statement.as_externalize().is_some() {
            return None;
        }

        self.quorum_set.as_ref()
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);

    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }

    out
}

/// Checks one signature, the same way Stellar itself does.
pub fn verify_signature(node_id: &[u8; 32], payload: &[u8], signature: &[u8; 64]) -> bool {
    let Ok(key) = VerifyingKey::from_bytes(node_id) else {
        return false;
    };

    key.verify_strict(payload, &Signature::from_bytes(signature))
        .is_ok()
}

/// Turns raw messages into evidence that can be trusted.
///
/// Checks every signature, that each message is for the slot being proven, and
/// that every quorum set supplied really hashes to what its validator named.
/// A validator whose quorum set cannot be matched is simply not counted,
/// rather than the whole proof being rejected.
///
/// This is the only way into the rest of this module.
pub fn authenticate(
    network_id: &[u8; 32],
    slot_index: u64,
    envelopes_xdr: &[Vec<u8>],
    quorum_sets_xdr: &[Vec<u8>],
) -> Result<Vec<Authenticated>> {
    let mut envelopes = Vec::with_capacity(envelopes_xdr.len());

    for raw in envelopes_xdr {
        let envelope = match Envelope::decode(raw) {
            Err(ScpError::NominationStatement) => continue,
            other => other?,
        };

        if envelope.slot_index != slot_index {
            return Err(ScpError::EnvelopeSlotMismatch {
                expected: slot_index,
                found: envelope.slot_index,
            });
        }

        if !verify_signature(
            &envelope.node_id,
            &envelope.signing_payload(network_id),
            &envelope.signature,
        ) {
            return Err(ScpError::UnauthenticatedEnvelope {
                node: hex(&envelope.node_id),
            });
        }

        envelopes.push(envelope);
    }

    if envelopes.is_empty() {
        return Err(ScpError::NoBallotEvidence);
    }

    let preimages = index_quorum_sets(quorum_sets_xdr);
    let mut evidence = Vec::with_capacity(envelopes.len());

    for envelope in envelopes {
        let quorum_set = resolve_quorum_set(&envelope, &preimages);

        evidence.push(Authenticated {
            node_id: envelope.node_id,
            statement: envelope.statement,
            quorum_set,
        });
    }

    Ok(evidence)
}

fn index_quorum_sets(raw: &[Vec<u8>]) -> Vec<([u8; 32], QuorumSet)> {
    let mut out = Vec::with_capacity(raw.len());

    for bytes in raw {
        let Ok(qset) = QuorumSet::decode(bytes) else {
            continue;
        };

        if qset.check_sane(false).is_err() {
            continue;
        }

        out.push((QuorumSet::hash(bytes), qset));
    }

    out
}

fn resolve_quorum_set(
    envelope: &Envelope,
    preimages: &[([u8; 32], QuorumSet)],
) -> Option<QuorumSet> {
    if envelope.statement.as_externalize().is_some() {
        return Some(singleton_quorum_set(envelope.node_id));
    }

    let named = envelope.statement.quorum_set_hash();

    preimages
        .iter()
        .find(|(hash, _)| *hash == named)
        .map(|(_, qset)| qset.clone())
}

/// Keeps only each validator's newest statement, so nobody can be counted twice.
pub fn latest_statements(evidence: &[Authenticated]) -> Vec<Authenticated> {
    let mut latest: Vec<Authenticated> = Vec::new();

    for item in evidence {
        match latest.iter_mut().find(|held| held.node_id == item.node_id) {
            Some(held) => {
                if item.statement.is_newer_than(&held.statement) {
                    *held = item.clone();
                }
            }
            None => latest.push(item.clone()),
        }
    }

    latest
}

extern crate alloc;
