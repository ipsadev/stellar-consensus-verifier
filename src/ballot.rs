use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use ed25519_dalek::Signature;
use ed25519_dalek::VerifyingKey;

use crate::envelope::{Ballot, Envelope, Statement};
use crate::error::ScpError;
use crate::quorum::{is_quorum, NodeId, QuorumSet};
use crate::xdr::Result;

/// A range of consensus rounds.
pub type Interval = (u32, u32);

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
        return Err(ScpError::NoConfirmedCommit);
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

/// A quorum set containing only this validator.
///
/// Stands in for a validator that has already declared a value final, whose
/// own configuration no longer affects the outcome.
pub fn singleton_quorum_set(node: NodeId) -> QuorumSet {
    QuorumSet {
        threshold: 1,
        validators: alloc::vec![node],
        inner_sets: Vec::new(),
    }
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

/// Whether a statement backs committing this value across a range of rounds.
pub fn commit_predicate(ballot: &Ballot, check: Interval, statement: &Statement) -> bool {
    match statement {
        Statement::Prepare(_) => false,
        Statement::Confirm(c) => {
            c.ballot.compatible(ballot)
                && c.commit_counter <= check.0
                && check.1 <= c.highest_confirmed_ballot_counter
        }
        Statement::Externalize(e) => e.commit.compatible(ballot) && e.commit.counter <= check.0,
    }
}

/// The rounds worth testing, gathered from what the validators actually said.
pub fn commit_boundaries(ballot: &Ballot, statements: &[&Statement]) -> Vec<u32> {
    let mut out: Vec<u32> = Vec::new();
    let mut push = |v: u32| {
        if !out.contains(&v) {
            out.push(v);
        }
    };

    for statement in statements {
        match statement {
            Statement::Prepare(p) => {
                if p.ballot.compatible(ballot) && p.commit_counter != 0 {
                    push(p.commit_counter);
                    push(p.highest_confirmed_ballot_counter);
                }
            }
            Statement::Confirm(c) => {
                if c.ballot.compatible(ballot) {
                    push(c.commit_counter);
                    push(c.highest_confirmed_ballot_counter);
                }
            }
            Statement::Externalize(e) => {
                if e.commit.compatible(ballot) {
                    push(e.commit.counter);
                    push(e.highest_confirmed_ballot_counter);
                    push(u32::MAX);
                }
            }
        }
    }

    out.sort_unstable();

    out
}

fn federated_ratify(
    local: &QuorumSet,
    evidence: &[Authenticated],
    voted: impl Fn(&Statement) -> bool,
) -> bool {
    let candidates: Vec<(NodeId, QuorumSet)> = evidence
        .iter()
        .filter(|item| voted(&item.statement))
        .filter_map(|item| item.quorum_set.clone().map(|qset| (item.node_id, qset)))
        .collect();

    is_quorum(local, &candidates)
}

/// Finds the widest range of rounds that satisfies a test.
///
/// Fixes the top of the range first, then stretches downwards.
pub fn find_extended_interval(
    boundaries: &[u32],
    predicate: impl Fn(Interval) -> bool,
) -> Option<Interval> {
    let mut candidate: Option<Interval> = None;

    for boundary in boundaries.iter().rev() {
        let current = match candidate {
            None => (*boundary, *boundary),
            Some((_, high)) => {
                if *boundary > high {
                    continue;
                }

                (*boundary, high)
            }
        };

        if predicate(current) {
            candidate = Some(current);
        } else if candidate.is_some() {
            break;
        }
    }

    candidate
}

/// Whether enough validators committed to this value for it to be settled.
///
/// This is the real question consensus answers, and it is not simply a count:
/// validators may have committed across different rounds, and a quorum has to
/// agree on a range they all cover.
pub fn confirmed_commit(
    local: &QuorumSet,
    evidence: &[Authenticated],
    value: &[u8],
) -> Option<Interval> {
    let latest = latest_statements(evidence);
    let ballot = Ballot {
        counter: 0,
        value: value.to_vec(),
    };
    let statements: Vec<&Statement> = latest.iter().map(|item| &item.statement).collect();
    let boundaries = commit_boundaries(&ballot, &statements);

    find_extended_interval(&boundaries, |check| {
        federated_ratify(local, &latest, |statement| {
            commit_predicate(&ballot, check, statement)
        })
    })
}

/// The value the network settled on, according to this evidence.
///
/// Fails if nothing reaches agreement, and reports fork evidence if two
/// different values somehow both do.
pub fn confirmed_value(local: &QuorumSet, evidence: &[Authenticated]) -> Result<Vec<u8>> {
    let latest = latest_statements(evidence);
    let mut candidates: Vec<Vec<u8>> = Vec::new();

    for item in &latest {
        let value = item.statement.value();

        if !value.is_empty() && !candidates.iter().any(|held| held == value) {
            candidates.push(value.to_vec());
        }
    }

    let mut confirmed: Option<Vec<u8>> = None;

    for value in candidates {
        if confirmed_commit(local, &latest, &value).is_none() {
            continue;
        }

        if confirmed.is_some() {
            return Err(ScpError::ForkedConfirmCommit);
        }

        confirmed = Some(value);
    }

    confirmed.ok_or(ScpError::NoConfirmedCommit)
}

extern crate alloc;
