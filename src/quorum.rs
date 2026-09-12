use alloc::vec::Vec;

use sha2::{Digest, Sha256};

use super::xdr::{Decoder, Result, MAX_QSET_DEPTH, MAX_QSET_VALIDATORS};
use crate::error::ScpError;

/// A validator, identified by its public key.
pub type NodeId = [u8; 32];

#[derive(Clone, Debug, PartialEq, Eq)]
/// Who a validator listens to, and how many of them it needs to agree.
///
/// Entries can be validators or nested groups, which lets an operator say
/// things like "five of these seven organisations".
pub struct QuorumSet {
    pub threshold: u32,
    pub validators: Vec<NodeId>,
    pub inner_sets: Vec<QuorumSet>,
}

fn bad(what: &str) -> ScpError {
    ScpError::InvalidWire(what.into())
}

impl QuorumSet {
    /// Reads a quorum set from its published bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut d = Decoder::new(bytes);
        let qset = Self::read(&mut d, 0)?;

        d.finish()?;

        Ok(qset)
    }

    fn read(d: &mut Decoder<'_>, depth: u32) -> Result<Self> {
        if depth > MAX_QSET_DEPTH {
            return Err(bad("quorum set nested too deeply"));
        }

        let threshold = d.u32()?;
        let n_validators = d.vec_len(MAX_QSET_VALIDATORS)?;
        let mut validators = Vec::with_capacity(n_validators);

        for _ in 0..n_validators {
            validators.push(d.node_id()?);
        }

        let n_inner = d.vec_len(MAX_QSET_VALIDATORS)?;
        let mut inner_sets = Vec::with_capacity(n_inner);

        for _ in 0..n_inner {
            inner_sets.push(Self::read(d, depth + 1)?);
        }

        Ok(Self {
            threshold,
            validators,
            inner_sets,
        })
    }

    fn count_validators(&self) -> usize {
        self.validators.len()
            + self
                .inner_sets
                .iter()
                .map(Self::count_validators)
                .sum::<usize>()
    }

    fn collect(&self, out: &mut Vec<NodeId>) {
        out.extend_from_slice(&self.validators);

        for inner in &self.inner_sets {
            inner.collect(out);
        }
    }

    /// Rejects a quorum set that could never work: no threshold, a threshold
    /// nothing could meet, too many or too few validators, or the same validator
    /// named twice.
    ///
    /// Set `extra` for a quorum set *you* are choosing to trust. It then also
    /// demands a strict majority at every level, which is what stops your own
    /// trust root from being split two ways.
    pub fn check_sane(&self, extra: bool) -> Result<()> {
        self.check_node(extra, 0)?;
        let total = self.count_validators();

        if !(1..=MAX_QSET_VALIDATORS).contains(&total) {
            return Err(bad("quorum set must name between 1 and 1000 validators"));
        }

        let mut all = Vec::with_capacity(total);

        self.collect(&mut all);
        let mut sorted = all.clone();

        sorted.sort_unstable();
        sorted.dedup();

        if sorted.len() != all.len() {
            return Err(bad("duplicate validator in quorum set"));
        }

        Ok(())
    }

    fn check_node(&self, extra: bool, depth: u32) -> Result<()> {
        if depth > MAX_QSET_DEPTH {
            return Err(bad("quorum set nested too deeply"));
        }

        if self.threshold < 1 {
            return Err(bad("quorum set threshold must be at least 1"));
        }

        let entries = self.validators.len() + self.inner_sets.len();

        if self.threshold as usize > entries {
            return Err(bad("quorum set threshold exceeds its entries"));
        }

        if extra {
            let v_blocking = entries - self.threshold as usize + 1;

            if (self.threshold as usize) < v_blocking {
                return Err(bad("quorum set threshold is below its v-blocking size"));
            }
        }

        for inner in &self.inner_sets {
            inner.check_node(extra, depth + 1)?;
        }

        Ok(())
    }

    /// Hashes a quorum set, so a validator's claim about which one it runs can be
    /// checked against the bytes supplied.
    pub fn hash(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }
}

/// Whether `nodes` contains enough of a quorum set to satisfy it.
///
/// A nested group counts as one entry, satisfied or not.
pub fn is_quorum_slice(qset: &QuorumSet, nodes: &[NodeId]) -> bool {
    let mut left = qset.threshold as i64;

    if left < 1 {
        return false;
    }

    for v in &qset.validators {
        if nodes.contains(v) {
            left -= 1;

            if left <= 0 {
                return true;
            }
        }
    }

    for inner in &qset.inner_sets {
        if is_quorum_slice(inner, nodes) {
            left -= 1;

            if left <= 0 {
                return true;
            }
        }
    }

    false
}

/// Whether this group of validators is self-sufficient: every one of them has
/// enough of the others present to satisfy its own quorum set.
pub fn is_quorum_closed(members: &[(NodeId, QuorumSet)]) -> bool {
    if members.is_empty() {
        return false;
    }

    let ids: Vec<NodeId> = members.iter().map(|(id, _)| *id).collect();

    members.iter().all(|(_, qset)| is_quorum_slice(qset, &ids))
}

/// Checks a claim that the network could split in two.
///
/// Stellar is only safe while every two self-sufficient groups share at least
/// one validator. Proving that holds is expensive; disproving it is cheap,
/// because the proof is just two such groups with nobody in common. This
/// verifies such a proof.
pub fn quorum_intersection_refuted(
    fbas: &[(NodeId, QuorumSet)],
    first: &[NodeId],
    second: &[NodeId],
) -> bool {
    if first.iter().any(|id| second.contains(id)) {
        return false;
    }

    let Some(one) = members_of(fbas, first) else {
        return false;
    };
    let Some(other) = members_of(fbas, second) else {
        return false;
    };

    is_quorum_closed(&one) && is_quorum_closed(&other)
}

/// Whether a split would actually endanger *you*.
///
/// A split elsewhere in the network is not your problem unless both sides can
/// satisfy your own trust root. Note that a trust root accepted by
/// [`QuorumSet::check_sane`] with `extra` set can never be split this way.
pub fn quorum_split_threatens(
    local: &QuorumSet,
    fbas: &[(NodeId, QuorumSet)],
    first: &[NodeId],
    second: &[NodeId],
) -> bool {
    quorum_intersection_refuted(fbas, first, second)
        && is_quorum_slice(local, first)
        && is_quorum_slice(local, second)
}

fn members_of(fbas: &[(NodeId, QuorumSet)], nodes: &[NodeId]) -> Option<Vec<(NodeId, QuorumSet)>> {
    let mut out = Vec::with_capacity(nodes.len());

    for node in nodes {
        if out
            .iter()
            .any(|(held, _): &(NodeId, QuorumSet)| held == node)
        {
            return None;
        }

        let qset = fbas.iter().find(|(id, _)| id == node)?;

        out.push(qset.clone());
    }

    Some(out)
}

/// Whether these signers amount to a quorum for your trust root.
///
/// Signers whose own quorum set is not satisfied by the others present are
/// dropped, repeatedly, until the group settles. Your trust root is then
/// checked against whoever is left.
pub fn is_quorum(local: &QuorumSet, signers: &[(NodeId, QuorumSet)]) -> bool {
    let mut surviving: Vec<NodeId> = signers.iter().map(|(id, _)| *id).collect();

    loop {
        let before = surviving.len();
        let snapshot = surviving.clone();

        surviving.retain(|id| {
            signers
                .iter()
                .find(|(other, _)| other == id)
                .is_some_and(|(_, qset)| is_quorum_slice(qset, &snapshot))
        });

        if surviving.len() == before {
            break;
        }
    }

    is_quorum_slice(local, &surviving)
}

extern crate alloc;
