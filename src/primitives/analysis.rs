use alloc::vec::Vec;

use crate::primitives::scp::quorum::{is_quorum_closed, is_quorum_slice, NodeId, QuorumSet};

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

extern crate alloc;
