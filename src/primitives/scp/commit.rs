use alloc::vec::Vec;

use crate::{
    error::ScpError,
    primitives::scp::{
        ballot::Ballot,
        envelope::{latest_statements, Authenticated},
        quorum::{is_quorum, NodeId, QuorumSet},
        statement::Statement,
    },
    xdr::Result,
};

/// A range of consensus rounds.
pub type Interval = (u32, u32);

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
        .filter(|item| voted(item.statement()))
        .filter_map(|item| {
            item.quorum_set()
                .cloned()
                .map(|qset| (item.node_id(), qset))
        })
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
    let statements: Vec<&Statement> = latest.iter().map(|item| item.statement()).collect();
    let boundaries = commit_boundaries(&ballot, &statements);

    find_extended_interval(&boundaries, |check| {
        federated_ratify(local, &latest, |statement| {
            commit_predicate(&ballot, check, statement)
        })
    })
    .filter(|(low, _)| *low != 0)
}

/// The value the network settled on, according to this evidence.
///
/// Fails if nothing reaches agreement, and reports fork evidence if two
/// different values somehow both do.
pub fn confirmed_value(local: &QuorumSet, evidence: &[Authenticated]) -> Result<Vec<u8>> {
    let latest = latest_statements(evidence);
    let mut candidates: Vec<Vec<u8>> = Vec::new();

    for item in &latest {
        let value = item.statement().value();

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
