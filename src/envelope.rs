use alloc::vec::Vec;

use super::xdr::{Decoder, Result};
use crate::error::ScpError;

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

fn bad(what: &str) -> ScpError {
    ScpError::InvalidWire(what.into())
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// A proposed value and which round proposed it.
///
/// Validators may need several rounds to agree; the value is what matters.
pub struct Ballot {
    pub counter: u32,
    pub value: Vec<u8>,
}

impl Ballot {
    /// Whether two ballots carry the same value, whatever round they came from.
    pub fn compatible(&self, other: &Self) -> bool {
        self.value == other.value
    }

    /// Whether this ballot is both older than another and about a different value.
    pub fn less_and_incompatible(&self, other: &Self) -> bool {
        self.compare(other) <= 0 && !self.compatible(other)
    }

    fn compare(&self, other: &Self) -> i32 {
        if self.counter != other.counter {
            return if self.counter < other.counter { -1 } else { 1 };
        }

        match self.value.cmp(&other.value) {
            core::cmp::Ordering::Less => -1,
            core::cmp::Ordering::Greater => 1,
            core::cmp::Ordering::Equal => 0,
        }
    }
}

#[derive(Clone, Debug)]
/// A validator weighing a value, not yet committed to it.
pub struct Prepare {
    pub quorum_set_hash: [u8; 32],
    pub ballot: Ballot,
    pub prepared: Option<Ballot>,
    pub prepared_prime: Option<Ballot>,
    pub commit_counter: u32,
    pub highest_confirmed_ballot_counter: u32,
}

#[derive(Clone, Debug)]
/// A validator that has accepted a value.
///
/// `commit_counter` and `highest_confirmed_ballot_counter` bound the rounds it
/// accepted it for, which is what makes it count as evidence.
pub struct Confirm {
    pub ballot: Ballot,
    pub prepared_counter: u32,
    pub commit_counter: u32,
    pub highest_confirmed_ballot_counter: u32,
    pub quorum_set_hash: [u8; 32],
}

#[derive(Clone, Debug)]
/// A validator declaring a value final.
pub struct Externalize {
    pub commit: Ballot,
    pub highest_confirmed_ballot_counter: u32,
    pub commit_quorum_set_hash: [u8; 32],
}

#[derive(Clone, Debug)]
/// What a validator said about a ledger.
pub enum Statement {
    Prepare(Prepare),
    Confirm(Confirm),
    Externalize(Externalize),
}

impl Statement {
    /// Which quorum set the validator says it was following.
    pub fn quorum_set_hash(&self) -> [u8; 32] {
        match self {
            Self::Prepare(p) => p.quorum_set_hash,
            Self::Confirm(c) => c.quorum_set_hash,
            Self::Externalize(e) => e.commit_quorum_set_hash,
        }
    }

    /// The ballot this statement effectively stands behind.
    pub fn working_ballot(&self) -> Ballot {
        match self {
            Self::Prepare(p) => p.ballot.clone(),
            Self::Confirm(c) => Ballot {
                counter: c.commit_counter,
                value: c.ballot.value.clone(),
            },
            Self::Externalize(e) => e.commit.clone(),
        }
    }

    /// The value the statement is about.
    pub fn value(&self) -> &[u8] {
        match self {
            Self::Prepare(p) => &p.ballot.value,
            Self::Confirm(c) => &c.ballot.value,
            Self::Externalize(e) => &e.commit.value,
        }
    }

    /// The statement as a final declaration, if that is what it is.
    pub fn as_externalize(&self) -> Option<&Externalize> {
        match self {
            Self::Externalize(e) => Some(e),
            _ => None,
        }
    }

    /// How far through consensus this kind of statement is.
    pub fn rank(&self) -> u8 {
        match self {
            Self::Prepare(_) => 0,
            Self::Confirm(_) => 1,
            Self::Externalize(_) => 2,
        }
    }

    /// Whether this statement supersedes an earlier one from the same validator.
    ///
    /// Only a validator's newest statement counts, so it cannot be made to look
    /// like several supporters.
    pub fn is_newer_than(&self, older: &Self) -> bool {
        if self.rank() != older.rank() {
            return older.rank() < self.rank();
        }

        match (older, self) {
            (Self::Externalize(_), Self::Externalize(_)) => false,
            (Self::Confirm(old), Self::Confirm(new)) => {
                let ballots = old.ballot.compare(&new.ballot);

                if ballots != 0 {
                    return ballots < 0;
                }

                if old.prepared_counter != new.prepared_counter {
                    return old.prepared_counter < new.prepared_counter;
                }

                old.highest_confirmed_ballot_counter < new.highest_confirmed_ballot_counter
            }
            (Self::Prepare(old), Self::Prepare(new)) => {
                let ballots = old.ballot.compare(&new.ballot);

                if ballots != 0 {
                    return ballots < 0;
                }

                let prepared = compare_optional(old.prepared.as_ref(), new.prepared.as_ref());

                if prepared != 0 {
                    return prepared < 0;
                }

                let prime =
                    compare_optional(old.prepared_prime.as_ref(), new.prepared_prime.as_ref());

                if prime != 0 {
                    return prime < 0;
                }

                old.highest_confirmed_ballot_counter < new.highest_confirmed_ballot_counter
            }
            _ => false,
        }
    }

    fn check_sane(&self) -> Result<()> {
        match self {
            Self::Prepare(p) => {
                if p.ballot.counter == 0 {
                    return Err(ScpError::BallotCounterZero);
                }

                let ordered = match (&p.prepared_prime, &p.prepared) {
                    (Some(prime), Some(prepared)) => prime.less_and_incompatible(prepared),
                    _ => true,
                };

                if !ordered {
                    return Err(ScpError::MalformedPrepare);
                }

                let highest = p.highest_confirmed_ballot_counter;
                let prepared_covers = match &p.prepared {
                    Some(prepared) => highest <= prepared.counter,
                    None => false,
                };

                if highest != 0 && !prepared_covers {
                    return Err(ScpError::MalformedPrepare);
                }

                if p.commit_counter != 0
                    && !(highest != 0 && p.ballot.counter >= highest && highest >= p.commit_counter)
                {
                    return Err(ScpError::MalformedPrepare);
                }

                Ok(())
            }
            Self::Confirm(c) => {
                if c.ballot.counter == 0 {
                    return Err(ScpError::BallotCounterZero);
                }

                if c.highest_confirmed_ballot_counter > c.ballot.counter
                    || c.commit_counter > c.highest_confirmed_ballot_counter
                {
                    return Err(ScpError::MalformedConfirm);
                }

                Ok(())
            }
            Self::Externalize(e) => {
                if e.commit.counter == 0 {
                    return Err(ScpError::CommitCounterZero);
                }

                if e.commit.value.is_empty() {
                    return Err(ScpError::EmptyCommitValue);
                }

                if e.highest_confirmed_ballot_counter < e.commit.counter {
                    return Err(ScpError::HighestConfirmedBelowCommit {
                        highest: e.highest_confirmed_ballot_counter,
                        commit: e.commit.counter,
                    });
                }

                Ok(())
            }
        }
    }
}

fn compare_optional(older: Option<&Ballot>, newer: Option<&Ballot>) -> i32 {
    match (older, newer) {
        (Some(a), Some(b)) => a.compare(b),
        (Some(_), None) => 1,
        (None, Some(_)) => -1,
        (None, None) => 0,
    }
}

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

fn read_ballot(d: &mut Decoder<'_>) -> Result<Ballot> {
    let counter = d.u32()?;
    let value = d.var_bytes()?.to_vec();

    Ok(Ballot { counter, value })
}

fn read_optional_ballot(d: &mut Decoder<'_>) -> Result<Option<Ballot>> {
    match d.u32()? {
        0 => Ok(None),
        1 => Ok(Some(read_ballot(d)?)),
        _ => Err(bad("optional ballot flag is not 0 or 1")),
    }
}

fn read_prepare(d: &mut Decoder<'_>) -> Result<Prepare> {
    let quorum_set_hash = d.fixed32()?;
    let ballot = read_ballot(d)?;
    let prepared = read_optional_ballot(d)?;
    let prepared_prime = read_optional_ballot(d)?;
    let commit_counter = d.u32()?;
    let highest_confirmed_ballot_counter = d.u32()?;

    Ok(Prepare {
        quorum_set_hash,
        ballot,
        prepared,
        prepared_prime,
        commit_counter,
        highest_confirmed_ballot_counter,
    })
}

fn read_confirm(d: &mut Decoder<'_>) -> Result<Confirm> {
    let ballot = read_ballot(d)?;
    let prepared_counter = d.u32()?;
    let commit_counter = d.u32()?;
    let highest_confirmed_ballot_counter = d.u32()?;
    let quorum_set_hash = d.fixed32()?;

    Ok(Confirm {
        ballot,
        prepared_counter,
        commit_counter,
        highest_confirmed_ballot_counter,
        quorum_set_hash,
    })
}

fn read_externalize(d: &mut Decoder<'_>) -> Result<Externalize> {
    let commit = read_ballot(d)?;
    let highest_confirmed_ballot_counter = d.u32()?;
    let commit_quorum_set_hash = d.fixed32()?;

    Ok(Externalize {
        commit,
        highest_confirmed_ballot_counter,
        commit_quorum_set_hash,
    })
}

extern crate alloc;
