use crate::xdr::{Decoder, Result};
use crate::{
    error::ScpError,
    primitives::scp::ballot::{compare_optional, read_ballot, read_optional_ballot, Ballot},
};

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

    pub fn check_sane(&self) -> Result<()> {
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

pub fn read_prepare(d: &mut Decoder<'_>) -> Result<Prepare> {
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

pub fn read_confirm(d: &mut Decoder<'_>) -> Result<Confirm> {
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

pub fn read_externalize(d: &mut Decoder<'_>) -> Result<Externalize> {
    let commit = read_ballot(d)?;
    let highest_confirmed_ballot_counter = d.u32()?;
    let commit_quorum_set_hash = d.fixed32()?;

    Ok(Externalize {
        commit,
        highest_confirmed_ballot_counter,
        commit_quorum_set_hash,
    })
}
