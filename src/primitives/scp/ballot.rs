use alloc::vec::Vec;

use crate::error::bad;
use crate::xdr::{Decoder, Result};

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

    pub fn compare(&self, other: &Self) -> i32 {
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

pub fn read_ballot(d: &mut Decoder<'_>) -> Result<Ballot> {
    let counter = d.u32()?;
    let value = d.var_bytes()?.to_vec();

    Ok(Ballot { counter, value })
}

pub fn read_optional_ballot(d: &mut Decoder<'_>) -> Result<Option<Ballot>> {
    match d.u32()? {
        0 => Ok(None),
        1 => Ok(Some(read_ballot(d)?)),
        _ => Err(bad("optional ballot flag is not 0 or 1")),
    }
}

pub fn compare_optional(older: Option<&Ballot>, newer: Option<&Ballot>) -> i32 {
    match (older, newer) {
        (Some(a), Some(b)) => a.compare(b),
        (Some(_), None) => 1,
        (None, Some(_)) => -1,
        (None, None) => 0,
    }
}

extern crate alloc;
