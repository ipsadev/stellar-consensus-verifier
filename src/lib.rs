#![no_std]

// needed on no_std targets; looks unused on a host build with std, e.g. cargo fuzz
#[allow(unused_extern_crates)]
extern crate alloc;

pub mod error;
pub mod primitives;
pub mod verify;
pub mod xdr;
