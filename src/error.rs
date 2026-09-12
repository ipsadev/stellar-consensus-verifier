extern crate alloc;

use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
/// Everything that can stop a proof from being accepted.
pub enum ScpError {
    #[error("invalid wire bytes: {0}")]
    InvalidWire(String),
    #[error("the EXTERNALIZE commit ballot has counter 0")]
    CommitCounterZero,
    #[error("the ballot has counter 0")]
    BallotCounterZero,
    #[error("the PREPARE statement is malformed")]
    MalformedPrepare,
    #[error("the CONFIRM statement is malformed")]
    MalformedConfirm,
    #[error("the statement is a nomination, not a ballot-protocol statement")]
    NominationStatement,
    #[error("the statement is not EXTERNALIZE")]
    NotExternalize,
    #[error("the signature on the envelope from node {node} does not verify")]
    UnauthenticatedEnvelope { node: alloc::string::String },
    #[error("the envelope is for slot {found}, not the slot {expected} being proven")]
    EnvelopeSlotMismatch { expected: u64, found: u64 },
    #[error("no value reaches confirm commit for the trust root")]
    NoConfirmedCommit,
    #[error("two different values each reach confirm commit — this is fork evidence")]
    ForkedConfirmCommit,
    #[error("the EXTERNALIZE commit ballot has an empty value")]
    EmptyCommitValue,
    #[error("the highest confirmed ballot counter {highest} is below the commit counter {commit}")]
    HighestConfirmedBelowCommit { highest: u32, commit: u32 },
    #[error("the result pairs do not hash to the header's txSetResultHash")]
    TxResultSetMismatch,
    #[error("the anchor ledger {anchor} is not ahead of the target {target}")]
    ChainNotDescending { anchor: u32, target: u32 },
    #[error("walking {anchor} back to {target} needs {expected} header(s), {found} supplied")]
    ChainLengthMismatch {
        anchor: u32,
        target: u32,
        expected: usize,
        found: usize,
    },
    #[error("expected ledger {expected} in the chain, found {found}")]
    ChainGap { expected: u32, found: u32 },
    #[error("ledger {seq} does not hash to the previousLedgerHash of ledger {child}")]
    ChainBroken { seq: u32, child: u32 },
    #[error("result index {index} is out of range for {len} result pair(s)")]
    ResultIndexOutOfRange { index: u32, len: usize },
    #[error("the success preimage does not hash to what the result committed to")]
    SuccessPreimageMismatch,
    #[error("the transaction did not succeed (result code {code})")]
    TransactionNotSuccessful { code: i32 },
    #[error("the result is not a single Soroban host-function invocation")]
    NotASorobanInvocation,
    #[error("the host-function invocation failed (result code {code})")]
    InvokeHostFunctionFailed { code: i32 },
    #[error("no ibc_root event from the router in the success preimage")]
    RouterEventMissing,
    #[error("more than one ibc_root event from the router — the state root is ambiguous")]
    AmbiguousRouterEvent,
    #[error("the ibc_root event payload is not a 32-byte state root")]
    StateRootMalformed,
}
