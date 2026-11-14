use sha2::{Digest, Sha256};
use stellar_consensus_verifier::{
    error::ScpError,
    primitives::execution::results::{verify_state_root, Inputs},
};

const ROUTER: [u8; 32] = [0x41; 32];
const TOPIC: &[u8] = b"ibc_root";
const ROOT: [u8; 32] = [0x5a; 32];

const TX_FAILED: i32 = -1;
const OP_BAD_AUTH: i32 = -1;
const OP_TYPE_PAYMENT: i32 = 1;
const INVOKE_HOST_FUNCTION_TRAPPED: i32 = -2;

const SYSTEM_EVENT: i32 = 0;
const CONTRACT_EVENT: i32 = 1;
const DIAGNOSTIC_EVENT: i32 = 2;

fn u32_bytes(value: u32) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

fn i32_bytes(value: i32) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

fn u64_bytes(value: u64) -> Vec<u8> {
    value.to_be_bytes().to_vec()
}

fn var_bytes(value: &[u8]) -> Vec<u8> {
    let mut out = u32_bytes(value.len() as u32);
    let pad = (4 - (value.len() % 4)) % 4;

    out.extend_from_slice(value);
    out.extend_from_slice(&vec![0u8; pad]);

    out
}

fn tagged(tag: i32, body: &[&[u8]]) -> Vec<u8> {
    let mut out = i32_bytes(tag);

    for part in body {
        out.extend_from_slice(part);
    }

    out
}

fn symbol(value: &[u8]) -> Vec<u8> {
    tagged(15, &[&var_bytes(value)])
}

fn bytes(value: &[u8]) -> Vec<u8> {
    tagged(13, &[&var_bytes(value)])
}

fn scval_vec(items: &[Vec<u8>]) -> Vec<u8> {
    let mut out = tagged(16, &[&u32_bytes(1), &u32_bytes(items.len() as u32)]);

    for item in items {
        out.extend_from_slice(item);
    }

    out
}

fn scval_map(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut out = tagged(17, &[&u32_bytes(1)]);

    out.extend_from_slice(&storage(entries)[4..]);

    out
}

fn storage(entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut out = u32_bytes(1);

    out.extend_from_slice(&u32_bytes(entries.len() as u32));

    for (key, value) in entries {
        out.extend_from_slice(key);
        out.extend_from_slice(value);
    }

    out
}

fn event(
    extension: i32,
    contract: Option<[u8; 32]>,
    event_type: i32,
    body: i32,
    topics: &[Vec<u8>],
    data: Vec<u8>,
) -> Vec<u8> {
    let mut out = i32_bytes(extension);

    match contract {
        None => out.extend_from_slice(&u32_bytes(0)),
        Some(id) => {
            out.extend_from_slice(&u32_bytes(1));
            out.extend_from_slice(&id);
        }
    }

    out.extend_from_slice(&i32_bytes(event_type));
    out.extend_from_slice(&i32_bytes(body));
    out.extend_from_slice(&u32_bytes(topics.len() as u32));

    for topic in topics {
        out.extend_from_slice(topic);
    }

    out.extend_from_slice(&data);

    out
}

fn root_event() -> Vec<u8> {
    event(
        0,
        Some(ROUTER),
        CONTRACT_EVENT,
        0,
        &[symbol(TOPIC)],
        bytes(&ROOT),
    )
}

fn preimage(return_value: Vec<u8>, events: &[Vec<u8>]) -> Vec<u8> {
    let mut out = return_value;

    out.extend_from_slice(&u32_bytes(events.len() as u32));

    for event in events {
        out.extend_from_slice(event);
    }

    out
}

fn void() -> Vec<u8> {
    i32_bytes(1)
}

fn result_pair(code: i32, body: &[u8]) -> Vec<u8> {
    let mut out = [0xab; 32].to_vec();

    out.extend_from_slice(&u64_bytes(100));
    out.extend_from_slice(&i32_bytes(code));
    out.extend_from_slice(body);

    out
}

fn invoke_body(operation: i32, operation_type: i32, outcome: i32, success: &[u8; 32]) -> Vec<u8> {
    let mut out = u32_bytes(1);

    out.extend_from_slice(&i32_bytes(operation));
    out.extend_from_slice(&i32_bytes(operation_type));
    out.extend_from_slice(&i32_bytes(outcome));
    out.extend_from_slice(success);
    out.extend_from_slice(&i32_bytes(0));

    out
}

fn success_pair(preimage: &[u8]) -> Vec<u8> {
    let success: [u8; 32] = Sha256::digest(preimage).into();

    result_pair(0, &invoke_body(0, 24, 0, &success))
}

fn prove(pairs: &[Vec<u8>], index: u32, preimage: &[u8]) -> Result<[u8; 32], ScpError> {
    let mut hasher = Sha256::new();

    hasher.update((pairs.len() as u32).to_be_bytes());

    for pair in pairs {
        hasher.update(pair);
    }

    let tx_set_result_hash: [u8; 32] = hasher.finalize().into();

    verify_state_root(&Inputs {
        tx_set_result_hash: &tx_set_result_hash,
        result_pairs: pairs,
        result_index: index,
        success_preimage_xdr: preimage,
        router_contract_id: &ROUTER,
        root_event_topic: TOPIC,
    })
}

fn prove_one(preimage: &[u8]) -> Result<[u8; 32], ScpError> {
    prove(&[success_pair(preimage)], 0, preimage)
}

fn every_scval_kind() -> Vec<u8> {
    let account = tagged(0, &[&i32_bytes(0), &[0x01; 32]]);
    let contract = tagged(1, &[&[0x02; 32]]);
    let addresses = [
        account.clone(),
        contract,
        tagged(2, &[&u64_bytes(7), &[0x03; 32]]),
        tagged(3, &[&i32_bytes(0), &[0x04; 32]]),
        tagged(4, &[&[0x05; 32]]),
        tagged(5, &[&u64_bytes(8), &[0x06; 32]]),
    ];
    let mut items = vec![
        tagged(0, &[&u32_bytes(1)]),
        void(),
        tagged(2, &[&i32_bytes(0), &u32_bytes(9)]),
        tagged(3, &[&u32_bytes(1)]),
        tagged(4, &[&i32_bytes(-1)]),
        tagged(5, &[&u64_bytes(2)]),
        tagged(6, &[&u64_bytes(3)]),
        tagged(7, &[&u64_bytes(4)]),
        tagged(8, &[&u64_bytes(5)]),
        tagged(9, &[&u64_bytes(0), &u64_bytes(6)]),
        tagged(10, &[&u64_bytes(0), &u64_bytes(7)]),
        tagged(
            11,
            &[&u64_bytes(0), &u64_bytes(0), &u64_bytes(0), &u64_bytes(8)],
        ),
        tagged(
            12,
            &[&u64_bytes(0), &u64_bytes(0), &u64_bytes(0), &u64_bytes(9)],
        ),
        bytes(b"raw"),
        tagged(14, &[&var_bytes(b"text")]),
        symbol(b"name"),
        tagged(16, &[&u32_bytes(0)]),
        tagged(17, &[&u32_bytes(0)]),
        scval_map(&[(symbol(b"key"), tagged(3, &[&u32_bytes(1)]))]),
        tagged(19, &[&i32_bytes(0), &[0x07; 32], &u32_bytes(0)]),
        tagged(
            19,
            &[
                &i32_bytes(1),
                &storage(&[(symbol(b"admin"), tagged(18, &[&account]))]),
            ],
        ),
        tagged(
            19,
            &[&i32_bytes(2), &account, &var_bytes(b"ref"), &u32_bytes(0)],
        ),
        i32_bytes(20),
        tagged(21, &[&u64_bytes(10)]),
        tagged(22, &[&var_bytes(b"tag")]),
    ];

    for address in &addresses {
        items.push(tagged(18, &[address]));
    }

    scval_vec(&items)
}

fn nested_vectors(depth: usize) -> Vec<u8> {
    let mut value = void();

    for _ in 0..depth {
        value = scval_vec(&[value]);
    }

    value
}

fn assert_invalid_wire(result: Result<[u8; 32], ScpError>, reason: &str) {
    match result {
        Err(ScpError::InvalidWire(_)) => {}
        other => panic!("{reason}: expected InvalidWire, got {other:?}"),
    }
}

#[test]
fn a_synthetic_router_invocation_yields_its_root() {
    let preimage = preimage(void(), &[root_event()]);

    assert_eq!(prove_one(&preimage), Ok(ROOT));
}

#[test]
fn the_root_is_found_at_the_named_index_among_other_results() {
    let preimage = preimage(void(), &[root_event()]);
    let pairs = vec![
        result_pair(TX_FAILED, &[]),
        success_pair(&preimage),
        result_pair(TX_FAILED, &[]),
    ];

    assert_eq!(prove(&pairs, 1, &preimage), Ok(ROOT));
}

#[test]
fn an_index_past_the_last_result_is_refused() {
    let preimage = preimage(void(), &[root_event()]);
    let err = prove(&[success_pair(&preimage)], 1, &preimage).expect_err("only one result");

    assert_eq!(err, ScpError::ResultIndexOutOfRange { index: 1, len: 1 });
}

#[test]
fn a_preimage_that_does_not_hash_to_the_success_hash_is_refused() {
    let committed = preimage(void(), &[root_event()]);
    let substituted = preimage(symbol(b"forged"), &[root_event()]);
    let err = prove(&[success_pair(&committed)], 0, &substituted)
        .expect_err("the preimage must be the one the result committed to");

    assert_eq!(err, ScpError::SuccessPreimageMismatch);
}

#[test]
fn a_failed_transaction_is_refused() {
    let preimage = preimage(void(), &[root_event()]);
    let err = prove(&[result_pair(TX_FAILED, &[])], 0, &preimage)
        .expect_err("a failed transaction published nothing");

    assert_eq!(err, ScpError::TransactionNotSuccessful { code: TX_FAILED });
}

#[test]
fn a_transaction_with_no_operations_is_not_a_soroban_invocation() {
    let preimage = preimage(void(), &[root_event()]);
    let err = prove(&[result_pair(0, &u32_bytes(0))], 0, &preimage)
        .expect_err("an invocation has exactly one operation");

    assert_eq!(err, ScpError::NotASorobanInvocation);
}

#[test]
fn an_operation_that_did_not_run_is_not_a_soroban_invocation() {
    let preimage = preimage(void(), &[root_event()]);
    let success: [u8; 32] = Sha256::digest(&preimage).into();
    let pair = result_pair(0, &invoke_body(OP_BAD_AUTH, 24, 0, &success));
    let err = prove(&[pair], 0, &preimage).expect_err("the operation result is not opINNER");

    assert_eq!(err, ScpError::NotASorobanInvocation);
}

#[test]
fn an_operation_of_another_type_is_not_a_soroban_invocation() {
    let preimage = preimage(void(), &[root_event()]);
    let success: [u8; 32] = Sha256::digest(&preimage).into();
    let pair = result_pair(0, &invoke_body(0, OP_TYPE_PAYMENT, 0, &success));
    let err = prove(&[pair], 0, &preimage).expect_err("a payment is not a contract call");

    assert_eq!(err, ScpError::NotASorobanInvocation);
}

#[test]
fn a_failed_host_function_is_refused() {
    let preimage = preimage(void(), &[root_event()]);
    let success: [u8; 32] = Sha256::digest(&preimage).into();
    let pair = result_pair(
        0,
        &invoke_body(0, 24, INVOKE_HOST_FUNCTION_TRAPPED, &success),
    );
    let err = prove(&[pair], 0, &preimage).expect_err("a trapped contract published nothing");

    assert_eq!(
        err,
        ScpError::InvokeHostFunctionFailed {
            code: INVOKE_HOST_FUNCTION_TRAPPED
        }
    );
}

#[test]
fn an_unknown_transaction_result_extension_is_refused() {
    let preimage = preimage(void(), &[root_event()]);
    let mut pair = success_pair(&preimage);
    let last = pair.len() - 1;

    pair[last] = 1;

    assert_invalid_wire(
        prove(&[pair], 0, &preimage),
        "a result extension this crate cannot read",
    );
}

#[test]
fn two_root_events_from_the_router_are_ambiguous() {
    let preimage = preimage(void(), &[root_event(), root_event()]);

    assert_eq!(prove_one(&preimage), Err(ScpError::AmbiguousRouterEvent));
}

#[test]
fn only_a_contract_event_carrying_the_router_id_counts() {
    let lookalikes = [
        event(
            0,
            None,
            CONTRACT_EVENT,
            0,
            &[symbol(TOPIC)],
            bytes(&[0x01; 32]),
        ),
        event(
            0,
            Some(ROUTER),
            SYSTEM_EVENT,
            0,
            &[symbol(TOPIC)],
            bytes(&[0x02; 32]),
        ),
        event(
            0,
            Some(ROUTER),
            DIAGNOSTIC_EVENT,
            0,
            &[symbol(TOPIC)],
            bytes(&[0x03; 32]),
        ),
        event(
            0,
            Some([0x42; 32]),
            CONTRACT_EVENT,
            0,
            &[symbol(TOPIC)],
            bytes(&[0x04; 32]),
        ),
    ];
    let mut events = lookalikes.to_vec();

    events.push(root_event());

    assert_eq!(prove_one(&preimage(void(), &events)), Ok(ROOT));
    assert_eq!(
        prove_one(&preimage(void(), &lookalikes)),
        Err(ScpError::RouterEventMissing)
    );
}

#[test]
fn a_root_event_whose_payload_is_not_32_bytes_is_malformed() {
    let short = event(
        0,
        Some(ROUTER),
        CONTRACT_EVENT,
        0,
        &[symbol(TOPIC)],
        bytes(&[0x5a; 31]),
    );
    let symbol_payload = event(
        0,
        Some(ROUTER),
        CONTRACT_EVENT,
        0,
        &[symbol(TOPIC)],
        symbol(b"root"),
    );

    assert_eq!(
        prove_one(&preimage(void(), &[short])),
        Err(ScpError::StateRootMalformed)
    );
    assert_eq!(
        prove_one(&preimage(void(), &[symbol_payload])),
        Err(ScpError::StateRootMalformed)
    );
}

#[test]
fn an_event_with_an_unknown_extension_body_or_contract_flag_is_refused() {
    let extension = event(
        1,
        Some(ROUTER),
        CONTRACT_EVENT,
        0,
        &[symbol(TOPIC)],
        bytes(&ROOT),
    );
    let body = event(
        0,
        Some(ROUTER),
        CONTRACT_EVENT,
        1,
        &[symbol(TOPIC)],
        bytes(&ROOT),
    );
    let mut flag = root_event();

    flag[7] = 2;

    assert_invalid_wire(
        prove_one(&preimage(void(), &[extension])),
        "event extension",
    );
    assert_invalid_wire(prove_one(&preimage(void(), &[body])), "event body");
    assert_invalid_wire(prove_one(&preimage(void(), &[flag])), "contract id flag");
}

#[test]
fn every_scval_kind_is_skipped_on_the_way_to_the_root() {
    let noisy = event(
        0,
        Some(ROUTER),
        CONTRACT_EVENT,
        0,
        &[symbol(b"noise"), every_scval_kind()],
        every_scval_kind(),
    );
    let preimage = preimage(every_scval_kind(), &[noisy, root_event()]);

    assert_eq!(prove_one(&preimage), Ok(ROOT));
}

#[test]
fn an_unknown_scval_kind_is_refused() {
    assert_invalid_wire(
        prove_one(&preimage(i32_bytes(23), &[root_event()])),
        "SCValType 23",
    );
    assert_invalid_wire(
        prove_one(&preimage(tagged(18, &[&i32_bytes(6)]), &[root_event()])),
        "SCAddressType 6",
    );
    assert_invalid_wire(
        prove_one(&preimage(tagged(19, &[&i32_bytes(3)]), &[root_event()])),
        "ContractExecutable 3",
    );
    assert_invalid_wire(
        prove_one(&preimage(tagged(16, &[&u32_bytes(2)]), &[root_event()])),
        "optional flag 2",
    );
}

#[test]
fn scval_nesting_is_bounded() {
    assert_eq!(
        prove_one(&preimage(nested_vectors(16), &[root_event()])),
        Ok(ROOT)
    );
    assert_invalid_wire(
        prove_one(&preimage(nested_vectors(17), &[root_event()])),
        "seventeen nested vectors",
    );
}
