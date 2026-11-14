use stellar_consensus_verifier::{
    error::ScpError,
    primitives::scp::{
        ballot::{compare_optional, Ballot},
        statement::{Confirm, Externalize, Prepare, Statement},
    },
};

const LOW: &[u8] = b"a value";
const HIGH: &[u8] = b"b value";

fn ballot(counter: u32, value: &[u8]) -> Ballot {
    Ballot {
        counter,
        value: value.to_vec(),
    }
}

fn prepare(
    ballot: Ballot,
    prepared: Option<Ballot>,
    prepared_prime: Option<Ballot>,
    commit_counter: u32,
    highest_confirmed_ballot_counter: u32,
) -> Statement {
    Statement::Prepare(Prepare {
        quorum_set_hash: [0x11; 32],
        ballot,
        prepared,
        prepared_prime,
        commit_counter,
        highest_confirmed_ballot_counter,
    })
}

fn confirm(
    ballot: Ballot,
    prepared_counter: u32,
    commit_counter: u32,
    highest_confirmed_ballot_counter: u32,
) -> Statement {
    Statement::Confirm(Confirm {
        ballot,
        prepared_counter,
        commit_counter,
        highest_confirmed_ballot_counter,
        quorum_set_hash: [0x22; 32],
    })
}

fn externalize(commit: Ballot, highest_confirmed_ballot_counter: u32) -> Statement {
    Statement::Externalize(Externalize {
        commit,
        highest_confirmed_ballot_counter,
        commit_quorum_set_hash: [0x33; 32],
    })
}

fn strictly_newer(newer: &Statement, older: &Statement) {
    assert!(
        newer.is_newer_than(older),
        "{newer:?} should replace {older:?}"
    );
    assert!(
        !older.is_newer_than(newer),
        "{older:?} should not replace {newer:?}"
    );
}

#[test]
fn ballots_order_by_counter_then_by_value_bytes() {
    assert_eq!(ballot(1, HIGH).compare(&ballot(2, LOW)), -1);
    assert_eq!(ballot(2, LOW).compare(&ballot(1, HIGH)), 1);
    assert_eq!(ballot(3, LOW).compare(&ballot(3, HIGH)), -1);
    assert_eq!(ballot(3, HIGH).compare(&ballot(3, LOW)), 1);
    assert_eq!(ballot(3, LOW).compare(&ballot(3, LOW)), 0);
}

#[test]
fn less_and_incompatible_needs_both_an_older_ballot_and_a_different_value() {
    assert!(ballot(1, LOW).less_and_incompatible(&ballot(2, HIGH)));
    assert!(ballot(2, LOW).less_and_incompatible(&ballot(2, HIGH)));
    assert!(!ballot(1, LOW).less_and_incompatible(&ballot(2, LOW)));
    assert!(!ballot(3, LOW).less_and_incompatible(&ballot(2, HIGH)));
    assert!(!ballot(2, HIGH).less_and_incompatible(&ballot(2, LOW)));
}

#[test]
fn an_absent_optional_ballot_orders_before_any_present_one() {
    let some = ballot(1, LOW);

    assert_eq!(compare_optional(None, None), 0);
    assert_eq!(compare_optional(None, Some(&some)), -1);
    assert_eq!(compare_optional(Some(&some), None), 1);
    assert_eq!(compare_optional(Some(&some), Some(&ballot(2, LOW))), -1);
}

#[test]
fn statement_kinds_order_prepare_then_confirm_then_externalize() {
    let p = prepare(ballot(9, LOW), None, None, 0, 0);
    let c = confirm(ballot(1, LOW), 1, 1, 1);
    let e = externalize(ballot(1, LOW), 1);

    strictly_newer(&c, &p);
    strictly_newer(&e, &c);
    strictly_newer(&e, &p);
}

#[test]
fn a_prepare_is_newer_with_a_higher_ballot() {
    strictly_newer(
        &prepare(ballot(2, LOW), None, None, 0, 0),
        &prepare(ballot(1, LOW), None, None, 0, 0),
    );
    strictly_newer(
        &prepare(ballot(2, HIGH), None, None, 0, 0),
        &prepare(ballot(2, LOW), None, None, 0, 0),
    );
}

#[test]
fn a_prepare_with_the_same_ballot_is_newer_with_a_higher_prepared() {
    let b = ballot(5, LOW);

    strictly_newer(
        &prepare(b.clone(), Some(ballot(1, LOW)), None, 0, 0),
        &prepare(b.clone(), None, None, 0, 0),
    );
    strictly_newer(
        &prepare(b.clone(), Some(ballot(3, LOW)), None, 0, 0),
        &prepare(b, Some(ballot(2, LOW)), None, 0, 0),
    );
}

#[test]
fn a_prepare_with_the_same_prepared_is_newer_with_a_higher_prepared_prime() {
    let b = ballot(5, HIGH);
    let p = Some(ballot(4, HIGH));

    strictly_newer(
        &prepare(b.clone(), p.clone(), Some(ballot(1, LOW)), 0, 0),
        &prepare(b.clone(), p.clone(), None, 0, 0),
    );
    strictly_newer(
        &prepare(b.clone(), p.clone(), Some(ballot(3, LOW)), 0, 0),
        &prepare(b, p, Some(ballot(2, LOW)), 0, 0),
    );
}

#[test]
fn a_prepare_equal_up_to_prepared_prime_is_newer_with_a_higher_confirmed_counter() {
    let b = ballot(5, LOW);
    let p = Some(ballot(4, LOW));

    strictly_newer(
        &prepare(b.clone(), p.clone(), None, 0, 4),
        &prepare(b.clone(), p.clone(), None, 0, 3),
    );
    assert!(!prepare(b.clone(), p.clone(), None, 0, 3).is_newer_than(&prepare(b, p, None, 0, 3)));
}

#[test]
fn a_confirm_is_newer_with_a_higher_ballot_then_prepared_then_confirmed_counter() {
    strictly_newer(
        &confirm(ballot(3, LOW), 1, 1, 1),
        &confirm(ballot(2, LOW), 2, 2, 2),
    );
    strictly_newer(
        &confirm(ballot(3, LOW), 3, 1, 1),
        &confirm(ballot(3, LOW), 2, 1, 2),
    );
    strictly_newer(
        &confirm(ballot(3, LOW), 3, 1, 3),
        &confirm(ballot(3, LOW), 3, 1, 2),
    );
}

#[test]
fn two_confirms_that_differ_only_in_commit_counter_are_incomparable() {
    let one = confirm(ballot(3, LOW), 3, 1, 3);
    let two = confirm(ballot(3, LOW), 3, 2, 3);

    assert!(!one.is_newer_than(&two));
    assert!(!two.is_newer_than(&one));
}

#[test]
fn two_externalizes_are_incomparable() {
    let one = externalize(ballot(1, LOW), 1);
    let two = externalize(ballot(2, HIGH), 2);

    assert!(!one.is_newer_than(&two));
    assert!(!two.is_newer_than(&one));
}

#[test]
fn a_well_formed_prepare_is_sane() {
    let statements = [
        prepare(ballot(1, LOW), None, None, 0, 0),
        prepare(
            ballot(3, HIGH),
            Some(ballot(2, HIGH)),
            Some(ballot(1, LOW)),
            0,
            0,
        ),
        prepare(ballot(3, LOW), Some(ballot(3, LOW)), None, 1, 2),
    ];

    for statement in statements {
        assert_eq!(statement.check_sane(), Ok(()), "{statement:?}");
    }
}

#[test]
fn a_prepare_with_a_zero_ballot_counter_is_refused() {
    let err = prepare(ballot(0, LOW), None, None, 0, 0)
        .check_sane()
        .expect_err("a ballot counter of zero is never sent");

    assert_eq!(err, ScpError::BallotCounterZero);
}

#[test]
fn a_prepare_whose_prepared_prime_does_not_sit_below_prepared_is_refused() {
    let compatible = prepare(
        ballot(3, LOW),
        Some(ballot(2, LOW)),
        Some(ballot(1, LOW)),
        0,
        0,
    );
    let above = prepare(
        ballot(3, LOW),
        Some(ballot(1, LOW)),
        Some(ballot(2, HIGH)),
        0,
        0,
    );

    assert_eq!(compatible.check_sane(), Err(ScpError::MalformedPrepare));
    assert_eq!(above.check_sane(), Err(ScpError::MalformedPrepare));
}

#[test]
fn a_prepare_whose_confirmed_counter_exceeds_prepared_is_refused() {
    let no_prepared = prepare(ballot(3, LOW), None, None, 0, 1);
    let below = prepare(ballot(3, LOW), Some(ballot(1, LOW)), None, 0, 2);

    assert_eq!(no_prepared.check_sane(), Err(ScpError::MalformedPrepare));
    assert_eq!(below.check_sane(), Err(ScpError::MalformedPrepare));
}

#[test]
fn a_prepare_whose_commit_counter_is_out_of_order_is_refused() {
    let no_confirmed = prepare(ballot(3, LOW), Some(ballot(3, LOW)), None, 1, 0);
    let commit_above_confirmed = prepare(ballot(3, LOW), Some(ballot(3, LOW)), None, 3, 2);
    let confirmed_above_ballot = prepare(ballot(2, LOW), Some(ballot(3, LOW)), None, 1, 3);

    assert_eq!(no_confirmed.check_sane(), Err(ScpError::MalformedPrepare));
    assert_eq!(
        commit_above_confirmed.check_sane(),
        Err(ScpError::MalformedPrepare)
    );
    assert_eq!(
        confirmed_above_ballot.check_sane(),
        Err(ScpError::MalformedPrepare)
    );
}

#[test]
fn a_well_formed_confirm_is_sane() {
    assert_eq!(confirm(ballot(3, LOW), 2, 1, 3).check_sane(), Ok(()));
}

#[test]
fn a_confirm_with_a_zero_ballot_counter_is_refused() {
    let err = confirm(ballot(0, LOW), 0, 0, 0)
        .check_sane()
        .expect_err("a ballot counter of zero is never sent");

    assert_eq!(err, ScpError::BallotCounterZero);
}

#[test]
fn a_confirm_whose_counters_are_out_of_order_is_refused() {
    let confirmed_above_ballot = confirm(ballot(3, LOW), 3, 1, 4);
    let commit_above_confirmed = confirm(ballot(3, LOW), 3, 3, 2);

    assert_eq!(
        confirmed_above_ballot.check_sane(),
        Err(ScpError::MalformedConfirm)
    );
    assert_eq!(
        commit_above_confirmed.check_sane(),
        Err(ScpError::MalformedConfirm)
    );
}

#[test]
fn each_statement_reports_the_quorum_set_it_names() {
    assert_eq!(
        prepare(ballot(1, LOW), None, None, 0, 0).quorum_set_hash(),
        [0x11; 32]
    );
    assert_eq!(
        confirm(ballot(1, LOW), 1, 1, 1).quorum_set_hash(),
        [0x22; 32]
    );
    assert_eq!(externalize(ballot(1, LOW), 1).quorum_set_hash(), [0x33; 32]);
}
