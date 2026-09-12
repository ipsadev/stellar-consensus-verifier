use sha2::{Digest, Sha256};
use stellar_consensus_verifier::{quorum::*, xdr::MAX_QSET_DEPTH};

fn encode(threshold: u32, validators: &[NodeId], inner: &[Vec<u8>]) -> Vec<u8> {
    let mut out = threshold.to_be_bytes().to_vec();

    out.extend_from_slice(&(validators.len() as u32).to_be_bytes());

    for v in validators {
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(v);
    }

    out.extend_from_slice(&(inner.len() as u32).to_be_bytes());

    for i in inner {
        out.extend_from_slice(i);
    }

    out
}

#[test]
fn a_flat_set_round_trips() {
    let raw = encode(2, &[[1u8; 32], [2u8; 32], [3u8; 32]], &[]);
    let qset = QuorumSet::decode(&raw).expect("decodes");

    assert_eq!(qset.threshold, 2);
    assert_eq!(qset.validators.len(), 3);
    assert!(qset.inner_sets.is_empty());
}

#[test]
fn a_nested_set_round_trips() {
    let inner = encode(1, &[[9u8; 32]], &[]);
    let raw = encode(2, &[[1u8; 32]], &[inner]);
    let qset = QuorumSet::decode(&raw).expect("decodes");

    assert_eq!(qset.threshold, 2);
    assert_eq!(qset.validators.len(), 1);
    assert_eq!(qset.inner_sets.len(), 1);
    assert_eq!(qset.inner_sets[0].validators[0], [9u8; 32]);
}

#[test]
fn trailing_bytes_are_refused() {
    let mut raw = encode(1, &[[1u8; 32]], &[]);

    raw.push(0);
    assert!(QuorumSet::decode(&raw).is_err());
}

#[test]
fn nesting_beyond_the_cap_is_refused() {
    let mut nested = encode(1, &[[3u8; 32]], &[]);

    for _ in 0..=MAX_QSET_DEPTH {
        nested = encode(1, &[], &[nested]);
    }

    assert!(QuorumSet::decode(&nested).is_err());
}

#[test]
fn the_hash_is_over_the_raw_bytes() {
    let raw = encode(1, &[[1u8; 32]], &[]);
    let expected: [u8; 32] = Sha256::digest(&raw).into();

    assert_eq!(QuorumSet::hash(&raw), expected);
}

#[test]
fn an_empty_set_is_insane() {
    let raw = encode(1, &[], &[]);
    let qset = QuorumSet::decode(&raw).expect("decodes");

    assert!(qset.check_sane(false).is_err());
}

#[test]
fn a_threshold_over_the_entry_count_is_insane() {
    let raw = encode(3, &[[1u8; 32], [2u8; 32]], &[]);
    let qset = QuorumSet::decode(&raw).expect("decodes");

    assert!(qset.check_sane(false).is_err());
}

#[test]
fn the_v_blocking_rule_only_applies_to_a_trust_root() {
    let raw = encode(1, &[[1u8; 32], [2u8; 32], [3u8; 32]], &[]);
    let qset = QuorumSet::decode(&raw).expect("decodes");

    assert!(qset.check_sane(false).is_ok());
    assert!(qset.check_sane(true).is_err());
}

#[test]
fn a_duplicate_validator_is_refused() {
    let raw = encode(1, &[[1u8; 32], [1u8; 32]], &[]);
    let qset = QuorumSet::decode(&raw).expect("decodes");

    assert!(qset.check_sane(false).is_err());
}

#[test]
fn a_zero_threshold_set_is_never_a_quorum_slice() {
    let qset = QuorumSet {
        threshold: 0,
        validators: vec![[1u8; 32]],
        inner_sets: vec![],
    };

    assert!(!is_quorum_slice(&qset, &[]));
    assert!(!is_quorum_slice(&qset, &[[1u8; 32]]));
}

#[test]
fn a_zero_threshold_trust_root_is_never_satisfied_by_no_one() {
    let local = QuorumSet {
        threshold: 0,
        validators: vec![[1u8; 32]],
        inner_sets: vec![],
    };

    assert!(!is_quorum(&local, &[]));
}

#[test]
fn check_sane_enforces_the_nesting_cap_on_its_own() {
    let mut qset = QuorumSet {
        threshold: 1,
        validators: vec![[3u8; 32]],
        inner_sets: vec![],
    };

    for _ in 0..=MAX_QSET_DEPTH {
        qset = QuorumSet {
            threshold: 1,
            validators: vec![],
            inner_sets: vec![qset],
        };
    }

    assert!(qset.check_sane(false).is_err());
}

fn key(i: usize) -> NodeId {
    let mut out = [0u8; 32];

    out[..8].copy_from_slice(&(i as u64).to_be_bytes());

    out
}

fn sane(raw: &[u8]) -> bool {
    QuorumSet::decode(raw)
        .map(|qset| qset.check_sane(false).is_ok())
        .unwrap_or(false)
}

#[test]
fn core_case_an_empty_set_with_threshold_zero_is_insane() {
    assert!(!sane(&encode(0, &[], &[])));
}

#[test]
fn core_case_one_validator_with_threshold_zero_is_insane() {
    assert!(!sane(&encode(0, &[key(0)], &[])));
}

#[test]
fn core_case_one_validator_with_threshold_two_is_insane() {
    assert!(!sane(&encode(2, &[key(0)], &[])));
}

#[test]
fn core_case_one_validator_with_threshold_one_is_sane() {
    assert!(sane(&encode(1, &[key(0)], &[])));
}

#[test]
fn core_case_a_singleton_inner_set_is_sane() {
    let inner = encode(1, &[key(1)], &[]);

    assert!(sane(&encode(1, &[key(0)], &[inner])));
}

#[test]
fn core_case_an_inner_threshold_above_its_entries_is_insane() {
    let first = encode(1, &[key(1)], &[]);
    let second = encode(2, &[key(2)], &[]);

    assert!(!sane(&encode(1, &[key(0)], &[first, second])));
}

#[test]
fn core_case_two_inner_sets_are_sane() {
    let first = encode(1, &[key(1)], &[]);
    let second = encode(1, &[key(2), key(3)], &[]);

    assert!(sane(&encode(1, &[key(0)], &[first, second])));
}

#[test]
fn core_case_a_set_wrapped_in_another_is_sane() {
    let first = encode(1, &[key(1)], &[]);
    let second = encode(1, &[key(2), key(3)], &[]);
    let inner = encode(1, &[key(0)], &[first, second]);

    assert!(sane(&encode(1, &[], &[inner])));
}

#[test]
fn core_case_nesting_at_the_cap_is_sane_and_one_deeper_is_not() {
    let nest = |levels: usize| {
        let mut raw = encode(1, &[key(levels)], &[]);

        for level in (0..levels).rev() {
            raw = encode(1, &[key(level)], &[raw]);
        }

        raw
    };

    assert!(sane(&nest(MAX_QSET_DEPTH as usize)));
    assert!(!sane(&nest(MAX_QSET_DEPTH as usize + 1)));
}

#[test]
fn core_case_a_thousand_validators_is_sane_and_one_more_is_not() {
    let thousand: Vec<NodeId> = (0..1000).map(key).collect();
    let one_more: Vec<NodeId> = (0..1001).map(key).collect();

    assert!(sane(&encode(1, &thousand, &[])));
    assert!(!sane(&encode(1, &one_more, &[])));
}

#[test]
fn core_case_a_thousand_and_one_validators_across_inner_sets_is_insane() {
    let inner: Vec<Vec<u8>> = (0..10)
        .map(|i| {
            let group: Vec<NodeId> = ((i * 100 + 1)..=((i + 1) * 100)).map(key).collect();

            encode(1, &group, &[])
        })
        .collect();

    assert!(!sane(&encode(1, &[key(0)], &inner)));
}

#[test]
fn a_duplicate_validator_across_nesting_levels_is_refused() {
    let inner = encode(1, &[key(1)], &[]);
    let raw = encode(1, &[key(1)], &[inner]);
    let qset = QuorumSet::decode(&raw).expect("decodes");

    assert!(qset.check_sane(false).is_err());
}

fn set(threshold: u32, validators: &[usize], inner: &[QuorumSet]) -> QuorumSet {
    QuorumSet {
        threshold,
        validators: validators.iter().map(|i| key(*i)).collect(),
        inner_sets: inner.to_vec(),
    }
}

#[test]
fn a_slice_counts_validators_and_inner_sets_together() {
    let qset = set(2, &[0], &[set(1, &[1, 2], &[])]);

    assert!(is_quorum_slice(&qset, &[key(0), key(1)]));
    assert!(!is_quorum_slice(&qset, &[key(1), key(2)]));
    assert!(!is_quorum_slice(&qset, &[key(0)]));
}

#[test]
fn an_inner_set_counts_once_however_many_of_its_members_are_present() {
    let qset = set(2, &[], &[set(1, &[0, 1], &[]), set(1, &[2], &[])]);

    assert!(!is_quorum_slice(&qset, &[key(0), key(1)]));
    assert!(is_quorum_slice(&qset, &[key(0), key(2)]));
}

#[test]
fn a_quorum_needs_every_member_to_satisfy_its_own_slice() {
    let local = set(2, &[0, 1, 2], &[]);
    let signers = vec![
        (key(0), local.clone()),
        (key(1), local.clone()),
        (key(2), local.clone()),
    ];

    assert!(is_quorum(&local, &signers));
}

#[test]
fn a_node_whose_own_slice_is_unsatisfied_is_pruned() {
    let local = set(1, &[0], &[]);
    let signers = vec![(key(0), set(1, &[9], &[]))];

    assert!(!is_quorum(&local, &signers));
}

#[test]
fn pruning_cascades_until_it_settles() {
    let local = set(2, &[0, 1], &[]);
    let signers = vec![
        (key(0), set(1, &[1], &[])),
        (key(1), set(1, &[2], &[])),
        (key(2), set(1, &[9], &[])),
    ];

    assert!(!is_quorum(&local, &signers));
}

#[test]
fn a_node_that_trusts_only_itself_survives_the_prune() {
    let local = set(1, &[0], &[]);
    let signers = vec![(key(0), set(1, &[0], &[]))];

    assert!(is_quorum(&local, &signers));
}

#[test]
fn a_signer_the_trust_root_does_not_name_cannot_satisfy_it() {
    let local = set(1, &[0], &[]);
    let signers = vec![(key(9), set(1, &[9], &[]))];

    assert!(!is_quorum(&local, &signers));
}

#[test]
fn no_signers_are_never_a_quorum() {
    assert!(!is_quorum(&set(1, &[0], &[]), &[]));
}

#[test]
fn a_repeated_signer_is_not_counted_twice() {
    let local = set(2, &[0, 1], &[]);
    let qset = set(1, &[0], &[]);
    let signers = vec![(key(0), qset.clone()), (key(0), qset)];

    assert!(!is_quorum(&local, &signers));
}

fn fbas(entries: &[(usize, QuorumSet)]) -> Vec<(NodeId, QuorumSet)> {
    entries.iter().map(|(i, q)| (key(*i), q.clone())).collect()
}

#[test]
fn a_set_is_quorum_closed_when_every_member_has_a_slice_inside_it() {
    let alone = fbas(&[(0, set(2, &[0, 1, 2], &[]))]);

    assert!(
        !is_quorum_closed(&alone),
        "one node cannot satisfy a threshold of two"
    );

    let pair = fbas(&[(0, set(2, &[0, 1, 2], &[])), (1, set(2, &[0, 1, 2], &[]))]);

    assert!(
        is_quorum_closed(&pair),
        "two of the three named validators are present, which is the threshold"
    );

    let outward = fbas(&[(0, set(1, &[9], &[])), (1, set(1, &[9], &[]))]);

    assert!(
        !is_quorum_closed(&outward),
        "a set whose members depend on a node outside it is not closed"
    );
}

#[test]
fn the_empty_set_is_not_a_quorum() {
    assert!(!is_quorum_closed(&[]));
}

#[test]
fn two_disjoint_quorums_refute_intersection() {
    let left = set(2, &[0, 1, 2], &[]);
    let right = set(2, &[3, 4, 5], &[]);
    let split = fbas(&[
        (0, left.clone()),
        (1, left.clone()),
        (2, left),
        (3, right.clone()),
        (4, right.clone()),
        (5, right),
    ]);

    assert!(quorum_intersection_refuted(
        &split,
        &[key(0), key(1), key(2)],
        &[key(3), key(4), key(5)]
    ));
}

#[test]
fn an_intersecting_configuration_cannot_be_refuted() {
    let shared = set(3, &[0, 1, 2, 3], &[]);
    let together = fbas(&[
        (0, shared.clone()),
        (1, shared.clone()),
        (2, shared.clone()),
        (3, shared),
    ]);

    assert!(!quorum_intersection_refuted(
        &together,
        &[key(0), key(1), key(2)],
        &[key(1), key(2), key(3)]
    ));
    assert!(!quorum_intersection_refuted(
        &together,
        &[key(0), key(1)],
        &[key(2), key(3)]
    ));
}

#[test]
fn a_refutation_naming_an_unknown_node_is_rejected() {
    let left = set(2, &[0, 1, 2], &[]);
    let known = fbas(&[(0, left.clone()), (1, left.clone()), (2, left)]);

    assert!(!quorum_intersection_refuted(
        &known,
        &[key(0), key(1), key(2)],
        &[key(7), key(8)]
    ));
}

#[test]
fn a_refutation_that_repeats_a_node_is_rejected() {
    let left = set(1, &[0], &[]);
    let right = set(1, &[1], &[]);
    let two = fbas(&[(0, left), (1, right)]);

    assert!(!quorum_intersection_refuted(
        &two,
        &[key(0), key(0)],
        &[key(1)]
    ));
}

#[test]
fn overlapping_sets_are_never_a_refutation() {
    let each = set(1, &[0], &[]);
    let one = fbas(&[(0, each.clone()), (1, each)]);

    assert!(!quorum_intersection_refuted(&one, &[key(0)], &[key(0)]));
}

#[test]
fn a_split_must_threaten_the_trust_root_to_matter() {
    let left = set(2, &[0, 1, 2], &[]);
    let right = set(2, &[3, 4, 5], &[]);
    let split = fbas(&[
        (0, left.clone()),
        (1, left.clone()),
        (2, left),
        (3, right.clone()),
        (4, right.clone()),
        (5, right),
    ]);
    let watching = set(2, &[0, 1, 2, 3, 4, 5], &[]);
    let elsewhere = set(1, &[9], &[]);

    assert!(quorum_split_threatens(
        &watching,
        &split,
        &[key(0), key(1), key(2)],
        &[key(3), key(4), key(5)]
    ));
    assert!(
        !quorum_split_threatens(
            &elsewhere,
            &split,
            &[key(0), key(1), key(2)],
            &[key(3), key(4), key(5)]
        ),
        "a split among nodes the trust root does not rely on is not this client's problem"
    );
}

#[test]
fn a_split_where_only_one_side_reaches_the_trust_root_is_not_a_threat() {
    let left = set(2, &[0, 1, 2], &[]);
    let right = set(2, &[3, 4, 5], &[]);
    let split = fbas(&[
        (0, left.clone()),
        (1, left.clone()),
        (2, left),
        (3, right.clone()),
        (4, right.clone()),
        (5, right),
    ]);
    let leaning = set(2, &[0, 1, 2], &[]);

    assert!(!quorum_split_threatens(
        &leaning,
        &split,
        &[key(0), key(1), key(2)],
        &[key(3), key(4), key(5)]
    ));
}

fn slices_of(qset: &QuorumSet, universe: &[NodeId]) -> Vec<Vec<NodeId>> {
    let mut out = Vec::new();

    for mask in 1u32..(1 << universe.len()) {
        let subset: Vec<NodeId> = universe
            .iter()
            .enumerate()
            .filter(|(i, _)| mask & (1 << i) != 0)
            .map(|(_, id)| *id)
            .collect();

        if is_quorum_slice(qset, &subset) {
            out.push(subset);
        }
    }

    out
}

#[test]
fn a_strict_majority_trust_root_has_no_two_disjoint_slices() {
    let universe: Vec<NodeId> = (0..8).map(key).collect();
    let roots = [
        set(2, &[0, 1, 2], &[]),
        set(3, &[0, 1, 2, 3], &[]),
        set(4, &[0, 1, 2, 3, 4], &[]),
        set(2, &[0], &[set(2, &[1, 2, 3], &[])]),
        set(2, &[], &[set(2, &[0, 1, 2], &[]), set(2, &[3, 4, 5], &[])]),
        set(
            3,
            &[],
            &[
                set(2, &[0, 1, 2], &[]),
                set(2, &[3, 4, 5], &[]),
                set(2, &[6, 7], &[]),
            ],
        ),
    ];

    for root in &roots {
        root.check_sane(true)
            .expect("the fixture is strict majority");

        let slices = slices_of(root, &universe);

        for (i, a) in slices.iter().enumerate() {
            for b in &slices[i..] {
                assert!(
                    a.iter().any(|id| b.contains(id)),
                    "two disjoint slices of a strict-majority trust root: {a:?} and {b:?}"
                );
            }
        }
    }
}

#[test]
fn a_strict_majority_trust_root_cannot_be_split() {
    let left = set(2, &[0, 1, 2], &[]);
    let right = set(2, &[3, 4, 5], &[]);
    let split = fbas(&[
        (0, left.clone()),
        (1, left.clone()),
        (2, left),
        (3, right.clone()),
        (4, right.clone()),
        (5, right),
    ]);
    let strict = set(4, &[0, 1, 2, 3, 4, 5], &[]);

    strict.check_sane(true).expect("strict majority");
    assert!(
        !quorum_split_threatens(
            &strict,
            &split,
            &[key(0), key(1), key(2)],
            &[key(3), key(4), key(5)]
        ),
        "a trust root that passes the strict-majority rule cannot have two disjoint slices, \
         so no split can threaten it"
    );
}
