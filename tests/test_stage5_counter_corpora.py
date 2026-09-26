"""The measurement wave's two counter-corpora keep the properties they exist to have.

Each test is named after the property a measurement in ``docs/stage-5-findings.md``
rests on, so weakening the corpus means deleting a test that says what it protected.
"""

from __future__ import annotations

import pytest

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.state.potential import phi
from pocketsec.stage5.labs.baselines import PLAYBOOK_PHI_THRESHOLD
from pocketsec.stage5.labs.counter_corpora import (
    DECOUPLING_MODULUS,
    build_decoupled_phi_corpus,
    build_hostile_leading_pairs,
    decoupled_indices,
)
from pocketsec.stage5.labs.response_corpus import (
    BENIGN_MECHANISMS,
    HOSTILE_MECHANISMS,
    MAX_CORPUS_CASES,
    ResponseCase,
    build_ambiguous_pairs,
    build_response_corpus,
    corpus_digest,
    corpus_identities,
)

SEED = 11


def _leading(case: ResponseCase) -> str:
    return str(max(case.resolution.hypotheses, key=lambda row: row["support"])["mechanism_id"])


def test_both_counter_corpora_are_deterministic_from_their_seed() -> None:
    assert corpus_digest(build_decoupled_phi_corpus(count=20, seed=SEED)) == corpus_digest(
        build_decoupled_phi_corpus(count=20, seed=SEED)
    )
    first = [m for p in build_hostile_leading_pairs(count=8, seed=SEED) for m in p]
    second = [m for p in build_hostile_leading_pairs(count=8, seed=SEED) for m in p]
    assert corpus_digest(first) == corpus_digest(second)


def test_the_decoupled_corpus_moves_only_the_playbooks_input() -> None:
    base = build_response_corpus(count=20, seed=SEED)
    moved = build_decoupled_phi_corpus(count=20, seed=SEED)
    chosen = decoupled_indices(20)
    assert len(chosen) == 2 * (20 // DECOUPLING_MODULUS)
    for index, (before, after) in enumerate(zip(base, moved, strict=True)):
        assert after.resolution.to_dict() == before.resolution.to_dict()
        assert after.truth == before.truth and after.harm == before.harm
        assert after.host.snapshot().processes == before.host.snapshot().processes
        above = phi(after.host.snapshot().security_state).total > PLAYBOOK_PHI_THRESHOLD
        agrees_with_truth = above == (not after.truth.benign_admin)
        # Outside the chosen set the playbook's input agrees with truth; inside it disagrees.
        assert agrees_with_truth == (index not in chosen)


def test_the_hostile_leading_pairs_are_indistinguishable_and_led_by_the_hostile_world() -> None:
    for benign, compromised in build_hostile_leading_pairs(count=12, seed=SEED):
        assert benign.resolution.to_dict() == compromised.resolution.to_dict()
        assert benign.host.snapshot().processes == compromised.host.snapshot().processes
        assert benign.truth.benign_admin and not compromised.truth.benign_admin
        assert _leading(benign) in HOSTILE_MECHANISMS
        supports = sorted(row["support"] for row in benign.resolution.hypotheses)
        assert supports[-1] - supports[0] == pytest.approx(0.10)


def test_the_benign_leading_pairs_are_led_by_the_benign_world() -> None:
    """Why the counter-corpus exists: G5.9's own pairs never let the hostile world lead."""
    assert all(
        _leading(benign) in BENIGN_MECHANISMS
        for benign, _ in build_ambiguous_pairs(count=12, seed=SEED)
    )


def test_no_operator_is_sufficient_on_one_half_and_harmless_on_the_other() -> None:
    """The structural reason no policy can satisfy G5.9 on an indistinguishable pair."""
    for pairs in (
        build_ambiguous_pairs(count=12, seed=SEED),
        build_hostile_leading_pairs(count=12, seed=SEED),
    ):
        for benign, compromised in pairs:
            assert not compromised.truth.sufficient_operator_ids - benign.truth.harmful_operator_ids


def test_pair_corpora_share_no_identity_across_orientations() -> None:
    """Rule 1: both orientations can run in one process without reusing an identity."""
    stems = {}
    for pairs in (
        build_ambiguous_pairs(count=30, seed=SEED),
        build_hostile_leading_pairs(count=30, seed=SEED),
    ):
        for benign, _ in pairs:
            stems[benign.case_id] = benign
    identities = corpus_identities(tuple(stems.values()))
    assert len(identities) == len(set(identities)) == 60


def test_the_hostile_leading_builder_refuses_a_count_that_would_reuse_identities() -> None:
    with pytest.raises(ContractError, match="MAX_CORPUS_CASES"):
        build_hostile_leading_pairs(count=MAX_CORPUS_CASES // 2 + 1, seed=SEED)
