"""D2.6 / D2.7 — the Behaviour Atom layer, and the invariants that bound it.

Every test is named after the invariant it protects, because the failure mode
this subsystem invites is not a crash: it is a lattice that quietly grows past
its bound, merges two behaviours that are not the same, or reports a stability
number that is true and meaningless. Several tests below exist specifically to
fail if someone later weakens an assertion to make a merge happen.

The last two tests are *measurements*, not assertions about which design wins.
They record the numbers ADR-0115 is built on.
"""

from __future__ import annotations

import math
import subprocess
import sys

import pytest

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.state.security_state import (
    DIMENSIONS,
    Privilege,
    SecurityStateV1,
)
from pocketsec.stage2.dataset import build_dataset
from pocketsec.stage2.encoder.ssir_encoder import (
    FEATURE_WIDTH,
    GROUP_OFFSETS,
    EncodedTransition,
)
from pocketsec.stage2.lattice.atom import (
    MAX_EPOCHS_PER_ATOM,
    BehaviourAtom,
    CompileStatus,
    welford_update,
)
from pocketsec.stage2.lattice.equivalence import (
    REASON_INSUFFICIENT_EVIDENCE,
    REASON_STATE,
    jensen_shannon,
    predictive_equivalence,
    successor_distribution,
)
from pocketsec.stage2.lattice.quantizer import (
    MAX_ATOMS,
    BehaviourQuantizer,
    HashBucketQuantizer,
    stable_bucket_id,
    stable_bucket_id,
)
from pocketsec.stage2.lattice.restructure import (
    REASON_DISABLED,
    REASON_NOT_HETEROGENEOUS,
    LatticeRestructurer,
    MacroState,
    successor_entropy,
)
from pocketsec.stage2.lattice.transitions import (
    MAX_TRANSITIONS,
    LatticeTransition,
    TransitionLattice,
)

_UNCERTAINTY = GROUP_OFFSETS["uncertainty"]
_DIMENSION_NAMES = list(DIMENSIONS)


def _encoded(
    *,
    axis: int = 0,
    value: float = 0.0,
    uncertainty: float = 0.5,
    delta_phi: float = 0.0,
    epoch_id: int = 1,
    relation_family: int = 0,
    state_delta_mask: int = 0,
    object_property_mask: int = 0,
) -> EncodedTransition:
    """One synthetic encoded transition placed at ``value`` along ``axis``.

    Synthetic on purpose: the corpus cannot produce two prototypes at a chosen
    distance, and the bounds under test are about geometry and counting, not
    about whether the corpus is realistic.
    """
    features = [0.0] * FEATURE_WIDTH
    features[axis] = value
    features[_UNCERTAINTY] = uncertainty
    return EncodedTransition(
        features=tuple(features),
        relation=0,
        relation_family=relation_family,
        state_delta_mask=state_delta_mask,
        time_bucket=0,
        delta_phi=delta_phi,
        object_property_mask=object_property_mask,
        epoch_id=epoch_id,
    )


def _state_from_mask(mask: int) -> SecurityStateV1:
    """A state summary implied by a transition's ``state_delta_mask``.

    ``Stage2Dataset`` carries encoded transitions, not ``SecurityStateV1``, so a
    corpus-driven test has to reconstruct a plausible summary. Raising each
    flagged dimension one level is a *stand-in*, stated here so no measurement
    below is mistaken for one taken against Stage 1's real lineage state.
    """
    state = SecurityStateV1()
    for index, name in enumerate(_DIMENSION_NAMES):
        if mask >> index & 1:
            state = state.raised_to(name, list(DIMENSIONS[name])[1])
    return state


def _atom(
    atom_id: int,
    *,
    visits: int = 10,
    epochs: tuple[int, ...] = (1,),
    envelope: tuple[float, float] = (0.4, 0.6),
    state: SecurityStateV1 | None = None,
) -> BehaviourAtom:
    return BehaviourAtom(
        atom_id=atom_id,
        prototype=tuple([0.0] * FEATURE_WIDTH),
        visit_count=visits,
        epoch_counts={epoch: visits for epoch in epochs},
        state_summary=state or SecurityStateV1(),
        delta_phi_mean=0.0,
        delta_phi_m2=0.0,
        uncertainty_envelope=envelope,
        compile_status=CompileStatus.NEURAL,
        first_sequence=0,
        last_sequence=visits,
    )


# --- atom invariants ---------------------------------------------------------


def test_prototype_width_must_equal_feature_width() -> None:
    with pytest.raises(ContractError, match="FEATURE_WIDTH"):
        BehaviourAtom(
            atom_id=1,
            prototype=(0.0, 1.0),
            visit_count=1,
            epoch_counts={1: 1},
            state_summary=SecurityStateV1(),
            delta_phi_mean=0.0,
            delta_phi_m2=0.0,
            uncertainty_envelope=(0.0, 0.0),
            compile_status=CompileStatus.NEURAL,
            first_sequence=0,
            last_sequence=0,
        )


def test_atom_refuses_an_inverted_uncertainty_envelope() -> None:
    """An inverted envelope makes every containment test silently false."""
    with pytest.raises(ContractError, match="inverted uncertainty envelope"):
        _atom(1, envelope=(0.9, 0.1))


def test_atom_refuses_negative_welford_mass() -> None:
    with pytest.raises(ContractError, match="M2 cannot be negative"):
        BehaviourAtom(
            atom_id=1,
            prototype=tuple([0.0] * FEATURE_WIDTH),
            visit_count=5,
            epoch_counts={1: 5},
            state_summary=SecurityStateV1(),
            delta_phi_mean=0.0,
            delta_phi_m2=-1.0,
            uncertainty_envelope=(0.0, 0.0),
            compile_status=CompileStatus.NEURAL,
            first_sequence=0,
            last_sequence=0,
        )


def test_epoch_counts_are_bounded_at_eight_on_atoms_and_edges() -> None:
    quantizer = BehaviourQuantizer()
    for epoch in range(1, 25):
        quantizer.quantize_behaviour_atom(
            _encoded(epoch_id=epoch),
            state=SecurityStateV1(),
            epoch_id=epoch,
            sequence=epoch,
        )
    atoms = quantizer.atoms()
    assert len(atoms) == 1, "identical points must not open new atoms"
    assert len(atoms[0].epoch_counts) == MAX_EPOCHS_PER_ATOM

    lattice = TransitionLattice()
    for epoch in range(1, 25):
        lattice.observe(1, 2, epoch_id=epoch, delta_phi=0.0, uncertainty=0.5)
    edge = lattice.edge(1, 2)
    assert edge is not None
    assert len(edge.epoch_counts) == MAX_EPOCHS_PER_ATOM
    assert edge.count == 24, "bounding epoch history must not lose the total count"


def test_welford_variance_needs_no_stored_samples() -> None:
    samples = [1.0, 2.0, 4.0, 8.0, 16.0]
    mean, m2 = 0.0, 0.0
    for index, sample in enumerate(samples, start=1):
        mean, m2 = welford_update(index, mean, m2, sample)
    expected_mean = sum(samples) / len(samples)
    expected_var = sum((s - expected_mean) ** 2 for s in samples) / (len(samples) - 1)
    assert mean == pytest.approx(expected_mean)
    assert m2 / (len(samples) - 1) == pytest.approx(expected_var)


def test_distance_within_never_beats_the_incumbent_when_it_abandons() -> None:
    """The early-exit optimisation must not change which prototype wins."""
    atom = _atom(1)
    far = [0.0] * FEATURE_WIDTH
    far[3] = 9.0
    exact = atom.distance(far)
    abandoned = atom.distance_within(far, 0.35)
    assert abandoned > 0.35
    assert atom.distance_within(far, exact + 1.0) == pytest.approx(exact)


# --- quantizer bounds --------------------------------------------------------


def test_atom_count_never_exceeds_max_atoms_and_evictions_are_counted() -> None:
    quantizer = BehaviourQuantizer(max_atoms=32)
    for index in range(200):
        quantizer.quantize_behaviour_atom(
            _encoded(value=float(index) * 2.0),
            state=SecurityStateV1(),
            epoch_id=1,
            sequence=index,
        )
    stats = quantizer.stats()
    assert stats.atoms == 32
    assert len(quantizer.atoms()) <= 32
    # Truncation is explicit: creations minus survivors must be accounted for.
    assert stats.evictions == stats.creations - stats.atoms
    assert stats.evictions > 0


def test_transition_table_never_exceeds_max_transitions() -> None:
    lattice = TransitionLattice(max_transitions=16)
    for index in range(100):
        lattice.observe(index, index + 1, epoch_id=1, delta_phi=0.0, uncertainty=0.5)
    assert len(lattice) == 16
    assert lattice.evictions() == 84
    assert MAX_TRANSITIONS == 4096, "the default bound is a contract, not a suggestion"


def test_quantization_is_deterministic_across_runs() -> None:
    sequence = [_encoded(value=float(i % 7) * 1.5, epoch_id=1) for i in range(60)]

    def run() -> list[int]:
        quantizer = BehaviourQuantizer()
        return [
            quantizer.quantize_behaviour_atom(
                step, state=SecurityStateV1(), epoch_id=1, sequence=index
            ).atom_id
            for index, step in enumerate(sequence)
        ]

    assert run() == run()


def test_quantization_is_unaffected_by_an_unrelated_prefix() -> None:
    """Content-addressed ids, not a counter.

    A counter would renumber every atom when unrelated traffic is prepended, and
    a lattice whose node names move cannot be exported to Stage 3 or compared
    across runs.
    """
    tail = [_encoded(value=float(i)) for i in range(10)]
    prefix = [_encoded(axis=5, value=100.0 + float(i)) for i in range(5)]

    def run(steps: list[EncodedTransition]) -> list[int]:
        quantizer = BehaviourQuantizer()
        return [
            quantizer.quantize_behaviour_atom(
                step, state=SecurityStateV1(), epoch_id=1, sequence=index
            ).atom_id
            for index, step in enumerate(steps)
        ]

    assert run(prefix + tail)[len(prefix) :] == run(tail)


def test_memory_bytes_grows_with_content_and_stays_bounded() -> None:
    quantizer = BehaviourQuantizer(max_atoms=16)
    observed: list[int] = []
    for index in range(120):
        quantizer.quantize_behaviour_atom(
            _encoded(value=float(index) * 2.0),
            state=SecurityStateV1(),
            epoch_id=1,
            sequence=index,
        )
        observed.append(quantizer.memory_bytes())
    assert observed == sorted(observed), "memory must not shrink while content grows"
    # An explicit ceiling derived from the declared bound, so a regression that
    # let an atom carry extra content would fail here rather than at 2 GB.
    per_atom_ceiling = _atom(1, epochs=tuple(range(MAX_EPOCHS_PER_ATOM))).memory_bytes()
    assert observed[-1] <= 16 * (per_atom_ceiling + 16)
    assert quantizer.memory_bytes() > 0


def test_memory_bytes_is_derived_from_content_not_a_constant() -> None:
    lean = _atom(1, epochs=(1,))
    fat = _atom(2, epochs=tuple(range(1, MAX_EPOCHS_PER_ATOM + 1)))
    assert fat.memory_bytes() > lean.memory_bytes()


# --- probability -------------------------------------------------------------


def test_probability_sums_to_one_over_successors_plus_unseen_mass() -> None:
    lattice = TransitionLattice()
    for target, repeats in ((10, 5), (11, 3), (12, 1)):
        for _ in range(repeats):
            lattice.observe(1, target, epoch_id=1, delta_phi=0.1, uncertainty=0.4)
    known = sum(lattice.probability(1, target) for target in lattice.known_targets(1))
    assert known + lattice.unseen_mass(1) == pytest.approx(1.0)
    # And the same holds per epoch, which is the property §24 depends on.
    known_epoch = sum(
        lattice.probability(1, target, epoch_id=1)
        for target in lattice.known_targets(1, epoch_id=1)
    )
    assert known_epoch + lattice.unseen_mass(1, epoch_id=1) == pytest.approx(1.0)


def test_epoch_filtered_probability_ignores_other_epochs() -> None:
    """Spec §24: a transition stable in one regime may be invalid in another."""
    lattice = TransitionLattice()
    for _ in range(20):
        lattice.observe(1, 10, epoch_id=1, delta_phi=0.0, uncertainty=0.5)
    lattice.observe(1, 11, epoch_id=2, delta_phi=0.0, uncertainty=0.5)
    assert lattice.probability(1, 10, epoch_id=2) < lattice.probability(1, 10)
    assert lattice.known_targets(1, epoch_id=2) == (11,)
    assert 10 not in lattice.known_targets(1, epoch_id=2)


def test_unobserved_source_reports_ignorance_not_certainty() -> None:
    """Without the vocabulary floor, no evidence would score 1.0 — free log-loss."""
    lattice = TransitionLattice()
    assert lattice.probability(999, 1) < 0.2
    assert lattice.unseen_mass(999) == pytest.approx(1.0)


def test_log_loss_is_finite_including_for_unknown_pairs() -> None:
    lattice = TransitionLattice()
    for _ in range(4):
        lattice.observe(1, 10, epoch_id=1, delta_phi=0.0, uncertainty=0.5)
    loss = lattice.log_loss([(1, 10), (1, 99), (7, 8)])
    assert math.isfinite(loss)
    assert loss > 0.0
    assert lattice.log_loss([]) == 0.0
    assert math.isfinite(lattice.perplexity([(1, 10)]))


def test_successor_ordering_is_total_under_ties() -> None:
    lattice = TransitionLattice()
    for target in (30, 20, 10):
        lattice.observe(1, target, epoch_id=1, delta_phi=0.0, uncertainty=0.5)
    assert [target for target, _ in lattice.successors(1)] == [10, 20, 30]


def test_lattice_eviction_keeps_the_probability_indices_consistent() -> None:
    lattice = TransitionLattice(max_transitions=2)
    for _ in range(5):
        lattice.observe(1, 10, epoch_id=1, delta_phi=0.0, uncertainty=0.5)
    lattice.observe(1, 11, epoch_id=1, delta_phi=0.0, uncertainty=0.5)
    lattice.observe(1, 12, epoch_id=1, delta_phi=0.0, uncertainty=0.5)
    assert lattice.evictions() == 1
    known = sum(lattice.probability(1, t) for t in lattice.known_targets(1))
    assert known + lattice.unseen_mass(1) == pytest.approx(1.0)


def test_edge_count_must_be_positive() -> None:
    with pytest.raises(ContractError, match="count must be >= 1"):
        LatticeTransition(
            source=1,
            target=2,
            count=0,
            epoch_counts={},
            delta_phi_sum=0.0,
            uncertainty_mean=0.0,
            compile_status=CompileStatus.NEURAL,
        )


# --- equivalence -------------------------------------------------------------


def test_jensen_shannon_is_symmetric_unit_bounded_and_zero_for_identical() -> None:
    left = {1: 0.5, 2: 0.3, "unseen": 0.2}
    right = {1: 0.1, 3: 0.6, "unseen": 0.3}
    forward = jensen_shannon(left, right)
    backward = jensen_shannon(right, left)
    assert forward == pytest.approx(backward)
    assert 0.0 <= forward <= 1.0
    assert jensen_shannon(left, dict(left)) == 0.0
    # Disjoint support is the maximum: one full bit.
    assert jensen_shannon({1: 1.0}, {2: 1.0}) == pytest.approx(1.0)


def test_merge_below_min_evidence_is_refused_and_counted() -> None:
    """An equivalence asserted on thin evidence is the silent merge bug."""
    lattice = TransitionLattice()
    for source in (1, 2):
        for _ in range(3):
            lattice.observe(source, 10, epoch_id=1, delta_phi=0.0, uncertainty=0.5)
    verdict = predictive_equivalence(
        lattice, _atom(1, visits=3), _atom(2, visits=3), min_evidence=8
    )
    assert verdict.equivalent is False
    assert verdict.reason == REASON_INSUFFICIENT_EVIDENCE
    # The distributions really are identical: the refusal is about evidence, not
    # about distance. If someone "fixes" the refusal, this line keeps the bug
    # visible.
    assert verdict.distance == pytest.approx(0.0)


def test_state_disagreement_blocks_a_predictively_identical_merge() -> None:
    """Same future, different capability state, different security fact (ADR-0005)."""
    lattice = TransitionLattice()
    for source in (1, 2):
        for _ in range(10):
            lattice.observe(source, 10, epoch_id=1, delta_phi=0.0, uncertainty=0.5)
    elevated = SecurityStateV1().raised_to("privilege", Privilege.ROOT)
    verdict = predictive_equivalence(
        lattice, _atom(1), _atom(2, state=elevated)
    )
    assert verdict.distance == pytest.approx(0.0)
    assert verdict.state_compatible is False
    assert verdict.equivalent is False
    assert verdict.reason == REASON_STATE


def test_equivalent_atoms_with_real_evidence_do_merge() -> None:
    """The refusal path must not be 'always refuse' — that would pass vacuously."""
    quantizer, lattice = _two_atom_fixture(visits=10)
    restructurer = LatticeRestructurer()
    report = restructurer.merge_equivalent_atoms(quantizer, lattice)
    assert report.merges == 1
    assert report.macro_states == 1
    macros = restructurer.macro_states()
    assert len(macros[0].members) == 2
    assert macros[0].merge_evidence, "a macro state must carry its justification"


def test_macro_state_refuses_to_exist_without_recorded_evidence() -> None:
    with pytest.raises(ContractError, match="no recorded verdict"):
        MacroState(
            macro_id=0,
            members=frozenset({1, 2}),
            created_at_sequence=0,
            merge_evidence=(),
        )


def test_macro_state_refuses_a_single_member() -> None:
    verdict = predictive_equivalence(TransitionLattice(), _atom(1), _atom(2))
    with pytest.raises(ContractError, match=">= 2 members"):
        MacroState(
            macro_id=0,
            members=frozenset({1}),
            created_at_sequence=0,
            merge_evidence=(verdict,),
        )


# --- restructuring -----------------------------------------------------------


def _two_atom_fixture(*, visits: int) -> tuple[BehaviourQuantizer, TransitionLattice]:
    """Two distinct, far-apart atoms with identical successor distributions."""
    quantizer = BehaviourQuantizer()
    left = _encoded(axis=0, value=0.0)
    right = _encoded(axis=1, value=2.0)
    ids: list[int] = []
    for point in (left, right):
        for index in range(visits):
            result = quantizer.quantize_behaviour_atom(
                point, state=SecurityStateV1(), epoch_id=1, sequence=index
            )
        ids.append(result.atom_id)
    assert ids[0] != ids[1], "fixture needs two atoms, not one"
    lattice = TransitionLattice()
    for atom_id in ids:
        for _ in range(5):
            lattice.observe(atom_id, 900, epoch_id=1, delta_phi=0.0, uncertainty=0.5)
    return quantizer, lattice


def test_max_macro_zero_performs_no_merges() -> None:
    """The fixed-K control for D2.7 must be a real setting, not a no-op path."""
    quantizer, lattice = _two_atom_fixture(visits=10)
    restructurer = LatticeRestructurer(max_macro=0)
    report = restructurer.merge_equivalent_atoms(quantizer, lattice)
    assert report.merges == 0
    assert report.macro_states == 0
    assert report.reason_counts == {REASON_DISABLED: 1}
    assert restructurer.partition() == frozenset(
        frozenset({atom.atom_id}) for atom in quantizer.atoms()
    )


def test_unmerge_restores_the_pre_merge_partition_exactly() -> None:
    """Spec §13: merging is reversible."""
    quantizer, lattice = _two_atom_fixture(visits=10)
    restructurer = LatticeRestructurer()
    restructurer.merge_equivalent_atoms(quantizer, lattice)
    before = frozenset(frozenset({atom.atom_id}) for atom in quantizer.atoms())
    macro_id = restructurer.macro_states()[0].macro_id
    report = restructurer.unmerge(macro_id)
    assert report.reason_counts == {"UNMERGED": 2}
    assert restructurer.macro_states() == ()
    assert restructurer.partition() == before
    assert all(restructurer.macro_of(a.atom_id) is None for a in quantizer.atoms())


def test_unmerge_of_an_unknown_macro_is_refused_not_silent() -> None:
    report = LatticeRestructurer().unmerge(4242)
    assert report.refused == 1
    assert report.merges == 0


def test_fission_increases_atom_count_and_lowers_successor_entropy() -> None:
    quantizer = BehaviourQuantizer()
    point = _encoded(axis=0, value=0.0)
    for index in range(12):
        result = quantizer.quantize_behaviour_atom(
            point, state=SecurityStateV1(), epoch_id=1, sequence=index
        )
    atom_id = result.atom_id
    lattice = TransitionLattice()
    for target in range(900, 908):
        lattice.observe(atom_id, target, epoch_id=1, delta_phi=0.0, uncertainty=0.5)

    restructurer = LatticeRestructurer()
    before_atoms = len(quantizer.atoms())
    before_entropy = successor_entropy(lattice, atom_id)
    report = restructurer.split_heterogeneous_atom(quantizer, lattice, atom_id)

    assert report.fissions == 1
    assert len(quantizer.atoms()) == before_atoms + 1
    assert successor_entropy(lattice, atom_id) < before_entropy


def test_fission_on_a_homogeneous_atom_is_refused_and_counted() -> None:
    """Fission triggers on measured heterogeneity only, never on an urge."""
    quantizer = BehaviourQuantizer()
    point = _encoded(axis=0, value=0.0)
    for index in range(12):
        result = quantizer.quantize_behaviour_atom(
            point, state=SecurityStateV1(), epoch_id=1, sequence=index
        )
    lattice = TransitionLattice()
    for _ in range(50):
        lattice.observe(
            result.atom_id, 900, epoch_id=1, delta_phi=0.0, uncertainty=0.5
        )
    report = LatticeRestructurer().split_heterogeneous_atom(
        quantizer, lattice, result.atom_id
    )
    assert report.fissions == 0
    assert report.refused == 1
    assert report.reason_counts == {REASON_NOT_HETEROGENEOUS: 1}
    assert len(quantizer.atoms()) == 1


def test_fission_of_an_unknown_atom_is_refused() -> None:
    report = LatticeRestructurer().split_heterogeneous_atom(
        BehaviourQuantizer(), TransitionLattice(), 12345
    )
    assert report.refused == 1
    assert report.fissions == 0


def test_stability_is_one_for_identical_runs() -> None:
    quantizer, lattice = _two_atom_fixture(visits=10)
    left = LatticeRestructurer()
    right = LatticeRestructurer()
    left.merge_equivalent_atoms(quantizer, lattice)
    right.merge_equivalent_atoms(quantizer, lattice)
    assert left.stability(right) == pytest.approx(1.0)


def test_stability_falls_when_one_run_merges_and_the_other_does_not() -> None:
    """A stability index that cannot fall is not measuring anything."""
    quantizer, lattice = _two_atom_fixture(visits=10)
    merging = LatticeRestructurer()
    fixed_k = LatticeRestructurer(max_macro=0)
    merging.merge_equivalent_atoms(quantizer, lattice)
    fixed_k.merge_equivalent_atoms(quantizer, lattice)
    assert merging.stability(fixed_k) == pytest.approx(0.0)


# --- the hash-bucket control -------------------------------------------------


def test_a_crc32_collision_never_merges_two_behaviours() -> None:
    """Pins S2-11.

    ``quantize_behaviour_atom`` used ``stable_bucket_id(*key)`` directly as the
    dict key with no collision handling, while ``BehaviourQuantizer._free_id``
    linear-probes with the comment "so a crc32 collision cannot merge two
    behaviours". ``ID_SPACE`` is 2**24, so two distinct
    ``(relation_family, state_delta_mask, object_property_mask)`` triples do
    collide, and the second triple's visits, epoch counts, ΔΦ statistics and
    joined state were folded into a bucket whose ``key`` field still named only
    the first. ``HashBucketQuantizer`` is the DEFAULT quantizer (ADR-0115), so
    this was the one that mattered.

    The pair below is a real collision, found by enumerating the key space:
    ``stable_bucket_id(0, 82, 51) == stable_bucket_id(1, 420, 10) == 11141380``.
    """
    left, right = (0, 82, 51), (1, 420, 10)
    assert stable_bucket_id(*left) == stable_bucket_id(*right)

    quantizer = HashBucketQuantizer()
    ids = []
    for family, mask, obj in (left, right):
        result = quantizer.quantize_behaviour_atom(
            _encoded(
                relation_family=family,
                state_delta_mask=mask,
                object_property_mask=obj,
            ),
            state=SecurityStateV1(),
            epoch_id=1,
            sequence=0,
        )
        ids.append(result.atom_id)
        assert result.created is True, "a colliding triple must not be absorbed"

    assert ids[0] != ids[1], "two behaviours shared one bucket"
    assert len(quantizer.buckets()) == 2
    assert {bucket.key for bucket in quantizer.buckets()} == {left, right}
    for bucket in quantizer.buckets():
        assert bucket.visit_count == 1, "one behaviour's visits landed on another"
    assert quantizer.get(ids[0]).key == left
    assert quantizer.get(ids[1]).key == right


def test_hash_bucket_gives_the_same_id_for_identical_key_triples() -> None:
    quantizer = HashBucketQuantizer()
    first = quantizer.quantize_behaviour_atom(
        _encoded(relation_family=3, state_delta_mask=5, object_property_mask=9),
        state=SecurityStateV1(),
        epoch_id=1,
        sequence=0,
    )
    second = quantizer.quantize_behaviour_atom(
        # Same triple, different geometry and uncertainty: the bucket ignores both.
        _encoded(
            axis=7,
            value=3.0,
            uncertainty=0.9,
            relation_family=3,
            state_delta_mask=5,
            object_property_mask=9,
        ),
        state=SecurityStateV1(),
        epoch_id=1,
        sequence=1,
    )
    assert first.atom_id == second.atom_id
    assert first.created is True
    assert second.created is False
    other = quantizer.quantize_behaviour_atom(
        _encoded(relation_family=4, state_delta_mask=5, object_property_mask=9),
        state=SecurityStateV1(),
        epoch_id=1,
        sequence=2,
    )
    assert other.atom_id != first.atom_id


def test_hash_bucket_ids_do_not_depend_on_pythonhashseed() -> None:
    """Builtin ``hash()`` is randomised per process; a bucket id must not be."""
    script = (
        "from pocketsec.stage2.lattice.quantizer import stable_bucket_id;"
        "print(stable_bucket_id(3, 5, 9), stable_bucket_id(0, 0, 0))"
    )
    outputs = set()
    for seed in ("random", "1", "12345"):
        completed = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            check=True,
            env={"PYTHONHASHSEED": seed, "PYTHONPATH": str(_repo_root())},
        )
        outputs.add(completed.stdout.strip())
    assert len(outputs) == 1, f"bucket ids varied with PYTHONHASHSEED: {outputs}"
    expected = f"{stable_bucket_id(3, 5, 9)} {stable_bucket_id(0, 0, 0)}"
    assert outputs == {expected}


def test_hash_bucket_is_bounded_and_counts_evictions() -> None:
    quantizer = HashBucketQuantizer(max_atoms=4)
    for index in range(40):
        quantizer.quantize_behaviour_atom(
            _encoded(relation_family=index, state_delta_mask=index),
            state=SecurityStateV1(),
            epoch_id=1,
            sequence=index,
        )
    stats = quantizer.stats()
    assert stats.atoms == 4
    assert stats.evictions == stats.creations - stats.atoms > 0


def _repo_root() -> object:
    from pocketsec.stage0.gate import REPO_ROOT

    return REPO_ROOT


# --- measurements (no winner is asserted) ------------------------------------


def _quantize_corpus(quantizer: object, samples: tuple, *, start: int) -> tuple:
    """Feed ``samples`` through ``quantizer``, returning (lattice-ready pairs, next seq)."""
    pairs: list[tuple[int, int]] = []
    sequence = start
    for sample in samples:
        previous: int | None = None
        for step in sample.steps:
            result = quantizer.quantize_behaviour_atom(  # type: ignore[attr-defined]
                step,
                state=_state_from_mask(step.state_delta_mask),
                epoch_id=step.epoch_id,
                sequence=sequence,
            )
            if previous is not None:
                pairs.append((previous, result.atom_id))
            previous = result.atom_id
            sequence += 1
    return pairs, sequence


def _lattice_from(pairs: list[tuple[int, int]]) -> TransitionLattice:
    lattice = TransitionLattice()
    for source, target in pairs:
        lattice.observe(source, target, epoch_id=1, delta_phi=0.0, uncertainty=0.5)
    return lattice


def _fit_and_score(quantizer: object, fit: tuple, score: tuple) -> tuple[float, object]:
    fit_pairs, sequence = _quantize_corpus(quantizer, fit, start=0)
    lattice = _lattice_from(fit_pairs)
    held, _ = _quantize_corpus(quantizer, score, start=sequence)
    return lattice.log_loss(held), quantizer.stats()  # type: ignore[attr-defined]


@pytest.mark.slow
def test_measured_transition_log_loss_learned_versus_hash_bucket() -> None:
    """D2.6's deciding metric, on the fixed split (ambiguous, 240, seed 11).

    Reports both numbers and asserts only that the comparison was *fair* — equal
    data, equal split, and the learned quantizer held at or below the control's
    byte budget. Which one wins is a finding for ADR-0115, not an assertion: a
    test that asserted the learned quantizer wins would be a test that has to be
    weakened when it does not.
    """
    dataset = build_dataset(name="d26-cmp", count=240, seed=11, corpus="ambiguous")
    split = int(len(dataset.samples) * 0.8)
    fit, score = dataset.samples[:split], dataset.samples[split:]

    hash_loss, hash_stats = _fit_and_score(
        HashBucketQuantizer(max_atoms=MAX_ATOMS), fit, score
    )
    budget = hash_stats.memory_bytes  # type: ignore[attr-defined]

    # Matched memory: shrink the learned quantizer until it fits the control's
    # budget. It needs ~1 KB per atom (96 floats) against the bucket's ~320 B, so
    # the match costs it most of its capacity — that is the honest comparison.
    capacity = MAX_ATOMS
    for _attempt in range(5):
        learned_loss, learned_stats = _fit_and_score(
            BehaviourQuantizer(max_atoms=capacity), fit, score
        )
        used = learned_stats.memory_bytes  # type: ignore[attr-defined]
        if used <= budget:
            break
        capacity = max(1, int(capacity * budget / used))

    print(
        f"\nD2.6 corpus=ambiguous count=240 seed=11 "
        f"transitions={dataset.transition_count}\n"
        f"  HASH    atoms={hash_stats.atoms} bytes={budget} "  # type: ignore[attr-defined]
        f"log_loss={hash_loss:.6f}\n"
        f"  LEARNED atoms={learned_stats.atoms} "  # type: ignore[attr-defined]
        f"bytes={learned_stats.memory_bytes} "  # type: ignore[attr-defined]
        f"max_atoms={capacity} log_loss={learned_loss:.6f}"
    )
    assert math.isfinite(hash_loss) and hash_loss > 0.0
    assert math.isfinite(learned_loss) and learned_loss > 0.0
    assert learned_stats.memory_bytes <= budget, (  # type: ignore[attr-defined]
        "the comparison is void unless the learned quantizer fits the control's budget"
    )


@pytest.mark.slow
def test_atom_identity_is_order_dependent_which_stability_alone_hides() -> None:
    """G2.4's stability index can be 1.0 while no atom is actually reusable.

    Quantizing the same corpus forward and reversed produces two partitions that
    a Rand index calls identical — because both are all singletons — while the
    atom *ids* barely overlap. This test exists so that number can never be
    quoted as evidence of atom reuse again.
    """
    dataset = build_dataset(name="d26-stab", count=60, seed=11, corpus="ambiguous")
    forward_q = BehaviourQuantizer()
    reverse_q = BehaviourQuantizer()
    forward_pairs, _ = _quantize_corpus(forward_q, dataset.samples, start=0)
    reverse_pairs, _ = _quantize_corpus(
        reverse_q, tuple(reversed(dataset.samples)), start=0
    )

    forward_ids = {atom.atom_id for atom in forward_q.atoms()}
    reverse_ids = {atom.atom_id for atom in reverse_q.atoms()}
    overlap = len(forward_ids & reverse_ids) / max(len(forward_ids), 1)

    # Each direction gets its OWN lattice. Sharing one — or worse, passing an
    # empty one — makes every successor distribution identical, so equivalence
    # collapses to the state/epoch checks and the measurement becomes fiction.
    left = LatticeRestructurer()
    right = LatticeRestructurer()
    left_report = left.merge_equivalent_atoms(forward_q, _lattice_from(forward_pairs))
    right_report = right.merge_equivalent_atoms(reverse_q, _lattice_from(reverse_pairs))
    stability = left.stability(right)

    print(
        f"\nG2.4 corpus=ambiguous count=60 seed=11 "
        f"forward_atoms={len(forward_ids)} reverse_atoms={len(reverse_ids)} "
        f"id_overlap={overlap:.4f} stability={stability:.4f} "
        f"forward_merges={left_report.merges} reverse_merges={right_report.merges}"
    )
    assert overlap < 0.90, (
        "if atom ids ever become order-stable this assertion should be inverted, "
        "not deleted"
    )
    assert stability > overlap, (
        "the point of this test: the Rand index reads higher than the fraction of "
        "atoms that actually survive a reordering, so it cannot stand in for reuse"
    )


def test_adr_0115_verdict_is_pinned_in_code_not_only_in_prose() -> None:
    """ADR-0115 rejected the learned quantizer; the default must say so.

    A finding that lives only in a document is not a decision the code obeys.
    Flipping this back on is a legitimate act — after a re-measurement — and it
    will fail here, which is the point.
    """
    from pocketsec.stage2.lattice import quantizer as module

    assert module.BEHAVIOUR_QUANTIZER_ENABLED is False
    assert module.DEFAULT_QUANTIZER is HashBucketQuantizer


def test_successor_distribution_reserves_mass_for_the_unrecorded() -> None:
    lattice = TransitionLattice()
    lattice.observe(1, 10, epoch_id=1, delta_phi=0.0, uncertainty=0.5)
    distribution = successor_distribution(lattice, 1)
    assert "unseen" in distribution
    assert sum(distribution.values()) == pytest.approx(1.0)
