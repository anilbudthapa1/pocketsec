"""D2.12 — epoch-conditioned adaptation, quarantine and gated promotion.

These tests are about a security boundary, so almost none of them assert that a
constructor works. They assert that things are *refused*: that behavioural
novelty cannot open an epoch, that an uncorroborated decision cannot invalidate
learned structure, that frequency cannot buy trust, that a high-consequence
sample is kept as evidence rather than learned from, and that the buffer's bounds
bound.

Two of them exist specifically to fail if someone weakens an invariant while
making something else pass:

* ``test_promotion_on_frequency_alone_is_refused_even_by_a_weakened_buffer``
  hands the promotion gate a verdict that claims every check passed but names a
  single epoch. If the gate ever starts trusting the buffer's own say-so, this is
  the test that breaks.
* ``test_no_escalating_sample_ever_reaches_trusted_state`` inspects every sample
  the trusted store actually accepted, rather than a summary count.

The measured controls are in
``test_accept_everything_and_accept_nothing_bound_the_measurement``: the
quarantine's effect is reported as a delta against no gate at all and against
refusing everything, because "malicious_patterns_normalised == 0" is also true of
a system that never learns anything.

All corpora are synthetic.
"""

from __future__ import annotations

import math
import statistics
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

import pytest

from pocketsec.stage0.benchmark.security_metrics import average_precision
from pocketsec.stage1.epoch.model import (
    Epoch,
    EpochDecision,
    EpochModel,
    EpochTransitionReason,
    SystemIdentity,
)
from pocketsec.stage1.labs.corpus import Scenario
from pocketsec.stage1.pipeline import Stage1Pipeline
from pocketsec.stage1.state.security_state import (
    DIMENSIONS,
    CredentialExposure,
    SecurityStateV1,
)
from pocketsec.stage2.adaptation.epoch_guard import (
    AdaptationPolicy,
    SystemChangeSignal,
    detect_epoch_mismatch,
    drift_report,
    run_adaptation,
)
from pocketsec.stage2.adaptation.promotion import (
    MAX_DELAYED_PROMOTIONS,
    REFUSE_DELAY_QUEUE_FULL,
    REFUSE_EVIDENCE,
    REFUSE_FREQUENCY_ALONE,
    PromotionController,
)
from pocketsec.stage2.adaptation.quarantine import (
    ESCALATION_MASK,
    ESCALATION_PROPERTIES,
    MAX_QUARANTINE,
    AdaptationSample,
    QuarantineBuffer,
    QuarantineOutcome,
    QuarantineVerdict,
    pattern_key,
)
from pocketsec.stage2.encoder.ssir_encoder import (
    FEATURE_WIDTH,
    GROUP_OFFSETS,
    EncodedTransition,
    encode_ssir_transition,
    feature_names,
)
from pocketsec.stage2.labs.drift_corpus import (
    DRIFT_TECHNIQUE_CORROBORATED_CHANGE,
    DRIFT_TECHNIQUE_UNCORROBORATED_CHANGE,
    DRIFT_VERSION,
    build_drift_corpus,
    malicious_lineage,
)
from pocketsec.stage2.labs.poison_suite import (
    POISON_ARMS,
    POISON_TECHNIQUE_LEGITIMATE,
    POISON_VERSION,
    adaptation_lineage,
    build_poison_suite,
    poison_lineage,
)

CORPUS_COUNT = 60
CORPUS_SEED = 11


# --- stand-ins for the trusted store ----------------------------------------
# `lattice/` is written by another work package in this wave. These implement the
# subset of its published signatures that the promotion gate touches, and they
# record what they were asked to accept so a test can inspect it rather than
# trust a summary.


@dataclass
class _StubAtom:
    atom_id: int
    prototype: tuple[float, ...]
    visit_count: int = 0
    epoch_counts: dict[int, int] = field(default_factory=dict)

    def epoch_valid(self, epoch_id: int) -> bool:
        return epoch_id in self.epoch_counts


@dataclass(frozen=True, slots=True)
class _StubResult:
    atom_id: int
    distance: float
    created: bool


class _StubQuantizer:
    """Nearest-prototype quantizer with the published bounds."""

    def __init__(self, *, max_atoms: int = 256, radius: float = 0.35) -> None:
        self.max_atoms = max_atoms
        self.radius = radius
        self.accepted: list[EncodedTransition] = []
        self._atoms: dict[int, _StubAtom] = {}
        self._next = 0

    def quantize_behaviour_atom(
        self,
        encoded: EncodedTransition,
        *,
        state: SecurityStateV1,
        epoch_id: int,
        sequence: int,
    ) -> _StubResult:
        self.accepted.append(encoded)
        best: _StubAtom | None = None
        best_distance: float | None = None
        for atom in self._atoms.values():
            distance = sum(
                (a - b) * (a - b) for a, b in zip(atom.prototype, encoded.features, strict=True)
            )
            if best_distance is None or distance < best_distance:
                best, best_distance = atom, distance
        if (best is None or best_distance is None or best_distance > self.radius) and len(
            self._atoms
        ) < self.max_atoms:
            atom = _StubAtom(atom_id=self._next, prototype=tuple(encoded.features))
            self._atoms[self._next] = atom
            self._next += 1
            atom.visit_count = 1
            atom.epoch_counts[epoch_id] = 1
            return _StubResult(atom.atom_id, 0.0, True)
        assert best is not None
        best.prototype = tuple(
            p + 0.05 * (f - p) for p, f in zip(best.prototype, encoded.features, strict=True)
        )
        best.visit_count += 1
        best.epoch_counts[epoch_id] = best.epoch_counts.get(epoch_id, 0) + 1
        return _StubResult(best.atom_id, best_distance or 0.0, False)

    def get(self, atom_id: int) -> _StubAtom | None:
        return self._atoms.get(atom_id)

    def atoms(self) -> tuple[_StubAtom, ...]:
        return tuple(self._atoms.values())


class _StubLattice:
    def __init__(self) -> None:
        self.observed: list[tuple[int, int, int]] = []

    def observe(
        self,
        source: int,
        target: int,
        *,
        epoch_id: int,
        delta_phi: float,
        uncertainty: float,
    ) -> None:
        self.observed.append((source, target, epoch_id))


DRIFT_SIGNALS = {
    DRIFT_TECHNIQUE_CORROBORATED_CHANGE: SystemChangeSignal(
        changed=frozenset({"package_digest", "service_digest"}),
        corroborated=frozenset({"package_digest", "service_digest"}),
    ),
    DRIFT_TECHNIQUE_UNCORROBORATED_CHANGE: SystemChangeSignal(
        changed=frozenset({"service_digest"}),
        corroborated=frozenset(),
    ),
}


# --- helpers -----------------------------------------------------------------


def _encoded(
    *,
    relation: int = 3,
    object_property_mask: int = 0,
    state_delta_mask: int = 0,
    features: tuple[float, ...] | None = None,
    delta_phi: float = 0.0,
) -> EncodedTransition:
    """A synthetic encoding, for the unit-level refusal tests."""
    return EncodedTransition(
        features=features if features is not None else (0.0,) * FEATURE_WIDTH,
        relation=relation,
        relation_family=1,
        state_delta_mask=state_delta_mask,
        time_bucket=4,
        delta_phi=delta_phi,
        object_property_mask=object_property_mask,
        epoch_id=0,
        evidence=("ev:1",),
    )


def _sample(
    encoded: EncodedTransition,
    *,
    epoch_id: int = 0,
    delta_phi: float = 0.0,
    uncertainty: float = 0.1,
    sequence: int = 1,
    causal_signature: str = "",
    parent_signature: str = "",
) -> AdaptationSample:
    return AdaptationSample(
        encoded=encoded,
        state=SecurityStateV1(),
        epoch_id=epoch_id,
        delta_phi=delta_phi,
        uncertainty=uncertainty,
        evidence=encoded.evidence,
        received_at_sequence=sequence,
        causal_signature=causal_signature,
        parent_signature=parent_signature,
    )


def _object_bit(name: str) -> int:
    """Bit position of one object property inside ``object_property_mask``."""
    names = feature_names()
    offset = GROUP_OFFSETS["object_semantics"]
    for index in range(offset, len(names)):
        if names[index] == f"object.{name}":
            return index - offset
    raise AssertionError(f"object.{name} not in the encoder layout")


def _corroborated(epoch_id: int) -> EpochDecision:
    return EpochDecision(
        epoch_id=epoch_id,
        reason=EpochTransitionReason.SYSTEM_CHANGE_CORROBORATED,
        changed_components=frozenset({"package_digest"}),
        corroborated=True,
        detail="test",
    )


def _pooled_order_free_scores(scenarios: tuple[Scenario, ...]) -> list[float]:
    """Multinomial naive Bayes over per-session operation counts.

    Order-free by construction, and fitted on the very data it scores — the most
    generous baseline of its kind. If it beats the base rate, the corpus leaks its
    label through operation vocabulary and no structural result measured on it
    would mean anything (``planning/MEMORY.md`` benchmarking trap 4).
    """
    vocabulary = sorted({b.operation for s in scenarios for b in s.behaviours})
    totals: dict[int, Counter[str]] = {0: Counter(), 1: Counter()}
    for scenario in scenarios:
        for behaviour in scenario.behaviours:
            totals[scenario.label][behaviour.operation] += 1
    sizes = {label: sum(totals[label].values()) for label in (0, 1)}
    log_p = {
        label: {
            operation: math.log(
                (totals[label][operation] + 1.0) / (sizes[label] + len(vocabulary))
            )
            for operation in vocabulary
        }
        for label in (0, 1)
    }
    scores: list[float] = []
    for scenario in scenarios:
        counts = Counter(b.operation for b in scenario.behaviours)
        scores.append(
            sum(n * (log_p[1][op] - log_p[0][op]) for op, n in counts.items())
        )
    return scores


def _compile(scenarios: tuple[Scenario, ...]) -> tuple[tuple[Scenario, tuple[Any, ...]], ...]:
    """Compile a corpus once. One pipeline, as a single host over time."""
    pipeline = Stage1Pipeline()
    return tuple(
        (scenario, pipeline.run_scenario(scenario, offset=index).transitions)
        for index, scenario in enumerate(scenarios)
    )


def _median_peak_delta_phi(
    compiled: tuple[tuple[Scenario, tuple[Any, ...]], ...],
) -> dict[int, float]:
    per_class: dict[int, list[float]] = {0: [], 1: []}
    for scenario, transitions in compiled:
        per_class[scenario.label].append(
            max((abs(t.delta_phi) for t in transitions), default=0.0)
        )
    return {label: statistics.median(values) for label, values in per_class.items() if values}


# --- fixtures ----------------------------------------------------------------


@pytest.fixture(scope="module")
def drift_scenarios() -> tuple[Scenario, ...]:
    return build_drift_corpus(count=CORPUS_COUNT, seed=CORPUS_SEED)


@pytest.fixture(scope="module")
def poison_scenarios() -> tuple[Scenario, ...]:
    return build_poison_suite(count=CORPUS_COUNT, seed=CORPUS_SEED)


@pytest.fixture(scope="module")
def compiled_poison(poison_scenarios):  # type: ignore[no-untyped-def]
    return _compile(poison_scenarios)


@pytest.fixture(scope="module")
def compiled_drift(drift_scenarios):  # type: ignore[no-untyped-def]
    return _compile(drift_scenarios)


@pytest.fixture(scope="module")
def drift_runs(drift_scenarios):  # type: ignore[no-untyped-def]
    """One pass per policy. The two controls are the measurement, not decoration."""
    runs = {}
    for policy in AdaptationPolicy:
        quantizer = _StubQuantizer()
        runs[policy] = (
            run_adaptation(
                drift_scenarios,
                quantizer=quantizer,
                epoch_signals=DRIFT_SIGNALS,
                lattice=_StubLattice(),
                policy=policy,
                attack_lineage=malicious_lineage,
            ),
            quantizer,
        )
    return runs


# --- DTL-F18: the epoch guard ------------------------------------------------


def test_escalation_mask_is_derived_from_the_encoder_layout() -> None:
    """A hardcoded mask silently points at the wrong property when a group grows."""
    expected = 0
    for prop in ESCALATION_PROPERTIES:
        expected |= 1 << _object_bit(prop.value)
    assert ESCALATION_MASK == expected
    assert ESCALATION_MASK != 0


def test_behavioural_novelty_alone_never_reports_a_corroborated_change() -> None:
    """The entire anti-poisoning mechanism, at its narrowest point.

    Stage 1 accepts ``behavioural_novelty`` and deliberately ignores it. Here the
    novelty is maximal and the identity has changed, and there is still no
    corroborated change — so an atom the attacker made look stale stays valid.
    """
    model = EpochModel(identity=SystemIdentity(kernel_id="6.1.0", service_digest="svc-a"))
    decision = model.evaluate(
        observed_identity=SystemIdentity(kernel_id="6.1.0", service_digest="svc-b"),
        corroborating_evidence=frozenset(),
        now_ns=1,
        behavioural_novelty=1.0,
    )
    assert decision.reason is EpochTransitionReason.REJECTED_NO_CORROBORATION
    assert decision.corroborated is False

    atom = _StubAtom(atom_id=7, prototype=(0.0,), epoch_counts={0: 5})
    mismatch = detect_epoch_mismatch(atom, epoch=model.current, decision=decision)
    assert mismatch.corroborated_system_change is False
    assert mismatch.may_invalidate is False


def test_uncorroborated_epoch_decision_cannot_invalidate_an_atom() -> None:
    """An atom valid only in epoch 0, a host in epoch 4, and no corroboration."""
    atom = _StubAtom(atom_id=1, prototype=(0.0,), epoch_counts={0: 3})
    epoch = Epoch(epoch_id=4, identity=SystemIdentity(), key="k", opened_at_ns=0)
    decision = EpochDecision(
        epoch_id=4,
        reason=EpochTransitionReason.REJECTED_NO_CORROBORATION,
        changed_components=frozenset({"service_digest"}),
        corroborated=False,
        detail="no corroboration",
    )
    mismatch = detect_epoch_mismatch(atom, epoch=epoch, decision=decision)
    assert mismatch.mismatch is True
    assert mismatch.may_invalidate is False
    assert "novelty alone never invalidates" in mismatch.detail


def test_a_stale_corroboration_cannot_invalidate_an_atom() -> None:
    """A receipt for epoch 2 does not authorise anything about epoch 5."""
    atom = _StubAtom(atom_id=2, prototype=(0.0,), epoch_counts={0: 1, 1: 1})
    epoch = Epoch(epoch_id=5, identity=SystemIdentity(), key="k", opened_at_ns=0)
    mismatch = detect_epoch_mismatch(atom, epoch=epoch, decision=_corroborated(2))
    assert mismatch.mismatch is True
    assert mismatch.corroborated_system_change is False
    assert mismatch.may_invalidate is False


def test_corroborated_change_into_this_epoch_may_invalidate() -> None:
    """The permitted case, so the refusals above are not vacuous."""
    atom = _StubAtom(atom_id=3, prototype=(0.0,), epoch_counts={0: 9})
    epoch = Epoch(epoch_id=1, identity=SystemIdentity(), key="k", opened_at_ns=0)
    mismatch = detect_epoch_mismatch(atom, epoch=epoch, decision=_corroborated(1))
    assert mismatch.mismatch is True
    assert mismatch.corroborated_system_change is True
    assert mismatch.may_invalidate is True
    assert mismatch.valid_epochs == frozenset({0})


def test_an_atom_seen_in_this_epoch_is_not_a_mismatch() -> None:
    atom = _StubAtom(atom_id=4, prototype=(0.0,), epoch_counts={0: 1, 2: 6})
    epoch = Epoch(epoch_id=2, identity=SystemIdentity(), key="k", opened_at_ns=0)
    mismatch = detect_epoch_mismatch(atom, epoch=epoch, decision=_corroborated(2))
    assert mismatch.mismatch is False
    assert mismatch.may_invalidate is False


# --- DTL-F19: the quarantine -------------------------------------------------


def test_high_delta_phi_sample_is_retained_as_evidence_not_refused() -> None:
    """Evidence is preserved, never discarded, and never quietly normalised."""
    buffer = QuarantineBuffer()
    verdict = buffer.quarantine_adaptation_sample(
        _sample(_encoded(), delta_phi=9.0, sequence=1)
    )
    assert verdict.outcome is QuarantineOutcome.RETAINED_AS_EVIDENCE
    assert verdict.outcome is not QuarantineOutcome.REFUSED
    assert buffer.evidence()[0].evidence == ("ev:1",)
    assert buffer.evidence()[0].delta_phi == 9.0
    # And it did not become the anchor for anything.
    assert buffer.pending() == ()


def test_escalating_object_is_retained_as_evidence_whatever_its_delta_phi() -> None:
    """Credential meaning is evidence even when ΔΦ is flat."""
    buffer = QuarantineBuffer()
    mask = 1 << _object_bit("CREDENTIAL")
    verdict = buffer.quarantine_adaptation_sample(
        _sample(_encoded(object_property_mask=mask), delta_phi=0.0)
    )
    assert verdict.outcome is QuarantineOutcome.RETAINED_AS_EVIDENCE
    assert "credential" in verdict.detail


def test_a_capability_raising_sample_is_never_learned_from() -> None:
    """Stage 1 refuses to aggregate one; Stage 2 refuses to learn from one."""
    buffer = QuarantineBuffer()
    verdict = buffer.quarantine_adaptation_sample(
        _sample(_encoded(state_delta_mask=0b100))
    )
    assert verdict.outcome is QuarantineOutcome.RETAINED_AS_EVIDENCE


def test_high_uncertainty_sample_is_retained_as_evidence() -> None:
    buffer = QuarantineBuffer()
    verdict = buffer.quarantine_adaptation_sample(_sample(_encoded(), uncertainty=0.9))
    assert verdict.outcome is QuarantineOutcome.RETAINED_AS_EVIDENCE


def test_a_walk_away_from_the_anchor_is_refused() -> None:
    """Slow drift, in miniature: each step small, the walk refused.

    The anchor is the *first* escalation-free sample, so the distance is measured
    from where the pattern started and not from where the attacker last left it.
    """
    buffer = QuarantineBuffer()
    base = [0.0] * FEATURE_WIDTH
    start = GROUP_OFFSETS["object_semantics"] + _object_bit("TEMP_LOCATION")
    second = GROUP_OFFSETS["object_semantics"] + _object_bit("USER_WRITABLE")
    anchor = buffer.quarantine_adaptation_sample(
        _sample(_encoded(features=tuple(base)), sequence=1)
    )
    assert anchor.outcome is QuarantineOutcome.HELD

    one_step = list(base)
    one_step[start] = 1.0
    near = buffer.quarantine_adaptation_sample(
        _sample(_encoded(features=tuple(one_step)), sequence=2)
    )
    assert near.outcome is QuarantineOutcome.HELD, "a single bit is within the radius"

    two_steps = list(one_step)
    two_steps[second] = 1.0
    far = buffer.quarantine_adaptation_sample(
        _sample(_encoded(features=tuple(two_steps)), sequence=3)
    )
    assert far.outcome is QuarantineOutcome.REFUSED
    assert far.distance is not None and far.distance > buffer.consistency_radius


def test_only_a_corroborated_change_releases_an_anchor() -> None:
    """Epoch-conditioned, and conditioned on corroboration alone."""
    buffer = QuarantineBuffer()
    base = [0.0] * FEATURE_WIDTH
    buffer.quarantine_adaptation_sample(_sample(_encoded(features=tuple(base)), sequence=1))
    moved = list(base)
    moved[GROUP_OFFSETS["object_semantics"] + _object_bit("TEMP_LOCATION")] = 1.0
    moved[GROUP_OFFSETS["object_semantics"] + _object_bit("USER_WRITABLE")] = 1.0

    uncorroborated = EpochDecision(
        epoch_id=1,
        reason=EpochTransitionReason.REJECTED_NO_CORROBORATION,
        changed_components=frozenset({"service_digest"}),
        corroborated=False,
        detail="",
    )
    assert buffer.record_epoch_decision(uncorroborated) is False
    assert (
        buffer.quarantine_adaptation_sample(
            _sample(_encoded(features=tuple(moved)), sequence=2)
        ).outcome
        is QuarantineOutcome.REFUSED
    )

    assert buffer.record_epoch_decision(_corroborated(1)) is True
    reanchored = buffer.quarantine_adaptation_sample(
        _sample(_encoded(features=tuple(moved)), epoch_id=1, sequence=3)
    )
    assert reanchored.outcome is QuarantineOutcome.HELD
    assert buffer.stats().reanchored == 1


def test_quarantine_buffer_is_bounded_and_counts_every_drop() -> None:
    """Under a flood of novel signatures, nothing grows and nothing is silent."""
    buffer = QuarantineBuffer(capacity=8)
    for index in range(400):
        buffer.quarantine_adaptation_sample(
            _sample(_encoded(relation=index % 24), sequence=index + 1)
        )
        buffer.quarantine_adaptation_sample(
            _sample(_encoded(relation=index % 24), delta_phi=9.0, sequence=index + 1)
        )
    stats = buffer.stats()
    assert stats.pending_patterns + stats.retained_evidence <= 8
    assert stats.dropped_patterns > 0, "a flood of new signatures must be refused"
    assert stats.dropped_evidence > 0
    assert buffer.dropped() == stats.dropped_patterns + stats.dropped_evidence


def test_a_flood_cannot_displace_a_waiting_pattern() -> None:
    """Failing closed: the newcomer is refused, the incumbent keeps its place."""
    buffer = QuarantineBuffer(capacity=4)
    first = buffer.quarantine_adaptation_sample(_sample(_encoded(relation=1), sequence=1))
    for index in range(50):
        buffer.quarantine_adaptation_sample(
            _sample(_encoded(relation=2 + index), sequence=index + 2)
        )
    assert first.key in buffer.pending()
    assert buffer.observations(first.key) == 1


def test_quarantine_memory_stops_growing_once_capacity_is_reached() -> None:
    """Bounded means bounded: held bytes must not track the stream's length.

    Measured on the drift corpus (2040 samples, count=60 seed=11): 52,704 bytes
    held, and offering the same stream five times over leaves it at exactly 52,704
    with 4,589 drops counted. Here the stream keeps arriving and the record counts
    must stop moving. Byte counts are allowed a few bytes of slack because a
    retained record stores its key, and ``relation:9`` is one character shorter
    than ``relation:10``.
    """
    small = QuarantineBuffer(capacity=8)
    large = QuarantineBuffer(capacity=MAX_QUARANTINE)
    halfway: dict[int, tuple[int, int]] = {}
    for index in range(4000):
        if index == 2000:
            halfway = {
                id(b): (b.memory_bytes(), b.stats().pending_patterns + b.stats().retained_evidence)
                for b in (small, large)
            }
        for buffer in (small, large):
            buffer.quarantine_adaptation_sample(
                _sample(_encoded(relation=index % 24), delta_phi=9.0, sequence=index + 1)
            )
    assert small.memory_bytes() < large.memory_bytes()
    for buffer in (small, large):
        was_bytes, was_records = halfway[id(buffer)]
        stats = buffer.stats()
        assert stats.pending_patterns + stats.retained_evidence == was_records, (
            "the number of held records grew between 2000 and 4000 offered samples"
        )
        assert buffer.memory_bytes() <= was_bytes * 1.05
        assert buffer.dropped() > 0, "and the truncation was counted, not silent"
    assert large.memory_bytes() < MAX_QUARANTINE * 4096


def test_quarantine_refuses_a_single_epoch_configuration() -> None:
    with pytest.raises(ValueError, match="poisoning path"):
        QuarantineBuffer(min_epochs=1)


# --- promotion ---------------------------------------------------------------


def _eligible_verdict(*, epochs: int, observations: int = 40) -> QuarantineVerdict:
    """A verdict that claims to have passed everything."""
    return QuarantineVerdict(
        outcome=QuarantineOutcome.HELD,
        checks_passed=("risk", "consistency", "epoch", "observations"),
        checks_failed=(),
        epochs_observed=epochs,
        detail="hand-built",
        key="relation:3",
        observations=observations,
    )


def test_promotion_on_frequency_alone_is_refused_even_by_a_weakened_buffer() -> None:
    """The invariant test. Spec §37: frequency never makes something trusted.

    The verdict below asserts that every check passed and reports 40 observations
    in ONE epoch. If the promotion gate ever takes the buffer's word for it, this
    test fails — which is exactly what should happen.
    """
    controller = PromotionController()
    quantizer = _StubQuantizer()
    record = controller.promote(
        _eligible_verdict(epochs=1, observations=40_000),
        _sample(_encoded(), sequence=1),
        quantizer=quantizer,
        lattice=None,
    )
    assert record.outcome is QuarantineOutcome.REFUSED
    assert record.reason == REFUSE_FREQUENCY_ALONE
    assert quantizer.accepted == [], "nothing may reach trusted state"
    assert controller.refusals()[-1].reason == REFUSE_FREQUENCY_ALONE


def test_promotion_requires_distinct_corroborated_epochs() -> None:
    """Two epochs and a served delay promote; one epoch never does."""
    controller = PromotionController(delay_sequences=2)
    quantizer = _StubQuantizer()
    lattice = _StubLattice()
    verdict = _eligible_verdict(epochs=2)
    queued = controller.promote(
        verdict, _sample(_encoded(), sequence=10), quantizer=quantizer, lattice=lattice
    )
    assert queued.outcome is QuarantineOutcome.HELD
    assert queued.reason == "queued_for_delay"
    assert quantizer.accepted == []

    promoted = controller.promote(
        verdict, _sample(_encoded(), sequence=12), quantizer=quantizer, lattice=lattice
    )
    assert promoted.outcome is QuarantineOutcome.PROMOTED
    assert promoted.atom_id is not None
    assert len(quantizer.accepted) == 1
    assert controller.stats().promoted == 1


def test_promotion_refuses_a_sample_that_is_only_frequent_in_an_uncorroborated_epoch() -> None:
    """An epoch the controller never corroborated cannot carry a promotion."""
    controller = PromotionController(delay_sequences=1)
    quantizer = _StubQuantizer()
    verdict = _eligible_verdict(epochs=2)
    record = controller.promote(
        verdict,
        _sample(_encoded(), epoch_id=7, sequence=1),
        quantizer=quantizer,
        lattice=None,
    )
    assert record.outcome is QuarantineOutcome.REFUSED
    assert record.reason == REFUSE_FREQUENCY_ALONE
    assert quantizer.accepted == []


def _promote(controller, quantizer, lattice, *, sig, parent, epoch, sequence):
    """Queue and then promote one sample, returning the promotion record."""
    verdict = _eligible_verdict(epochs=2)
    controller.promote(
        verdict,
        _sample(
            _encoded(),
            epoch_id=epoch,
            sequence=sequence,
            causal_signature=sig,
            parent_signature=parent,
        ),
        quantizer=quantizer,
        lattice=lattice,
    )
    return controller.promote(
        verdict,
        _sample(
            _encoded(),
            epoch_id=epoch,
            sequence=sequence + 2,
            causal_signature=sig,
            parent_signature=parent,
        ),
        quantizer=quantizer,
        lattice=lattice,
    )


def test_promotion_never_writes_a_lattice_edge_nobody_observed() -> None:
    """Pins S2-AUTH-05.

    ``_write`` used to call ``lattice.observe(self._last_atom, atom_id, ...)``
    unconditionally, where ``_last_atom`` was simply the previously *promoted*
    atom — from any behaviour signature, any lineage, any epoch, any distance in
    the event stream — and the edge was stamped with the TARGET's ``epoch_id``.
    An inline comment asserted "this atom followed that one, in this epoch",
    which is not what the code established. Over a long run the trusted lattice
    accumulated a synthetic path through atom space whose ``count`` and
    ``epoch_counts`` were indistinguishable from observed evidence — and those
    are exactly the fields ``propose_compile_candidate`` reads to build a
    candidate's ``ValidityBoundary.epochs``, inside the one module that
    documents itself as the sole trust-boundary write path.

    Two promotions with no causal relationship, an epoch boundary and a million
    events between them must produce NO edge.
    """
    controller = PromotionController(delay_sequences=2)
    quantizer = _StubQuantizer()
    lattice = _StubLattice()
    controller.record_epoch_decision(_corroborated(5))

    first = _promote(
        controller, quantizer, lattice, sig="sig-a", parent="root", epoch=0, sequence=10
    )
    second = _promote(
        controller,
        quantizer,
        lattice,
        sig="sig-b",
        parent="unrelated",
        epoch=5,
        sequence=1_000_010,
    )
    assert first.outcome is QuarantineOutcome.PROMOTED
    assert second.outcome is QuarantineOutcome.PROMOTED
    assert lattice.observed == [], lattice.observed


def test_promotion_writes_the_edge_stage_one_actually_recorded() -> None:
    """The mirror of the above: a genuine causal link still reaches the lattice.

    ``sig-b``'s parent IS ``sig-a``, and both were promoted in the same epoch,
    so Stage 1 itself recorded that one followed the other. Removing the
    fabrication must not remove the mechanism.
    """
    controller = PromotionController(delay_sequences=2)
    quantizer = _StubQuantizer()
    lattice = _StubLattice()

    first = _promote(
        controller, quantizer, lattice, sig="sig-a", parent="root", epoch=0, sequence=10
    )
    second = _promote(
        controller, quantizer, lattice, sig="sig-b", parent="sig-a", epoch=0, sequence=14
    )
    assert lattice.observed == [(first.atom_id, second.atom_id, 0)], lattice.observed


def test_promotion_refuses_retained_evidence_and_records_the_reason() -> None:
    controller = PromotionController()
    quantizer = _StubQuantizer()
    evidence_verdict = QuarantineVerdict(
        outcome=QuarantineOutcome.RETAINED_AS_EVIDENCE,
        checks_passed=(),
        checks_failed=("risk",),
        epochs_observed=4,
        detail="high consequence",
        key="relation:3",
        observations=99,
    )
    record = controller.promote(
        evidence_verdict, _sample(_encoded(), sequence=1), quantizer=quantizer, lattice=None
    )
    assert record.outcome is QuarantineOutcome.REFUSED
    assert record.reason == REFUSE_EVIDENCE
    assert quantizer.accepted == []


def test_delayed_promotion_queue_is_bounded_and_drops_are_counted() -> None:
    assert MAX_DELAYED_PROMOTIONS == 64, "the published bound is part of the contract"
    controller = PromotionController(delay_sequences=10_000, max_delayed=4)
    quantizer = _StubQuantizer()
    refusals = 0
    for index in range(50):
        verdict = QuarantineVerdict(
            outcome=QuarantineOutcome.HELD,
            checks_passed=("risk", "consistency", "epoch", "observations"),
            checks_failed=(),
            epochs_observed=2,
            detail="",
            key=f"relation:{index}",
            observations=20,
        )
        record = controller.promote(
            verdict, _sample(_encoded(), sequence=index + 1), quantizer=quantizer, lattice=None
        )
        if record.reason == REFUSE_DELAY_QUEUE_FULL:
            refusals += 1
    assert len(controller.delayed_promotion()) <= 4
    assert refusals > 0
    assert controller.stats().delayed_dropped == refusals
    assert quantizer.accepted == []


def test_a_candidate_that_stops_recurring_expires_unpromoted() -> None:
    """Waiting is only a control if it can fail."""
    controller = PromotionController(delay_sequences=4)
    quantizer = _StubQuantizer()
    verdict = _eligible_verdict(epochs=2)
    controller.promote(verdict, _sample(_encoded(), sequence=1), quantizer=quantizer, lattice=None)
    assert len(controller.delayed_promotion()) == 1
    controller.promote(
        _eligible_verdict(epochs=2),
        _sample(_encoded(relation=9), sequence=100),
        quantizer=quantizer,
        lattice=None,
    )
    assert controller.stats().delayed_expired == 1
    assert quantizer.accepted == []


def test_promotion_refuses_a_single_epoch_configuration() -> None:
    with pytest.raises(ValueError, match="frequency alone"):
        PromotionController(min_epochs=1)


# --- the corpora: mandatory guards ------------------------------------------


def test_corpus_versions_are_exported() -> None:
    assert DRIFT_VERSION.startswith("stage2-drift-")
    assert POISON_VERSION.startswith("stage2-poison-")


@pytest.mark.parametrize("builder", [build_drift_corpus, build_poison_suite])
def test_corpora_use_session_unique_process_identities(builder) -> None:  # type: ignore[no-untyped-def]
    """The corpus trap that retracted a published result.

    ``Stage1Pipeline`` carries lineage state across scenarios. Reusing a pid puts
    every lineage at saturated privilege by the second session, which drove the
    measured median per-class ΔΦ to 0.00 for BOTH classes and made a +0.042
    "improvement" out of pure label noise.
    """
    owners: dict[tuple[str, str], set[str]] = {}
    for scenario in builder(count=CORPUS_COUNT, seed=CORPUS_SEED):
        for behaviour in scenario.behaviours:
            identity = (behaviour.fields["pid"], behaviour.fields["start_time"])
            owners.setdefault(identity, set()).add(scenario.name)
    shared = {k: v for k, v in owners.items() if len(v) > 1}
    assert not shared, f"process identities reused across sessions: {sorted(shared)[:5]}"


def test_drift_corpus_median_delta_phi_is_non_zero_for_both_classes(
    compiled_drift,
) -> None:  # type: ignore[no-untyped-def]
    """Asserted BEFORE any model is fitted, because the signal can be erased."""
    medians = _median_peak_delta_phi(compiled_drift)
    assert set(medians) == {0, 1}
    assert medians[0] > 0.0, f"benign median ΔΦ is {medians[0]}"
    assert medians[1] > 0.0, f"malicious median ΔΦ is {medians[1]}"
    assert medians[1] > medians[0], "single-lineage accumulation must move Φ further"


def test_poison_suite_median_delta_phi_is_non_zero_for_both_classes(
    compiled_poison,
) -> None:  # type: ignore[no-untyped-def]
    medians = _median_peak_delta_phi(compiled_poison)
    assert set(medians) == {0, 1}
    assert medians[0] > 0.0
    assert medians[1] > 0.0


@pytest.mark.parametrize("builder", [build_drift_corpus, build_poison_suite])
def test_corpora_carry_no_operation_vocabulary_signal(builder) -> None:  # type: ignore[no-untyped-def]
    """Per-operation counts match across classes, and a pooled model learns nothing.

    Object paths DO differ between classes — they have to, since the mechanism
    under test reads object semantics. What must not differ is the operation
    vocabulary, or a bag-of-features model gets a free score and every structural
    comparison on the corpus becomes meaningless.
    """
    scenarios = builder(count=CORPUS_COUNT, seed=CORPUS_SEED)
    totals: dict[int, Counter[str]] = {0: Counter(), 1: Counter()}
    sessions = {0: 0, 1: 0}
    for scenario in scenarios:
        sessions[scenario.label] += 1
        for behaviour in scenario.behaviours:
            totals[scenario.label][behaviour.operation] += 1
    assert sessions[0] and sessions[1]
    for operation in set(totals[0]) | set(totals[1]):
        benign = totals[0][operation] / sessions[0]
        attack = totals[1][operation] / sessions[1]
        assert abs(benign - attack) < max(0.5, 0.05 * max(benign, attack)), (
            f"{operation!r} differs across classes: {benign:.2f} vs {attack:.2f}"
        )

    labels = [s.label for s in scenarios]
    base_rate = sum(labels) / len(labels)
    pooled = average_precision(labels, _pooled_order_free_scores(scenarios)) or 0.0
    assert pooled - base_rate < 0.05, (
        f"an order-free pooled baseline reaches {pooled:.4f} against a "
        f"{base_rate:.4f} base rate; the corpus leaks its label"
    )


# --- acceptance criterion 8: drift without normalising an attack -------------


def test_uncorroborated_change_in_the_corpus_does_not_open_an_epoch(
    drift_runs,
) -> None:  # type: ignore[no-untyped-def]
    run, _ = drift_runs[AdaptationPolicy.QUARANTINED]
    reasons = [d["reason"] for d in run.epoch_decisions]
    assert reasons.count(EpochTransitionReason.SYSTEM_CHANGE_CORROBORATED.value) == 2
    assert EpochTransitionReason.REJECTED_NO_CORROBORATION.value in reasons
    assert run.final_epoch == 2, "three change attempts, two corroborated"


def test_repeated_malicious_pattern_is_never_normalised(
    drift_runs,
) -> None:  # type: ignore[no-untyped-def]
    run, _ = drift_runs[AdaptationPolicy.QUARANTINED]
    report = drift_report(run)
    assert report.malicious_patterns_normalised == 0
    assert run.escalating_samples > 0, "the corpus must contain escalating samples"


def test_no_escalating_sample_ever_reaches_trusted_state(
    drift_runs,
) -> None:  # type: ignore[no-untyped-def]
    """Inspects what the trusted store accepted, not a summary of it.

    An atom's ``epoch_counts`` is written only by ``quantize_behaviour_atom``, so
    a pattern that never reaches the store never becomes epoch-valid either.
    """
    _, quantizer = drift_runs[AdaptationPolicy.QUARANTINED]
    assert quantizer.accepted, "the gate must promote something, or it proves nothing"
    offending = [
        encoded
        for encoded in quantizer.accepted
        if encoded.object_property_mask & ESCALATION_MASK or encoded.state_delta_mask
    ]
    assert offending == [], f"{len(offending)} escalating samples became trusted atoms"


def test_transitions_to_recover_is_none_when_recovery_did_not_happen(
    drift_scenarios,
) -> None:  # type: ignore[no-untyped-def]
    """Unmeasured is not measured: ``None``, never a large stand-in number."""
    accept_nothing, _ = (
        run_adaptation(
            drift_scenarios,
            quantizer=_StubQuantizer(),
            epoch_signals=DRIFT_SIGNALS,
            policy=AdaptationPolicy.ACCEPT_NOTHING,
            attack_lineage=malicious_lineage,
        ),
        None,
    )
    assert drift_report(accept_nothing).transitions_to_recover is None

    # And with no epoch change at all there is nothing to recover from.
    no_change = run_adaptation(
        drift_scenarios[:6],
        quantizer=_StubQuantizer(),
        epoch_signals={},
        policy=AdaptationPolicy.QUARANTINED,
    )
    assert no_change.epoch_decisions == ()
    assert drift_report(no_change).transitions_to_recover is None


def test_recovery_after_a_corroborated_change_is_measured(
    drift_runs,
) -> None:  # type: ignore[no-untyped-def]
    """Adaptation has to actually happen, or the refusals above are worthless."""
    run, _ = drift_runs[AdaptationPolicy.QUARANTINED]
    report = drift_report(run)
    assert report.transitions_to_recover is not None
    assert 0 < report.transitions_to_recover <= run.samples
    assert report.atoms_invalidated > 0, "the workload change must invalidate something"
    assert report.atoms_reused_after_change > 0, "and some structure must be reusable"


def test_accept_everything_and_accept_nothing_bound_the_measurement(
    drift_runs,
) -> None:  # type: ignore[no-untyped-def]
    """The quarantine's effect as a delta against both trivial policies.

    Without the accept-everything control, ``malicious_patterns_normalised == 0``
    would be unfalsifiable. Without accept-nothing, it would be satisfiable by
    never learning at all.
    """
    gated, gated_q = drift_runs[AdaptationPolicy.QUARANTINED]
    everything, everything_q = drift_runs[AdaptationPolicy.ACCEPT_EVERYTHING]
    nothing, nothing_q = drift_runs[AdaptationPolicy.ACCEPT_NOTHING]

    assert drift_report(everything).malicious_patterns_normalised > 0
    assert drift_report(gated).malicious_patterns_normalised == 0
    assert drift_report(nothing).malicious_patterns_normalised == 0

    # Accept-nothing is safe and useless; the gate is safe and useful.
    assert nothing.promotions == 0
    assert nothing_q.accepted == []
    assert drift_report(nothing).transitions_to_recover is None
    assert gated.promotions > 0
    assert drift_report(gated).transitions_to_recover is not None

    # And the gate is far more selective than no gate at all.
    assert gated.promotions < everything.promotions / 10
    assert len(gated_q.atoms()) < len(everything_q.atoms())


# --- acceptance criterion 9: the poisoning arms ------------------------------


def _poison_samples(
    compiled: tuple[tuple[Scenario, tuple[Any, ...]], ...],
) -> dict[str, list[AdaptationSample]]:
    """Group each arm's samples by the lineage the corpus says is poisoning."""
    grouped: dict[str, list[AdaptationSample]] = {}
    sequence = 0
    for scenario, transitions in compiled:
        owner = poison_lineage(scenario)
        arm = scenario.technique or ""
        states: dict[str, SecurityStateV1] = {}
        for transition in transitions:
            identity = transition.actor.identity
            state = states.get(identity, SecurityStateV1())
            for dimension, (_before, after) in transition.state_delta.raised.items():
                state = state.raised_to(dimension, DIMENSIONS[dimension](after))
            states[identity] = state
            sequence += 1
            if owner is None or identity != owner:
                continue
            grouped.setdefault(arm, []).append(
                AdaptationSample(
                    encoded=encode_ssir_transition(transition),
                    state=state,
                    epoch_id=0,
                    delta_phi=transition.delta_phi,
                    uncertainty=transition.uncertainty,
                    evidence=tuple(r.locator for r in transition.evidence),
                    received_at_sequence=sequence,
                )
            )
    return grouped


def test_every_poison_arm_is_represented(compiled_poison) -> None:  # type: ignore[no-untyped-def]
    grouped = _poison_samples(compiled_poison)
    assert set(grouped) == set(POISON_ARMS), sorted(grouped)
    for arm, samples in grouped.items():
        assert len(samples) >= 8, f"{arm} has only {len(samples)} samples"


def test_no_poison_arm_carries_its_attack_meaning_into_trusted_state(
    compiled_poison,
) -> None:  # type: ignore[no-untyped-def]
    """Each arm's *attack-carrying* samples end REFUSED or RETAINED_AS_EVIDENCE.

    A poison session also contains ordinary behaviour by the same lineage, which
    is indistinguishable from legitimate traffic by construction — identity is
    frozen out of the encoding (ADR-0007), so there is no mechanism that could
    refuse it without refusing the real thing. The invariant that matters is that
    nothing carrying the arm's meaning is ever learned from.
    """
    buffer = QuarantineBuffer()
    buffer.quarantine_adaptation_sample(
        _sample(_encoded(relation=3), sequence=0)
    )  # anchor the read pattern on ordinary meaning first
    grouped = _poison_samples(compiled_poison)
    per_arm: dict[str, Counter[str]] = {}
    for arm, samples in grouped.items():
        counts: Counter[str] = Counter()
        for sample in samples:
            verdict = buffer.quarantine_adaptation_sample(sample)
            attack_meaning = (
                sample.encoded.object_property_mask & ESCALATION_MASK
                or sample.encoded.state_delta_mask
                or (verdict.distance or 0.0) > buffer.consistency_radius
            )
            counts[verdict.outcome.value if attack_meaning else "ordinary"] += 1
            if attack_meaning:
                assert verdict.outcome in (
                    QuarantineOutcome.REFUSED,
                    QuarantineOutcome.RETAINED_AS_EVIDENCE,
                ), f"{arm}: {verdict.to_dict()}"
        per_arm[arm] = counts
    for arm in POISON_ARMS:
        assert sum(
            count for outcome, count in per_arm[arm].items() if outcome != "ordinary"
        ) > 0, f"{arm} contributed no attack-carrying sample: {per_arm[arm]}"


def test_poisoned_corpus_never_normalises_an_escalating_pattern(
    poison_scenarios,
) -> None:  # type: ignore[no-untyped-def]
    """The whole path, and the accept-everything control beside it."""
    signals = {
        DRIFT_TECHNIQUE_CORROBORATED_CHANGE: DRIFT_SIGNALS[
            DRIFT_TECHNIQUE_CORROBORATED_CHANGE
        ]
    }
    gated_q = _StubQuantizer()
    gated = run_adaptation(
        poison_scenarios,
        quantizer=gated_q,
        epoch_signals=signals,
        policy=AdaptationPolicy.QUARANTINED,
        attack_lineage=poison_lineage,
    )
    ungated_q = _StubQuantizer()
    ungated = run_adaptation(
        poison_scenarios,
        quantizer=ungated_q,
        epoch_signals=signals,
        policy=AdaptationPolicy.ACCEPT_EVERYTHING,
        attack_lineage=poison_lineage,
    )
    assert gated.escalating_promotions == 0
    assert ungated.escalating_promotions > 0
    assert gated.promotions > 0, "legitimate adaptation must still get through"
    assert all(
        not (e.object_property_mask & ESCALATION_MASK) and not e.state_delta_mask
        for e in gated_q.accepted
    )
    assert any(
        e.object_property_mask & ESCALATION_MASK or e.state_delta_mask
        for e in ungated_q.accepted
    )


def test_the_sample_the_gate_sees_carries_no_label() -> None:
    """A decidable gate. If the sample carried ground truth, nothing measured here
    would transfer to a host, where no such field exists."""
    fields = set(AdaptationSample.__dataclass_fields__)
    assert fields == {
        "encoded",
        "state",
        "epoch_id",
        "delta_phi",
        "uncertainty",
        "evidence",
        "received_at_sequence",
        # Stage 1's causal chain links, added under S2-AUTH-05 so promotion can
        # tell a genuinely observed transition from two unrelated promotions.
        # They are visible on the endpoint, they are not ground truth, and
        # `PromotionController` consults them only when deciding whether to
        # write a lattice edge — never when deciding whether to promote.
        "causal_signature",
        "parent_signature",
    }
    assert not any("label" in name or "malicious" in name for name in fields)


def test_promotion_signatures_are_never_consulted_by_the_promotion_decision() -> None:
    """The two S2-AUTH-05 fields may inform an edge, never a verdict.

    Read from the source: ``_eligible``/``_check`` and everything they reach
    must not mention either field, or the trust gate would be deciding on
    provenance the quarantine never validated.
    """
    import ast
    import inspect

    from pocketsec.stage2.adaptation import promotion as module

    tree = ast.parse(inspect.getsource(module))
    deciders = {"_eligible", "_check", "_refuse", "_delay", "offer", "promote"}
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name in deciders:
            names = {
                child.attr for child in ast.walk(node) if isinstance(child, ast.Attribute)
            }
            assert "causal_signature" not in names, node.name
            assert "parent_signature" not in names, node.name


def test_pattern_key_is_coarser_than_object_meaning() -> None:
    """If the key included the object's semantics, a walk would never be visible."""
    mask = 1 << _object_bit("CREDENTIAL")
    assert pattern_key(_encoded()) == pattern_key(_encoded(object_property_mask=mask))
    assert pattern_key(_encoded(relation=3)) != pattern_key(_encoded(relation=4))


def test_legitimate_adaptation_lineage_is_identifiable_for_accounting(
    poison_scenarios,
) -> None:  # type: ignore[no-untyped-def]
    """Ground truth travels in the scenario name, never in a behaviour field."""
    legitimate = [
        s for s in poison_scenarios if s.technique == POISON_TECHNIQUE_LEGITIMATE
    ]
    assert legitimate
    for scenario in legitimate:
        assert poison_lineage(scenario) is None
        assert adaptation_lineage(scenario) is not None
        for behaviour in scenario.behaviours:
            assert not any(
                key in behaviour.fields for key in ("label", "poison", "technique")
            )


def test_state_reconstruction_uses_stage1_dimensions() -> None:
    """The harness replays lineage state through Stage 1's own lattice types."""
    state = SecurityStateV1().raised_to("credential", CredentialExposure.READABLE)
    assert state.level("credential") == int(CredentialExposure.READABLE)
    assert set(DIMENSIONS) >= {"privilege", "credential", "reachability"}
