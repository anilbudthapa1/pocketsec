"""Stage 2 `export` package — D2.13 and D2.15.

Two things are being tested here, and only one of them is code.

The first is the bounded transition cache and its forgetting policies. The test
that matters is not "a hit returns the entry"; it is that a *saving* cannot be
claimed unless a :class:`WorkLedger` proves the avoided work did not run. ADR-0010
recorded a router reporting 100 % cheap-path resolution while computing every
branch, and D2.13 sits one stage closer to the hub than that router did.

The second is whether the compile format can carry a rule that is already a rule.
``test_stage3_can_compile_a_rule_that_is_already_a_rule`` is the load-bearing test
of the whole package: the Φ-oracle scores 0.7484 PR-AUC with zero parameters, so
if the export format cannot carry it as a first-class candidate then the entire
Stage 2 → Stage 3 compilation path is refuted before any neural region is
attempted.

Every measured figure in this file was produced by running this file.
"""

from __future__ import annotations

import ast
import hashlib
import json
import math
import random
from pathlib import Path

import pytest

from pocketsec.stage0.contracts.common import (
    ContractError,
    EvidenceRef,
    digest_of_bytes,
    register_schema,
)
from pocketsec.stage0.contracts.threat_prediction_v1 import FORBIDDEN_AUTHORITY_FIELDS, Verdict
from pocketsec.stage0.gate import REPO_ROOT
from pocketsec.stage1.state.security_state import DIMENSIONS, Privilege, StateDelta
from pocketsec.stage2.cache.transition_cache import (
    CORE_INFERENCE_UNITS,
    MAX_CACHE_ENTRIES,
    CachedTransition,
    CacheStats,
    TransitionCache,
    transition_cache_key,
)
from pocketsec.stage2.cache.utility import (
    forget_low_utility_memory,
    future_security_utility,
    lru_control,
    random_control,
)
from pocketsec.stage2.compile_candidates.candidate import (
    COMPILE_CANDIDATE_V1_ID,
    COMPILE_CANDIDATE_V1_VERSION,
    CandidateKind,
    CandidateStability,
    CompileCandidateV1,
    MeasuredCost,
    UNSEEN_INPUT_ABSTAIN,
    ValidityBoundary,
)
from pocketsec.stage2.compile_candidates.exporter import (
    REFUSAL_EMPTY_BOUNDARY,
    REFUSAL_OVERFLOW,
    REFUSAL_UNMEASURED_COST,
    REFUSAL_UNSTABLE,
    export_candidates,
    propose_compile_candidate,
)
from pocketsec.stage2.compile_candidates.phi_oracle_candidate import (
    PHI_ORACLE_SCORER,
    PHI_SIGN_FEATURE_INDEX,
    PHI_SQUASHED_FEATURE_INDEX,
    DeterministicScorerSpec,
    phi_oracle_candidate,
)
from pocketsec.stage2.compile_candidates.stage3_interface import (
    STAGE3_HANDOFF_V1_ID,
    EvidenceBoundPrediction,
    Stage3Handoff,
    build_handoff,
    export_evidence_bound_prediction,
    seam_violations,
    write_handoff,
)
from pocketsec.stage2.core_ids import ExecutionPath
from pocketsec.stage2.encoder.ssir_encoder import ENCODER_VERSION, FEATURE_WIDTH, EncodedTransition
from pocketsec.stage2.router.accounting import WorkKind, WorkLedger
from pocketsec.stage2.state.window import LineageWindow
from pocketsec.stage2.uncertainty.abstention import (
    EpistemicQuadrant,
    UncertaintyEstimate,
    UncertaintySource,
)

MODEL_VERSION = "stage2-tcn.1.0.0"
EXPERIMENT_ID = "PS-S2-20260924-H1-compile-candidate-seam-0007"


# --- helpers -----------------------------------------------------------------


def evidence(count: int = 1) -> tuple[EvidenceRef, ...]:
    return tuple(
        EvidenceRef(
            store="stage1.raw",
            locator=f"transition/{index}",
            digest=digest_of_bytes(f"transition-{index}".encode()),
        )
        for index in range(count)
    )


def measured_cost(
    *,
    microseconds: float | None = 6.6,
    parameters: int = 4096,
    measured_by: str = "tests.test_stage2_export:measured_cost",
) -> MeasuredCost:
    return MeasuredCost(
        microseconds_per_event=microseconds,
        parameters=parameters,
        bytes_on_disk=2048,
        peak_rss_bytes=None,
        measured_by=measured_by,
    )


def stable_stability() -> CandidateStability:
    return CandidateStability(
        observations=32,
        distinct_epochs=3,
        reruns_agreeing=2,
        reruns_total=2,
        drift_invalidations=0,
    )


def boundary(
    *, epochs: frozenset[int] = frozenset({1, 2}), encoder: str = ENCODER_VERSION
) -> ValidityBoundary:
    return ValidityBoundary(
        epochs=epochs,
        encoder_version=encoder,
        state_dimensions=frozenset(DIMENSIONS),
        max_uncertainty=0.4,
        min_evidence_count=1,
    )


def candidate(
    *,
    kind: CandidateKind = CandidateKind.TRANSITION_TABLE,
    payload: dict | None = None,
    cost: MeasuredCost | None = None,
    stability: CandidateStability | None = None,
    bound: ValidityBoundary | None = None,
    candidate_id: str = "pocketsec.candidate.edge.3-7",
    experiment_id: str = EXPERIMENT_ID,
    lineage: tuple[EvidenceRef, ...] | None = None,
) -> CompileCandidateV1:
    return CompileCandidateV1(
        candidate_id=candidate_id,
        kind=kind,
        boundary=bound if bound is not None else boundary(),
        evidence_lineage=evidence() if lineage is None else lineage,
        cost=cost if cost is not None else measured_cost(),
        experiment_id=experiment_id,
        payload=(
            {"transition": {"source": 3, "target": 7, "count": 12}} if payload is None else payload
        ),
        stability=stability if stability is not None else stable_stability(),
    )


def cached(
    *,
    atom_id: int,
    epoch_id: int = 1,
    mask: int = 5,
    hits: int = 0,
    utility: float = 1.0,
    sequence: int = 0,
    phi: float = 1.5,
    model_version: str = MODEL_VERSION,
    encoder_version: str = ENCODER_VERSION,
) -> CachedTransition:
    return CachedTransition(
        key=transition_cache_key(atom_id=atom_id, epoch_id=epoch_id, state_delta_mask=mask),
        atom_id=atom_id,
        epoch_id=epoch_id,
        model_version=model_version,
        encoder_version=encoder_version,
        predicted_delta=StateDelta(raised={"privilege": (0, int(Privilege.ROOT))}),
        predicted_phi=phi,
        uncertainty=0.2,
        hits=hits,
        utility=utility,
        last_sequence=sequence,
    )


def fresh_cache(*, capacity: int = 8) -> TransitionCache:
    return TransitionCache(
        capacity=capacity, model_version=MODEL_VERSION, encoder_version=ENCODER_VERSION
    )


def window(values: tuple[float, ...]) -> LineageWindow:
    steps = []
    for value in values:
        features = [0.0] * FEATURE_WIDTH
        features[PHI_SQUASHED_FEATURE_INDEX] = value
        features[PHI_SIGN_FEATURE_INDEX] = 1.0
        steps.append(
            EncodedTransition(
                features=tuple(features),
                relation=0,
                relation_family=0,
                state_delta_mask=0,
                time_bucket=0,
                delta_phi=0.0,
                object_property_mask=0,
                epoch_id=1,
            )
        )
    return LineageWindow(
        lineage_key="lineage-a", steps=tuple(steps), truncated=False, last_sequence=len(values)
    )


def estimate(*, calibration_id: str | None = None) -> UncertaintyEstimate:
    return UncertaintyEstimate(
        value=0.7,
        sources={UncertaintySource.ENTROPY.value: 0.5, UncertaintySource.CONE_AMBIGUITY.value: 0.2},
        calibration_id=calibration_id,
        quadrant=EpistemicQuadrant.ESCALATE,
        abstain=True,
        detail="synthetic estimate for the seam test",
    )


# --- the cache is bounded, and says so ---------------------------------------


def test_cache_never_exceeds_capacity_and_counts_every_eviction() -> None:
    cache = fresh_cache(capacity=8)
    for index in range(64):
        cache.store(cached(atom_id=index, sequence=index))
        assert len(cache) <= 8, "the cache exceeded its declared capacity"
    stats = cache.stats()
    assert stats.entries == 8
    assert stats.evictions == 56, stats.to_dict()
    assert stats.memory_bytes > 0


def test_cache_key_is_a_hashlib_digest_not_a_salted_builtin_hash() -> None:
    expected = hashlib.sha256(b"12|3|5").hexdigest()[:32]
    assert transition_cache_key(atom_id=12, epoch_id=3, state_delta_mask=5) == expected
    with pytest.raises(ContractError):
        transition_cache_key(atom_id=-1, epoch_id=3, state_delta_mask=5)


def test_hit_rate_is_none_on_zero_lookups_not_zero() -> None:
    cache = fresh_cache()
    assert cache.stats().hit_rate() is None, "an unexercised cache has no hit rate"
    cache.store(cached(atom_id=1))
    assert cache.lookup_transition_cache(atom_id=1, epoch_id=1, state_delta_mask=5) is not None
    assert cache.stats().hit_rate() == 1.0
    assert CacheStats(0, 0, 0, 0, 0, 0.0, 0).hit_rate() is None


@pytest.mark.parametrize("field", ["model_version", "encoder_version"])
def test_a_stale_version_is_a_miss_counted_as_a_version_rejection(field: str) -> None:
    cache = fresh_cache()
    stale = cached(atom_id=4, **{field: "stale.0.0.1"})  # type: ignore[arg-type]
    # store() refuses the mismatch outright, so plant it the way a reloaded
    # on-disk cache would: the entry predates the current versions.
    with pytest.raises(ContractError):
        cache.store(stale)
    cache._entries[stale.key] = stale  # simulating a cache restored from an older run
    result = cache.lookup_transition_cache(atom_id=4, epoch_id=1, state_delta_mask=5)
    assert result is None, "a stale-version entry was served as a hit"
    stats = cache.stats()
    assert (stats.hits, stats.misses, stats.version_rejections) == (0, 1, 1)
    assert stats.entries == 0, "the stale entry must not survive the rejection"


def test_invalidate_epoch_removes_exactly_that_epochs_entries() -> None:
    cache = fresh_cache(capacity=16)
    for index in range(4):
        cache.store(cached(atom_id=index, epoch_id=1, sequence=index))
    for index in range(4, 7):
        cache.store(cached(atom_id=index, epoch_id=2, sequence=index))
    assert cache.invalidate_epoch(1) == 4
    remaining = {entry.epoch_id for entry in cache.entries()}
    assert remaining == {2}
    assert len(cache) == 3
    assert cache.invalidate_epoch(99) == 0


# --- the saving is ledger-proven or it is not claimed ------------------------


def test_a_cache_hit_records_core_inference_as_not_performed() -> None:
    cache = fresh_cache()
    cache.store(cached(atom_id=9))
    ledger = WorkLedger()
    ledger.begin("event-1")
    entry = cache.lookup_transition_cache(
        atom_id=9, epoch_id=1, state_delta_mask=5, ledger=ledger
    )
    assert entry is not None
    account = ledger.close()
    assert WorkKind.CORE_INFERENCE in account.skipped_kinds
    assert account.path is ExecutionPath.P0_COMPILED, "a proven skip must earn the cheap path"
    ledger.assert_no_phantom_savings()
    assert cache.stats().proven_skipped_units == pytest.approx(CORE_INFERENCE_UNITS)


def test_a_miss_never_records_a_skipped_inference() -> None:
    cache = fresh_cache()
    ledger = WorkLedger()
    ledger.begin("event-1")
    assert (
        cache.lookup_transition_cache(atom_id=1, epoch_id=1, state_delta_mask=5, ledger=ledger)
        is None
    )
    account = ledger.close()
    assert WorkKind.CORE_INFERENCE not in account.skipped_kinds
    assert cache.stats().proven_skipped_units == 0.0


def test_hits_without_a_ledger_claim_no_saving_at_all() -> None:
    """The honesty asymmetry: an unprovable saving is not a saving."""
    cache = fresh_cache()
    cache.store(cached(atom_id=2))
    for _ in range(5):
        assert cache.lookup_transition_cache(atom_id=2, epoch_id=1, state_delta_mask=5) is not None
    stats = cache.stats()
    assert stats.hits == 5
    assert stats.proven_skipped_units == 0.0, "savings were claimed with no ledger to prove them"


def test_a_fabricated_skip_fails_assert_no_phantom_savings() -> None:
    """Reproduces the ADR-0010 defect through the cache's own call path.

    The cache records the skip; it does not adjudicate it. The ledger does, and
    it refuses a run in which the avoided inference was performed anyway.
    """
    cache = fresh_cache()
    cache.store(cached(atom_id=3))
    ledger = WorkLedger()
    ledger.begin("event-1")
    # The caller ran the core anyway, then asks the cache to report a hit.
    ledger.record(WorkKind.CORE_INFERENCE, performed=True, units=40.0, detail="ran it anyway")
    assert cache.lookup_transition_cache(
        atom_id=3, epoch_id=1, state_delta_mask=5, ledger=ledger
    ) is not None
    with pytest.raises(ContractError, match="phantom"):
        ledger.assert_no_phantom_savings()
    # The derived path also refuses to look cheap: the inference that ran lifts it.
    assert ledger.close().path is not ExecutionPath.P0_COMPILED


def test_the_cache_default_capacity_is_the_declared_bound() -> None:
    assert MAX_CACHE_ENTRIES == 1024
    cache = TransitionCache(model_version=MODEL_VERSION, encoder_version=ENCODER_VERSION)
    assert cache.capacity == MAX_CACHE_ENTRIES


#: Ceiling for a full 1024-entry cache. MEASURED by this test: 287_744 bytes
#: (281.0 KB) with a one-dimension ΔS per entry. The ceiling is stated at 512 KB
#: so a future field addition has room but a ten-fold regression does not.
CACHE_MEMORY_CEILING_BYTES = 512 * 1024


def test_a_full_cache_stays_under_its_declared_memory_ceiling() -> None:
    """The 2 GB host target is a hard constraint, so the P0 cache must be small."""
    cache = TransitionCache(model_version=MODEL_VERSION, encoder_version=ENCODER_VERSION)
    for index in range(MAX_CACHE_ENTRIES * 2):
        cache.store(cached(atom_id=index, mask=index % 32, sequence=index))
    stats = cache.stats()
    assert stats.entries == MAX_CACHE_ENTRIES
    assert stats.memory_bytes == 287_744, "the measured per-entry footprint changed"
    assert stats.memory_bytes < CACHE_MEMORY_CEILING_BYTES
    assert stats.evictions == MAX_CACHE_ENTRIES


def test_a_cache_hit_returns_a_new_entry_and_never_mutates_the_stored_one() -> None:
    """Immutability is a project invariant, and the fast copy must not break it."""
    cache = fresh_cache()
    original = cached(atom_id=7, hits=3)
    cache.store(original)
    returned = cache.lookup_transition_cache(atom_id=7, epoch_id=1, state_delta_mask=5)
    assert returned is not None
    assert returned is not original
    assert original.hits == 3, "the stored entry was mutated in place"
    assert returned.hits == 4
    assert returned.key == original.key
    assert returned.predicted_delta is original.predicted_delta


# --- forgetting by future utility, and its controls -------------------------


def test_utility_forgetting_keeps_the_highest_utility_entries() -> None:
    cache = fresh_cache(capacity=16)
    for index in range(8):
        cache.store(cached(atom_id=index, sequence=index, utility=float(index)))
    evicted = forget_low_utility_memory(cache, keep=3)
    assert len(evicted) == 5
    kept = sorted(entry.utility for entry in cache.entries())
    assert kept == [5.0, 6.0, 7.0], "utility forgetting did not keep the most useful entries"
    assert forget_low_utility_memory(cache, keep=9) == (), "nothing to forget must evict nothing"


def test_future_security_utility_floors_an_unattributed_entry() -> None:
    hot = cached(atom_id=1, hits=20, phi=4.0)
    cold = cached(atom_id=2, hits=0, phi=0.0)
    # Credit 0.0 means "not yet attributed", not "worthless".
    hot_utility = future_security_utility(hot, credit=0.0, uncertainty_reduction=0.0)
    cold_utility = future_security_utility(cold, credit=0.0, uncertainty_reduction=0.0)
    assert hot_utility > cold_utility > 0.0
    assert future_security_utility(hot, credit=1.0, uncertainty_reduction=1.0) > hot_utility
    with pytest.raises(ContractError):
        future_security_utility(hot, credit=math.nan, uncertainty_reduction=1.0)


def test_lru_and_random_controls_are_deterministic_and_bounded() -> None:
    cache = fresh_cache(capacity=16)
    for index in range(8):
        cache.store(cached(atom_id=index, sequence=index, utility=1.0))
    assert lru_control(cache, keep=6) == tuple(
        cached(atom_id=index, sequence=index).key for index in range(2)
    )
    first = fresh_cache(capacity=16)
    second = fresh_cache(capacity=16)
    for index in range(8):
        first.store(cached(atom_id=index, sequence=index))
        second.store(cached(atom_id=index, sequence=index))
    assert random_control(first, keep=4, seed=11) == random_control(second, keep=4, seed=11)


def test_a_removal_preserves_read_recency_not_insertion_order() -> None:
    """Pins S2-03.

    ``_rebuild_recency`` used to re-derive the LRU index from
    ``CachedTransition.last_sequence``, which is only ever written at store
    time. ``lookup_transition_cache`` refreshes ``hits`` but never rewrote it,
    so every ``drop``/``drop_many``/``invalidate_epoch``/
    ``forget_low_utility_memory`` replaced real access recency with insertion
    order and the hottest entry became the next eviction victim.

    Atom 1 is stored first and then read 50 times; atom 9 is stored in a
    different epoch and never read. Invalidating atom 9's epoch — an operation
    that has nothing to do with atom 1 — used to make atom 1 the least-recently-
    used entry in the rebuilt index.
    """
    cache = fresh_cache(capacity=4)
    for index in (1, 2, 3):
        cache.store(cached(atom_id=index, sequence=index))
    cache.store(cached(atom_id=9, epoch_id=7, sequence=9))
    for _ in range(50):
        assert cache.lookup_transition_cache(atom_id=1, epoch_id=1, state_delta_mask=5)

    hot = cached(atom_id=1).key
    assert cache.get(hot) is not None and cache.get(hot).hits == 50
    # The hot entry is the MOST recently used, so it must be last in the order.
    assert cache.recency_order()[-1] == hot

    assert cache.invalidate_epoch(7) == 1
    # After the unrelated removal, the hot entry must still not be the victim.
    assert cache.recency_order()[-1] == hot
    expected = cache.recency_order()[:2]
    assert lru_control(cache, keep=1) == expected
    assert cache.get(hot) is not None, "the 50-hit entry was evicted first"


def test_lru_control_is_lru_for_a_reread_workload_not_fifo() -> None:
    """Pins S2-03's second half.

    ``lru_control`` sorted on ``last_sequence``, so for a workload that re-reads
    entries rather than re-storing them it was insertion-order (FIFO) while
    calling itself "evict the least-recently-used". It is the declared control
    for the DTL-F15/F16 verdicts, so a control that is not what it says it is
    cannot settle whether the mechanism earns its place.
    """
    cache = fresh_cache(capacity=8)
    for index in range(4):
        cache.store(cached(atom_id=index, sequence=index))
    # Re-read the oldest-stored entry. LRU must now protect it; FIFO would not.
    assert cache.lookup_transition_cache(atom_id=0, epoch_id=1, state_delta_mask=5)
    victims = lru_control(cache, keep=3)
    assert victims == (cached(atom_id=1).key,)
    assert cache.get(cached(atom_id=0).key) is not None


# --- the measured comparison: does utility forgetting earn its place? --------

_KEEP = 64
_N_KEYS = 256
_STEPS = 4000


def _consequence(key: int) -> float:
    return float((key % 8) + 1)


def _consequence_correlated_trace(seed: int) -> list[int]:
    rng = random.Random(seed)
    keys = list(range(_N_KEYS))
    return rng.choices(keys, weights=[_consequence(k) for k in keys], k=_STEPS)


def _recency_driven_trace(seed: int) -> list[int]:
    rng = random.Random(seed)
    span = 16
    return [
        ((step // 4) % (_N_KEYS - span)) + rng.randrange(span) for step in range(_STEPS)
    ]


def _replay(trace: list[int], policy: str, *, correlated: bool, seed: int = 7) -> float:
    rng = random.Random(seed)
    consequence = (
        {k: _consequence(k) for k in range(_N_KEYS)}
        if correlated
        else {k: float(rng.randrange(1, 9)) for k in range(_N_KEYS)}
    )
    # Capacity is deliberately generous so the *policy*, not the cache's internal
    # LRU, decides every eviction; all three policies then run at keep=_KEEP.
    cache = TransitionCache(
        capacity=_N_KEYS * 4, model_version=MODEL_VERSION, encoder_version=ENCODER_VERSION
    )
    for step, key in enumerate(trace):
        entry = cache.lookup_transition_cache(atom_id=key, epoch_id=1, state_delta_mask=key % 32)
        hits = 0 if entry is None else entry.hits
        stored = cached(
            atom_id=key,
            mask=key % 32,
            hits=hits,
            sequence=step,
            phi=consequence[key],
            utility=0.0,
        )
        cache.store(stored)
        cache.replace_utilities(
            [
                (
                    stored.key,
                    future_security_utility(
                        stored,
                        credit=consequence[key] / 8.0,
                        uncertainty_reduction=1.0 - stored.uncertainty,
                    ),
                )
            ]
        )
        if len(cache) > _KEEP:
            if policy == "utility":
                forget_low_utility_memory(cache, keep=_KEEP)
            elif policy == "lru":
                lru_control(cache, keep=_KEEP)
            else:
                random_control(cache, keep=_KEEP, seed=step)
    rate = cache.stats().hit_rate()
    assert rate is not None
    return rate


def test_utility_forgetting_measured_against_lru_and_random() -> None:
    """MEASURED, 4000 accesses, 256 keys, keep=64, seeds fixed.

    Produced by running this test (Python 3.14.7, Linux 7.1.5+kali-amd64):

    | trace                          | utility | lru     | random  |
    |--------------------------------|---------|---------|---------|
    | A consequence-correlated reuse | 0.41325 | 0.31525 | 0.31650 |
    | B recency-driven reuse         | 0.27350 | 0.74425 | 0.72075 |

    The conclusion is a split one and it is recorded in ADR-0118:
    utility-based forgetting beats LRU **only** when future reuse correlates with
    security consequence, and is catastrophically worse (−0.471 hit rate) when
    reuse is recency-driven. No synthetic corpus in this repository can say which
    a real host looks like, so **LRU remains the recommended default** and
    DTL-F15 is NOT_YET_JUSTIFIED rather than justified.
    """
    trace_a = _consequence_correlated_trace(11)
    row_a = {p: _replay(trace_a, p, correlated=True) for p in ("utility", "lru", "random")}
    assert row_a["utility"] > row_a["lru"], row_a
    assert row_a["utility"] > row_a["random"], row_a
    assert row_a["utility"] == pytest.approx(0.41325, abs=5e-4), row_a
    assert row_a["lru"] == pytest.approx(0.31525, abs=5e-4), row_a

    trace_b = _recency_driven_trace(11)
    row_b = {p: _replay(trace_b, p, correlated=False) for p in ("utility", "lru", "random")}
    assert row_b["lru"] > row_b["utility"], row_b
    assert row_b["random"] > row_b["utility"], row_b
    assert row_b["lru"] == pytest.approx(0.74425, abs=5e-4), row_b
    assert row_b["utility"] == pytest.approx(0.27350, abs=5e-4), row_b


# --- a candidate with no recorded measurement is rejectable by construction --


def test_empty_evidence_lineage_raises() -> None:
    with pytest.raises(ContractError, match="evidence_lineage"):
        candidate(lineage=())


def test_an_unparseable_experiment_id_raises() -> None:
    with pytest.raises(ContractError, match="experiment_id"):
        candidate(experiment_id="not-an-experiment")
    with pytest.raises(ContractError, match="experiment_id"):
        candidate(experiment_id="PS-S2-20260924-X1-bad-hypothesis-0007")
    with pytest.raises(ContractError, match="experiment_id"):
        candidate(experiment_id="PS-S2-20260924-H1-short-sequence-007")


def test_unmeasured_cost_raises_for_a_neural_region_and_is_tolerated_for_a_scorer() -> None:
    with pytest.raises(ContractError, match="UNMEASURED"):
        candidate(kind=CandidateKind.NEURAL_REGION, cost=measured_cost(microseconds=None))
    tolerated = candidate(
        kind=CandidateKind.DETERMINISTIC_SCORER,
        cost=measured_cost(microseconds=None, parameters=0),
        candidate_id="pocketsec.candidate.scorer.untimed",
        payload={"scorer": PHI_ORACLE_SCORER.to_dict()},
    )
    assert tolerated.cost.measured is False


def test_an_untimed_scorer_is_still_refused_by_the_exporter(tmp_path: Path) -> None:
    """The schema tolerates it; the seam does not. UNMEASURED never reaches Stage 3."""
    untimed = candidate(
        kind=CandidateKind.DETERMINISTIC_SCORER,
        cost=measured_cost(microseconds=None, parameters=0),
        candidate_id="pocketsec.candidate.scorer.untimed",
        payload={"scorer": PHI_ORACLE_SCORER.to_dict()},
    )
    report = export_candidates([untimed], tmp_path / "candidates.json")
    assert report.candidates == ()
    assert report.refused[0][0] == "pocketsec.candidate.scorer.untimed"
    assert report.refused[0][1].startswith(REFUSAL_UNMEASURED_COST)


@pytest.mark.parametrize("bad", ["", "   ", "moduleonly", "module:", ":function"])
def test_an_empty_or_malformed_measured_by_raises(bad: str) -> None:
    with pytest.raises(ContractError, match="measured_by"):
        measured_cost(measured_by=bad)


@pytest.mark.parametrize(
    "payload",
    [
        {"action": "kill"},
        {"meta": {"remediation": "restore"}},
        {"rows": [{"recommended_action": "isolate"}]},
        {"privilege_escalation_command": "sudo"},
    ],
)
def test_a_payload_key_naming_response_authority_raises(payload: dict) -> None:
    with pytest.raises(ContractError, match="authority"):
        candidate(payload=payload)


def test_every_forbidden_authority_field_is_actually_refused() -> None:
    """Anti-weakening: if the recursive key check is loosened, this fails."""
    for token in sorted(FORBIDDEN_AUTHORITY_FIELDS):
        with pytest.raises(ContractError):
            candidate(payload={"outer": {f"nested_{token}_field": 1}})


@pytest.mark.parametrize("payload", [{"p": {1, 2}}, {"p": float("nan")}, {"p": object()}])
def test_a_non_json_payload_raises(payload: dict) -> None:
    with pytest.raises(ContractError, match="JSON"):
        candidate(payload=payload)


def test_unseen_input_behaviour_must_be_abstain() -> None:
    assert UNSEEN_INPUT_ABSTAIN == "ABSTAIN"
    for forbidden in ("GUESS", "BEST_EFFORT", "abstain", ""):
        with pytest.raises(ContractError, match="unseen_input_behaviour"):
            ValidityBoundary(
                epochs=frozenset({1}),
                encoder_version=ENCODER_VERSION,
                state_dimensions=frozenset(DIMENSIONS),
                max_uncertainty=0.5,
                min_evidence_count=1,
                unseen_input_behaviour=forbidden,
            )


def test_validity_boundary_rejects_a_foreign_encoder_version() -> None:
    bound = boundary(epochs=frozenset({1, 2}))
    assert bound.contains(epoch_id=1, encoder_version=ENCODER_VERSION, uncertainty=0.1)
    assert not bound.contains(epoch_id=1, encoder_version="dtl-encoder.2.0.0", uncertainty=0.1)
    assert not bound.contains(epoch_id=99, encoder_version=ENCODER_VERSION, uncertainty=0.1)
    assert not bound.contains(epoch_id=1, encoder_version=ENCODER_VERSION, uncertainty=0.9)


def test_an_empty_boundary_contains_nothing_and_is_refused(tmp_path: Path) -> None:
    empty = ValidityBoundary(
        epochs=frozenset(),
        encoder_version=ENCODER_VERSION,
        state_dimensions=frozenset(DIMENSIONS),
        max_uncertainty=1.0,
        min_evidence_count=1,
    )
    assert empty.is_empty
    assert not empty.contains(epoch_id=0, encoder_version=ENCODER_VERSION, uncertainty=0.0)
    report = export_candidates([candidate(bound=empty)], tmp_path / "c.json")
    assert report.candidates == ()
    assert report.refused[0][1].startswith(REFUSAL_EMPTY_BOUNDARY)


def test_an_unknown_state_dimension_is_refused() -> None:
    with pytest.raises(ContractError, match="state_dimensions"):
        ValidityBoundary(
            epochs=frozenset({1}),
            encoder_version=ENCODER_VERSION,
            state_dimensions=frozenset({"privilege", "vibes"}),
            max_uncertainty=0.5,
            min_evidence_count=1,
        )


def test_frequency_alone_is_not_stability() -> None:
    frequent_one_epoch = CandidateStability(
        observations=10_000,
        distinct_epochs=1,
        reruns_agreeing=3,
        reruns_total=3,
        drift_invalidations=0,
    )
    assert not frequent_one_epoch.stable
    assert "distinct_epochs" in frequent_one_epoch.instability_reason()
    assert not CandidateStability(32, 3, 1, 2, 0).stable
    assert not CandidateStability(32, 3, 2, 2, 1).stable
    assert stable_stability().stable
    with pytest.raises(ContractError):
        CandidateStability(32, 3, 5, 2, 0)


def test_an_unstable_candidate_is_refused_with_a_reason(tmp_path: Path) -> None:
    unstable = candidate(stability=CandidateStability(2, 1, 1, 1, 0))
    report = export_candidates([unstable], tmp_path / "c.json")
    assert report.candidates == ()
    assert report.refused[0][1].startswith(REFUSAL_UNSTABLE)
    assert "observations" in report.refused[0][1]


def test_the_exporter_refuses_overflow_instead_of_dropping_silently(tmp_path: Path) -> None:
    batch = [candidate(candidate_id=f"pocketsec.candidate.edge.{i}") for i in range(5)]
    report = export_candidates(batch, tmp_path / "c.json", max_candidates=3)
    assert len(report.candidates) == 3
    assert len(report.refused) == 2
    assert all(reason.startswith(REFUSAL_OVERFLOW) for _, reason in report.refused)
    assert len(report.candidates) + len(report.refused) == len(batch), "a candidate vanished"


def test_the_schema_is_registered_and_cannot_be_silently_revised() -> None:
    assert COMPILE_CANDIDATE_V1_VERSION == "1.0.0"
    assert register_schema(COMPILE_CANDIDATE_V1_ID, "1.0.0") == "1.0.0"
    with pytest.raises(ContractError):
        register_schema(COMPILE_CANDIDATE_V1_ID, "1.1.0")
    with pytest.raises(ContractError):
        register_schema(STAGE3_HANDOFF_V1_ID, "2.0.0")


# --- propose_compile_candidate ----------------------------------------------


class _FakeEdge:
    """A lattice edge's *shape*, to keep this package's imports off `lattice`."""

    source = 3
    target = 7
    epoch_counts = {1: 8, 2: 5}
    uncertainty_mean = 0.3

    def to_dict(self) -> dict:
        return {"source": 3, "target": 7, "count": 13, "probability_hint": 0.42}


def test_propose_compile_candidate_derives_kind_and_boundary() -> None:
    proposed = propose_compile_candidate(
        transition=_FakeEdge(),
        cost=measured_cost(),
        experiment_id=EXPERIMENT_ID,
        evidence=evidence(2),
        stability=stable_stability(),
    )
    assert proposed.kind is CandidateKind.TRANSITION_TABLE
    assert proposed.boundary.epochs == frozenset({1, 2})
    assert proposed.boundary.max_uncertainty == pytest.approx(0.3)
    assert proposed.payload["transition"]["probability_hint"] == pytest.approx(0.42)


def test_propose_compile_candidate_bounds_a_scorers_epochs_to_what_was_observed() -> None:
    proposed = propose_compile_candidate(
        scorer=PHI_ORACLE_SCORER,
        cost=measured_cost(microseconds=0.0, parameters=0),
        experiment_id=EXPERIMENT_ID,
        evidence=evidence(),
        stability=stable_stability(),
        epochs=(2, 5),
    )
    assert proposed.kind is CandidateKind.DETERMINISTIC_SCORER
    assert proposed.boundary.epochs == frozenset({2, 5})
    assert not proposed.boundary.contains(
        epoch_id=9, encoder_version=ENCODER_VERSION, uncertainty=0.0
    )


def test_propose_compile_candidate_needs_exactly_one_source() -> None:
    kwargs = dict(
        cost=measured_cost(),
        experiment_id=EXPERIMENT_ID,
        evidence=evidence(),
        stability=stable_stability(),
    )
    with pytest.raises(ContractError, match="exactly one"):
        propose_compile_candidate(**kwargs)
    with pytest.raises(ContractError, match="exactly one"):
        propose_compile_candidate(transition=_FakeEdge(), scorer=PHI_ORACLE_SCORER, **kwargs)


# --- the Φ-oracle as a first-class candidate --------------------------------


def test_the_phi_feature_index_is_the_squashed_absolute_delta_phi() -> None:
    assert PHI_SQUASHED_FEATURE_INDEX == 73
    assert PHI_SIGN_FEATURE_INDEX == 74
    assert PHI_ORACLE_SCORER.feature_index == PHI_SQUASHED_FEATURE_INDEX
    assert PHI_ORACLE_SCORER.aggregation == "max_over_window"
    # The scorer reads magnitude only; the sign bit is set in the fixture and
    # must not change the score.
    assert PHI_ORACLE_SCORER.evaluate(window((0.1, 0.8, 0.3))) == pytest.approx(0.8)
    assert PHI_ORACLE_SCORER.evaluate(window(())) == 0.0, "no evidence is not a low score"


def test_a_scorer_spec_refuses_an_out_of_range_index_or_unknown_aggregation() -> None:
    with pytest.raises(ContractError, match="feature_index"):
        DeterministicScorerSpec(
            scorer_id="bad-index",
            feature_index=FEATURE_WIDTH,
            aggregation="max_over_window",
            threshold=None,
            expression="x",
        )
    with pytest.raises(ContractError, match="aggregation"):
        DeterministicScorerSpec(
            scorer_id="bad-agg",
            feature_index=0,
            aggregation="vibes_over_window",
            threshold=None,
            expression="x",
        )


def test_the_phi_oracle_candidate_must_carry_zero_parameters() -> None:
    with pytest.raises(ContractError, match="zero-parameter"):
        phi_oracle_candidate(
            cost=measured_cost(microseconds=0.0, parameters=1),
            experiment_id=EXPERIMENT_ID,
            evidence=evidence(),
            stability=stable_stability(),
        )


def phi_candidate() -> CompileCandidateV1:
    return phi_oracle_candidate(
        cost=measured_cost(
            microseconds=0.0,
            parameters=0,
            measured_by="pocketsec.stage2.research.sleeping_brain:sleeping_brain_report",
        ),
        experiment_id=EXPERIMENT_ID,
        evidence=evidence(3),
        stability=stable_stability(),
        epochs=(1, 2),
    )


def test_stage3_can_compile_a_rule_that_is_already_a_rule(tmp_path: Path) -> None:
    """The load-bearing test of this package.

    The Φ-oracle reaches 0.7484 PR-AUC with zero parameters and ~0 µs/event
    (MEMORY.md), and integration plan §6.3 makes it Stage 3's first
    crystallisation target. If the export format cannot carry a zero-parameter
    deterministic scorer as a **first-class** candidate — not as a degenerate
    neural region — then the compilation path is refuted before any neural
    region is attempted, because there would be nothing worth crystallising.
    """
    oracle = phi_candidate()
    assert oracle.kind is CandidateKind.DETERMINISTIC_SCORER
    assert oracle.cost.parameters == 0
    assert oracle.cost.microseconds_per_event == 0.0, "0.0 is measured; None would be UNMEASURED"
    assert oracle.stability.stable

    report = export_candidates([oracle], tmp_path / "candidates.json")
    assert report.refused == (), report.refused
    assert report.candidates == (oracle,)
    assert report.total_bytes > 0

    handoff = build_handoff(report, handoff_id="pocketsec.stage3-handoff.0007")
    digest = write_handoff(handoff, tmp_path / "handoff.json")

    reloaded = Stage3Handoff.from_dict(json.loads((tmp_path / "handoff.json").read_text()))
    assert reloaded == handoff, "the handoff did not round-trip"
    # Stage 3 can rebuild the scorer from plain JSON without importing Stage 2.
    rebuilt = DeterministicScorerSpec.from_dict(reloaded.candidates[0].payload["scorer"])
    assert rebuilt == PHI_ORACLE_SCORER
    assert rebuilt.evaluate(window((0.2, 0.9))) == pytest.approx(0.9)
    assert digest.startswith("sha256:")


def test_the_candidate_round_trips_to_dict_and_from_dict_exactly() -> None:
    oracle = phi_candidate()
    assert CompileCandidateV1.from_dict(oracle.to_dict()) == oracle
    assert CompileCandidateV1.from_dict(oracle.to_dict()).to_dict() == oracle.to_dict()
    with pytest.raises(ContractError, match="missing field"):
        CompileCandidateV1.from_dict({"candidate_id": "x"})


# --- the Stage 3 seam -------------------------------------------------------


def test_write_handoff_digest_is_reproducible_from_the_written_bytes(tmp_path: Path) -> None:
    report = export_candidates([phi_candidate()], tmp_path / "candidates.json")
    handoff = build_handoff(report, handoff_id="pocketsec.stage3-handoff.0007")
    first = write_handoff(handoff, tmp_path / "handoff.json")
    on_disk = digest_of_bytes((tmp_path / "handoff.json").read_bytes())
    assert first == on_disk, "the returned digest does not describe the written file"
    second = write_handoff(handoff, tmp_path / "handoff-again.json")
    assert second == first, "two writes of the same handoff produced different digests"
    reloaded = Stage3Handoff.from_dict(json.loads((tmp_path / "handoff.json").read_text()))
    assert write_handoff(reloaded, tmp_path / "handoff-3.json") == first


def test_the_handoff_names_no_stage2_class_and_holds_no_non_json_value(tmp_path: Path) -> None:
    report = export_candidates([phi_candidate()], tmp_path / "candidates.json")
    handoff = build_handoff(report, handoff_id="pocketsec.stage3-handoff.0007")
    payload = handoff.to_dict()
    assert seam_violations(payload) == ()
    # Serialisable with strict JSON: no NaN, no sets, no objects.
    json.dumps(payload, allow_nan=False, sort_keys=True)
    for key in ("atom_prototypes", "transition_statistics", "uncertainty_envelopes"):
        assert isinstance(payload[key], list)
    assert payload["uncertainty_envelopes"][0]["unseen_input_behaviour"] == UNSEEN_INPUT_ABSTAIN


def test_a_handoff_refuses_a_row_naming_a_stage2_class() -> None:
    with pytest.raises(ContractError, match="plain data"):
        Stage3Handoff(
            handoff_id="pocketsec.stage3-handoff.0008",
            candidates=(),
            atom_prototypes=({"BehaviourAtom": {"prototype": [0.0]}},),
            transition_statistics=(),
            uncertainty_envelopes=(),
            evidence_requirements=(),
            encoder_version=ENCODER_VERSION,
        )
    with pytest.raises(ContractError, match="JSON"):
        Stage3Handoff(
            handoff_id="pocketsec.stage3-handoff.0009",
            candidates=(),
            atom_prototypes=({"prototype": object()},),
            transition_statistics=(),
            uncertainty_envelopes=(),
            evidence_requirements=(),
            encoder_version=ENCODER_VERSION,
        )


def test_a_handoff_refuses_a_candidate_from_a_foreign_encoder() -> None:
    foreign = candidate(bound=boundary(encoder="dtl-encoder.2.0.0"))
    with pytest.raises(ContractError, match="encoder"):
        Stage3Handoff(
            handoff_id="pocketsec.stage3-handoff.0010",
            candidates=(foreign,),
            atom_prototypes=(),
            transition_statistics=(),
            uncertainty_envelopes=(),
            evidence_requirements=(),
            encoder_version=ENCODER_VERSION,
        )


def test_an_empty_handoff_is_legitimate_and_still_writes(tmp_path: Path) -> None:
    """Exporting nothing is a result. It must not be an error."""
    report = export_candidates([], tmp_path / "candidates.json")
    handoff = build_handoff(report, handoff_id="pocketsec.stage3-handoff.empty")
    assert handoff.candidates == ()
    assert handoff.encoder_version == ENCODER_VERSION
    assert write_handoff(handoff, tmp_path / "handoff.json").startswith("sha256:")


# --- DTL-F20: evidence-bound predictions -----------------------------------


def test_an_evidence_bound_prediction_cannot_be_detached_from_its_evidence() -> None:
    with pytest.raises(ContractError, match="evidence"):
        export_evidence_bound_prediction(
            score=0.9,
            verdict=Verdict.SUSPICIOUS,
            uncertainty=estimate(),
            evidence=(),
            compute_path=ExecutionPath.P3_PREDICTIVE,
        )


def test_the_unknown_and_unidentifiable_verdicts_are_reachable() -> None:
    for verdict in (Verdict.UNKNOWN, Verdict.UNIDENTIFIABLE, Verdict.INSUFFICIENT_EVIDENCE):
        prediction = export_evidence_bound_prediction(
            score=0.0,
            verdict=verdict,
            uncertainty=estimate(),
            evidence=evidence(),
            compute_path=ExecutionPath.P4_DEEP,
        )
        assert prediction.verdict == verdict.value
        assert prediction.to_dict()["verdict"] == verdict.value
    with pytest.raises(ContractError, match="Verdict"):
        export_evidence_bound_prediction(
            score=0.0,
            verdict="PROBABLY_FINE",
            uncertainty=estimate(),
            evidence=evidence(),
            compute_path=ExecutionPath.P0_COMPILED,
        )


def test_a_prediction_carries_no_authority_field() -> None:
    """Anti-weakening: adding an action-shaped field breaks construction."""
    names = {field for field in EvidenceBoundPrediction.__dataclass_fields__}
    for name in names:
        assert not any(token in name.lower() for token in FORBIDDEN_AUTHORITY_FIELDS), name
    assert "authority" not in names and "action" not in names
    with pytest.raises(ContractError, match="authority"):
        EvidenceBoundPrediction(
            score=0.5,
            verdict=Verdict.BENIGN.value,
            uncertainty=UncertaintyEstimate(
                value=0.1,
                sources={"recommended_action": 1.0},
                calibration_id=None,
                quadrant=EpistemicQuadrant.CHEAP_PATH,
                abstain=False,
                detail="",
            ),
            evidence=evidence(),
            compute_path=ExecutionPath.P0_COMPILED,
            calibration_id=None,
            candidate_id=None,
        )


def test_calibration_id_defaults_to_the_estimates_own_and_stays_none_when_absent() -> None:
    uncalibrated = export_evidence_bound_prediction(
        score=0.3,
        verdict=Verdict.BENIGN,
        uncertainty=estimate(calibration_id=None),
        evidence=evidence(),
        compute_path=ExecutionPath.P1_LATTICE,
    )
    assert uncalibrated.calibration_id is None, "an uncalibrated score must say so"
    calibrated = export_evidence_bound_prediction(
        score=0.3,
        verdict=Verdict.BENIGN,
        uncertainty=estimate(calibration_id="stage2-isotonic-abc123def456"),
        evidence=evidence(),
        compute_path=ExecutionPath.P1_LATTICE,
        candidate_id="pocketsec.candidate.phi-oracle-max-squashed-dphi",
    )
    assert calibrated.calibration_id == "stage2-isotonic-abc123def456"
    assert calibrated.to_dict()["candidate_id"].endswith("squashed-dphi")


@pytest.mark.parametrize("score", [-0.1, 1.5, math.nan])
def test_a_prediction_score_outside_the_unit_interval_raises(score: float) -> None:
    with pytest.raises(ContractError, match="score"):
        export_evidence_bound_prediction(
            score=score,
            verdict=Verdict.BENIGN,
            uncertainty=estimate(),
            evidence=evidence(),
            compute_path=ExecutionPath.P0_COMPILED,
        )


# --- the seam rule, asserted by AST ----------------------------------------


def _package_modules() -> list[Path]:
    root = REPO_ROOT / "pocketsec" / "stage2"
    return sorted(
        path
        for directory in ("cache", "compile_candidates")
        for path in (root / directory).rglob("*.py")
    )


def test_no_export_module_imports_research_code() -> None:
    """ADR-0008 in the direction that matters: numpy must not reach the endpoint."""
    modules = _package_modules()
    assert modules, "the export package has no modules to check"
    offenders: list[str] = []
    for path in modules:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            if any("research" in name for name in names):
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}")
    assert not offenders, f"export modules importing research code: {offenders}"


def test_the_export_package_declares_every_public_name() -> None:
    """An empty package is a defect; so is a module with no declared surface."""
    for path in _package_modules():
        if path.name == "__init__.py":
            assert path.read_text(encoding="utf-8").strip() == "", (
                f"{path.name} must stay empty; consumers import from the leaf module"
            )
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        exported = [
            node
            for node in tree.body
            if isinstance(node, ast.Assign)
            and any(getattr(t, "id", "") == "__all__" for t in node.targets)
        ]
        assert exported, f"{path.name} declares no __all__"
        assert ast.get_docstring(tree), f"{path.name} has no module docstring"


def test_the_uncached_control_pass_banks_no_phantom_saving() -> None:
    """Pins S2-02 / S2-05 (MEDIUM).

    ``runtime_pass(honour_cache=False)`` — the control half of G2.10's headline
    comparison — reproduced the exact ADR-0010 defect inside the module built to
    prevent it. ``_cache_step`` passed the ledger unconditionally, so on a hit
    the cache wrote ``CORE_INFERENCE performed=False`` and added
    ``CORE_INFERENCE_UNITS`` to ``proven_skipped_units``; the ``honour_cache``
    flag was only consulted afterwards, so ``_deep_step`` then wrote
    ``CORE_INFERENCE performed=True`` for the same event. The resulting ledger
    fails ``assert_no_phantom_savings()``, and the gate applied that assertion
    only to ``cached_ledger`` — so the one ledger in this repository that
    actually failed it was never checked.
    """
    from pocketsec.stage2.encoder.ssir_encoder import ENCODER_VERSION as ENC
    from pocketsec.stage2.gate_measures import compile_split, runtime_pass
    from pocketsec.stage2.lattice.quantizer import DEFAULT_QUANTIZER
    from pocketsec.stage2.lattice.transitions import TransitionLattice
    from pocketsec.stage2.router.accounting import WorkLedger
    from pocketsec.stage2.state.window import WindowStore

    flat = compile_split("ambiguous", count=4, seed=11).flat
    for honour in (True, False):
        ledger = WorkLedger()
        measured = runtime_pass(
            flat,
            store=WindowStore(),
            quantizer=DEFAULT_QUANTIZER(),
            lattice=TransitionLattice(),
            cache=TransitionCache(model_version="test", encoder_version=ENC),
            ledger=ledger,
            honour_cache=honour,
        )
        assert measured.events > 0
        # Raises ContractError if any kind was recorded both skipped and
        # performed in one event. The control must pass this too.
        ledger.assert_no_phantom_savings()

    # And the control now measures whether the cheap path's ANSWER is the
    # answer, which nothing in this repository did before (S2-06).
    ledger = WorkLedger()
    control = runtime_pass(
        flat,
        store=WindowStore(),
        quantizer=DEFAULT_QUANTIZER(),
        lattice=TransitionLattice(),
        cache=TransitionCache(model_version="test", encoder_version=ENC),
        ledger=ledger,
        honour_cache=False,
    )
    checked = control.cache_agreements + control.cache_disagreements
    assert checked > 0, "no would-be hit was ever compared against the deep path"
    assert control.cache_agreement is not None
    assert 0.0 <= control.cache_agreement <= 1.0


def test_an_infinite_cost_is_not_a_measured_cost() -> None:
    """Pins S2-10.

    ``MeasuredCost.__post_init__`` claimed to require a "finite float >= 0" but
    only tested ``x != x`` (NaN) and negatives. ``float('inf')`` was accepted,
    ``measured`` returned True, and the exporter's UNMEASURED_COST refusal never
    fired — so a candidate could reach Stage 3 carrying an infinite per-event
    cost as a measured one.
    """
    from pocketsec.stage2.compile_candidates.candidate import MeasuredCost

    for bad in (float("inf"), float("-inf"), float("nan"), -1.0):
        with pytest.raises(ContractError, match="finite"):
            MeasuredCost(
                microseconds_per_event=bad,
                parameters=0,
                bytes_on_disk=1,
                peak_rss_bytes=None,
                measured_by="tests:test_stage2_export",
            )
    unmeasured = MeasuredCost(
        microseconds_per_event=None,
        parameters=0,
        bytes_on_disk=1,
        peak_rss_bytes=None,
        measured_by="tests:test_stage2_export",
    )
    assert unmeasured.measured is False
