"""Stdlib-only measurements the Stage 2 acceptance gate runs.

The gate has to *run* its criteria, not read them out of a document, and the CI
``gate`` job installs the package with a bare ``pip install -e .`` — so every
measurement a check depends on must exist without numpy. That is what this
module is for: the shared corpus walk, the runtime path with its work ledger,
and the small metric routines (multi-class Brier, hazard truth, atom pairs) that
more than one check needs.

It is deliberately the *subset* of ``research/stage2_report.py`` that carries no
research dependency. The two do not duplicate each other: the report imports the
primitives from here, so there is exactly one definition of "walk this corpus
through the quantizer" in Stage 2 and a gate number and a report number cannot
drift apart while appearing to measure the same thing.

Nothing here decides anything. Every function returns measurements; the verdicts
live in ``gate.py`` beside the criterion they answer.
"""

from __future__ import annotations

import math
import time
from collections import Counter
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from pocketsec.stage0.benchmark.profiles import ProfileReport, check_profile
from pocketsec.stage0.benchmark.resource_metrics import ResourceMetrics, ResourceSampler
from pocketsec.stage1.labs.ambiguous_corpus import build_ambiguous_corpus
from pocketsec.stage1.labs.corpus import Scenario
from pocketsec.stage1.labs.hard_corpus import build_hard_corpus
from pocketsec.stage1.labs.longhorizon_corpus import build_long_horizon_corpus
from pocketsec.stage1.pipeline import ScenarioResult, Stage1Pipeline
from pocketsec.stage1.ssir.transition import SSIRTransitionV1
from pocketsec.stage1.state.potential import phi
from pocketsec.stage1.state.security_state import DIMENSIONS, SecurityStateV1
from pocketsec.stage2.adaptation.epoch_guard import SystemChangeSignal
from pocketsec.stage2.cache.transition_cache import (
    CACHE_LOOKUP_UNITS,
    CachedTransition,
    TransitionCache,
    transition_cache_key,
)
from pocketsec.stage2.dataset import Stage2Dataset
from pocketsec.stage2.dataset import _encode  # Stage 2's own encoder, not a copy of it
from pocketsec.stage2.labs.drift_corpus import (
    DRIFT_TECHNIQUE_CORROBORATED_CHANGE,
    DRIFT_TECHNIQUE_UNCORROBORATED_CHANGE,
)
from pocketsec.stage2.encoder.ssir_encoder import (
    ENCODER_VERSION,
    FEATURE_WIDTH,
    EncodedTransition,
    encode_ssir_transition,
)
from pocketsec.stage2.lattice.quantizer import (
    BehaviourQuantizer,
    QuantizeResult,
)
from pocketsec.stage2.lattice.transitions import TransitionLattice
from pocketsec.stage2.predictors.future_cone import (
    FUTURE_CONE_DEFAULT_ENABLED,
    UNKNOWN_LABEL,
    FutureCone,
    predict_future_cone,
)
from pocketsec.stage2.predictors.hazard import HORIZONS, OUTCOME_DIMENSIONS
from pocketsec.stage2.predictors.heads import HeadPrediction
from pocketsec.stage2.router.accounting import MAX_LEDGER_EVENTS, WorkKind, WorkLedger
from pocketsec.stage2.router.policy import NeedSignals, route_information_need
from pocketsec.stage2.state.window import WindowStore
from pocketsec.stage2.uncertainty.abstention import estimate_uncertainty

__all__ = [
    "CORPUS_BUILDERS",
    "CompiledSplit",
    "DRIFT_EPOCH_SIGNALS",
    "STAGE2_INCREMENTAL_RSS_CEILING_BYTES",
    "QuantizedStep",
    "RuntimePass",
    "atom_pairs",
    "build_lattice",
    "cone_distribution",
    "cone_heads",
    "compile_corpus",
    "compile_scenario_list",
    "compile_split",
    "fold_state",
    "hazard_base_rates",
    "hazard_truth",
    "lineage_windows",
    "lru_key_control",
    "multiclass_brier",
    "next_transition",
    "positions",
    "resource_pass",
    "runtime_pass",
    "walk",
]

#: The three corpora Stage 1 ships. Named here so a gate and a report cannot
#: disagree about what ``"ambiguous"`` means.
CORPUS_BUILDERS: Mapping[str, Any] = {
    "hard": build_hard_corpus,
    "long": build_long_horizon_corpus,
    "ambiguous": build_ambiguous_corpus,
}

#: Architecture spec section 31: Stage 2 may add at most this much resident
#: memory on top of Stage 1. Defined here, imported by both the gate and the
#: offline report, so one ceiling cannot drift into two.
STAGE2_INCREMENTAL_RSS_CEILING_BYTES: int = 80 * 1024 * 1024

#: What an out-of-band source reports alongside each drift-corpus phase. The
#: corpus says *when* a change happened; this says what a change *is*. Behaviour
#: never appears here, which is the anti-poisoning invariant (ADR-0007): only a
#: corroborated system change may open an epoch.
DRIFT_EPOCH_SIGNALS: Mapping[str, SystemChangeSignal] = {
    DRIFT_TECHNIQUE_CORROBORATED_CHANGE: SystemChangeSignal(
        changed=frozenset({"package_digest", "service_digest"}),
        corroborated=frozenset({"package_digest", "service_digest"}),
    ),
    DRIFT_TECHNIQUE_UNCORROBORATED_CHANGE: SystemChangeSignal(
        changed=frozenset({"service_digest"}),
        corroborated=frozenset(),
    ),
}


# --- the shared corpus walk --------------------------------------------------


@dataclass(frozen=True, slots=True)
class CompiledSplit:
    """One corpus split, compiled once and reused by every measurement.

    Compiling a split costs tens of seconds, and the gate needs the same split
    three ways: as SSIR sessions (the stdlib path), as labelled sessions (the
    calibration probe) and as a :class:`Stage2Dataset` (the baseline suite). It
    is compiled once so those three cannot silently disagree about the corpus.
    """

    corpus: str
    count: int
    seed: int
    results: tuple[ScenarioResult, ...]
    dataset: Stage2Dataset

    @property
    def sessions(self) -> tuple[tuple[SSIRTransitionV1, ...], ...]:
        return tuple(result.transitions for result in self.results if result.transitions)

    @property
    def labelled(self) -> tuple[tuple[int, tuple[SSIRTransitionV1, ...]], ...]:
        return tuple(
            (result.scenario.label, result.transitions)
            for result in self.results
            if result.transitions
        )

    @property
    def flat(self) -> tuple[SSIRTransitionV1, ...]:
        return tuple(t for session in self.sessions for t in session)

    def to_provenance(self) -> dict[str, Any]:
        return {
            "corpus": self.corpus,
            "count": self.count,
            "seed": self.seed,
            "sessions": len(self.sessions),
            "transitions": len(self.flat),
            "base_rate": self.dataset.base_rate,
        }


def compile_split(
    name: str, *, count: int, seed: int, split: str = "eval"
) -> CompiledSplit:
    """Replay one corpus split through a fresh Stage 1 pipeline.

    A pipeline per split, never shared: Stage 1 carries lineage state across
    scenarios, so a shared pipeline lets the split a model is fitted on warm the
    novelty engine that scores the split it is evaluated on (``planning/
    MEMORY.md`` corpus trap).

    The encoded :class:`Stage2Dataset` is built here from the same
    ``ScenarioResult``s with ``dataset._encode`` — Stage 2's own encoder, reached
    by name rather than re-implemented, so the gate's dataset is byte-identical
    to ``build_dataset``'s and the gate does not compile the corpus twice.
    """
    builder = CORPUS_BUILDERS.get(name)
    if builder is None:
        raise ValueError(f"unknown corpus {name!r}; known: {sorted(CORPUS_BUILDERS)}")
    pipeline = Stage1Pipeline()
    results = tuple(
        pipeline.run_scenario(scenario, offset=index)
        for index, scenario in enumerate(builder(count=count, seed=seed, split=split))
    )
    samples = tuple(
        sample
        for sample in (_encode(result, index) for index, result in enumerate(results))
        if sample is not None
    )
    return CompiledSplit(
        corpus=name,
        count=count,
        seed=seed,
        results=results,
        dataset=Stage2Dataset(
            name=f"s2-gate-{name}-{seed}",
            corpus=name,
            seed=seed,
            encoder_version=ENCODER_VERSION,
            feature_width=FEATURE_WIDTH,
            samples=samples,
        ),
    )


def compile_corpus(
    name: str, *, count: int, seed: int, split: str = "eval"
) -> tuple[tuple[SSIRTransitionV1, ...], ...]:
    """Just the SSIR sessions of one split."""
    return compile_split(name, count=count, seed=seed, split=split).sessions


def compile_scenario_list(
    scenarios: Sequence[Scenario],
) -> tuple[tuple[SSIRTransitionV1, ...], ...]:
    """Same, for a corpus a caller already built (the drift and poison fixtures)."""
    pipeline = Stage1Pipeline()
    return tuple(
        pipeline.run_scenario(scenario, offset=index).transitions
        for index, scenario in enumerate(scenarios)
    )


def fold_state(state: SecurityStateV1, transition: SSIRTransitionV1) -> SecurityStateV1:
    """Re-apply one transition's ΔS to a lineage state.

    Stage 1 owns the state calculus; this replays only the dimensions the
    transition already recorded, so no new semantics are invented here.
    """
    for name, (_, after) in transition.state_delta.raised.items():
        state = state.raised_to(name, DIMENSIONS[name](after))
    return state


@dataclass(frozen=True, slots=True)
class QuantizedStep:
    """One quantized transition, with everything an evaluator needs about it."""

    transition: SSIRTransitionV1
    state: SecurityStateV1
    encoded: EncodedTransition
    result: QuantizeResult
    previous_atom: int | None


def walk(
    quantizer: Any, sessions: tuple[tuple[SSIRTransitionV1, ...], ...]
) -> Iterator[QuantizedStep]:
    """Quantize every session in order, one :class:`QuantizedStep` at a time.

    Every evaluator shares this walk so that no two of them can quantize the
    same corpus in subtly different ways — a divergence there would silently
    become the component delta.

    The quantizer is stateful and online: it is still adapting while an
    evaluation split is walked, exactly as it would on a host. That adaptation is
    information a frozen control does not get, so an evaluator says so.
    """
    for session in sessions:
        state = SecurityStateV1()
        previous: int | None = None
        for transition in session:
            state = fold_state(state, transition)
            encoded = encode_ssir_transition(transition)
            result = quantizer.quantize_behaviour_atom(
                encoded,
                state=state,
                epoch_id=transition.epoch_id,
                sequence=transition.sequence,
            )
            yield QuantizedStep(transition, state, encoded, result, previous)
            previous = result.atom_id


def build_lattice(
    quantizer: Any, sessions: tuple[tuple[SSIRTransitionV1, ...], ...]
) -> tuple[TransitionLattice, dict[int, Counter[int]]]:
    """Learn the atom lattice, and the modal relation family of each atom."""
    lattice = TransitionLattice()
    families: dict[int, Counter[int]] = {}
    for step in walk(quantizer, sessions):
        families.setdefault(step.result.atom_id, Counter())[step.encoded.relation_family] += 1
        if step.previous_atom is not None:
            lattice.observe(
                step.previous_atom,
                step.result.atom_id,
                epoch_id=step.transition.epoch_id,
                delta_phi=step.transition.delta_phi,
                uncertainty=step.transition.uncertainty,
            )
    return lattice, families


def atom_pairs(
    quantizer: Any, sessions: tuple[tuple[SSIRTransitionV1, ...], ...]
) -> tuple[tuple[int, int], ...]:
    """Held-out (source, target) atom pairs under an already-fitted quantizer."""
    return tuple(
        (step.previous_atom, step.result.atom_id)
        for step in walk(quantizer, sessions)
        if step.previous_atom is not None
    )


def positions(
    sessions: tuple[tuple[SSIRTransitionV1, ...], ...],
) -> dict[int, tuple[tuple[SSIRTransitionV1, ...], int]]:
    """Where each transition sits, keyed by identity so the walk stays a stream."""
    return {
        id(transition): (session, index)
        for session in sessions
        for index, transition in enumerate(session)
    }


def next_transition(
    sessions: tuple[tuple[SSIRTransitionV1, ...], ...],
) -> dict[int, SSIRTransitionV1]:
    """Each transition's actual successor within its own session."""
    return {
        id(session[index]): session[index + 1]
        for session in sessions
        for index in range(len(session) - 1)
    }


def lineage_windows(
    transitions: Sequence[SSIRTransitionV1],
) -> tuple[Any, ...]:
    """Every lineage's final window, not just the last one touched.

    A session interleaves several lineages, so probing only the window the last
    transition happened to land in would attribute one lineage and silently miss
    the attack in another.
    """
    return tuple(window for window, _ in lineage_windows_with_signatures(transitions))


def lineage_windows_with_signatures(
    transitions: Sequence[SSIRTransitionV1],
) -> tuple[tuple[Any, tuple[str, ...]], ...]:
    """Each lineage's final window, paired with its steps' causal signatures.

    ``EncodedTransition`` carries no causal signature — ADR-0007 keeps identity
    out of the model-facing encoding — so a caller that probes ``window.steps[i]``
    has no way to name the transition it probed to Stage 1's causal memory. The
    counterfactual twin's ``target_signature`` is a positional locator
    (``lineage:index:rN:mM``) and its own docstring says it is "provenance for
    the probe itself, never an identity the ledger trusts".

    G2.7 looked its probes up in a dict keyed by ``CausalNode.signature`` — a
    bare 16-hex string — using that locator as the key. The two key spaces are
    structurally disjoint, so ``assign_causal_credit`` was never called even
    once, and the gate reported "no probe's divergence reached
    MATERIAL_DIVERGENCE" about a comparison that never ran (S2-FC-01). This
    returns the real signatures, index-aligned with ``window.steps``, so the
    join can be made on identity rather than on a locator.
    """
    store = WindowStore()
    latest: dict[str, Any] = {}
    signatures: dict[str, list[str]] = {}
    for transition in transitions:
        window = store.update_multiscale_state(transition)
        key = window.lineage_key
        history = signatures.setdefault(key, [])
        history.append(transition.causal_signature)
        # The store truncates to MAX_WINDOW; mirror that exactly so index i of
        # the signature tuple is always index i of `window.steps`.
        del history[: len(history) - len(window.steps)]
        latest[key] = window
    return tuple((latest[key], tuple(signatures[key])) for key in sorted(latest))


# --- metric primitives -------------------------------------------------------


def multiclass_brier(distribution: Mapping[str, float], actual: str) -> float:
    """Multi-class Brier over the union of predicted and observed labels."""
    labels = set(distribution) | {actual}
    return sum(
        (distribution.get(label, 0.0) - (1.0 if label == actual else 0.0)) ** 2
        for label in labels
    )


def cone_distribution(cone: FutureCone) -> dict[str, float]:
    """A cone as a label distribution, unresolved mass kept as a real class."""
    distribution: dict[str, float] = {UNKNOWN_LABEL: cone.unresolved_mass}
    for branch in cone.branches:
        distribution[branch.label] = distribution.get(branch.label, 0.0) + branch.probability
    return distribution


def cone_heads(cone: FutureCone) -> dict[str, HeadPrediction]:
    """A head-shaped view of the cone's branch mass.

    These are *not* trained head weights — ``models/experimental/`` holds none —
    so the id says so. They exist because ``estimate_uncertainty`` and the
    ``one_minus_max`` control are defined over a probability vector, and the
    cone is the only probability vector the stdlib path actually produces.
    """
    probabilities = tuple(branch.probability for branch in cone.branches) + (
        cone.unresolved_mass,
    )
    argmax = max(range(len(probabilities)), key=probabilities.__getitem__)
    entropy = -sum(p * math.log(p) for p in probabilities if p > 0.0)
    return {
        "cone_branch_mass": HeadPrediction(
            head_id="cone_branch_mass",
            probabilities=probabilities,
            argmax=argmax,
            entropy=entropy,
        )
    }


def hazard_truth(
    session: tuple[SSIRTransitionV1, ...], index: int, outcome: str, horizon: int
) -> int:
    """Did ``outcome`` actually move within ``horizon`` following events?"""
    dimension = OUTCOME_DIMENSIONS[outcome]
    for transition in session[index + 1 : index + 1 + horizon]:
        if dimension in transition.state_delta.raised:
            return 1
    return 0


def hazard_base_rates(
    sessions: tuple[tuple[SSIRTransitionV1, ...], ...],
) -> dict[tuple[str, int], tuple[int, int]]:
    """Empirical (events, total) per (outcome, horizon) — the constant control's input."""
    counts: dict[tuple[str, int], tuple[int, int]] = {}
    for session in sessions:
        for index in range(len(session)):
            for outcome in OUTCOME_DIMENSIONS:
                for horizon in HORIZONS:
                    events, total = counts.get((outcome, horizon), (0, 0))
                    counts[(outcome, horizon)] = (
                        events + hazard_truth(session, index, outcome, horizon),
                        total + 1,
                    )
    return counts


# --- the stdlib runtime path -------------------------------------------------


@dataclass(slots=True)
class RuntimePass:
    """What one pass of the runtime path produced. Counts and seconds, no verdicts."""

    events: int = 0
    cache_resolved: int = 0
    inferred: int = 0
    abstentions: int = 0
    #: Only populated by the ``honour_cache=False`` control, where the deep path
    #: runs anyway and the cached answer can be compared against it. Without
    #: these, ``cache_fraction`` measures key repetition and nothing checks that
    #: the cheap path's answer is the answer (S2-06).
    cache_agreements: int = 0
    cache_disagreements: int = 0
    #: ``route_information_need``'s *proposal* per event — what a router would
    #: have claimed. Kept beside the ledger's derived path so the two can be
    #: compared, which is the whole point of ADR-0114.
    proposed_paths: Counter[str] = field(default_factory=Counter)
    #: The path the ledger *derived* from work that genuinely ran.
    derived_paths: Counter[str] = field(default_factory=Counter)
    seconds: float = 0.0
    seconds_by_kind: dict[str, float] = field(default_factory=dict)

    @property
    def microseconds_per_event(self) -> float | None:
        if self.events <= 0:
            return None
        return self.seconds / self.events * 1e6

    @property
    def cache_fraction(self) -> float | None:
        if self.events <= 0:
            return None
        return self.cache_resolved / self.events

    @property
    def cache_agreement(self) -> float | None:
        """Fraction of would-be hits whose cached answer matched the deep path's.

        ``None`` — never 1.0 — when no hit was ever checked, which is the case
        in any pass that honours the cache: the deep path did not run, so there
        was nothing to compare against.
        """
        checked = self.cache_agreements + self.cache_disagreements
        if checked == 0:
            return None
        return self.cache_agreements / checked

    def to_dict(self) -> dict[str, Any]:
        return {
            "events": self.events,
            "cache_resolved": self.cache_resolved,
            "inferred": self.inferred,
            "abstentions": self.abstentions,
            "proposed_paths": dict(self.proposed_paths),
            "derived_paths": dict(self.derived_paths),
            "microseconds_per_event": self.microseconds_per_event,
            "cache_agreements": self.cache_agreements,
            "cache_disagreements": self.cache_disagreements,
            "cache_agreement": self.cache_agreement,
        }


def runtime_pass(
    transitions: Sequence[SSIRTransitionV1],
    *,
    store: WindowStore,
    quantizer: Any,
    lattice: TransitionLattice,
    cache: TransitionCache,
    ledger: WorkLedger,
    honour_cache: bool = True,
    max_events: int = MAX_LEDGER_EVENTS,
) -> RuntimePass:
    """One pass of the whole stdlib path, with every unit of work accounted.

    The order is the one the spec fixes: ``WindowStore`` → quantizer →
    ``TransitionLattice`` → ``TransitionCache`` → ``predict_future_cone`` →
    ``estimate_uncertainty``.

    A cache hit **genuinely skips** the cone and the uncertainty estimate. That
    is not an optimisation, it is the honesty requirement: the cache writes a
    ``performed=False`` record for ``CORE_INFERENCE`` on a hit, and if this
    function ran the inference anyway ``assert_no_phantom_savings()`` would
    refuse the run — which is exactly the ADR-0010 defect it exists to catch.

    ``honour_cache=False`` is the control: identical work, except that a hit is
    ignored and the deep path always runs. It is what makes "the cache reduced
    measured compute" a comparison rather than an assertion.

    ``max_events`` matches the ledger's own bound; past it accounting stops being
    complete, so the measured window stops with it.
    """
    result = RuntimePass()
    states: dict[str, SecurityStateV1] = {}
    previous_atom: dict[str, int] = {}
    started_all = time.perf_counter()

    for transition in transitions[:max_events]:
        ledger.begin(f"{transition.causal_signature}:{transition.sequence}")
        window = _timed(
            result, WorkKind.WINDOW_UPDATE, ledger, 1.0, store.update_multiscale_state, transition
        )
        key = window.lineage_key
        state = fold_state(states.get(key, SecurityStateV1()), transition)
        states[key] = state
        encoded = encode_ssir_transition(transition, actor_slot=0)
        result.proposed_paths[route_information_need(NeedSignals.from_encoded(encoded)).value] += 1
        quantized: QuantizeResult = _timed(
            result,
            WorkKind.LATTICE_LOOKUP,
            ledger,
            2.0,
            quantizer.quantize_behaviour_atom,
            encoded,
            state=state,
            epoch_id=transition.epoch_id,
            sequence=transition.sequence,
        )
        source = previous_atom.get(key)
        if source is not None:
            _timed(
                result,
                WorkKind.LATTICE_LOOKUP,
                ledger,
                2.0,
                lattice.observe,
                source,
                quantized.atom_id,
                epoch_id=transition.epoch_id,
                delta_phi=transition.delta_phi,
                uncertainty=transition.uncertainty,
            )
        previous_atom[key] = quantized.atom_id
        hit = _cache_step(
            result,
            ledger,
            cache,
            encoded,
            quantized,
            state,
            transition,
            claim_skip=honour_cache,
        )
        if hit is not None and honour_cache:
            result.cache_resolved += 1
        else:
            _audit_hit(result, hit, state=state, transition=transition)
            _deep_step(result, ledger, transition, state, quantized, lattice, quantizer)
        result.derived_paths[ledger.close().path.value] += 1
        result.events += 1

    result.seconds = time.perf_counter() - started_all
    return result


def _deep_step(
    result: RuntimePass,
    ledger: WorkLedger,
    transition: SSIRTransitionV1,
    state: SecurityStateV1,
    quantized: QuantizeResult,
    lattice: TransitionLattice,
    quantizer: Any,
) -> None:
    """The expensive half of the path, run only when the cache could not answer.

    The cone is expanded only while ``FUTURE_CONE_DEFAULT_ENABLED`` is true.
    G2.6's detail string asserts that "neither mechanism may reach a verdict, a
    score or a compile candidate while those flags are off", and that was false:
    no runtime code read either constant, this function called
    ``predict_future_cone`` on every deep event, and the cone's output then
    supplied 0.45 of the uncertainty weight that decides abstention
    (CONE_AMBIGUITY 0.20 + ENTROPY 0.25, whose source is ``cone_heads(cone)``).
    A rejected mechanism that still runs and still moves the number is not off.

    With the flag off the cone is not expanded, no ``CONE_EXPANSION`` work is
    charged, and ``estimate_uncertainty`` records ``cone=not_evaluated`` and
    ``heads=not_evaluated`` in its notes — which is what it was built to do.
    """
    cone = (
        _timed(
            result,
            WorkKind.CONE_EXPANSION,
            ledger,
            8.0,
            predict_future_cone,
            lattice,
            quantizer,
            from_atom=quantized.atom_id,
            state=state,
            epoch_id=transition.epoch_id,
        )
        if FUTURE_CONE_DEFAULT_ENABLED
        else None
    )
    estimate = _timed(
        result,
        WorkKind.CORE_INFERENCE,
        ledger,
        40.0,
        estimate_uncertainty,
        heads=None if cone is None else cone_heads(cone),
        cone=cone,
        prototype_distance=quantized.distance,
        transition=transition,
        phi_total=phi(state).total,
    )
    result.inferred += 1
    result.abstentions += int(estimate.abstain)


#: How close a cached Φ may be to the freshly computed one and still count as
#: the same answer. Φ is a float sum, so exact equality would measure floating
#: point rather than cache correctness.
_PHI_AGREEMENT_TOLERANCE = 1e-9


def _audit_hit(
    result: RuntimePass,
    hit: CachedTransition | None,
    *,
    state: SecurityStateV1,
    transition: SSIRTransitionV1,
) -> None:
    """Compare a would-be hit's answer with the one the deep path is about to give.

    Called only from the ``honour_cache=False`` branch, where the deep path runs
    regardless, so the comparison is free and the measured path is not perturbed.
    This is the only place in this repository where a cheap-path answer is
    checked rather than counted (S2-06).
    """
    if hit is None:
        return
    if _agrees(hit, state=state, transition=transition):
        result.cache_agreements += 1
    else:
        result.cache_disagreements += 1


def _agrees(
    hit: CachedTransition, *, state: SecurityStateV1, transition: SSIRTransitionV1
) -> bool:
    """Does the cached answer match what the deep path would compute now?

    The P0 key is ``(atom_id, epoch_id, state_delta_mask)`` and carries **no
    lineage**, while the stored payload is the *first* inserting lineage's own
    state snapshot. So every later hit on that key serves another lineage's
    numbers, and nothing in the runtime path ever noticed. This is the check
    that turns G2.10's skipped fraction from "how often a key repeated" into a
    figure with a correctness number beside it (S2-06).
    """
    return (
        abs(hit.predicted_phi - phi(state).total) <= _PHI_AGREEMENT_TOLERANCE
        and hit.predicted_delta.raised == state.delta_from(SecurityStateV1()).raised
        and hit.epoch_id == transition.epoch_id
    )


def _timed(
    _result: RuntimePass,
    _kind: WorkKind,
    _ledger: WorkLedger,
    _units: float,
    _call: Any,
    /,
    *args: Any,
    **kwargs: Any,
) -> Any:
    """Run one unit of work, time it, and record that it genuinely ran.

    ``performed=True`` is written only after the call returned, so the ledger
    cannot bank work that was skipped. The leading parameters are positional-only
    so a wrapped callable may take its own ``ledger`` keyword.
    """
    started = time.perf_counter()
    value = _call(*args, **kwargs)
    elapsed = time.perf_counter() - started
    _result.seconds_by_kind[_kind.value] = (
        _result.seconds_by_kind.get(_kind.value, 0.0) + elapsed
    )
    _ledger.record(_kind, performed=True, units=_units, detail=getattr(_call, "__name__", ""))
    return value


def _cache_step(
    result: RuntimePass,
    ledger: WorkLedger,
    cache: TransitionCache,
    encoded: EncodedTransition,
    quantized: QuantizeResult,
    state: SecurityStateV1,
    transition: SSIRTransitionV1,
    *,
    claim_skip: bool = True,
) -> CachedTransition | None:
    """Look the transition up, and store it on a miss.

    ``claim_skip=False`` is the ``honour_cache=False`` control: the lookup really
    runs and is charged, but the hit is about to be thrown away and the inference
    run anyway, so no ``CORE_INFERENCE performed=False`` may be written for it.

    Passing the ledger unconditionally reproduced the exact ADR-0010 defect
    inside the module built to prevent it: on a hit the cache banked a skipped
    ``CORE_INFERENCE`` and then ``_deep_step`` recorded a performed one for the
    same event, so ``uncached_ledger`` failed ``assert_no_phantom_savings()`` —
    and the gate applied that assertion only to ``cached_ledger``, so the half of
    the two-pass comparison that actually failed it was never checked (S2-02).
    """
    started = time.perf_counter()
    hit = cache.lookup_transition_cache(
        atom_id=quantized.atom_id,
        epoch_id=encoded.epoch_id,
        state_delta_mask=encoded.state_delta_mask,
        ledger=ledger if claim_skip else None,
    )
    if not claim_skip:
        # The lookup genuinely ran, so it is still charged — just without the
        # skip claim the cache would otherwise attach to a hit.
        ledger.record(
            WorkKind.CACHE_LOOKUP,
            performed=True,
            units=CACHE_LOOKUP_UNITS,
            detail="control: hit ignored, no skip claimed",
        )
    result.seconds_by_kind[WorkKind.CACHE_LOOKUP.value] = (
        result.seconds_by_kind.get(WorkKind.CACHE_LOOKUP.value, 0.0)
        + time.perf_counter()
        - started
    )
    if hit is not None:
        return hit
    cache.store(
        CachedTransition(
            key=transition_cache_key(
                atom_id=quantized.atom_id,
                epoch_id=encoded.epoch_id,
                state_delta_mask=encoded.state_delta_mask,
            ),
            atom_id=quantized.atom_id,
            epoch_id=encoded.epoch_id,
            model_version=cache.model_version,
            encoder_version=cache.encoder_version,
            predicted_delta=state.delta_from(SecurityStateV1()),
            predicted_phi=phi(state).total,
            uncertainty=transition.uncertainty,
            hits=0,
            utility=0.0,
            last_sequence=max(0, transition.sequence),
        )
    )
    return None


def lru_key_control(
    transitions: Sequence[SSIRTransitionV1], *, capacity: int = 1024
) -> float | None:
    """F10's control: a plain LRU keyed on (relation_family, state_delta_mask).

    Stage 1 already ships a bounded LRU (``novelty/sketches.py``), so this reuses
    it rather than reimplementing one. The figure returned is the fraction of
    events whose key was already resident — the most a key cache alone could ever
    skip, with no atom, no lattice and no epoch in the key.
    """
    from pocketsec.stage1.novelty.sketches import BoundedLRUCounter

    counter = BoundedLRUCounter(capacity=capacity)
    resident = 0
    total = 0
    for transition in transitions:
        encoded = encode_ssir_transition(transition)
        key = f"{encoded.relation_family}:{encoded.state_delta_mask}"
        if key in counter:
            resident += 1
        counter.add(key)
        total += 1
    return None if total == 0 else resident / total


def resource_pass(
    transitions: Sequence[SSIRTransitionV1], *, max_events: int = MAX_LEDGER_EVENTS
) -> dict[str, Any]:
    """Measure the runtime path with ``ResourceSampler`` and the Stage 0 Edge profile.

    The learned ``BehaviourQuantizer`` is used rather than the cheaper default
    ``HashBucketQuantizer``, deliberately: ADR-0115 disabled the learned layer,
    and measuring the *more* expensive configuration cannot understate Stage 2's
    resource cost.
    """
    store = WindowStore()
    quantizer = BehaviourQuantizer()
    lattice = TransitionLattice()
    cache = TransitionCache(model_version="stage2-gate", encoder_version=ENCODER_VERSION)
    ledger = WorkLedger()

    with ResourceSampler(interval_seconds=0.01) as sampler:
        measured = runtime_pass(
            transitions,
            store=store,
            quantizer=quantizer,
            lattice=lattice,
            cache=cache,
            ledger=ledger,
            max_events=max_events,
        )
    metrics: ResourceMetrics = sampler.result(
        events_processed=measured.events, startup_seconds=None
    )
    model_bytes = quantizer.memory_bytes() + lattice.memory_bytes() + store.memory_bytes()
    profile: ProfileReport = check_profile(metrics, "edge", model_bytes=model_bytes)
    ledger.assert_no_phantom_savings()
    return {
        "pass": measured.to_dict(),
        "metrics": metrics.to_dict(),
        "profile": profile.to_dict(),
        "within_target": profile.within_target,
        "model_bytes": model_bytes,
        "component_bytes": {
            "window_store": store.memory_bytes(),
            "quantizer": quantizer.memory_bytes(),
            "lattice": lattice.memory_bytes(),
            "cache": cache.stats().memory_bytes,
        },
        "incremental_rss_bytes": metrics.delta_rss_bytes,
        "work_histogram": ledger.histogram(),
        "path_fractions": ledger.path_fractions(),
        "ledger_truncated": ledger.truncated(),
        "cache": cache.stats().to_dict(),
        "measured_by": "pocketsec.stage2.gate_measures:resource_pass",
    }
