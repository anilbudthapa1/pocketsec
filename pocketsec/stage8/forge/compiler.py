"""D8.14 / PROM-F17 — the FORGE compiler: can this representation express the theory, and if
so, what plain-data artifact would ship?

**Expressibility is checked before compiling (lesson 2).** Stage 3's bytecode lacked division
and could only emit a constant; the measurement that followed measured nothing. So every
representation first answers :func:`can_express`, and a representation that cannot say what
the theory says is *refused with a code*, never compiled into an approximation and then
measured as if it were the theory:

=================  ==========================================================================
``TYPED_RULE``      always (it is the genome)
``MOTIF``           ``SINGLE`` without a modifier and ``PRECEDES`` only, with no forbidden
                    observation (Stage 6's grammar has no co-occurrence, absence, count or
                    veto): ``MOTIF_CANNOT_EXPRESS_`` + ``CO_OCCURS``, ``WITHOUT``,
                    ``REPEATED`` or ``FORBIDDEN_OBSERVATION``
``FSM``             every grammar member, while the per-actor states (``k + 1`` for
                    ``REPEATED(k)``, 3 for ``PRECEDES``, 5 for ``CO_OCCURS``, 2 for ``WITHOUT``,
                    plus one sink for a veto) fit ``MAX_FSM_STATES``: ``FSM_STATE_EXPLOSION``
``THRESHOLD`` …     students: always syntactically compilable; fitted on TRAIN to the genome's
``STUMP_TREE``      *decisions*, never to the labels (hard labels only measure them, §30).
                    A student whose TRAIN targets are one class learns nothing and is refused
                    ``NO_BOTH_CLASSES``; one with no varying pooled slot, ``NO_VARYING_FEATURE``
=================  ==========================================================================

What the compiler refuses to do:

* **Fit on held-out data.** ``compile_all`` takes TRAIN episodes only; anything else is a
  ``ContractError``. A student fitted on REPLICATION would be measured on what it memorised.
* **Build a representation it has no executor for.** ``KNOWLEDGE_CELL`` (Stage 3's cell ISA
  is single-frame and straight-line), tiny neural models (no research package, no numpy),
  INT8 and ONNX are not in :class:`RepresentationKind` (ADR-0072, ADR-0070).
* **Load anything but data.** :func:`load_detector` rebuilds an executor from the artifact
  mapping alone and refuses a refused entrant, a kind mismatch or an artifact that does not
  re-serialise to the same bytes.
* **Spend unbudgeted work.** Every fit charges the run's ``ResearchGovernor`` before it runs.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.guillotine.features import LogisticProbe
from pocketsec.stage1.ssir.relations import Relation
from pocketsec.stage2.encoder.ssir_encoder import FEATURE_WIDTH
from pocketsec.stage6.resources import WorkMeter
from pocketsec.stage8.episode import Episode, Split
from pocketsec.stage8.forge.package import RepresentationKind
from pocketsec.stage8.forge.representations import (
    BINARISE_AT,
    MAX_FSM_STATES,
    STUMP_TREE_MAX_DEPTH,
    Detector,
    FsmDetector,
    LogisticDetector,
    MotifDetector,
    PrototypeDetector,
    StumpTreeDetector,
    ThresholdDetector,
    TypedRuleDetector,
    detector_from_artifact,
    pooled_features,
)
from pocketsec.stage8.genome.grammar import (
    DIMENSION_NAMES,
    FEATURE_NAMES,
    MechanismRelation,
    Modifier,
    StepPredicate,
)
from pocketsec.stage8.genome.hypothesis import HypothesisGenome
from pocketsec.stage8.governor.budget import ResearchGovernor

__all__ = [
    "COMPILER_COMPONENT",
    "MAX_TRAIN_EPISODES",
    "REFUSAL_CODES",
    "STUDENT_KINDS",
    "CompiledDetector",
    "GovernedMeter",
    "can_express",
    "canonical_artifact_bytes",
    "compile_all",
    "fsm_state_count",
    "load_detector",
    "required_features",
]

COMPILER_COMPONENT = "forge.compiler"
#: A student fit is O(iterations x rows x slots); the cap keeps one fit bounded. Chosen.
MAX_TRAIN_EPISODES: int = 4096
STUDENT_KINDS: frozenset[RepresentationKind] = frozenset({
    RepresentationKind.THRESHOLD, RepresentationKind.LOGISTIC,
    RepresentationKind.PROTOTYPE, RepresentationKind.STUMP_TREE,
})
REFUSAL_CODES: frozenset[str] = frozenset({
    "MOTIF_CANNOT_EXPRESS_CO_OCCURS", "MOTIF_CANNOT_EXPRESS_WITHOUT",
    "MOTIF_CANNOT_EXPRESS_REPEATED", "MOTIF_CANNOT_EXPRESS_FORBIDDEN_OBSERVATION",
    "FSM_STATE_EXPLOSION", "NO_BOTH_CLASSES", "NO_VARYING_FEATURE",
})
_REFUSAL = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_OBJECT_SLOTS: tuple[int, ...] = tuple(
    index for index, name in enumerate(FEATURE_NAMES) if name.startswith("object."))


class GovernedMeter(WorkMeter):
    """A ``WorkMeter`` whose every charge is first paid to the run's governor, under one
    component name — so a detector that knows only ``meter.charge`` is still budgeted, and
    the meter's own ``spent`` is what *this* measurement cost."""

    __slots__ = ("_component", "_governor")

    def __init__(self, governor: ResearchGovernor, component: str) -> None:
        super().__init__(budget=None)
        if not isinstance(governor, ResearchGovernor):
            raise ContractError("a governed meter needs the run's ResearchGovernor")
        self._governor = governor
        self._component = component

    def charge(self, units: int = 1) -> None:
        self._governor.charge(self._component, units)  # raises before anything is paid
        super().charge(units)


def canonical_artifact_bytes(artifact: Mapping[str, Any]) -> bytes:
    """Sorted, compact JSON of the artifact: what ships, what is hashed, what is sized."""
    return json.dumps(_plain(artifact), sort_keys=True, separators=(",", ":"),
                      allow_nan=False).encode("utf-8")


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(item) for item in value]
    return value


def _frozen(value: Any) -> Any:
    if isinstance(value, Mapping):
        return MappingProxyType({key: _frozen(item) for key, item in value.items()})
    if isinstance(value, (list, tuple)):
        return tuple(_frozen(item) for item in value)
    return value


@dataclass(frozen=True, slots=True)
class CompiledDetector:
    """One representation of one theory: its artifact, or the code saying why it has none."""

    kind: RepresentationKind
    expressible: bool
    refusal: str | None
    artifact: Mapping[str, Any] | None
    artifact_bytes: int | None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, RepresentationKind):
            raise ContractError(f"kind must be a RepresentationKind, got {self.kind!r}")
        if not isinstance(self.expressible, bool):
            raise ContractError("expressible must be a bool")
        if self.expressible != (self.refusal is None) or \
                self.expressible != (self.artifact is not None):
            raise ContractError("an expressible entrant has an artifact and no refusal; a "
                                "refused one has a refusal code and no artifact")
        if self.refusal is not None:
            if not isinstance(self.refusal, str) or not _REFUSAL.fullmatch(self.refusal):
                raise ContractError(f"refusal must be an UPPER_SNAKE code, got {self.refusal!r}")
            if self.artifact_bytes is not None:
                raise ContractError("a refused entrant has no artifact bytes")
            return
        if not isinstance(self.artifact, Mapping):
            raise ContractError("artifact must be a mapping of plain JSON data")
        size = len(canonical_artifact_bytes(self.artifact))
        if self.artifact_bytes != size:
            raise ContractError(f"artifact_bytes {self.artifact_bytes!r} is not the artifact's "
                                f"canonical size {size}")
        if self.artifact.get("kind") != self.kind.value:
            raise ContractError("the artifact is not of this entrant's kind")
        object.__setattr__(self, "artifact", _frozen(self.artifact))


def _compiled(kind: RepresentationKind, artifact: Mapping[str, Any]) -> CompiledDetector:
    return CompiledDetector(kind, True, None, artifact, len(canonical_artifact_bytes(artifact)))


def _refused(kind: RepresentationKind, code: str) -> CompiledDetector:
    return CompiledDetector(kind, False, code, None, None)


# --- expressibility ------------------------------------------------------------------


def fsm_state_count(genome: HypothesisGenome) -> int:
    """Per-actor states the FSM needs for this genome, sink included."""
    mechanism = genome.proposed_mechanism
    base = {
        MechanismRelation.SINGLE: mechanism.repeat_min + 1,
        MechanismRelation.PRECEDES: 3,
        MechanismRelation.CO_OCCURS: 5,
        MechanismRelation.WITHOUT: 2,
    }[mechanism.relation]
    vetoed = bool(genome.forbidden_observations) or \
        mechanism.relation is MechanismRelation.WITHOUT
    return base + (1 if vetoed else 0)


def _motif_refusal(genome: HypothesisGenome) -> str | None:
    mechanism = genome.proposed_mechanism
    if mechanism.relation is MechanismRelation.CO_OCCURS:
        return "MOTIF_CANNOT_EXPRESS_CO_OCCURS"
    if mechanism.relation is MechanismRelation.WITHOUT:
        return "MOTIF_CANNOT_EXPRESS_WITHOUT"
    if mechanism.modifier is Modifier.REPEATED:
        return "MOTIF_CANNOT_EXPRESS_REPEATED"
    if genome.forbidden_observations:
        return "MOTIF_CANNOT_EXPRESS_FORBIDDEN_OBSERVATION"
    return None


def can_express(genome: HypothesisGenome, kind: RepresentationKind) -> tuple[bool, str | None]:
    """Whether ``kind`` can say what ``genome`` says, decided from the theory's form alone.

    Students answer True here: whether their TRAIN targets hold both classes is a fact about
    data, checked (and refused ``NO_BOTH_CLASSES``) when :func:`compile_all` fits them.
    """
    if not isinstance(genome, HypothesisGenome):
        raise ContractError(f"can_express reads a HypothesisGenome, got {type(genome).__name__}")
    if not isinstance(kind, RepresentationKind):
        raise ContractError(f"kind must be a RepresentationKind, got {kind!r}")
    code: str | None = None
    if kind is RepresentationKind.MOTIF:
        code = _motif_refusal(genome)
    elif kind is RepresentationKind.FSM and fsm_state_count(genome) > MAX_FSM_STATES:
        code = "FSM_STATE_EXPLOSION"
    return code is None, code


# --- the FSM table -------------------------------------------------------------------

# Columns: NONE, A, B, AB, F. "S" marks the veto column, filled with the sink (or a self-loop
# when the genome has no veto, since F then never occurs).
_S = -1


def _fsm_rows(genome: HypothesisGenome) -> tuple[list[list[int]], int, bool]:
    """(rows before the sink, the accepting state, whether acceptance is absorbing)."""
    mechanism = genome.proposed_mechanism
    relation = mechanism.relation
    if relation is MechanismRelation.SINGLE:
        k = mechanism.repeat_min
        rows = [[i, i + 1, i, i + 1, _S] for i in range(k)] + [[k, k, k, k, _S]]
        return rows, k, True
    if relation is MechanismRelation.PRECEDES:
        # b is tested before a arms (match_motif): one step that is both halves only arms.
        return [[0, 1, 0, 1, _S], [1, 1, 2, 2, _S], [2, 2, 2, 2, _S]], 2, True
    if relation is MechanismRelation.CO_OCCURS:
        # 0 {}, 1 {a}, 2 {b}, 3 {a and b from ONE step}, 4 two distinct steps: accept.
        return ([[0, 1, 2, 3, _S], [1, 1, 4, 4, _S], [2, 4, 2, 4, _S], [3, 4, 4, 4, _S],
                 [4, 4, 4, 4, _S]], 4, True)
    # WITHOUT: absence is global, so acceptance is read at the end and b sinks the actor.
    return [[0, 1, _S, _S, _S], [1, 1, _S, _S, _S]], 1, False


def _fsm(genome: HypothesisGenome) -> FsmDetector:
    rows, accept, absorbing = _fsm_rows(genome)
    mechanism = genome.proposed_mechanism
    vetoed = bool(genome.forbidden_observations) or \
        mechanism.relation is MechanismRelation.WITHOUT
    sink = len(rows) if vetoed else None
    table = [[(sink if sink is not None else index) if n == _S else n for n in row]
             for index, row in enumerate(rows)]
    if sink is not None:
        table.append([sink] * len(table[0]))
    return FsmDetector(
        a=mechanism.steps[0],
        b=mechanism.steps[1] if len(mechanism.steps) == 2 else None,
        forbidden=genome.forbidden_observations,
        table=tuple(tuple(row) for row in table),
        accepting=frozenset({accept}),
        sink=sink,
        early_accept=absorbing and not genome.forbidden_observations,
    )


# --- the students --------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _TrainingSet:
    rows: tuple[tuple[float, ...], ...]  # pooled features, every slot
    targets: tuple[int, ...]  # the genome's decisions, never the labels


def _training_set(genome: HypothesisGenome, train: Sequence[Episode],
                  meter: GovernedMeter) -> _TrainingSet:
    targets = tuple(int(genome.decides(episode, meter=meter)) for episode in train)
    rows = tuple(pooled_features(episode, meter=meter) for episode in train)
    return _TrainingSet(rows, targets)


def _varying(rows: Sequence[Sequence[float]]) -> tuple[int, ...]:
    return tuple(s for s in range(FEATURE_WIDTH) if len({row[s] for row in rows}) > 1)


def _fit_threshold(data: _TrainingSet, meter: GovernedMeter) -> ThresholdDetector:
    """The single slot and cut ``>= t`` that agree most with the theory's decisions.

    Ties break to the lower slot, then the lower cut (deterministic). One unit per row per
    slot pays for the sweep.
    """
    best: tuple[int, int, float] | None = None  # (agreement, -slot, -threshold)
    total_positive = sum(data.targets)
    for slot in range(FEATURE_WIDTH):
        meter.charge(len(data.rows))
        pairs = sorted(((row[slot], y) for row, y in zip(data.rows, data.targets, strict=True)),
                       key=lambda pair: -pair[0])
        above_pos = above = 0
        index = 0
        while index < len(pairs):
            value = pairs[index][0]
            while index < len(pairs) and pairs[index][0] == value:
                above += 1
                above_pos += pairs[index][1]
                index += 1
            negatives_below = (len(pairs) - above) - (total_positive - above_pos)
            candidate = (above_pos + negatives_below, -slot, -value)
            if best is None or candidate > best:
                best = candidate
    if best is None:  # unreachable: an empty training set is refused NO_BOTH_CLASSES first
        raise ContractError("a threshold needs at least one training row")
    return ThresholdDetector(-best[1], -best[2])


def _fit_logistic(data: _TrainingSet, meter: GovernedMeter) -> LogisticDetector | None:
    slots = _varying(data.rows)
    if not slots:
        return None
    probe = LogisticProbe()
    meter.charge(probe.iterations * len(data.rows) * len(slots) + 2 * len(data.rows) * len(slots))
    rows = [[row[s] for s in slots] for row in data.rows]
    probe.fit(rows, list(data.targets))
    # The probe's fitted state is shipped verbatim; the detector recomputes Stage 1's own
    # sigmoid over it, so the artifact scores exactly as the probe (a test pins this).
    fitted = {name: getattr(probe, "_" + name) for name in ("weights", "bias", "mean", "scale")}
    return LogisticDetector(slots=slots, mean=tuple(fitted["mean"]),
                            scale=tuple(fitted["scale"]), weights=tuple(fitted["weights"]),
                            bias=float(fitted["bias"]))


def _fit_prototype(data: _TrainingSet, meter: GovernedMeter) -> PrototypeDetector | None:
    meter.charge(2 * FEATURE_WIDTH * len(data.rows))
    centroids = []
    for target in (1, 0):
        members = [row for row, y in zip(data.rows, data.targets, strict=True) if y == target]
        centroids.append(tuple(sum(row[s] for row in members) / len(members)
                               for s in range(FEATURE_WIDTH)))
    positive, negative = centroids
    slots = tuple(s for s in range(FEATURE_WIDTH) if positive[s] != negative[s])
    if not slots:
        return None
    return PrototypeDetector(slots=slots, positive=tuple(positive[s] for s in slots),
                             negative=tuple(negative[s] for s in slots))


def _gini(positives: int, total: int) -> float:
    if total == 0:
        return 0.0
    share = positives / total
    return 2.0 * share * (1.0 - share)


def _grow(bits: Sequence[Sequence[bool]], targets: Sequence[int], members: Sequence[int],
          depth: int, meter: GovernedMeter) -> dict[str, Any]:
    """Greedy Gini: the slot whose binary split lowers impurity most, while it strictly does."""
    positives = sum(targets[i] for i in members)
    leaf: dict[str, Any] = {"leaf": [positives, len(members)]}
    parent = _gini(positives, len(members))
    if depth >= STUMP_TREE_MAX_DEPTH or parent == 0.0:
        return leaf
    meter.charge(len(members) * FEATURE_WIDTH)
    best: tuple[float, int] | None = None
    for slot in range(FEATURE_WIDTH):
        high = [i for i in members if bits[i][slot]]
        if not high or len(high) == len(members):
            continue
        high_pos = sum(targets[i] for i in high)
        low_n = len(members) - len(high)
        impurity = (len(high) * _gini(high_pos, len(high))
                    + low_n * _gini(positives - high_pos, low_n)) / len(members)
        if impurity < parent - 1e-12 and (best is None or impurity < best[0]):
            best = (impurity, slot)
    if best is None:
        return leaf
    slot = best[1]
    high = [i for i in members if bits[i][slot]]
    low = [i for i in members if not bits[i][slot]]
    return {"slot": slot, "feature": FEATURE_NAMES[slot],
            "low": _grow(bits, targets, low, depth + 1, meter),
            "high": _grow(bits, targets, high, depth + 1, meter)}


def _fit_stump_tree(data: _TrainingSet, meter: GovernedMeter) -> StumpTreeDetector:
    bits = [tuple(value >= BINARISE_AT for value in row) for row in data.rows]
    return StumpTreeDetector(_grow(bits, data.targets, range(len(bits)), 0, meter))


_FITTERS = {
    RepresentationKind.THRESHOLD: _fit_threshold,
    RepresentationKind.LOGISTIC: _fit_logistic,
    RepresentationKind.PROTOTYPE: _fit_prototype,
    RepresentationKind.STUMP_TREE: _fit_stump_tree,
}


# --- compile, load, read -------------------------------------------------------------


def _checked_train(train: Sequence[Episode]) -> tuple[Episode, ...]:
    episodes = tuple(train)
    if len(episodes) > MAX_TRAIN_EPISODES:
        raise ContractError(f"compile_all fits on at most {MAX_TRAIN_EPISODES} episodes")
    for episode in episodes:
        if not isinstance(episode, Episode):
            raise ContractError("compile_all takes Episode values only")
        if episode.split is not Split.TRAIN:
            raise ContractError(f"students fit on TRAIN only; got a {episode.split} episode")
    return episodes


def _mask_artifact(genome: HypothesisGenome, kind: RepresentationKind) -> Mapping[str, Any]:
    if kind is RepresentationKind.TYPED_RULE:
        return TypedRuleDetector(genome).artifact()
    if kind is RepresentationKind.MOTIF:
        steps = tuple(p.to_motif_step() for p in genome.proposed_mechanism.steps)
        return MotifDetector(steps).artifact()
    return _fsm(genome).artifact()


def compile_all(
    genome: HypothesisGenome, train: Sequence[Episode], *, governor: ResearchGovernor,
    kinds: Sequence[RepresentationKind] = tuple(RepresentationKind),
) -> tuple[CompiledDetector, ...]:
    """One :class:`CompiledDetector` per requested kind, in request order, refusals included."""
    chosen = tuple(kinds)
    if any(not isinstance(k, RepresentationKind) for k in chosen) or \
            len(set(chosen)) != len(chosen):
        raise ContractError("kinds must be distinct RepresentationKind values")
    episodes = _checked_train(train)
    meter = GovernedMeter(governor, COMPILER_COMPONENT)
    data: _TrainingSet | None = None
    out: list[CompiledDetector] = []
    for kind in chosen:
        ok, code = can_express(genome, kind)
        if not ok:
            out.append(_refused(kind, code or "UNEXPRESSIBLE"))
            continue
        if kind not in STUDENT_KINDS:
            out.append(_compiled(kind, _mask_artifact(genome, kind)))
            continue
        if data is None:
            data = _training_set(genome, episodes, meter)
        if len(set(data.targets)) < 2:
            out.append(_refused(kind, "NO_BOTH_CLASSES"))
            continue
        student = _FITTERS[kind](data, meter)
        out.append(_refused(kind, "NO_VARYING_FEATURE") if student is None
                   else _compiled(kind, student.artifact()))
    return tuple(out)


def load_detector(compiled: CompiledDetector) -> Detector:
    """The executor, rebuilt from the shipped plain data and nothing else."""
    if not isinstance(compiled, CompiledDetector):
        raise ContractError(f"load_detector takes a CompiledDetector, got {type(compiled)}")
    if not compiled.expressible or compiled.artifact is None:
        raise ContractError(f"{compiled.kind.value} was refused ({compiled.refusal}); a refused "
                            "entrant has no executor")
    detector = detector_from_artifact(compiled.kind, compiled.artifact)
    if canonical_artifact_bytes(detector.artifact()) != \
            canonical_artifact_bytes(compiled.artifact):
        raise ContractError(f"{compiled.kind.value} artifact does not round-trip to its bytes")
    return detector


def _predicate_features(predicate: StepPredicate) -> set[int]:
    slots = {FEATURE_NAMES.index("relation=" + Relation(predicate.relation).name)}
    for bit, slot in enumerate(_OBJECT_SLOTS):
        if (predicate.require_properties | predicate.forbid_properties) >> bit & 1:
            slots.add(slot)
    for bit, name in enumerate(DIMENSION_NAMES):
        if predicate.require_raised >> bit & 1:
            slots.add(FEATURE_NAMES.index("raised." + name))
    return slots


def required_features(compiled: CompiledDetector) -> tuple[str, ...]:
    """The encoder slot names the detector reads, in encoder order (``feature_names()``).

    Mask representations read the relation, object-property and raised-dimension slots their
    predicates test; pooled students read the slots they ship.
    """
    detector = load_detector(compiled)
    slots: set[int] = set()
    predicates: list[StepPredicate] = []
    if isinstance(detector, TypedRuleDetector):
        predicates = [*detector.genome.proposed_mechanism.steps,
                      *detector.genome.forbidden_observations]
    elif isinstance(detector, MotifDetector):
        predicates = [StepPredicate(*step.to_payload()) for step in detector.motif]
    elif isinstance(detector, FsmDetector):
        predicates = [detector.a, *([detector.b] if detector.b else []), *detector.forbidden]
    elif isinstance(detector, ThresholdDetector):
        slots = {detector.slot}
    elif isinstance(detector, StumpTreeDetector):
        slots = set(detector.slots())
    elif isinstance(detector, (LogisticDetector, PrototypeDetector)):
        slots = set(detector.slots)
    for predicate in predicates:
        slots |= _predicate_features(predicate)
    return tuple(FEATURE_NAMES[s] for s in sorted(slots))
