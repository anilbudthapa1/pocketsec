"""D8.14 / PROM-F17 — FORGE detector executors: every representation a theory may ship as.

FORGE exists to answer one question about a theory that survived falsification: is there a
cheaper executable form that still decides what the theory decides? Every representation
below is therefore an *executor of plain data*: it is built from the JSON artifact that
would ship (:meth:`from_artifact`), it decides an :class:`~pocketsec.stage8.episode.Episode`
and it charges the caller's ``WorkMeter`` one unit per predicate test of one step, per
feature read of one step, or per state update — before doing that work — so the
tournament measures cost in the same unit the research loop is budgeted in.

The catalogue is exactly the representations with an executor here (lesson 3, ADR-0072):

=================  ===========================================================================
``TYPED_RULE``      the genome itself (``genome.decides``); the reference; artifact = the full
                    genome's canonical JSON
``MOTIF``           Stage 6's own detector grammar, run by Stage 6's ``match_motif``
``FSM``             a per-actor state table over the symbols {none, a, b, a+b, forbidden}
``THRESHOLD``       one pooled feature ``>= t``
``LOGISTIC``        Stage 1's ``LogisticProbe`` weights over pooled features, cut at 0.5
``PROTOTYPE``       two centroids over pooled features, nearest by L1
``STUMP_TREE``      depth <= 2 over pooled features binarised at 0.5
=================  ===========================================================================

``pooled_features`` is the per-slot maximum over an episode's steps: order-free, so the four
pooled students cannot see *which actor* or *which order* — that is what they give up for
being cheap, and what the tournament measures them losing.

What this module refuses to do:

* **Carry authority.** A detector returns a boolean and a score. It writes nothing, installs
  nothing, calls nothing outside this process. Its artifact is plain JSON data with no
  ``FORBIDDEN_AUTHORITY_FIELDS`` key (checked at load).
* **Load from anything but data.** ``from_artifact`` rebuilds each executor from the shipped
  mapping alone, validating every field; there is no code, no pickle, no dynamic import.
* **Stand in for what it cannot express.** Which representation may compile which theory is
  :mod:`pocketsec.stage8.forge.compiler`'s decision, made *before* compiling (lesson 2).
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, ClassVar, Protocol

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage2.encoder.ssir_encoder import FEATURE_WIDTH
from pocketsec.stage6.capsule.experience_capsule import EncodedStep
from pocketsec.stage6.memory.semantic import MAX_MOTIF_LENGTH, MotifStep, match_motif
from pocketsec.stage6.resources import WorkMeter
from pocketsec.stage8.episode import Episode
from pocketsec.stage8.forge.package import RepresentationKind
from pocketsec.stage8.genome.grammar import FEATURE_NAMES, StepPredicate
from pocketsec.stage8.genome.hypothesis import HypothesisGenome, authority_key_paths

__all__ = [
    "ARTIFACT_VERSION",
    "BINARISE_AT",
    "FSM_SYMBOLS",
    "LOGISTIC_CUT",
    "MAX_FSM_STATES",
    "MAX_STUDENT_SLOTS",
    "STUMP_TREE_MAX_DEPTH",
    "Detector",
    "FsmDetector",
    "LogisticDetector",
    "MotifDetector",
    "PrototypeDetector",
    "StumpTreeDetector",
    "ThresholdDetector",
    "TypedRuleDetector",
    "detector_from_artifact",
    "pooled_features",
]

#: §4.21 — chosen parameters, not measurements.
MAX_FSM_STATES: int = 8
STUMP_TREE_MAX_DEPTH: int = 2
#: The LOGISTIC decision cut and the STUMP_TREE binarisation point (spec D8.14). Chosen.
LOGISTIC_CUT: float = 0.5
BINARISE_AT: float = 0.5
#: A pooled student reads at most every encoder slot once per step.
MAX_STUDENT_SLOTS: int = FEATURE_WIDTH
ARTIFACT_VERSION = "stage8-forge-artifact.1.0.0"

#: FSM input alphabet, in table-column order. ``F`` (a forbidden observation matched) wins
#: over every other symbol, so a step that is both ``a`` and forbidden reaches the sink.
FSM_SYMBOLS: tuple[str, ...] = ("NONE", "A", "B", "AB", "F")
_F = 4


class Detector(Protocol):
    """What every FORGE representation is: a decision, a score, an artifact, a size."""

    kind: ClassVar[RepresentationKind]

    def decide(self, episode: Episode, meter: WorkMeter | None = None) -> bool: ...

    def score(self, episode: Episode, meter: WorkMeter | None = None) -> float: ...

    def artifact(self) -> Mapping[str, Any]: ...

    def interpretability(self) -> int: ...


# --- shared helpers ------------------------------------------------------------------


def _charge(meter: WorkMeter | None, units: int) -> None:
    if meter is not None:
        meter.charge(units)


def pooled_features(
    episode: Episode, slots: Sequence[int] | None = None, *, meter: WorkMeter | None = None
) -> tuple[float, ...]:
    """Per-slot maximum over the episode's steps, for ``slots`` (every slot when ``None``).

    One work unit per slot per step, charged before reading: a student that reads three
    slots pays for three, not for the encoder's 96.
    """
    chosen = range(FEATURE_WIDTH) if slots is None else tuple(slots)
    _charge(meter, len(chosen) * len(episode.steps))
    steps = episode.steps
    return tuple(max(step.features[slot] for step in steps) for slot in chosen)


def _require_int(value: object, field: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ContractError(f"{field} must be an int in [{low}, {high}], got {value!r}")
    return value


def _require_float(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ContractError(f"{field} must be a finite number, got {value!r}")
    return float(value)


def _require_seq(value: object, field: str, cap: int) -> tuple[Any, ...]:
    if not isinstance(value, (list, tuple)) or len(value) > cap:
        raise ContractError(f"{field} must be a list of at most {cap} items")
    return tuple(value)


def _require_slots(value: object, field: str, names: object) -> tuple[int, ...]:
    """Slot indices, distinct and in range, each paired with its encoder name."""
    slots = tuple(_require_int(s, field, 0, FEATURE_WIDTH - 1)
                  for s in _require_seq(value, field, MAX_STUDENT_SLOTS))
    if len(set(slots)) != len(slots):
        raise ContractError(f"{field} names a slot twice")
    labels = _require_seq(names, f"{field} names", MAX_STUDENT_SLOTS)
    if tuple(labels) != tuple(FEATURE_NAMES[s] for s in slots):
        raise ContractError(f"{field} names do not match the encoder's slot names")
    return slots


def _predicate(value: object, field: str) -> StepPredicate:
    row = _require_seq(value, field, 4)
    if len(row) != 4:
        raise ContractError(f"{field} is [relation, require, forbid, raised]")
    return StepPredicate(*row)


def _header(artifact: Mapping[str, Any], kind: RepresentationKind,
            keys: frozenset[str]) -> Mapping[str, Any]:
    """Exact keys, the right kind and version, and no authority key at any depth."""
    if not isinstance(artifact, Mapping):
        raise ContractError("a detector artifact is a mapping of plain data")
    found = authority_key_paths(artifact)
    if found:
        raise ContractError(f"authority keys refused in a detector artifact: {list(found)[:4]}")
    expected = keys | {"kind", "version"}
    if set(artifact) != expected:
        raise ContractError(f"{kind.value} artifact keys must be exactly {sorted(expected)}")
    if artifact["kind"] != kind.value or artifact["version"] != ARTIFACT_VERSION:
        raise ContractError(f"artifact is not a {kind.value} {ARTIFACT_VERSION} artifact")
    return artifact


# --- the reference and the two mask representations ----------------------------------


@dataclass(frozen=True, slots=True)
class TypedRuleDetector:
    """The theory itself, as a detector: ``genome.decides``. Every other entrant is judged
    against this one's decisions and costs (it is the uncompressed reference)."""

    kind: ClassVar[RepresentationKind] = RepresentationKind.TYPED_RULE
    genome: HypothesisGenome

    def decide(self, episode: Episode, meter: WorkMeter | None = None) -> bool:
        return self.genome.decides(episode, meter=meter)

    def score(self, episode: Episode, meter: WorkMeter | None = None) -> float:
        return 1.0 if self.decide(episode, meter) else 0.0

    def artifact(self) -> Mapping[str, Any]:
        return {"kind": self.kind.value, "version": ARTIFACT_VERSION,
                "genome": self.genome.to_dict()}

    def interpretability(self) -> int:
        return (len(self.genome.proposed_mechanism.steps)
                + len(self.genome.forbidden_observations))

    @classmethod
    def from_artifact(cls, artifact: Mapping[str, Any]) -> TypedRuleDetector:
        data = _header(artifact, RepresentationKind.TYPED_RULE, frozenset({"genome"}))
        return cls(HypothesisGenome.from_dict(data["genome"]))


class _CountingStep:
    """A ``MotifStep`` seen through a meter: Stage 6's matcher runs unchanged and every
    predicate test it makes is paid for before it is made."""

    __slots__ = ("_meter", "_step")

    def __init__(self, step: MotifStep, meter: WorkMeter) -> None:
        self._step = step
        self._meter = meter

    def matches(self, step: EncodedStep) -> bool:
        self._meter.charge(1)
        return self._step.matches(step)


@dataclass(frozen=True, slots=True)
class MotifDetector:
    """Stage 6's DETECTOR grammar, executed by Stage 6's own ``match_motif`` (lesson 3)."""

    kind: ClassVar[RepresentationKind] = RepresentationKind.MOTIF
    motif: tuple[MotifStep, ...]

    def __post_init__(self) -> None:
        if not 1 <= len(self.motif) <= MAX_MOTIF_LENGTH or any(
                not isinstance(step, MotifStep) for step in self.motif):
            raise ContractError(f"a motif is 1..{MAX_MOTIF_LENGTH} MotifStep values")

    def decide(self, episode: Episode, meter: WorkMeter | None = None) -> bool:
        if meter is None:
            return match_motif(self.motif, episode.steps)
        counted = tuple(_CountingStep(step, meter) for step in self.motif)
        return match_motif(counted, episode.steps)  # type: ignore[arg-type]

    def score(self, episode: Episode, meter: WorkMeter | None = None) -> float:
        return 1.0 if self.decide(episode, meter) else 0.0

    def artifact(self) -> Mapping[str, Any]:
        return {"kind": self.kind.value, "version": ARTIFACT_VERSION,
                "motif": [step.to_payload() for step in self.motif]}

    def interpretability(self) -> int:
        return len(self.motif)

    @classmethod
    def from_artifact(cls, artifact: Mapping[str, Any]) -> MotifDetector:
        data = _header(artifact, RepresentationKind.MOTIF, frozenset({"motif"}))
        rows = _require_seq(data["motif"], "motif", MAX_MOTIF_LENGTH)
        return cls(tuple(_predicate(row, "motif step").to_motif_step() for row in rows))


@dataclass(frozen=True, slots=True)
class FsmDetector:
    """A per-actor finite-state machine over the symbols of :data:`FSM_SYMBOLS`.

    Each actor slot starts in state 0. ``sink`` (if any) is absorbing and rejecting — a
    forbidden observation, or ``b`` under ``WITHOUT`` — so a sunk actor costs nothing more.
    An actor accepts when it ends in an accepting state; when ``early_accept`` holds the
    accepting states are absorbing and the first accepting actor decides the episode.

    Cost, read from the table alone: in each state only the predicates whose outcome can
    change the next state are tested (``b`` is irrelevant before ``a`` arms a PRECEDES), and
    a unit is charged per real transition, not per self-loop. The genome's own evaluator
    charges predicate tests and none of its bookkeeping (arming, counting), so the FSM is
    still charged at least as much as the reference for the same information.
    """

    kind: ClassVar[RepresentationKind] = RepresentationKind.FSM
    a: StepPredicate
    b: StepPredicate | None
    forbidden: tuple[StepPredicate, ...]
    table: tuple[tuple[int, ...], ...]  # states x len(FSM_SYMBOLS) -> next state
    accepting: frozenset[int]
    sink: int | None
    early_accept: bool
    _relevant: tuple[tuple[bool, bool], ...] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        states = len(self.table)
        if not 2 <= states <= MAX_FSM_STATES:
            raise ContractError(f"an FSM holds 2..{MAX_FSM_STATES} states, got {states}")
        for row in self.table:
            if len(row) != len(FSM_SYMBOLS) or any(
                    isinstance(n, bool) or not isinstance(n, int) or not 0 <= n < states
                    for n in row):
                raise ContractError("every FSM row maps each symbol to a state in range")
        if not self.accepting or any(not 0 <= s < states for s in self.accepting):
            raise ContractError("an FSM needs accepting states in range")
        if self.sink is not None and (not 0 <= self.sink < states or self.sink in self.accepting
                                      or any(n != self.sink for n in self.table[self.sink])):
            raise ContractError("the FSM sink must be an absorbing, rejecting state")
        if not isinstance(self.early_accept, bool):
            raise ContractError("early_accept must be a bool")
        if self.b is None and any(row[2] != row[0] or row[3] != row[1] for row in self.table):
            raise ContractError("an FSM without b cannot move on a b symbol")
        # (NONE, A, B, AB) = columns 0..3: a matters where A/AB differ from NONE/B, and so on.
        object.__setattr__(self, "_relevant", tuple(
            (row[1] != row[0] or row[3] != row[2], row[2] != row[0] or row[3] != row[1])
            for row in self.table))

    def _symbol(self, state: int, step: EncodedStep, meter: WorkMeter | None) -> int:
        for predicate in self.forbidden:
            _charge(meter, 1)
            if predicate.matches(step):
                return _F
        test_a, test_b = self._relevant[state]
        symbol = 0
        if test_a:
            _charge(meter, 1)
            symbol |= 1 if self.a.matches(step) else 0
        if test_b and self.b is not None:
            _charge(meter, 1)
            symbol |= 2 if self.b.matches(step) else 0
        return symbol

    def decide(self, episode: Episode, meter: WorkMeter | None = None) -> bool:
        states: dict[int, int] = {}
        for step in episode.steps:
            state = states.get(step.actor_slot, 0)
            if state == self.sink:
                continue  # absorbing: nothing this actor does can change its answer
            following = self.table[state][self._symbol(state, step, meter)]
            if following != state:
                _charge(meter, 1)  # a real transition; a self-loop writes nothing
                states[step.actor_slot] = state = following
            if self.early_accept and state in self.accepting:
                return True
        return any(state in self.accepting for state in states.values())

    def score(self, episode: Episode, meter: WorkMeter | None = None) -> float:
        return 1.0 if self.decide(episode, meter) else 0.0

    def artifact(self) -> Mapping[str, Any]:
        return {
            "kind": self.kind.value, "version": ARTIFACT_VERSION,
            "a": list(self.a.payload()),
            "b": None if self.b is None else list(self.b.payload()),
            "forbidden": [list(p.payload()) for p in self.forbidden],
            "table": [list(row) for row in self.table],
            "accepting": sorted(self.accepting), "sink": self.sink,
            "early_accept": self.early_accept,
        }

    def interpretability(self) -> int:
        return len(self.table)

    @classmethod
    def from_artifact(cls, artifact: Mapping[str, Any]) -> FsmDetector:
        data = _header(artifact, RepresentationKind.FSM, frozenset(
            {"a", "b", "forbidden", "table", "accepting", "sink", "early_accept"}))
        table = tuple(tuple(_require_seq(row, "table row", len(FSM_SYMBOLS)))
                      for row in _require_seq(data["table"], "table", MAX_FSM_STATES))
        accepting = _require_seq(data["accepting"], "accepting", MAX_FSM_STATES)
        sink = data["sink"]
        if sink is not None:
            sink = _require_int(sink, "sink", 0, MAX_FSM_STATES - 1)
        return cls(
            a=_predicate(data["a"], "a"),
            b=None if data["b"] is None else _predicate(data["b"], "b"),
            forbidden=tuple(_predicate(p, "forbidden") for p in
                            _require_seq(data["forbidden"], "forbidden", 4)),
            table=table,
            accepting=frozenset(_require_int(s, "accepting", 0, MAX_FSM_STATES - 1)
                                for s in accepting),
            sink=sink,
            early_accept=data["early_accept"],
        )


# --- the pooled students -------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ThresholdDetector:
    """One pooled feature, ``max over steps >= threshold``. One read per step."""

    kind: ClassVar[RepresentationKind] = RepresentationKind.THRESHOLD
    slot: int
    threshold: float

    def __post_init__(self) -> None:
        _require_int(self.slot, "slot", 0, FEATURE_WIDTH - 1)
        _require_float(self.threshold, "threshold")

    def score(self, episode: Episode, meter: WorkMeter | None = None) -> float:
        return pooled_features(episode, (self.slot,), meter=meter)[0]

    def decide(self, episode: Episode, meter: WorkMeter | None = None) -> bool:
        return self.score(episode, meter) >= self.threshold

    def artifact(self) -> Mapping[str, Any]:
        return {"kind": self.kind.value, "version": ARTIFACT_VERSION, "slot": self.slot,
                "feature": FEATURE_NAMES[self.slot], "threshold": self.threshold}

    def interpretability(self) -> int:
        return 1

    @classmethod
    def from_artifact(cls, artifact: Mapping[str, Any]) -> ThresholdDetector:
        data = _header(artifact, RepresentationKind.THRESHOLD,
                       frozenset({"slot", "feature", "threshold"}))
        slot = _require_slots([data["slot"]], "slot", [data["feature"]])[0]
        return cls(slot, _require_float(data["threshold"], "threshold"))


def _sigmoid(value: float) -> float:
    """``LogisticProbe._sigmoid``, the same clamps, so a loaded artifact scores identically."""
    if value >= 0:
        return 1.0 / (1.0 + math.exp(-min(value, 60.0)))
    exp_value = math.exp(max(value, -60.0))
    return exp_value / (1.0 + exp_value)


@dataclass(frozen=True, slots=True)
class LogisticDetector:
    """Stage 1's ``LogisticProbe``, fitted elsewhere, evaluated from its shipped weights:
    ``sigmoid(bias + sum w_i (x_i - mean_i) / scale_i) >= 0.5`` over the pooled slots.

    Slots the probe standardised to a constant carry no information and are not shipped
    (their scaled value is 0 on every training row, so their weight never moved from 0).
    """

    kind: ClassVar[RepresentationKind] = RepresentationKind.LOGISTIC
    slots: tuple[int, ...]
    mean: tuple[float, ...]
    scale: tuple[float, ...]
    weights: tuple[float, ...]
    bias: float

    def __post_init__(self) -> None:
        width = len(self.slots)
        if not 1 <= width <= MAX_STUDENT_SLOTS or {len(self.mean), len(self.scale),
                                                   len(self.weights)} != {width}:
            raise ContractError("LOGISTIC needs 1..96 slots with one mean, scale and weight each")
        if any(_require_float(s, "scale") <= 0.0 for s in self.scale):
            raise ContractError("LOGISTIC scales must be positive")
        for value in (*self.mean, *self.weights, self.bias):
            _require_float(value, "LOGISTIC parameter")

    def score(self, episode: Episode, meter: WorkMeter | None = None) -> float:
        row = pooled_features(episode, self.slots, meter=meter)
        _charge(meter, len(self.slots))  # one multiply-accumulate per weight
        raw = self.bias + sum(w * (x - m) / s for w, x, m, s in
                              zip(self.weights, row, self.mean, self.scale, strict=True))
        return _sigmoid(raw)

    def decide(self, episode: Episode, meter: WorkMeter | None = None) -> bool:
        return self.score(episode, meter) >= LOGISTIC_CUT

    def artifact(self) -> Mapping[str, Any]:
        return {"kind": self.kind.value, "version": ARTIFACT_VERSION,
                "slots": list(self.slots), "features": [FEATURE_NAMES[s] for s in self.slots],
                "mean": list(self.mean), "scale": list(self.scale),
                "weights": list(self.weights), "bias": self.bias}

    def interpretability(self) -> int:
        return sum(1 for weight in self.weights if weight != 0.0)

    @classmethod
    def from_artifact(cls, artifact: Mapping[str, Any]) -> LogisticDetector:
        data = _header(artifact, RepresentationKind.LOGISTIC, frozenset(
            {"slots", "features", "mean", "scale", "weights", "bias"}))
        numbers = {name: tuple(_require_float(v, name) for v in
                               _require_seq(data[name], name, MAX_STUDENT_SLOTS))
                   for name in ("mean", "scale", "weights")}
        return cls(slots=_require_slots(data["slots"], "slots", data["features"]),
                   bias=_require_float(data["bias"], "bias"), **numbers)


@dataclass(frozen=True, slots=True)
class PrototypeDetector:
    """Two centroids over pooled features; an episode fires when it is strictly nearer (L1)
    the centroid of the theory's matches than the centroid of its non-matches. Only slots
    where the centroids differ are shipped: every other slot adds the same to both sides."""

    kind: ClassVar[RepresentationKind] = RepresentationKind.PROTOTYPE
    slots: tuple[int, ...]
    positive: tuple[float, ...]
    negative: tuple[float, ...]

    def __post_init__(self) -> None:
        width = len(self.slots)
        if not 1 <= width <= MAX_STUDENT_SLOTS or {len(self.positive), len(self.negative)} \
                != {width}:
            raise ContractError("PROTOTYPE needs 1..96 slots with one value per centroid each")
        for value in (*self.positive, *self.negative):
            _require_float(value, "centroid")

    def score(self, episode: Episode, meter: WorkMeter | None = None) -> float:
        """Distance to the non-match centroid minus distance to the match centroid."""
        row = pooled_features(episode, self.slots, meter=meter)
        _charge(meter, 2 * len(self.slots))  # two absolute differences per slot
        near = sum(abs(x - c) for x, c in zip(row, self.positive, strict=True))
        far = sum(abs(x - c) for x, c in zip(row, self.negative, strict=True))
        return far - near

    def decide(self, episode: Episode, meter: WorkMeter | None = None) -> bool:
        return self.score(episode, meter) > 0.0  # a tie is not a match (conservative)

    def artifact(self) -> Mapping[str, Any]:
        return {"kind": self.kind.value, "version": ARTIFACT_VERSION,
                "slots": list(self.slots), "features": [FEATURE_NAMES[s] for s in self.slots],
                "positive": list(self.positive), "negative": list(self.negative)}

    def interpretability(self) -> int:
        return 2 * len(self.slots)

    @classmethod
    def from_artifact(cls, artifact: Mapping[str, Any]) -> PrototypeDetector:
        data = _header(artifact, RepresentationKind.PROTOTYPE,
                       frozenset({"slots", "features", "positive", "negative"}))
        centroids = {name: tuple(_require_float(v, name) for v in
                                 _require_seq(data[name], name, MAX_STUDENT_SLOTS))
                     for name in ("positive", "negative")}
        return cls(slots=_require_slots(data["slots"], "slots", data["features"]), **centroids)


def _node_depth(node: Mapping[str, Any]) -> int:
    if "leaf" in node:
        return 0
    return 1 + max(_node_depth(node["low"]), _node_depth(node["high"]))


def _check_node(node: object, depth: int) -> Mapping[str, Any]:
    """A tree node: ``{"leaf": [positives, total]}`` or ``{"slot", "feature", "low", "high"}``."""
    if not isinstance(node, Mapping) or depth > STUMP_TREE_MAX_DEPTH + 1:
        raise ContractError(f"a STUMP_TREE is a mapping tree of depth <= {STUMP_TREE_MAX_DEPTH}")
    if set(node) == {"leaf"}:
        counts = _require_seq(node["leaf"], "leaf", 2)
        if len(counts) != 2:
            raise ContractError("a leaf is [positives, total]")
        total = _require_int(counts[1], "leaf total", 1, 1 << 30)
        _require_int(counts[0], "leaf positives", 0, total)
        return node
    if set(node) != {"slot", "feature", "low", "high"}:
        raise ContractError("a STUMP_TREE split is exactly slot, feature, low, high")
    _require_slots([node["slot"]], "slot", [node["feature"]])
    _check_node(node["low"], depth + 1)
    _check_node(node["high"], depth + 1)
    return node


@dataclass(frozen=True, slots=True)
class StumpTreeDetector:
    """A depth <= 2 tree over pooled features binarised at 0.5, fitted by greedy Gini. A
    leaf fires when a strict majority of its training rows were the theory's matches."""

    kind: ClassVar[RepresentationKind] = RepresentationKind.STUMP_TREE
    tree: Mapping[str, Any]

    def __post_init__(self) -> None:
        _check_node(self.tree, 1)
        if _node_depth(self.tree) > STUMP_TREE_MAX_DEPTH:
            raise ContractError(f"STUMP_TREE depth exceeds {STUMP_TREE_MAX_DEPTH}")

    def _leaf(self, episode: Episode, meter: WorkMeter | None) -> tuple[int, int]:
        node = self.tree
        while "leaf" not in node:
            value = pooled_features(episode, (node["slot"],), meter=meter)[0]
            _charge(meter, 1)  # the branch
            node = node["high"] if value >= BINARISE_AT else node["low"]
        positives, total = node["leaf"]
        return int(positives), int(total)

    def score(self, episode: Episode, meter: WorkMeter | None = None) -> float:
        positives, total = self._leaf(episode, meter)
        return positives / total

    def decide(self, episode: Episode, meter: WorkMeter | None = None) -> bool:
        positives, total = self._leaf(episode, meter)
        return 2 * positives > total

    def artifact(self) -> Mapping[str, Any]:
        return {"kind": self.kind.value, "version": ARTIFACT_VERSION, "tree": _thaw(self.tree)}

    def interpretability(self) -> int:
        return _node_count(self.tree)

    def slots(self) -> tuple[int, ...]:
        return tuple(dict.fromkeys(_node_slots(self.tree)))

    @classmethod
    def from_artifact(cls, artifact: Mapping[str, Any]) -> StumpTreeDetector:
        data = _header(artifact, RepresentationKind.STUMP_TREE, frozenset({"tree"}))
        return cls(_thaw(data["tree"]))


def _node_count(node: Mapping[str, Any]) -> int:
    return 1 if "leaf" in node else 1 + _node_count(node["low"]) + _node_count(node["high"])


def _node_slots(node: Mapping[str, Any]) -> list[int]:
    if "leaf" in node:
        return []
    return [int(node["slot"]), *_node_slots(node["low"]), *_node_slots(node["high"])]


def _thaw(value: Any) -> Any:
    """Frozen JSON (mapping proxies, tuples) back to plain dicts and lists."""
    if isinstance(value, Mapping):
        return {key: _thaw(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_thaw(item) for item in value]
    return value


_READERS: Mapping[RepresentationKind, Any] = {
    RepresentationKind.TYPED_RULE: TypedRuleDetector.from_artifact,
    RepresentationKind.MOTIF: MotifDetector.from_artifact,
    RepresentationKind.FSM: FsmDetector.from_artifact,
    RepresentationKind.THRESHOLD: ThresholdDetector.from_artifact,
    RepresentationKind.LOGISTIC: LogisticDetector.from_artifact,
    RepresentationKind.PROTOTYPE: PrototypeDetector.from_artifact,
    RepresentationKind.STUMP_TREE: StumpTreeDetector.from_artifact,
}


def detector_from_artifact(kind: RepresentationKind, artifact: Mapping[str, Any]) -> Detector:
    """The executor for ``kind``, rebuilt from plain data only (frozen or not)."""
    if not isinstance(kind, RepresentationKind):
        raise ContractError(f"kind must be a RepresentationKind, got {kind!r}")
    detector: Detector = _READERS[kind](_thaw(artifact))
    return detector
