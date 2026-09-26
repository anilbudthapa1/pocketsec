"""D8.3 / PROM-F04 — ``HypothesisGenome``: an immutable, content-addressed, falsifiable theory.

Stage 8's discipline is that it kills its own hypotheses. That is only possible if a
hypothesis is a value that cannot move after it is tested. A genome therefore:

* **is content-addressed.** ``hypothesis_id`` is ``"hyp-"`` plus 24 hex of the sha256 of
  everything else in it. An id that does not match its content is refused, so a tampered
  payload fails loudly instead of loading under someone else's name. "Editing" a genome
  makes a new id with a parent link, which needs its own preregistration (ADR-0073).
* **carries its own refutation rules from birth.** ``falsification_tests`` must cover
  :data:`MANDATORY_FALSIFIERS` (holdout enrichment, holdout false positives,
  replication), and every threshold is fixed here — before any held-out data is looked
  at. A genome with no way to be wrong does not construct (DL-05).
* **has no status field.** Where a theory stands (proposed, registered, falsified …) is
  the Theory Ledger's append-only record, never a mutable field of the theory.
* **has no free-text field.** :meth:`HypothesisGenome.render` produces English on
  demand and nothing stores it; external text enters only through the grammar's parser
  and survives only as ``GenomeProvenance.source_digest`` (ADR-0074).
* **grants nothing.** Its vocabulary names detection, explanation and containment
  knowledge. :class:`ExperimentClass` has no production-intervention member (ADR-0075),
  and ``from_dict`` refuses any ``FORBIDDEN_AUTHORITY_FIELDS`` key at any depth.

``decides`` is the typed-rule reference detector: the mechanism fires in some actor and
no forbidden observation matches in that same actor.

The default refutation rules (§4.21 values, every one a chosen parameter):

=============================  ============  ===============================================
falsifier                       split         refutes the theory when
=============================  ============  ===============================================
HOLDOUT_ENRICHMENT              HOLDOUT       exact binomial P(X >= true | matched, base) > alpha/m
HOLDOUT_FALSE_POSITIVES         HOLDOUT       matched negatives / negatives > 0.01
HOLDOUT_RECALL                  HOLDOUT       true matches / positives < 0.10
COUNTERFACTUAL_INVARIANCE       LAB_POOL      agreement under PRESERVING transforms < 0.98
NECESSARY_STEP_ABLATION         LAB_POOL      deleting a necessary step removes < 0.50 of matches
DOPPELGANGER_SEPARATION         CHALLENGE     max family matched share > 0.05
REPLICATION                     REPLICATION   the genome's HOLDOUT rules, re-run in own batch
=============================  ============  ===============================================

For the two alpha-bearing kinds the threshold *is* alpha (one number, one meaning).
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass, fields
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from pocketsec.stage0.contracts.common import ContractError, digest_of_bytes, require_identifier
from pocketsec.stage0.contracts.threat_prediction_v1 import FORBIDDEN_AUTHORITY_FIELDS
from pocketsec.stage6.resources import WorkMeter
from pocketsec.stage8.episode import EPISODE_ID_PATTERN, Episode, Split
from pocketsec.stage8.genome.grammar import (
    Mechanism,
    MechanismRelation,
    Modifier,
    StepPredicate,
    mechanism_from_canonical,
)

__all__ = [
    "ALPHA_FALSIFIERS",
    "DEFAULT_FALSIFIERS",
    "DEFAULT_PREDICTIONS",
    "FALSIFIER_SPLITS",
    "FOREIGN_GENERATORS",
    "GENOME_VERSION",
    "HYPOTHESIS_ID_PATTERN",
    "MANDATORY_FALSIFIERS",
    "MAX_COMPETITORS",
    "MAX_FALSIFIERS",
    "MAX_FORBIDDEN",
    "MAX_INFORMATION_REQUESTS",
    "MAX_PARENTS",
    "MAX_SCOPE_EPISODES",
    "MAX_SCOPE_RESIDUALS",
    "CausalAssumption",
    "Direction",
    "ExperimentClass",
    "Falsifier",
    "FalsifierKind",
    "GeneratorKind",
    "GenomeProvenance",
    "HypothesisGenome",
    "ObservationScope",
    "Prediction",
    "ResidualType",
    "VisibilityAssumption",
    "authority_key_paths",
    "genome_for",
]

GENOME_VERSION = "stage8-hypothesis-genome.1.0.0"

# §4.21 — chosen parameters, not measurements.
MAX_SCOPE_RESIDUALS = 16
MAX_SCOPE_EPISODES = 64
MAX_FORBIDDEN = 4
MAX_COMPETITORS = 8
MAX_FALSIFIERS = 8
MAX_PARENTS = 2
MAX_INFORMATION_REQUESTS = 4

HYPOTHESIS_ID_PATTERN = re.compile(r"^hyp-[0-9a-f]{24}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
#: Deepest nesting the authority-key screen walks. Deeper payloads are refused, not
#: skipped: an unscreened level is exactly where a smuggled key would sit.
_MAX_SCREEN_DEPTH = 32


class Direction(StrEnum):
    """What a match predicts."""

    MALICIOUS = "MALICIOUS"
    BENIGN = "BENIGN"


class GeneratorKind(StrEnum):
    SYMBOLIC_ENUMERATOR = "SYMBOLIC_ENUMERATOR"
    RESIDUAL_MOTIF = "RESIDUAL_MOTIF"
    ANALOGY = "ANALOGY"
    NULL_BENIGN = "NULL_BENIGN"
    STAGE7_SEED = "STAGE7_SEED"
    EXTERNAL_PROPOSAL = "EXTERNAL_PROPOSAL"
    RANDOM_BASELINE = "RANDOM_BASELINE"
    EXHAUSTIVE_SINGLE_BASELINE = "EXHAUSTIVE_SINGLE_BASELINE"
    MUTATION = "MUTATION"
    MERGE = "MERGE"
    SPLIT = "SPLIT"


#: The generators whose input came from outside this host's own TRAIN data. Their
#: genomes are ``foreign=True``; no other generator may claim it (DL-04).
FOREIGN_GENERATORS: frozenset[GeneratorKind] = frozenset(
    {GeneratorKind.STAGE7_SEED, GeneratorKind.EXTERNAL_PROPOSAL}
)


class ResidualType(StrEnum):
    OBSERVATION = "OBSERVATION"
    CAUSAL = "CAUSAL"
    VISIBILITY = "VISIBILITY"
    COLLECTIVE = "COLLECTIVE"


class CausalAssumption(StrEnum):
    SAME_ACTOR = "SAME_ACTOR"
    ORDER_MATTERS = "ORDER_MATTERS"
    ABSENCE_OBSERVABLE = "ABSENCE_OBSERVABLE"
    COUNT_MATTERS = "COUNT_MATTERS"


class VisibilityAssumption(StrEnum):
    REQUIRES_COMPLETE_OBSERVATION = "REQUIRES_COMPLETE_OBSERVATION"
    TOLERATES_STEP_LOSS = "TOLERATES_STEP_LOSS"


class ExperimentClass(StrEnum):
    """Every way a Stage 8 hypothesis may be tested. All are replay or lab-only.

    There is NO production-intervention member: architecture §16 "no direct path"
    (ADR-0075). ``ISOLATED_EMULATION`` needs sandbox clearance and, with no emulator in
    this repository, is always refused by the sandbox.
    """

    HISTORICAL_REPLAY = "HISTORICAL_REPLAY"
    COUNTERFACTUAL_MUTATION = "COUNTERFACTUAL_MUTATION"
    TELEMETRY_DROPOUT = "TELEMETRY_DROPOUT"
    METAMORPHIC_TRANSFORM = "METAMORPHIC_TRANSFORM"
    BENIGN_ALTERNATIVE = "BENIGN_ALTERNATIVE"
    SYNTHETIC_EVENT_WORLD = "SYNTHETIC_EVENT_WORLD"
    ISOLATED_EMULATION = "ISOLATED_EMULATION"


class FalsifierKind(StrEnum):
    HOLDOUT_ENRICHMENT = "HOLDOUT_ENRICHMENT"
    HOLDOUT_FALSE_POSITIVES = "HOLDOUT_FALSE_POSITIVES"
    HOLDOUT_RECALL = "HOLDOUT_RECALL"
    COUNTERFACTUAL_INVARIANCE = "COUNTERFACTUAL_INVARIANCE"
    NECESSARY_STEP_ABLATION = "NECESSARY_STEP_ABLATION"
    DOPPELGANGER_SEPARATION = "DOPPELGANGER_SEPARATION"
    REPLICATION = "REPLICATION"


MANDATORY_FALSIFIERS: frozenset[FalsifierKind] = frozenset(
    {FalsifierKind.HOLDOUT_ENRICHMENT, FalsifierKind.HOLDOUT_FALSE_POSITIVES,
     FalsifierKind.REPLICATION}
)
#: The kinds whose rule is a family-wise test; their threshold is alpha.
ALPHA_FALSIFIERS: frozenset[FalsifierKind] = frozenset(
    {FalsifierKind.HOLDOUT_ENRICHMENT, FalsifierKind.REPLICATION}
)
#: The split each kind's rule reads (refutation-rule table). A rule registered against
#: another split would test the theory on data its pre-registration never named.
FALSIFIER_SPLITS: Mapping[FalsifierKind, Split] = MappingProxyType(
    {
        FalsifierKind.HOLDOUT_ENRICHMENT: Split.HOLDOUT,
        FalsifierKind.HOLDOUT_FALSE_POSITIVES: Split.HOLDOUT,
        FalsifierKind.HOLDOUT_RECALL: Split.HOLDOUT,
        FalsifierKind.COUNTERFACTUAL_INVARIANCE: Split.LAB_POOL,
        FalsifierKind.NECESSARY_STEP_ABLATION: Split.LAB_POOL,
        FalsifierKind.DOPPELGANGER_SEPARATION: Split.CHALLENGE,
        FalsifierKind.REPLICATION: Split.REPLICATION,
    }
)
_PREDICTION_SPLITS = (Split.HOLDOUT, Split.REPLICATION)


def _require_unit(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ContractError(f"{field} must be a number in [0, 1], got {value!r}")
    number = float(value)
    if not math.isfinite(number) or not 0.0 <= number <= 1.0:
        raise ContractError(f"{field} must be finite and within [0, 1], got {value!r}")
    return number


def _require_tuple(value: object, field: str, cap: int) -> tuple[Any, ...]:
    if not isinstance(value, (tuple, list)):
        raise ContractError(f"{field} must be a tuple, got {type(value).__name__}")
    items = tuple(value)
    if len(items) > cap:
        raise ContractError(f"{field} holds {len(items)} items; the cap is {cap}")
    if len(set(items)) != len(items):
        raise ContractError(f"{field} holds a duplicate")
    return items


def _require_ids(value: object, field: str, cap: int, pattern: re.Pattern[str]) -> tuple[str, ...]:
    items = _require_tuple(value, field, cap)
    for item in items:
        if not isinstance(item, str) or not pattern.fullmatch(item):
            raise ContractError(f"{field} holds a malformed id {item!r}")
    return items


def _require_members(value: object, field: str, enum: type[StrEnum]) -> frozenset[Any]:
    if not isinstance(value, (set, frozenset)):
        raise ContractError(f"{field} must be a frozenset, got {type(value).__name__}")
    if any(not isinstance(item, enum) for item in value):
        raise ContractError(f"{field} must hold {enum.__name__} members only")
    return frozenset(value)


@dataclass(frozen=True, slots=True)
class Falsifier:
    """One refutation rule, registered at birth. Its meaning per kind is the table above."""

    kind: FalsifierKind
    split: Split
    threshold: float
    alpha: float | None  # family-wise alpha for HOLDOUT_ENRICHMENT / REPLICATION, else None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, FalsifierKind):
            raise ContractError(f"Falsifier.kind must be a FalsifierKind, got {self.kind!r}")
        if not isinstance(self.split, Split) or self.split is not FALSIFIER_SPLITS[self.kind]:
            raise ContractError(
                f"{self.kind.value} reads {FALSIFIER_SPLITS[self.kind].value}, not {self.split!r}"
            )
        object.__setattr__(self, "threshold", _require_unit(self.threshold, "Falsifier.threshold"))
        if self.kind in ALPHA_FALSIFIERS:
            alpha = self.alpha
            if isinstance(alpha, bool) or not isinstance(alpha, (int, float)):
                raise ContractError(f"{self.kind.value} needs a numeric alpha, got {alpha!r}")
            if not 0.0 < float(alpha) <= 0.5:
                raise ContractError(f"alpha must be in (0, 0.5], got {alpha!r}")
            object.__setattr__(self, "alpha", float(alpha))
            if self.threshold != self.alpha:
                raise ContractError(f"{self.kind.value}: the threshold is alpha; they must agree")
        elif self.alpha is not None:
            raise ContractError(f"{self.kind.value} is not a family-wise test; alpha must be None")

    def to_dict(self) -> dict[str, Any]:
        return {"kind": self.kind.value, "split": self.split.value,
                "threshold": self.threshold, "alpha": self.alpha}


@dataclass(frozen=True, slots=True)
class Prediction:
    """What the theory says a held-out split will show, recorded before it is evaluated."""

    split: Split  # HOLDOUT or REPLICATION
    min_precision: float
    min_recall: float
    max_false_positive_rate: float

    def __post_init__(self) -> None:
        if not isinstance(self.split, Split) or self.split not in _PREDICTION_SPLITS:
            raise ContractError(f"a Prediction is about HOLDOUT or REPLICATION, not {self.split!r}")
        for name in ("min_precision", "min_recall", "max_false_positive_rate"):
            object.__setattr__(self, name, _require_unit(getattr(self, name), f"Prediction.{name}"))

    def to_dict(self) -> dict[str, Any]:
        return {"split": self.split.value, "min_precision": self.min_precision,
                "min_recall": self.min_recall,
                "max_false_positive_rate": self.max_false_positive_rate}


@dataclass(frozen=True, slots=True)
class ObservationScope:
    """What the generator read: residual clusters and the TRAIN episodes behind them."""

    residual_cluster_ids: tuple[str, ...]  # ≤ MAX_SCOPE_RESIDUALS
    residual_types: frozenset[ResidualType]
    episode_ids: tuple[str, ...]  # TRAIN episodes the generator read, ≤ MAX_SCOPE_EPISODES

    def __post_init__(self) -> None:
        clusters = _require_tuple(self.residual_cluster_ids, "residual_cluster_ids",
                                  MAX_SCOPE_RESIDUALS)
        for cluster in clusters:
            require_identifier(cluster, "ObservationScope.residual_cluster_ids[]")
        object.__setattr__(self, "residual_cluster_ids", clusters)
        object.__setattr__(self, "residual_types",
                           _require_members(self.residual_types, "residual_types", ResidualType))
        object.__setattr__(self, "episode_ids", _require_ids(
            self.episode_ids, "ObservationScope.episode_ids", MAX_SCOPE_EPISODES,
            EPISODE_ID_PATTERN))

    def to_dict(self) -> dict[str, Any]:
        return {"residual_cluster_ids": list(self.residual_cluster_ids),
                "residual_types": sorted(item.value for item in self.residual_types),
                "episode_ids": list(self.episode_ids)}


@dataclass(frozen=True, slots=True)
class GenomeProvenance:
    """Which generator proposed the theory, from what input (by digest only), and seed."""

    generator: GeneratorKind
    source_digest: str  # sha256: of the generator's input (cluster, text, capsule ids)
    foreign: bool  # True for STAGE7_SEED and EXTERNAL_PROPOSAL, refused otherwise
    seed: int

    def __post_init__(self) -> None:
        if not isinstance(self.generator, GeneratorKind):
            raise ContractError(f"generator must be a GeneratorKind, got {self.generator!r}")
        if not isinstance(self.source_digest, str) or not _DIGEST.fullmatch(self.source_digest):
            raise ContractError(f"source_digest must be sha256:<64 hex>: {self.source_digest!r}")
        if not isinstance(self.foreign, bool):
            raise ContractError("GenomeProvenance.foreign must be a bool")
        if self.foreign != (self.generator in FOREIGN_GENERATORS):
            raise ContractError(
                f"{self.generator.value}: foreign must be {self.generator in FOREIGN_GENERATORS}"
            )
        if not isinstance(self.seed, int) or isinstance(self.seed, bool) or self.seed < 0:
            raise ContractError(f"GenomeProvenance.seed must be an int >= 0, got {self.seed!r}")

    def to_dict(self) -> dict[str, Any]:
        return {"generator": self.generator.value, "source_digest": self.source_digest,
                "foreign": self.foreign, "seed": self.seed}


def authority_key_paths(payload: object, *, _path: str = "$", _depth: int = 0) -> tuple[str, ...]:
    """Every key, at any depth, containing a ``FORBIDDEN_AUTHORITY_FIELDS`` member.

    Substring, lowercased — the same screen T5 applies to field names — so ``Execute``
    and ``kill_switch`` are caught as well as ``action``. A payload nested deeper than
    the screen walks is reported rather than passed unread.
    """
    if _depth > _MAX_SCREEN_DEPTH:
        return (f"{_path}: nested deeper than {_MAX_SCREEN_DEPTH}; not screened, refused",)
    found: list[str] = []
    if isinstance(payload, Mapping):
        for key, value in payload.items():
            text = str(key).lower()
            if any(word in text for word in FORBIDDEN_AUTHORITY_FIELDS):
                found.append(f"{_path}.{key}")
            found.extend(authority_key_paths(value, _path=f"{_path}.{key}", _depth=_depth + 1))
    elif isinstance(payload, (list, tuple)):
        for index, value in enumerate(payload):
            found.extend(authority_key_paths(value, _path=f"{_path}[{index}]", _depth=_depth + 1))
    return tuple(found)


def _check_falsifiers(value: object) -> tuple[Falsifier, ...]:
    tests = _require_tuple(value, "falsification_tests", MAX_FALSIFIERS)
    if not tests:
        raise ContractError("a genome with no falsification test cannot be wrong (DL-05)")
    if any(not isinstance(test, Falsifier) for test in tests):
        raise ContractError("falsification_tests must hold Falsifier values")
    kinds = [test.kind for test in tests]
    if len(set(kinds)) != len(kinds):
        raise ContractError("one refutation rule per FalsifierKind")
    missing = MANDATORY_FALSIFIERS - set(kinds)
    if missing:
        raise ContractError(f"mandatory falsifiers missing: {sorted(k.value for k in missing)}")
    return tests


def _check_predictions(value: object) -> tuple[Prediction, ...]:
    predictions = _require_tuple(value, "predicted_observations", len(_PREDICTION_SPLITS))
    if any(not isinstance(item, Prediction) for item in predictions):
        raise ContractError("predicted_observations must hold Prediction values")
    splits = [item.split for item in predictions]
    if sorted(splits) != sorted(_PREDICTION_SPLITS):
        raise ContractError("predicted_observations must cover HOLDOUT and REPLICATION once each")
    return predictions


@dataclass(frozen=True, slots=True)
class HypothesisGenome:
    """A typed, testable theory. Immutable; its status lives in the Theory Ledger."""

    hypothesis_id: str  # "hyp-" + sha256(canonical minus id)[:24]; "" derives
    observation_scope: ObservationScope
    proposed_mechanism: Mechanism
    direction: Direction
    predicted_observations: tuple[Prediction, ...]  # covers HOLDOUT and REPLICATION
    forbidden_observations: tuple[StepPredicate, ...]  # ≤ MAX_FORBIDDEN; same actor → no fire
    competing_explanations: tuple[str, ...]  # hypothesis ids, ≤ MAX_COMPETITORS
    visibility_assumptions: frozenset[VisibilityAssumption]  # non-empty
    falsification_tests: tuple[Falsifier, ...]  # ⊇ MANDATORY_FALSIFIERS, ≤ MAX_FALSIFIERS
    information_requests: tuple[ExperimentClass, ...]  # ≤ MAX_INFORMATION_REQUESTS
    provenance: GenomeProvenance
    parent_hypotheses: tuple[str, ...]  # ≤ MAX_PARENTS
    schema_version: str = GENOME_VERSION

    def __post_init__(self) -> None:
        self._check_parts()
        self._check_links()
        self._check_forbidden()
        if self.schema_version != GENOME_VERSION:
            raise ContractError(f"schema_version must be {GENOME_VERSION}")
        derived = "hyp-" + self.digest()[len("sha256:"):][:24]
        if self.hypothesis_id == "":
            object.__setattr__(self, "hypothesis_id", derived)
        elif self.hypothesis_id != derived:
            raise ContractError(f"hypothesis_id {self.hypothesis_id!r} does not match its content")
        if self.hypothesis_id in self.competing_explanations + self.parent_hypotheses:
            raise ContractError("a genome cannot be its own parent or competitor")

    def _check_parts(self) -> None:
        checks: tuple[tuple[str, type], ...] = (
            ("observation_scope", ObservationScope), ("proposed_mechanism", Mechanism),
            ("direction", Direction), ("provenance", GenomeProvenance),
        )
        for name, kind in checks:
            if not isinstance(getattr(self, name), kind):
                raise ContractError(f"HypothesisGenome.{name} must be a {kind.__name__}")
        object.__setattr__(self, "predicted_observations",
                           _check_predictions(self.predicted_observations))
        object.__setattr__(self, "falsification_tests", _check_falsifiers(self.falsification_tests))
        visibility = _require_members(self.visibility_assumptions, "visibility_assumptions",
                                      VisibilityAssumption)
        if len(visibility) != 1:
            # Empty says nothing; both at once contradict each other.
            raise ContractError("visibility_assumptions must hold exactly one assumption")
        object.__setattr__(self, "visibility_assumptions", visibility)
        requests = _require_tuple(self.information_requests, "information_requests",
                                  MAX_INFORMATION_REQUESTS)
        if any(not isinstance(item, ExperimentClass) for item in requests):
            raise ContractError("information_requests must hold ExperimentClass members")
        object.__setattr__(self, "information_requests", requests)

    def _check_links(self) -> None:
        object.__setattr__(self, "competing_explanations", _require_ids(
            self.competing_explanations, "competing_explanations", MAX_COMPETITORS,
            HYPOTHESIS_ID_PATTERN))
        object.__setattr__(self, "parent_hypotheses", _require_ids(
            self.parent_hypotheses, "parent_hypotheses", MAX_PARENTS, HYPOTHESIS_ID_PATTERN))

    def _check_forbidden(self) -> None:
        forbidden = _require_tuple(self.forbidden_observations, "forbidden_observations",
                                   MAX_FORBIDDEN)
        if any(not isinstance(item, StepPredicate) for item in forbidden):
            raise ContractError("forbidden_observations must hold StepPredicate values")
        object.__setattr__(self, "forbidden_observations", forbidden)
        for condition in self.necessary_conditions:
            if any(condition.implies(item) for item in forbidden):
                # Every actor that could fire holds a step the forbidden predicate matches:
                # a theory that can never fire cannot be falsified by what it fires on.
                raise ContractError("a forbidden observation subsumes a necessary step")

    # --- derived, never stored --------------------------------------------------------

    @property
    def causal_dependencies(self) -> tuple[CausalAssumption, ...]:
        mechanism = self.proposed_mechanism
        needed: set[CausalAssumption] = set()
        if mechanism.relation is not MechanismRelation.SINGLE or self.forbidden_observations:
            needed.add(CausalAssumption.SAME_ACTOR)
        if mechanism.modifier is Modifier.REPEATED:
            needed |= {CausalAssumption.SAME_ACTOR, CausalAssumption.COUNT_MATTERS}
        if mechanism.relation is MechanismRelation.PRECEDES:
            needed.add(CausalAssumption.ORDER_MATTERS)
        if mechanism.relation is MechanismRelation.WITHOUT or self.forbidden_observations:
            needed.add(CausalAssumption.ABSENCE_OBSERVABLE)
        return tuple(item for item in CausalAssumption if item in needed)

    @property
    def necessary_conditions(self) -> tuple[StepPredicate, ...]:
        """Predicates every firing actor must hold a step for (WITHOUT: the first only)."""
        steps = self.proposed_mechanism.steps
        return steps[:1] if self.proposed_mechanism.relation is MechanismRelation.WITHOUT else steps

    @property
    def sufficient_conditions_candidate(self) -> Mechanism:
        return self.proposed_mechanism

    @property
    def complexity_cost(self) -> int:
        """TheoryCost §12: bits + 4·causal + 8·forbidden + predicate count."""
        predicates = len(self.proposed_mechanism.steps) + len(self.forbidden_observations)
        return (self.proposed_mechanism.description_length_bits()
                + 4 * len(self.causal_dependencies)
                + 8 * len(self.forbidden_observations) + predicates)

    # --- the reference detector -------------------------------------------------------

    def decides(self, episode: Episode, *, meter: WorkMeter | None = None) -> bool:
        """The mechanism fires in some actor and no forbidden observation matches there."""
        mechanism = self.proposed_mechanism
        if not self.forbidden_observations:
            return mechanism.matches(episode.steps, meter=meter)
        for slot in sorted(mechanism.firing_actors(episode.steps, meter=meter)):
            clean = True
            for step in episode.steps:
                if step.actor_slot != slot:
                    continue
                if meter is not None:
                    meter.charge(len(self.forbidden_observations))
                if any(item.matches(step) for item in self.forbidden_observations):
                    clean = False
                    break
            if clean:
                return True
        return False

    # --- serialisation ----------------------------------------------------------------

    def _content(self) -> dict[str, Any]:
        return {
            "observation_scope": self.observation_scope.to_dict(),
            "proposed_mechanism": self.proposed_mechanism.canonical(),
            "direction": self.direction.value,
            "predicted_observations": [item.to_dict() for item in self.predicted_observations],
            "forbidden_observations": [list(p.payload()) for p in self.forbidden_observations],
            "competing_explanations": list(self.competing_explanations),
            "visibility_assumptions": sorted(item.value for item in self.visibility_assumptions),
            "falsification_tests": [item.to_dict() for item in self.falsification_tests],
            "information_requests": [item.value for item in self.information_requests],
            "provenance": self.provenance.to_dict(),
            "parent_hypotheses": list(self.parent_hypotheses),
            "schema_version": self.schema_version,
        }

    def canonical_bytes(self) -> bytes:
        """Everything but the id, as sorted compact JSON: what the id and digest address."""
        return json.dumps(self._content(), sort_keys=True, separators=(",", ":"),
                          allow_nan=False).encode("utf-8")

    def digest(self) -> str:
        """``sha256:`` of :meth:`canonical_bytes`; the id is this digest's first 24 hex."""
        return digest_of_bytes(self.canonical_bytes())

    def render(self) -> str:
        """English, for people; never stored, never parsed."""
        text = f"{self.direction.value}: {self.proposed_mechanism.render()}"
        if self.forbidden_observations:
            text += "; unless the same actor also performs " + " or ".join(
                item.render() for item in self.forbidden_observations)
        kinds = ", ".join(test.kind.value for test in self.falsification_tests)
        return f"{text}. Refuted by: {kinds}."

    def to_dict(self) -> dict[str, Any]:
        return {"hypothesis_id": self.hypothesis_id, **self._content()}

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> HypothesisGenome:
        """Strict: exact keys at every level, no authority key anywhere, id must match."""
        found = authority_key_paths(payload)
        if found:
            raise ContractError(f"authority keys refused in a genome payload: {list(found)[:4]}")
        data = _exact(payload, {item.name for item in fields(cls)}, "HypothesisGenome")
        return cls(
            hypothesis_id=data["hypothesis_id"],
            observation_scope=_scope_from(data["observation_scope"]),
            proposed_mechanism=mechanism_from_canonical(data["proposed_mechanism"]),
            direction=_enum(Direction, data["direction"]),
            predicted_observations=tuple(_prediction_from(p) for p in
                                         _seq(data["predicted_observations"])),
            forbidden_observations=tuple(_predicate_from(p) for p in
                                         _seq(data["forbidden_observations"])),
            competing_explanations=tuple(_seq(data["competing_explanations"])),
            visibility_assumptions=frozenset(_enum(VisibilityAssumption, v) for v in
                                             _seq(data["visibility_assumptions"])),
            falsification_tests=tuple(_falsifier_from(f) for f in
                                      _seq(data["falsification_tests"])),
            information_requests=tuple(_enum(ExperimentClass, v) for v in
                                       _seq(data["information_requests"])),
            provenance=_provenance_from(data["provenance"]),
            parent_hypotheses=tuple(_seq(data["parent_hypotheses"])),
            schema_version=data["schema_version"],
        )


# --- strict readers ------------------------------------------------------------------


def _exact(payload: object, expected: set[str], name: str) -> Mapping[str, Any]:
    if not isinstance(payload, Mapping):
        raise ContractError(f"{name} payload must be a mapping, got {type(payload).__name__}")
    missing, extra = sorted(expected - set(payload)), sorted(set(payload) - expected)
    if missing or extra:
        raise ContractError(f"{name} payload missing {missing}, unexpected {extra}")
    return payload


def _seq(value: object) -> Iterator[Any]:
    if not isinstance(value, (list, tuple)):
        raise ContractError(f"expected a list, got {type(value).__name__}")
    return iter(value)


def _enum(kind: type[StrEnum], value: object) -> Any:
    if not isinstance(value, str):
        raise ContractError(f"{kind.__name__} value must be a string, got {value!r}")
    try:
        return kind(value)
    except ValueError:
        raise ContractError(f"{value!r} is not a {kind.__name__}") from None


def _scope_from(payload: object) -> ObservationScope:
    data = _exact(payload, {"residual_cluster_ids", "residual_types", "episode_ids"},
                  "ObservationScope")
    return ObservationScope(
        residual_cluster_ids=tuple(_seq(data["residual_cluster_ids"])),
        residual_types=frozenset(_enum(ResidualType, v) for v in _seq(data["residual_types"])),
        episode_ids=tuple(_seq(data["episode_ids"])),
    )


def _prediction_from(payload: object) -> Prediction:
    data = _exact(payload, {"split", "min_precision", "min_recall", "max_false_positive_rate"},
                  "Prediction")
    return Prediction(_enum(Split, data["split"]), data["min_precision"], data["min_recall"],
                      data["max_false_positive_rate"])


def _falsifier_from(payload: object) -> Falsifier:
    data = _exact(payload, {"kind", "split", "threshold", "alpha"}, "Falsifier")
    return Falsifier(_enum(FalsifierKind, data["kind"]), _enum(Split, data["split"]),
                     data["threshold"], data["alpha"])


def _predicate_from(payload: object) -> StepPredicate:
    if not isinstance(payload, (list, tuple)) or len(payload) != 4:
        raise ContractError("a predicate payload is [relation, require, forbid, raised]")
    return StepPredicate(*payload)


def _provenance_from(payload: object) -> GenomeProvenance:
    data = _exact(payload, {"generator", "source_digest", "foreign", "seed"}, "GenomeProvenance")
    return GenomeProvenance(_enum(GeneratorKind, data["generator"]), data["source_digest"],
                            data["foreign"], data["seed"])


# --- defaults and the builder --------------------------------------------------------

#: The refutation-rule table's values (§4.21). Chosen, not calibrated.
DEFAULT_FALSIFIERS: tuple[Falsifier, ...] = (
    Falsifier(FalsifierKind.HOLDOUT_ENRICHMENT, Split.HOLDOUT, 0.05, 0.05),
    Falsifier(FalsifierKind.HOLDOUT_FALSE_POSITIVES, Split.HOLDOUT, 0.01, None),
    Falsifier(FalsifierKind.HOLDOUT_RECALL, Split.HOLDOUT, 0.10, None),
    Falsifier(FalsifierKind.COUNTERFACTUAL_INVARIANCE, Split.LAB_POOL, 0.98, None),
    Falsifier(FalsifierKind.NECESSARY_STEP_ABLATION, Split.LAB_POOL, 0.50, None),
    Falsifier(FalsifierKind.DOPPELGANGER_SEPARATION, Split.CHALLENGE, 0.05, None),
    Falsifier(FalsifierKind.REPLICATION, Split.REPLICATION, 0.05, 0.05),
)

#: ``min_precision`` is 0.0 because the refutation table registers no precision rule:
#: enrichment over the base rate is the precision test. Recall and FPR are the table's.
DEFAULT_PREDICTIONS: tuple[Prediction, ...] = (
    Prediction(Split.HOLDOUT, 0.0, 0.10, 0.01),
    Prediction(Split.REPLICATION, 0.0, 0.10, 0.01),
)


def genome_for(
    mechanism: Mechanism,
    *,
    direction: Direction,
    scope: ObservationScope,
    provenance: GenomeProvenance,
    parents: tuple[str, ...] = (),
    competing: tuple[str, ...] = (),
    forbidden: tuple[StepPredicate, ...] = (),
    falsifiers: tuple[Falsifier, ...] = DEFAULT_FALSIFIERS,
    predictions: tuple[Prediction, ...] = DEFAULT_PREDICTIONS,
    visibility: frozenset[VisibilityAssumption] = frozenset(
        {VisibilityAssumption.REQUIRES_COMPLETE_OBSERVATION}),
    information_requests: tuple[ExperimentClass, ...] = (),
) -> HypothesisGenome:
    """A genome with its id derived. The defaults are the registered refutation rules.

    ``visibility`` defaults to REQUIRES_COMPLETE_OBSERVATION: a mechanism is a test of
    recorded steps, and a step the sensor dropped is a step it cannot see.
    """
    return HypothesisGenome(
        hypothesis_id="",
        observation_scope=scope,
        proposed_mechanism=mechanism,
        direction=direction,
        predicted_observations=predictions,
        forbidden_observations=forbidden,
        competing_explanations=competing,
        visibility_assumptions=visibility,
        falsification_tests=falsifiers,
        information_requests=information_requests,
        provenance=provenance,
        parent_hypotheses=parents,
    )
