"""D8.16 / PROM-F20 — ``DiscoveryPackageV1``: the typed Stage 8 candidate. THE STAGE 9 INTERFACE.

A discovery that survived Stage 8's discipline leaves the research loop as one value of
this type and in no other form. It carries the mechanism (a grammar value, never text),
the evidence lineage, every falsification result, the conditions under which the theory
is known to fail, the measured representation tournament, and content hashes that
:func:`verify_package` recomputes.

What a package is NOT, by construction:

* **Not authority.** No field, and no key at any depth of :meth:`DiscoveryPackageV1.to_dict`,
  may contain a ``FORBIDDEN_AUTHORITY_FIELDS`` word; ``from_dict`` refuses one and
  :func:`verify_package` reports one. Stage 6's ``QuarantineGateway.admit`` refuses this
  type outright (it admits only ``ExperienceCapsuleV1``). A package reaches an endpoint
  only through ``adapters/stage6.py``, as evidence capsules of its supporting sessions,
  and today none is adopted (spec §0 M0.2, blocker B8-1, ADR-0076).
* **Not a novelty claim.** ``novelty_claim_permitted`` is read from the Stage 0
  prior-art ledger, never set here, and any package that says True fails verification
  this wave (D8.13).
* **Not an ATT&CK mapping.** ``known_technique_mappings`` holds local library ids only
  (``"stage1:ATTACK_EXFIL"``); an external technique id does not construct.
* **Not unmeasured-as-measured.** Every figure that could not be measured is ``None``.
  ``endpoint_incremental_rss_bytes=None`` is UNMEASURED, never "within target".

Construction checks shapes, types, bounds and the content-derived id. The semantic
invariants (hashes recompute, non-empty records, digest formats, selection agreement, no
novelty claim, no authority key) are :func:`verify_package`'s, so a bad package is
*reported* with every problem named; ``()`` is the only passing answer.

Frozen after the Build phase: a shape change needs a new schema ``$id`` and an ADR.
Imports: ``episode.py``, ``genome/*`` and Stage 0 only.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, fields, is_dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from pocketsec.stage0.contracts.common import ContractError, digest_of_bytes, register_schema
from pocketsec.stage8.episode import EPISODE_ID_PATTERN, Split
from pocketsec.stage8.genome.grammar import FEATURE_NAMES, Mechanism, mechanism_from_canonical
from pocketsec.stage8.genome.hypothesis import (
    HYPOTHESIS_ID_PATTERN,
    Direction,
    FalsifierKind,
    HypothesisGenome,
    authority_key_paths,
)

__all__ = [
    "ARTIFACT_HASH_NAMES",
    "DISCOVERY_PACKAGE_V1_ID",
    "DISCOVERY_PACKAGE_V1_VERSION",
    "FAILURE_CONTEXT_PATTERN",
    "MAX_ARTIFACT_DEPTH",
    "MAX_ENTRANTS",
    "MAX_EVIDENCE_EPISODES",
    "MAX_FAILURE_CONDITIONS",
    "MAX_FALSIFICATION_RECORDS",
    "MAX_PACKAGE_EVIDENCE",
    "MAX_PACKAGE_LINEAGE",
    "MAX_REASONS",
    "DiscoveryPackageV1",
    "FailureCondition",
    "FalsificationRecord",
    "IdentifiabilityClass",
    "NoveltyClass",
    "RepresentationKind",
    "RepresentationMeasurement",
    "ReproducibilityRecord",
    "ReproducibilityStatus",
    "ResourceProfile",
    "RobustnessProfile",
    "TournamentResult",
    "artifact_hashes_for",
    "verify_package",
]

DISCOVERY_PACKAGE_V1_ID = "pocketsec.discovery_package.v1"
DISCOVERY_PACKAGE_V1_VERSION = register_schema(DISCOVERY_PACKAGE_V1_ID, "1.0.0")

# §4.21 — chosen parameters, not measurements.
MAX_PACKAGE_LINEAGE = 64
MAX_PACKAGE_EVIDENCE = 32
MAX_FAILURE_CONDITIONS = 16
MAX_ENTRANTS = 8
#: Not in §4.21; bounds this module adds so no tuple field is unbounded. Chosen.
MAX_EVIDENCE_EPISODES = 8  # the adapter's MAX_CAPSULES_PER_PACKAGE
MAX_FALSIFICATION_RECORDS = 16  # ≤ 8 registered rules + the REPLICATION re-runs
MAX_REASONS = 32
MAX_ROBUSTNESS_ROWS = 16
MAX_TECHNIQUE_MAPPINGS = 16
MAX_ARTIFACT_DEPTH = 8
MAX_DETAIL_CHARS = 160

ARTIFACT_HASH_NAMES: tuple[str, ...] = ("mechanism", "artifact", "tournament", "genome")
#: Closed failure-condition codes. ``conservation:`` carries FORGE's §85 conservation
#: failures, which the spec routes into failure conditions without naming a prefix.
FAILURE_CONTEXT_PATTERN = re.compile(
    r"^(?:(?:challenge|doppelganger|dropout|identifiability|conservation):[A-Z][A-Z0-9_]{0,47}"
    r"|independent:fp)$"
)
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_CODE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-]{0,95}$")
_REFUSAL = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_REGISTRATION = re.compile(r"^reg-[0-9a-f]{24}$")
_LINEAGE_NODE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:\-]{0,127}$")
_TECHNIQUE = re.compile(r"^stage[0-9]{1,2}:[A-Z][A-Z0-9_]{0,63}$")


class RepresentationKind(StrEnum):
    TYPED_RULE = "TYPED_RULE"
    MOTIF = "MOTIF"
    FSM = "FSM"
    THRESHOLD = "THRESHOLD"
    LOGISTIC = "LOGISTIC"
    PROTOTYPE = "PROTOTYPE"
    STUMP_TREE = "STUMP_TREE"


class NoveltyClass(StrEnum):
    KNOWN = "KNOWN"
    KNOWN_COMBINATION = "KNOWN_COMBINATION"
    CONTEXT_EXTENSION = "CONTEXT_EXTENSION"
    POTENTIALLY_NOVEL = "POTENTIALLY_NOVEL"


class IdentifiabilityClass(StrEnum):
    IDENTIFIED = "IDENTIFIED"
    EQUIVALENCE_CLASS = "EQUIVALENCE_CLASS"
    UNIDENTIFIABLE = "UNIDENTIFIABLE"


class ReproducibilityStatus(StrEnum):
    REPRODUCED = "REPRODUCED"
    NOT_REPRODUCED = "NOT_REPRODUCED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"


# --- validation helpers --------------------------------------------------------------


def _opt_number(value: object, field: str, upper: float) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ContractError(f"{field} must be a number or None, got {value!r}")
    number = float(value)
    if not math.isfinite(number) or not 0.0 <= number <= upper:
        raise ContractError(f"{field} must be finite and within [0, {upper}], got {value!r}")
    return number


def _opt_unit(value: object, field: str) -> float | None:
    return _opt_number(value, field, 1.0)


def _opt_nonneg(value: object, field: str) -> float | None:
    return _opt_number(value, field, math.inf)


def _opt_count(value: object, field: str, *, signed: bool = False) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or (not signed and value < 0):
        raise ContractError(f"{field} must be an int{'' if signed else ' >= 0'}, got {value!r}")
    return value


def _tuple(value: object, field: str, cap: int) -> tuple[Any, ...]:
    if not isinstance(value, (tuple, list)):
        raise ContractError(f"{field} must be a tuple, got {type(value).__name__}")
    items = tuple(value)
    if len(items) > cap:
        raise ContractError(f"{field} holds {len(items)} items; the cap is {cap}")
    return items


def _strings(value: object, field: str, cap: int, pattern: re.Pattern[str]) -> tuple[str, ...]:
    items = _tuple(value, field, cap)
    for item in items:
        if not isinstance(item, str) or not pattern.fullmatch(item):
            raise ContractError(f"{field} holds a malformed entry {item!r}")
    if len(set(items)) != len(items):
        raise ContractError(f"{field} holds a duplicate")
    return items


def _require(value: object, kind: type, field: str) -> None:
    if not isinstance(value, kind):
        raise ContractError(f"{field} must be a {kind.__name__}, got {type(value).__name__}")


def _require_hypothesis_id(value: object) -> None:
    if not isinstance(value, str) or not HYPOTHESIS_ID_PATTERN.fullmatch(value):
        raise ContractError(f"hypothesis_id is malformed: {value!r}")


def _loadavg(value: object, field: str) -> tuple[float, float, float]:
    items = _tuple(value, field, 3)
    if len(items) != 3 or any(
        isinstance(x, bool) or not isinstance(x, (int, float)) or not math.isfinite(x)
        for x in items
    ):
        raise ContractError(f"{field} must be three finite numbers")
    return (float(items[0]), float(items[1]), float(items[2]))


def _canonical_json(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _freeze_json(value: object, field: str, depth: int = 0) -> Any:
    """A deep, immutable copy of plain JSON data; anything else is refused."""
    if depth > MAX_ARTIFACT_DEPTH:
        raise ContractError(f"{field} nests deeper than {MAX_ARTIFACT_DEPTH}")
    if isinstance(value, float) and not math.isfinite(value):
        raise ContractError(f"{field} holds a non-finite float")
    if value is None or isinstance(value, (bool, str, int, float)):
        return value
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise ContractError(f"{field} keys must be strings")
        return MappingProxyType(
            {key: _freeze_json(item, field, depth + 1) for key, item in value.items()}
        )
    if isinstance(value, (list, tuple)):
        return tuple(_freeze_json(item, field, depth + 1) for item in value)
    raise ContractError(f"{field} must be plain JSON data, got {type(value).__name__}")


def _exact(payload: object, cls: type, name: str) -> Mapping[str, Any]:
    if not isinstance(payload, Mapping):
        raise ContractError(f"{name} payload must be a mapping, got {type(payload).__name__}")
    expected = {item.name for item in fields(cls)}
    missing, extra = sorted(expected - set(payload)), sorted(set(payload) - expected)
    if missing or extra:
        raise ContractError(f"{name} payload missing {missing}, unexpected {extra}")
    return payload


def _enum(kind: type[StrEnum], value: object) -> Any:
    if not isinstance(value, str):
        raise ContractError(f"{kind.__name__} value must be a string, got {value!r}")
    try:
        return kind(value)
    except ValueError:
        raise ContractError(f"{value!r} is not a {kind.__name__}") from None


def _tuples(value: Any) -> Any:
    """JSON lists back to tuples, recursively (mappings are left to their readers)."""
    return tuple(_tuples(item) for item in value) if isinstance(value, list) else value


def _record_from(cls: type, payload: object, **enums: type[StrEnum]) -> Any:
    """Strict reader for a flat record: exact keys, enum fields by value, lists as tuples."""
    data = _exact(payload, cls, cls.__name__)
    return cls(**{key: (None if value is None else _enum(enums[key], value)) if key in enums
                  else _tuples(value) for key, value in data.items()})


def _plain(record: object) -> dict[str, Any]:
    """A dataclass record as plain JSON data: enums by value, tuples as lists."""
    return {item.name: _plain_value(getattr(record, item.name))
            for item in fields(record)}  # type: ignore[arg-type]


def _plain_value(value: Any) -> Any:
    if is_dataclass(value) and not isinstance(value, type):
        return _plain(value)
    if isinstance(value, StrEnum):
        return value.value
    if isinstance(value, Mapping):
        return {key: _plain_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain_value(item) for item in value]
    return value


# --- plain records -------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class FalsificationRecord:
    """One refutation rule's outcome. ``registration_id`` is "" for pre-holdout screens."""

    kind: FalsifierKind
    split: Split
    passed: bool
    statistic: float | None  # p-value, share or agreement, per kind
    parameter: float  # the registered threshold / alpha
    registration_id: str

    def __post_init__(self) -> None:
        _require(self.kind, FalsifierKind, "FalsificationRecord.kind")
        _require(self.split, Split, "FalsificationRecord.split")
        _require(self.passed, bool, "FalsificationRecord.passed")
        object.__setattr__(self, "statistic", _opt_nonneg(self.statistic, "statistic"))
        parameter = _opt_unit(self.parameter, "FalsificationRecord.parameter")
        if parameter is None:
            raise ContractError("FalsificationRecord.parameter is the registered rule; not None")
        object.__setattr__(self, "parameter", parameter)
        if self.registration_id != "" and (
            not isinstance(self.registration_id, str)
            or not _REGISTRATION.fullmatch(self.registration_id)
        ):
            raise ContractError(f"registration_id is '' or reg-<24 hex>: {self.registration_id!r}")

    @classmethod
    def from_dict(cls, payload: object) -> FalsificationRecord:
        return _record_from(cls, payload, kind=FalsifierKind, split=Split)  # type: ignore[no-any-return]


@dataclass(frozen=True, slots=True)
class FailureCondition:
    """Where the theory is known to fail. A package with none has not been challenged."""

    context: str  # closed codes, FAILURE_CONTEXT_PATTERN
    observed_rate: float | None  # recall retained / matched share / FP share
    detail: str  # ≤ 160 printable ASCII chars, a fixed-vocabulary rendering

    def __post_init__(self) -> None:
        if not isinstance(self.context, str) or not FAILURE_CONTEXT_PATTERN.fullmatch(self.context):
            raise ContractError(f"FailureCondition.context is not a closed code: {self.context!r}")
        object.__setattr__(self, "observed_rate", _opt_unit(self.observed_rate, "observed_rate"))
        detail = self.detail
        if (not isinstance(detail, str) or len(detail) > MAX_DETAIL_CHARS or not detail.isascii()
                or not detail.isprintable()):
            raise ContractError(f"detail must be <= {MAX_DETAIL_CHARS} printable ASCII chars")

    @classmethod
    def from_dict(cls, payload: object) -> FailureCondition:
        return _record_from(cls, payload)  # type: ignore[no-any-return]


@dataclass(frozen=True, slots=True)
class ReproducibilityRecord:
    status: ReproducibilityStatus
    replication_precision: float | None
    replication_recall: float | None
    replication_false_positive_rate: float | None
    imbalance_precision: float | None  # at IMBALANCE_RATIO negatives per positive
    independent_false_positive_rate: float | None
    independent_positives_available: bool
    reasons: tuple[str, ...]

    def __post_init__(self) -> None:
        _require(self.status, ReproducibilityStatus, "ReproducibilityRecord.status")
        for name in ("replication_precision", "replication_recall",
                     "replication_false_positive_rate", "imbalance_precision",
                     "independent_false_positive_rate"):
            object.__setattr__(self, name, _opt_unit(getattr(self, name), name))
        _require(self.independent_positives_available, bool, "independent_positives_available")
        object.__setattr__(self, "reasons", _strings(self.reasons, "reasons", MAX_REASONS, _CODE))
        if self.status is ReproducibilityStatus.REPRODUCED and None in (
            self.replication_precision, self.replication_recall,
            self.replication_false_positive_rate,
        ):
            raise ContractError("REPRODUCED needs measured replication precision, recall and FPR")

    @classmethod
    def from_dict(cls, payload: object) -> ReproducibilityRecord:
        return _record_from(cls, payload, status=ReproducibilityStatus)  # type: ignore[no-any-return]


_MEASURED_FIELDS = ("precision", "recall", "false_positive_rate", "pr_auc", "decision_agreement",
                    "work_units_per_event", "artifact_bytes", "wall_ratio_to_reference",
                    "robustness_recall", "interpretability")


@dataclass(frozen=True, slots=True)
class RepresentationMeasurement:
    """One tournament entrant, measured — or refused, with the reason and nothing else."""

    kind: RepresentationKind
    expressible: bool
    refusal: str | None  # e.g. "MOTIF_CANNOT_EXPRESS_REPEATED"; None iff expressible
    precision: float | None
    recall: float | None
    false_positive_rate: float | None
    pr_auc: float | None
    decision_agreement: float | None  # vs the TYPED_RULE reference on the same episodes
    work_units_per_event: float | None
    artifact_bytes: int | None  # len(canonical JSON of the artifact)
    wall_ratio_to_reference: float | None  # within-run ratio; never used to select
    loadavg: tuple[float, float, float]
    robustness_recall: float | None  # min over challenge kinds of recall retained
    interpretability: int | None  # predicate / weight / node count

    def __post_init__(self) -> None:
        _require(self.kind, RepresentationKind, "RepresentationMeasurement.kind")
        _require(self.expressible, bool, "RepresentationMeasurement.expressible")
        if self.expressible != (self.refusal is None):
            raise ContractError("refusal is None exactly when the entrant is expressible")
        if self.refusal is not None and (
            not isinstance(self.refusal, str) or not _REFUSAL.fullmatch(self.refusal)
        ):
            raise ContractError(f"refusal must be an UPPER_SNAKE code, got {self.refusal!r}")
        for name in ("precision", "recall", "false_positive_rate", "pr_auc",
                     "decision_agreement", "robustness_recall"):
            object.__setattr__(self, name, _opt_unit(getattr(self, name), name))
        for name in ("work_units_per_event", "wall_ratio_to_reference"):
            object.__setattr__(self, name, _opt_nonneg(getattr(self, name), name))
        _opt_count(self.artifact_bytes, "artifact_bytes")
        _opt_count(self.interpretability, "interpretability")
        object.__setattr__(self, "loadavg", _loadavg(self.loadavg, "loadavg"))
        if not self.expressible and any(getattr(self, n) is not None for n in _MEASURED_FIELDS):
            # A refused entrant was never compiled; a figure beside it measured nothing.
            raise ContractError(f"{self.kind.value} was refused; it carries no measurement")

    @classmethod
    def from_dict(cls, payload: object) -> RepresentationMeasurement:
        return _record_from(cls, payload, kind=RepresentationKind)  # type: ignore[no-any-return]


@dataclass(frozen=True, slots=True)
class TournamentResult:
    """Every representation FORGE measured for one theory, including refused ones."""

    tournament_id: str  # "tn-" + 24 hex of the content; "" derives
    hypothesis_id: str
    split: Split  # REPLICATION: the one split detection value is measured on
    entrants: tuple[RepresentationMeasurement, ...]
    pareto_front: tuple[RepresentationKind, ...]
    selected: RepresentationKind | None
    deployable: bool
    reasons: tuple[str, ...]
    discovery_work_units: int
    deployed_work_units_per_event: float | None
    compression_ratio: float | None  # DCR = discovery_work_units / deployed_work_units_per_event
    knowledge_bytes_saved: int | None  # research-state bytes - selected artifact bytes
    synthetic_data: bool

    def __post_init__(self) -> None:
        self._check_shape()
        self._check_selection()
        self._check_costs()
        derived = "tn-" + hashlib.sha256(_canonical_json(self._content())).hexdigest()[:24]
        if self.tournament_id == "":
            object.__setattr__(self, "tournament_id", derived)
        elif self.tournament_id != derived:
            raise ContractError(f"tournament_id {self.tournament_id!r} does not match its content")

    def _check_shape(self) -> None:
        _require_hypothesis_id(self.hypothesis_id)
        if self.split is not Split.REPLICATION:
            raise ContractError("a tournament is measured on REPLICATION, the one decisive split")
        entrants = _tuple(self.entrants, "entrants", MAX_ENTRANTS)
        if any(not isinstance(item, RepresentationMeasurement) for item in entrants):
            raise ContractError("entrants must hold RepresentationMeasurement values")
        kinds = [item.kind for item in entrants]
        if len(set(kinds)) != len(kinds):
            raise ContractError("one entrant per RepresentationKind")
        if RepresentationKind.TYPED_RULE not in kinds:
            raise ContractError("TYPED_RULE is the reference; without it nothing is measured")
        object.__setattr__(self, "entrants", entrants)
        object.__setattr__(self, "reasons", _strings(self.reasons, "reasons", MAX_REASONS, _CODE))
        _require(self.deployable, bool, "deployable")
        _require(self.synthetic_data, bool, "synthetic_data")

    def _check_selection(self) -> None:
        front = _tuple(self.pareto_front, "pareto_front", MAX_ENTRANTS)
        expressible = {item.kind for item in self.entrants if item.expressible}
        if any(not isinstance(k, RepresentationKind) or k not in expressible for k in front):
            raise ContractError("the Pareto front holds only expressible entrants")
        if len(set(front)) != len(front):
            raise ContractError("pareto_front holds a duplicate")
        object.__setattr__(self, "pareto_front", front)
        if self.selected is not None and (
            not isinstance(self.selected, RepresentationKind) or self.selected not in front
        ):
            raise ContractError("the selected representation must sit on the Pareto front")
        if self.deployable != (self.selected is not None):
            raise ContractError("deployable exactly when a representation is selected")

    def _check_costs(self) -> None:
        _opt_count(self.discovery_work_units, "discovery_work_units")
        if self.discovery_work_units is None:
            raise ContractError("discovery_work_units is counted, never None")
        deployed = _opt_nonneg(self.deployed_work_units_per_event, "deployed_work_units_per_event")
        ratio = _opt_nonneg(self.compression_ratio, "compression_ratio")
        object.__setattr__(self, "deployed_work_units_per_event", deployed)
        object.__setattr__(self, "compression_ratio", ratio)
        _opt_count(self.knowledge_bytes_saved, "knowledge_bytes_saved", signed=True)
        if self.selected is None and (deployed is not None or ratio is not None):
            raise ContractError("nothing deployed: deployed cost and DCR are None")
        if self.selected is not None:
            chosen = next(item for item in self.entrants if item.kind is self.selected)
            if deployed != chosen.work_units_per_event:
                raise ContractError("deployed cost must be the selected entrant's measured cost")
        if ratio is not None:
            if not deployed:
                raise ContractError("a DCR needs a positive deployed cost")
            if not math.isclose(ratio, self.discovery_work_units / deployed, rel_tol=1e-9):
                raise ContractError("compression_ratio must equal discovery / deployed work units")

    def _content(self) -> dict[str, Any]:
        out = _plain(self)
        del out["tournament_id"]
        return out

    def to_dict(self) -> dict[str, Any]:
        return _plain(self)

    @classmethod
    def from_dict(cls, payload: object) -> TournamentResult:
        data = dict(_exact(payload, cls, "TournamentResult"))
        data["entrants"] = tuple(RepresentationMeasurement.from_dict(item)
                                 for item in _tuple(data["entrants"], "entrants", MAX_ENTRANTS))
        data["pareto_front"] = tuple(_enum(RepresentationKind, kind) for kind in
                                     _tuple(data["pareto_front"], "pareto_front", MAX_ENTRANTS))
        return _record_from(cls, data, split=Split, selected=RepresentationKind)  # type: ignore[no-any-return]


@dataclass(frozen=True, slots=True)
class ResourceProfile:
    artifact_bytes: int | None
    work_units_per_event: float | None
    endpoint_incremental_rss_bytes: int | None  # None = UNMEASURED
    loadavg: tuple[float, float, float]

    def __post_init__(self) -> None:
        _opt_count(self.artifact_bytes, "artifact_bytes")
        object.__setattr__(self, "work_units_per_event",
                           _opt_nonneg(self.work_units_per_event, "work_units_per_event"))
        _opt_count(self.endpoint_incremental_rss_bytes, "endpoint_incremental_rss_bytes")
        object.__setattr__(self, "loadavg", _loadavg(self.loadavg, "loadavg"))

    @classmethod
    def from_dict(cls, payload: object) -> ResourceProfile:
        return _record_from(cls, payload)  # type: ignore[no-any-return]


def _pairs(value: object, field: str, *, allow_none: bool) -> tuple[tuple[str, float | None], ...]:
    rows = _tuple(value, field, MAX_ROBUSTNESS_ROWS)
    out: list[tuple[str, float | None]] = []
    for row in rows:
        if not isinstance(row, (tuple, list)) or len(row) != 2 or not isinstance(row[0], str):
            raise ContractError(f"{field} rows are (code, rate) pairs")
        if not _REFUSAL.fullmatch(row[0]):
            raise ContractError(f"{field} code must be an UPPER_SNAKE enum value, got {row[0]!r}")
        rate = _opt_unit(row[1], field)
        if rate is None and not allow_none:
            raise ContractError(f"{field} rates are measured shares, never None")
        out.append((row[0], rate))
    if len({code for code, _ in out}) != len(out):
        raise ContractError(f"{field} names a code twice")
    return tuple(out)


@dataclass(frozen=True, slots=True)
class RobustnessProfile:
    recall_retained: tuple[tuple[str, float | None], ...]  # (ChallengeKind value, rate)
    doppelganger_matched_share: tuple[tuple[str, float], ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "recall_retained",
                           _pairs(self.recall_retained, "recall_retained", allow_none=True))
        object.__setattr__(self, "doppelganger_matched_share", _pairs(
            self.doppelganger_matched_share, "doppelganger_matched_share", allow_none=False))

    @classmethod
    def from_dict(cls, payload: object) -> RobustnessProfile:
        return _record_from(cls, payload)  # type: ignore[no-any-return]


# --- the package ---------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DiscoveryPackageV1:
    """The typed candidate a surviving theory leaves Stage 8 as. Never authority."""

    package_id: str  # "dp-" + sha256(canonical minus id)[:24]; "" derives
    hypothesis_id: str
    mechanism: Mechanism
    direction: Direction
    required_features: tuple[str, ...]  # feature_names() entries the selected detector reads
    detector_candidates: TournamentResult
    selected_representation: RepresentationKind | None
    compiled_artifact: Mapping[str, Any] | None  # plain JSON data of the selected detector
    evidence_lineage: tuple[str, ...]  # lineage node ids root → package, ≤ MAX_PACKAGE_LINEAGE
    evidence_digests: tuple[str, ...]  # sha256: of supporting episodes' evidence, ≤ 32
    evidence_episode_ids: tuple[str, ...]  # REPLICATION true matches, ≤ 8 (the adapter's input)
    falsification_results: tuple[FalsificationRecord, ...]  # every registered falsifier
    failure_conditions: tuple[FailureCondition, ...]  # NON-EMPTY, ≤ MAX_FAILURE_CONDITIONS
    resource_profile: ResourceProfile
    robustness_profile: RobustnessProfile
    known_technique_mappings: tuple[str, ...]  # local library ids only; never ATT&CK ids
    novelty_classification: NoveltyClass
    novelty_claim_permitted: bool  # always False this wave (D8.13)
    identifiability: IdentifiabilityClass
    reproducibility: ReproducibilityRecord
    artifact_hashes: tuple[tuple[str, str], ...]  # (name, sha256:…)
    synthetic_data: bool
    schema_version: str = DISCOVERY_PACKAGE_V1_VERSION

    def __post_init__(self) -> None:
        self._check_parts()
        self._check_evidence()
        self._check_records()
        if self.schema_version != DISCOVERY_PACKAGE_V1_VERSION:
            raise ContractError(f"schema_version must be {DISCOVERY_PACKAGE_V1_VERSION}")
        derived = "dp-" + hashlib.sha256(_canonical_json(self._content())).hexdigest()[:24]
        if self.package_id == "":
            object.__setattr__(self, "package_id", derived)
        elif self.package_id != derived:
            raise ContractError(f"package_id {self.package_id!r} does not match its content")

    def _check_parts(self) -> None:
        _require_hypothesis_id(self.hypothesis_id)
        for name, kind in (("mechanism", Mechanism), ("direction", Direction),
                           ("detector_candidates", TournamentResult),
                           ("resource_profile", ResourceProfile),
                           ("robustness_profile", RobustnessProfile),
                           ("novelty_classification", NoveltyClass),
                           ("identifiability", IdentifiabilityClass),
                           ("reproducibility", ReproducibilityRecord),
                           ("novelty_claim_permitted", bool), ("synthetic_data", bool)):
            _require(getattr(self, name), kind, f"DiscoveryPackageV1.{name}")
        if self.selected_representation is not None:
            _require(self.selected_representation, RepresentationKind, "selected_representation")
        features = _strings(self.required_features, "required_features", len(FEATURE_NAMES),
                            re.compile(r"^.{1,64}$"))
        unknown = [name for name in features if name not in FEATURE_NAMES]
        if unknown:
            raise ContractError(f"required_features names no encoder slot: {unknown[0]!r}")
        object.__setattr__(self, "required_features", features)
        if self.compiled_artifact is not None:
            if not isinstance(self.compiled_artifact, Mapping):
                raise ContractError("compiled_artifact must be a mapping of plain JSON data")
            object.__setattr__(self, "compiled_artifact",
                               _freeze_json(self.compiled_artifact, "compiled_artifact"))

    def _check_evidence(self) -> None:
        object.__setattr__(self, "evidence_lineage", _strings(
            self.evidence_lineage, "evidence_lineage", MAX_PACKAGE_LINEAGE, _LINEAGE_NODE))
        # Digest *format* is verify_package's to report; construction bounds and types.
        digests = _tuple(self.evidence_digests, "evidence_digests", MAX_PACKAGE_EVIDENCE)
        if any(not isinstance(item, str) for item in digests) or len(set(digests)) != len(digests):
            raise ContractError("evidence_digests must be distinct strings")
        object.__setattr__(self, "evidence_digests", digests)
        object.__setattr__(self, "evidence_episode_ids", _strings(
            self.evidence_episode_ids, "evidence_episode_ids", MAX_EVIDENCE_EPISODES,
            EPISODE_ID_PATTERN))
        object.__setattr__(self, "known_technique_mappings", _strings(
            self.known_technique_mappings, "known_technique_mappings", MAX_TECHNIQUE_MAPPINGS,
            _TECHNIQUE))

    def _check_records(self) -> None:
        results = _tuple(self.falsification_results, "falsification_results",
                         MAX_FALSIFICATION_RECORDS)
        if any(not isinstance(item, FalsificationRecord) for item in results):
            raise ContractError("falsification_results must hold FalsificationRecord values")
        object.__setattr__(self, "falsification_results", results)
        conditions = _tuple(self.failure_conditions, "failure_conditions", MAX_FAILURE_CONDITIONS)
        if any(not isinstance(item, FailureCondition) for item in conditions):
            raise ContractError("failure_conditions must hold FailureCondition values")
        object.__setattr__(self, "failure_conditions", conditions)
        hashes = _tuple(self.artifact_hashes, "artifact_hashes", len(ARTIFACT_HASH_NAMES))
        rows: list[tuple[str, str]] = []
        for row in hashes:
            if (not isinstance(row, (tuple, list)) or len(row) != 2
                    or row[0] not in ARTIFACT_HASH_NAMES or not isinstance(row[1], str)):
                raise ContractError("artifact_hashes rows are (hash name, digest)")
            rows.append((row[0], row[1]))
        if len({name for name, _ in rows}) != len(rows):
            raise ContractError("artifact_hashes names one artifact twice")
        object.__setattr__(self, "artifact_hashes", tuple(rows))

    def _content(self) -> dict[str, Any]:
        out = self.to_dict()
        del out["package_id"]
        return out

    def to_dict(self) -> dict[str, Any]:
        out = _plain(self)
        out["mechanism"] = self.mechanism.canonical()
        return out

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> DiscoveryPackageV1:
        """Strict: exact keys, no authority key at any depth, and the id must match."""
        found = authority_key_paths(payload)
        if found:
            raise ContractError(f"authority keys refused in a discovery package: {list(found)[:4]}")
        data = dict(_exact(payload, cls, "DiscoveryPackageV1"))
        data["mechanism"] = mechanism_from_canonical(data["mechanism"])
        data["detector_candidates"] = TournamentResult.from_dict(data["detector_candidates"])
        for name, reader, cap in (
            ("falsification_results", FalsificationRecord.from_dict, MAX_FALSIFICATION_RECORDS),
            ("failure_conditions", FailureCondition.from_dict, MAX_FAILURE_CONDITIONS),
        ):
            data[name] = tuple(reader(row) for row in _tuple(data[name], name, cap))
        data["resource_profile"] = ResourceProfile.from_dict(data["resource_profile"])
        data["robustness_profile"] = RobustnessProfile.from_dict(data["robustness_profile"])
        data["reproducibility"] = ReproducibilityRecord.from_dict(data["reproducibility"])
        return _record_from(  # type: ignore[no-any-return]
            cls, data, direction=Direction, selected_representation=RepresentationKind,
            novelty_classification=NoveltyClass, identifiability=IdentifiabilityClass,
        )


# --- hashes and verification ---------------------------------------------------------


def _artifact_digest(artifact: Mapping[str, Any]) -> str:
    frozen = _freeze_json(artifact, "compiled_artifact")  # refuse before hashing
    return digest_of_bytes(_canonical_json(_plain_value(frozen)))


def artifact_hashes_for(
    *, mechanism: Mechanism, tournament: TournamentResult,
    compiled_artifact: Mapping[str, Any] | None, genome: HypothesisGenome,
) -> tuple[tuple[str, str], ...]:
    """The ``artifact_hashes`` a package must carry, computed the way verification does.

    ``"genome"`` is the genome's own ``digest()``; the package does not carry the genome,
    so :func:`verify_package` checks it against ``hypothesis_id``, which is that digest's
    first 24 hex by construction.
    """
    rows = [("mechanism", digest_of_bytes(mechanism.canonical_bytes()))]
    if compiled_artifact is not None:
        rows.append(("artifact", _artifact_digest(compiled_artifact)))
    rows.append(("tournament", digest_of_bytes(_canonical_json(tournament.to_dict()))))
    rows.append(("genome", genome.digest()))
    return tuple(rows)


def _hash_problems(package: DiscoveryPackageV1) -> list[str]:
    problems: list[str] = []
    hashes = dict(package.artifact_hashes)
    expected: dict[str, str] = {
        "mechanism": digest_of_bytes(package.mechanism.canonical_bytes()),
        "tournament": digest_of_bytes(_canonical_json(package.detector_candidates.to_dict())),
    }
    if package.compiled_artifact is not None:
        expected["artifact"] = _artifact_digest(package.compiled_artifact)
    elif "artifact" in hashes:
        problems.append("artifact hash present but no compiled_artifact")
    for name, digest in expected.items():
        if name not in hashes:
            problems.append(f"artifact hash missing: {name}")
        elif hashes[name] != digest:
            problems.append(f"artifact hash does not recompute: {name}")
    genome = hashes.get("genome")
    if genome is None:
        problems.append("artifact hash missing: genome")
    elif _DIGEST.fullmatch(genome) and "hyp-" + genome[7:31] != package.hypothesis_id:
        problems.append("genome hash does not match hypothesis_id")
    for name, digest in package.artifact_hashes:
        if not _DIGEST.fullmatch(digest):
            problems.append(f"artifact hash is not sha256: {name}")
    return problems


def verify_package(package: DiscoveryPackageV1) -> tuple[str, ...]:
    """Every problem with ``package``; ``()`` is the only passing answer."""
    if not isinstance(package, DiscoveryPackageV1):
        return (f"not a DiscoveryPackageV1: {type(package).__name__}",)
    problems = _hash_problems(package)
    tournament = package.detector_candidates
    if not package.failure_conditions:
        problems.append("failure_conditions is empty: the theory was never challenged")
    if not package.falsification_results:
        problems.append("falsification_results is empty")
    if package.reproducibility.status is ReproducibilityStatus.REPRODUCED and any(
            r.kind is FalsifierKind.REPLICATION and not r.passed
            for r in package.falsification_results):
        # S8-AUTH-01: a package cannot claim REPRODUCED beside its own failed replication.
        problems.append("status REPRODUCED contradicts a failed REPLICATION record")
    if not package.evidence_lineage:
        problems.append("evidence_lineage is empty")
    problems.extend(f"evidence digest is not sha256: {d!r}"
                    for d in package.evidence_digests if not _DIGEST.fullmatch(d))
    if package.selected_representation != tournament.selected:
        problems.append("selected_representation disagrees with detector_candidates.selected")
    if (package.compiled_artifact is None) != (package.selected_representation is None):
        problems.append("compiled_artifact is present exactly when a representation is selected")
    if package.hypothesis_id != tournament.hypothesis_id:
        problems.append("the tournament measured another hypothesis")
    if package.synthetic_data != tournament.synthetic_data:
        problems.append("synthetic_data disagrees with the tournament's")
    missing = set(RepresentationKind) - {item.kind for item in tournament.entrants}
    if missing:
        problems.append(f"tournament entrants missing: {sorted(k.value for k in missing)}")
    if package.novelty_claim_permitted:
        problems.append("novelty_claim_permitted is True: no prior-art review permits it")
    problems.extend(f"authority key: {path}" for path in authority_key_paths(package.to_dict()))
    return tuple(problems)
