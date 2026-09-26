"""D9.15 (ONTO-F15) — the Homeostatic Runtime: which validated phenotype runs under which budget.

Architecture §39-§40 and §55-§57 ask for resource management as a closed loop: when memory,
CPU or queue headroom shrinks, the endpoint steps down through cognitive regimes, and it must
*say what it shed* instead of silently pretending full coverage. This module is that loop and
nothing more:

* :class:`Regime` has exactly four members, ``ADAPTIVE > REDUCED > REFLEX > SURVIVAL``. The
  Ω-research regime ("offline Stage 8/9 only") is **not representable**: no enum member exists,
  so no observation, failure or catalog can put the endpoint in research. Ω-deep is absent too.
* :class:`PhenotypeCatalog` holds at most one *pre-validated* genome per regime, each refused
  unless its static work units and state bytes fit that regime's cap. The catalog is built from
  held-out fitness records (:func:`build_catalog`); nothing here searches, mutates or compiles.
* :func:`survival_entry` is the Φ-oracle genome — zero parameters, 3 WU/event — and it is the
  floor that can never be isolated. ``HomeostaticController(None)`` runs it alone, so the
  endpoint stays useful with every Stage 7-9 artefact absent (G9.10(c)).
* Every :class:`RegimeDecision` below ``ADAPTIVE`` carries a :class:`CoverageVector`, the
  dimensions lost against ``ADAPTIVE`` and an ``uncertainty_penalty`` = held-out worst-case AP
  of the ``ADAPTIVE`` entry minus this entry's, ``None`` when either is unmeasured (G9.5).
* :meth:`HomeostaticController.report_failure` is architecture §57's self-repair, limited to
  *substitution among pre-validated components*: a failed regime's phenotype is isolated and the
  next lower validated one runs. The canary/monitor/rollback half of §57 is NOT BUILT.

What it refuses to do. Coverage is a **static input-read** statement (``STATIC_INPUT_READ``),
never measured recall, and a lower bound: ``relation_onehot`` slots are not credited (the
relation->family map is outside the spec §2.3 allow-list), and :data:`UNCREDITED_INPUTS` map
to no dimension. The resource traces are SIMULATED and labelled so on every decision; nothing
here reads a real host's memory. Hysteresis ships off until :func:`compare_hysteresis` returns
JUSTIFIED and the integrator cites it.

This module is endpoint-side, so it imports no ``ontogenesis.search``, laws or physics module.
"""

from __future__ import annotations

import math
import random
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.ssir.relations import RelationFamily
from pocketsec.stage1.state.security_state import DIMENSIONS
from pocketsec.stage2.encoder.ssir_encoder import FEATURE_WIDTH, GROUP_OFFSETS
from pocketsec.stage9.chemistry.typed_ir import InputSource
from pocketsec.stage9.genome.computational import ComputationalGenomeV1
from pocketsec.stage9.genome.expressibility import phi_oracle_genome
from pocketsec.stage9.ontogenesis.fitness import FitnessRecord
from pocketsec.stage9.spec.mssc import DetectorComparison, MechanismVerdict

__all__ = [
    "COVERAGE_BASIS",
    "COVERAGE_DIMENSIONS",
    "CPU_PRESSURE_FRACTION",
    "HYSTERESIS_DEFAULT_ENABLED",
    "HYSTERESIS_MARGIN",
    "HYSTERESIS_STEPS",
    "MAX_DECISION_HISTORY",
    "OBSERVATION_BASES",
    "QUEUE_PRESSURE_DEPTH",
    "REGIME_BUDGET_BYTES",
    "REGIME_ORDER",
    "REGIME_WU_CAP",
    "UNCREDITED_INPUTS",
    "CoverageVector",
    "HomeostaticController",
    "PhenotypeCatalog",
    "PhenotypeEntry",
    "Regime",
    "RegimeDecision",
    "ResourceObservation",
    "build_catalog",
    "compare_hysteresis",
    "coverage_of",
    "degradation_trace",
    "drive",
    "pressure_trace",
    "self_repair_substitutions",
    "survival_entry",
    "synthetic_resource_trace",
]

#: Off until :func:`compare_hysteresis` returns JUSTIFIED and the integrator cites it (§4.22).
HYSTERESIS_DEFAULT_ENABLED: bool = False
#: Consecutive supporting steps before a move *up* (chosen, spec §4.19).
HYSTERESIS_STEPS = 5
#: A move up needs ``available >= budget * (1 + margin)`` on every one of those steps (chosen).
HYSTERESIS_MARGIN = 0.10
#: The controller's decision history is a bounded ring; older decisions are evicted and counted.
MAX_DECISION_HISTORY = 256
#: A CPU window this busy demotes the target one regime (chosen, not measured).
CPU_PRESSURE_FRACTION = 0.90
#: A queue this deep demotes the target one regime: half of the IR's per-session event bound
#: ``MAX_SESSION_EVENTS`` = 4096 (chosen, not measured).
QUEUE_PRESSURE_DEPTH = 2048
#: What a coverage figure means. It is never measured recall.
COVERAGE_BASIS = "STATIC_INPUT_READ"
#: The only provenance labels an observation may carry.
OBSERVATION_BASES: frozenset[str] = frozenset({"SIMULATED", "MEASURED"})

_MIB = 1024 * 1024


class Regime(StrEnum):
    """Architecture §40's regimes that exist on an endpoint. There is no research member."""

    ADAPTIVE = "ADAPTIVE"
    REDUCED = "REDUCED"
    REFLEX = "REFLEX"
    SURVIVAL = "SURVIVAL"


#: Highest to lowest. "Lower" always means a later position here.
REGIME_ORDER: tuple[Regime, ...] = (Regime.ADAPTIVE, Regime.REDUCED, Regime.REFLEX, Regime.SURVIVAL)
_RANK: Mapping[Regime, int] = MappingProxyType({r: i for i, r in enumerate(REGIME_ORDER)})

#: Architecture §55: 600 MB full, 250 MB reduced, 100 MB motifs/FSM, 40 MB critical reflex.
REGIME_BUDGET_BYTES: Mapping[Regime, int] = MappingProxyType(
    dict(zip(REGIME_ORDER, (600 * _MIB, 250 * _MIB, 100 * _MIB, 40 * _MIB), strict=True))
)
#: Static update work units per event a regime's phenotype may cost (chosen, spec §4.21).
REGIME_WU_CAP: Mapping[Regime, int] = MappingProxyType(
    {Regime.ADAPTIVE: 64, Regime.REDUCED: 16, Regime.REFLEX: 8, Regime.SURVIVAL: 4}
)

COVERAGE_DIMENSIONS: tuple[str, ...] = (
    "process", "auth", "persistence", "network", "file", "temporal", "semantic"
)

# --- the static input -> coverage-channel map -------------------------------------------------

#: Each Stage 1 state dimension, credited to one coverage dimension (spec §4.19).
_STATE_DIMENSION_COVERAGE: Mapping[str, str] = MappingProxyType(
    {"privilege": "process", "execution": "process", "trust": "auth", "credential": "auth",
     "isolation": "auth", "persistence": "persistence", "reachability": "network",
     "modification": "file", "discovery": "file"}
)  # fmt: skip
#: Each relation family, credited to one coverage dimension (spec §4.19).
_FAMILY_COVERAGE: Mapping[RelationFamily, str] = MappingProxyType(
    {RelationFamily.EXECUTION: "process", RelationFamily.LOADING: "process",
     RelationFamily.CONTROL: "process", RelationFamily.FILESYSTEM: "file",
     RelationFamily.NETWORK: "network", RelationFamily.IDENTITY: "auth",
     RelationFamily.AUTHORIZATION: "auth", RelationFamily.PACKAGING: "persistence"}
)  # fmt: skip
# An upstream dimension or family added without a coverage home would be silently uncredited.
if set(DIMENSIONS) != set(_STATE_DIMENSION_COVERAGE) or set(RelationFamily) != set(
    _FAMILY_COVERAGE
):
    raise ContractError(
        "coverage map is out of step with Stage 1: every DIMENSIONS entry and every "
        "RelationFamily member needs a coverage dimension"
    )

#: Inputs that map to no coverage dimension — the reasons the vector is a lower bound.
UNCREDITED_INPUTS: tuple[str, ...] = (
    "FEATURE relation_onehot slots (relation->family map is outside the Stage 9 allow-list)",
    "FEATURE novelty_tensor / novelty_scalars / uncertainty / causal / representation_level",
    "EPOCH_ID",
    "LINEAGE_FIRST_EVENT",
)

Channel = tuple[str, str]


def _group_ranges() -> Mapping[str, range]:
    """Feature group -> its slot range, derived from ``GROUP_OFFSETS`` (never hard-coded)."""
    ordered = sorted(GROUP_OFFSETS.items(), key=lambda item: item[1])
    ends = [offset for _, offset in ordered[1:]] + [FEATURE_WIDTH]
    return MappingProxyType(
        {group: range(start, end) for (group, start), end in zip(ordered, ends, strict=True)}
    )


_GROUP_RANGES: Mapping[str, range] = _group_ranges()
_STATE_NAMES: tuple[str, ...] = tuple(DIMENSIONS)
_ALL_STATE: frozenset[Channel] = frozenset(("state", name) for name in _STATE_NAMES)
_ALL_FAMILIES: frozenset[Channel] = frozenset(("family", f.name) for f in RelationFamily)


#: Feature groups whose every slot is its own channel: group -> (coverage dimension, prefix).
_SLOT_GROUPS: Mapping[str, tuple[str, str]] = MappingProxyType(
    {"temporal": ("temporal", "slot"), "actor_semantics": ("semantic", "actor"),
     "object_semantics": ("semantic", "object")}
)  # fmt: skip


def _slot_channels(group: str) -> frozenset[Channel]:
    dim, prefix = _SLOT_GROUPS[group]
    return frozenset((dim, f"{prefix}{k}") for k in range(len(_GROUP_RANGES[group])))


_OBJECT_CHANNELS = _slot_channels("object_semantics")
_ACTOR_CHANNELS = _slot_channels("actor_semantics")
_TEMPORAL_CHANNELS = _slot_channels("temporal") | {("temporal", "time_bucket")}


def _universe() -> Mapping[str, frozenset[Channel]]:
    """Every channel that counts toward each coverage dimension."""
    buckets: dict[str, set[Channel]] = {dim: set() for dim in COVERAGE_DIMENSIONS}
    for name, dim in _STATE_DIMENSION_COVERAGE.items():
        buckets[dim].add(("state", name))
    for family, dim in _FAMILY_COVERAGE.items():
        buckets[dim].add(("family", family.name))
    buckets["temporal"].update(_TEMPORAL_CHANNELS)
    buckets["semantic"].update(_ACTOR_CHANNELS | _OBJECT_CHANNELS)
    return MappingProxyType({dim: frozenset(chs) for dim, chs in buckets.items()})


_UNIVERSE: Mapping[str, frozenset[Channel]] = _universe()


def _feature_channels(index: int) -> frozenset[Channel]:
    """The coverage channels one ``FEATURE[index]`` slot carries."""
    for group, slots in _GROUP_RANGES.items():
        if index not in slots:
            continue
        position = index - slots.start
        if group in ("delta_phi", "state_delta_scalars"):
            return _ALL_STATE  # ΔΦ and the delta magnitude are functions of all 9 dimensions
        if group == "state_delta_raised":
            return frozenset({("state", _STATE_NAMES[position])})
        if group == "relation_family_onehot":
            return frozenset({("family", RelationFamily(position).name)})
        if group in _SLOT_GROUPS:
            dim, prefix = _SLOT_GROUPS[group]
            return frozenset({(dim, f"{prefix}{position}")})
        return frozenset()
    return frozenset()


def _input_channels(source: InputSource, index: int) -> frozenset[Channel]:
    if source is InputSource.FEATURE:
        return _feature_channels(index)
    if source in (InputSource.DELTA_PHI, InputSource.STATE_DELTA_MASK):
        return _ALL_STATE
    if source in (InputSource.RELATION, InputSource.RELATION_FAMILY):
        return _ALL_FAMILIES
    if source is InputSource.TIME_BUCKET:
        return frozenset({("temporal", "time_bucket")})
    if source is InputSource.OBJECT_PROPERTY_MASK:
        return _OBJECT_CHANNELS
    return frozenset()  # EPOCH_ID, LINEAGE_FIRST_EVENT: see UNCREDITED_INPUTS


@dataclass(frozen=True, slots=True)
class CoverageVector:
    """Architecture §56's seven dimensions: the fraction of each dimension's channels read."""

    process: float
    auth: float
    persistence: float
    network: float
    file: float
    temporal: float
    semantic: float
    basis: str = COVERAGE_BASIS

    def __post_init__(self) -> None:
        for dim in COVERAGE_DIMENSIONS:
            value = getattr(self, dim)
            if not isinstance(value, float) or not 0.0 <= value <= 1.0:
                raise ContractError(f"coverage {dim} must be a float in [0, 1], got {value!r}")
        if self.basis != COVERAGE_BASIS:
            raise ContractError(f"coverage basis must be {COVERAGE_BASIS!r}, never measured recall")

    def as_tuple(self) -> tuple[tuple[str, float], ...]:
        return tuple((dim, float(getattr(self, dim))) for dim in COVERAGE_DIMENSIONS)


def coverage_of(genome: ComputationalGenomeV1) -> CoverageVector:
    """Static coverage of ``genome``: which dimensions its observation map can see at all."""
    read: set[Channel] = set()
    for source, index in genome.observation_map:
        read |= _input_channels(source, index)
    f = {dim: len(read & _UNIVERSE[dim]) / len(_UNIVERSE[dim]) for dim in COVERAGE_DIMENSIONS}
    return CoverageVector(
        process=f["process"], auth=f["auth"], persistence=f["persistence"],
        network=f["network"], file=f["file"], temporal=f["temporal"], semantic=f["semantic"],
    )  # fmt: skip


# --- the catalog ------------------------------------------------------------------------------


def _check_ap(value: float | None, name: str) -> None:
    if value is None:
        return
    if not isinstance(value, float) or not math.isfinite(value) or not 0.0 <= value <= 1.0:
        raise ContractError(f"{name} must be None or a float in [0, 1], got {value!r}")


@dataclass(frozen=True, slots=True)
class PhenotypeEntry:
    """One pre-validated genome admitted to one regime; its cost figures are its static bounds."""

    regime: Regime
    genome: ComputationalGenomeV1
    heldout_worst_case_ap: float | None
    wu_per_event: int
    state_bytes: int
    coverage: CoverageVector

    def __post_init__(self) -> None:
        if not isinstance(self.regime, Regime):
            raise ContractError(f"regime must be a Regime, got {self.regime!r}")
        if not isinstance(self.genome, ComputationalGenomeV1):
            raise ContractError("a catalog entry holds a constructed (validated) genome")
        _check_ap(self.heldout_worst_case_ap, "heldout_worst_case_ap")
        bounds = self.genome.bounds
        # The figures are copies of the static bounds; a caller cannot understate them.
        if self.wu_per_event != bounds.update_wu_per_event:
            raise ContractError("wu_per_event must equal the genome's static update WU")
        if self.state_bytes != bounds.session_state_bytes_max:
            raise ContractError("state_bytes must equal the genome's static session bound")
        if self.coverage != coverage_of(self.genome):
            raise ContractError("coverage must be coverage_of(genome)")
        if self.wu_per_event > REGIME_WU_CAP[self.regime]:
            raise ContractError(
                f"{self.regime} caps update WU at {REGIME_WU_CAP[self.regime]}, "
                f"genome needs {self.wu_per_event}"
            )
        if self.state_bytes > REGIME_BUDGET_BYTES[self.regime]:
            raise ContractError(f"genome state exceeds the {self.regime} byte budget")


def _entry(regime: Regime, genome: ComputationalGenomeV1, ap: float | None) -> PhenotypeEntry:
    bounds = genome.bounds
    return PhenotypeEntry(
        regime=regime, genome=genome, heldout_worst_case_ap=ap,
        wu_per_event=bounds.update_wu_per_event, state_bytes=bounds.session_state_bytes_max,
        coverage=coverage_of(genome),
    )  # fmt: skip


@dataclass(frozen=True, slots=True)
class PhenotypeCatalog:
    """At most one validated phenotype per regime. A missing regime falls to the next lower."""

    entries: tuple[PhenotypeEntry, ...]

    def __post_init__(self) -> None:
        regimes = [entry.regime for entry in self.entries]
        if len(regimes) != len(set(regimes)):
            raise ContractError("a catalog holds at most one entry per regime")

    def for_regime(self, regime: Regime) -> PhenotypeEntry | None:
        for entry in self.entries:
            if entry.regime is regime:
                return entry
        return None


def survival_entry(heldout_worst_case_ap: float | None = None) -> PhenotypeEntry:
    """The Φ-oracle genome in ``SURVIVAL``: zero parameters, always available, never isolated."""
    return _entry(Regime.SURVIVAL, phi_oracle_genome(), heldout_worst_case_ap)


def _pick(
    pool: Sequence[tuple[ComputationalGenomeV1, FitnessRecord]], regime: Regime
) -> tuple[ComputationalGenomeV1, float] | None:
    """Best measured held-out worst-case AP within the regime's caps; cheaper wins a tie."""
    best: tuple[tuple[float, int, int, str], ComputationalGenomeV1, float] | None = None
    for genome, record in pool:
        ap, bounds = record.worst_case_ap, genome.bounds
        if ap is None or bounds.update_wu_per_event > REGIME_WU_CAP[regime]:
            continue
        if bounds.session_state_bytes_max > REGIME_BUDGET_BYTES[regime]:
            continue
        key = (-ap, bounds.update_wu_per_event, bounds.session_state_bytes_max, genome.digest)
        if best is None or key < best[0]:
            best = (key, genome, ap)
    return None if best is None else (best[1], best[2])


def build_catalog(
    pareto: Sequence[tuple[ComputationalGenomeV1, FitnessRecord]],
) -> PhenotypeCatalog:
    """One entry per regime from HELD-OUT records; ``SURVIVAL`` is always the Φ-oracle.

    Pass the Φ-oracle's own held-out record in ``pareto`` to measure the ``SURVIVAL`` entry's
    AP; without it that AP, and every penalty against it, stays ``None`` (UNMEASURED).
    """
    for genome, record in pareto:
        if record.genome_digest != genome.digest:
            raise ContractError(
                f"record {record.genome_digest[:19]} is not the record of genome "
                f"{genome.digest[:19]}"
            )
    entries: list[PhenotypeEntry] = []
    for regime in REGIME_ORDER[:-1]:
        picked = _pick(pareto, regime)
        if picked is not None:
            entries.append(_entry(regime, picked[0], picked[1]))
    floor_digest = phi_oracle_genome().digest
    floor_ap = next(
        (rec.worst_case_ap for gen, rec in pareto if gen.digest == floor_digest), None
    )
    entries.append(survival_entry(floor_ap))
    return PhenotypeCatalog(entries=tuple(entries))


# --- observations and decisions ----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ResourceObservation:
    """One control-loop sample. ``basis`` says whether it was measured or simulated.

    ``cpu_share`` is the spec's ``cpu_fraction``, renamed: "fr*action*" holds a forbidden
    authority fragment (spec §2.2), and the boundary check refuses it.
    """

    available_bytes: int
    cpu_share: float
    queue_depth: int
    basis: str = "MEASURED"

    def __post_init__(self) -> None:
        if isinstance(self.available_bytes, bool) or not isinstance(self.available_bytes, int):
            raise ContractError("available_bytes must be an int")
        if self.available_bytes < 0:
            raise ContractError("available_bytes must be >= 0")
        cpu = self.cpu_share
        if not isinstance(cpu, float) or not math.isfinite(cpu) or not 0.0 <= cpu <= 1.0:
            raise ContractError(f"cpu_share must be a float in [0, 1], got {cpu!r}")
        if isinstance(self.queue_depth, bool) or not isinstance(self.queue_depth, int):
            raise ContractError("queue_depth must be an int")
        if self.queue_depth < 0:
            raise ContractError("queue_depth must be >= 0")
        if self.basis not in OBSERVATION_BASES:
            raise ContractError(f"basis must be one of {sorted(OBSERVATION_BASES)}")


@dataclass(frozen=True, slots=True)
class RegimeDecision:
    """What ran at one control step, and what that choice cost in coverage and confidence."""

    step: int
    regime: Regime
    phenotype_digest: str
    coverage: CoverageVector
    lost: tuple[str, ...]
    uncertainty_penalty: float | None
    transitioned: bool
    substituted: bool
    #: The observation's basis, or ``"FAILURE_REPORT"`` for a self-repair decision.
    basis: str = "SIMULATED"
    genome_digest: str = ""


def _lost(reference: PhenotypeEntry | None, current: CoverageVector) -> tuple[str, ...]:
    """Dimensions the ADAPTIVE entry reads and this one does not."""
    if reference is None:
        return ()
    top = reference.coverage
    return tuple(
        d for d in COVERAGE_DIMENSIONS if getattr(top, d) > 0.0 and getattr(current, d) == 0.0
    )


def _penalty(reference: PhenotypeEntry | None, current: PhenotypeEntry) -> float | None:
    if reference is None:
        return None
    top, here = reference.heldout_worst_case_ap, current.heldout_worst_case_ap
    return None if top is None or here is None else top - here


def _supported(observation: ResourceObservation, margin: float) -> Regime:
    """The highest regime whose byte budget, scaled by ``1 + margin``, the observation covers."""
    for regime in REGIME_ORDER[:-1]:
        if observation.available_bytes >= REGIME_BUDGET_BYTES[regime] * (1.0 + margin):
            return regime
    return Regime.SURVIVAL  # the floor: there is nothing lower to fall to


def _lower(a: Regime, b: Regime) -> Regime:
    return a if _RANK[a] >= _RANK[b] else b


def _demote(regime: Regime, levels: int) -> Regime:
    return REGIME_ORDER[min(len(REGIME_ORDER) - 1, _RANK[regime] + levels)]


def _pressure_levels(observation: ResourceObservation) -> int:
    return int(observation.cpu_share >= CPU_PRESSURE_FRACTION) + int(
        observation.queue_depth >= QUEUE_PRESSURE_DEPTH
    )


class HomeostaticController:
    """Architecture §39-§40 as a bounded closed loop over a :class:`PhenotypeCatalog`.

    Down moves happen on the step that needs them. With hysteresis on, an up move waits for
    :data:`HYSTERESIS_STEPS` consecutive steps that each support it with
    :data:`HYSTERESIS_MARGIN` headroom. A regime with no entry, or whose entry was isolated
    by :meth:`report_failure`, falls to the next lower one; ``SURVIVAL`` always has the
    Φ-oracle. ``catalog=None`` means no Stage 9 artefact exists: every decision is
    ``SURVIVAL`` on the Φ-oracle.
    """

    def __init__(
        self,
        catalog: PhenotypeCatalog | None,
        *,
        hysteresis: bool = HYSTERESIS_DEFAULT_ENABLED,
    ) -> None:
        if catalog is not None and not isinstance(catalog, PhenotypeCatalog):
            raise ContractError("catalog must be a PhenotypeCatalog or None")
        self._catalog = catalog
        self._hysteresis = bool(hysteresis)
        self._floor = survival_entry()
        self._reference = None if catalog is None else catalog.for_regime(Regime.ADAPTIVE)
        entries = [self._floor] if catalog is None else [*catalog.entries, self._floor]
        # Bounded by the catalog size + 1: one phenotype digest per validated genome.
        self._phenotype_digests = {e.genome.digest: e.genome.phenotype().digest for e in entries}
        self._failed: set[Regime] = set()
        self._target = Regime.SURVIVAL
        self._current: PhenotypeEntry | None = None
        self._current_regime: Regime | None = None
        self._streak = 0
        self._streak_ceiling = Regime.ADAPTIVE
        self._decisions = 0
        self._transitions = 0
        self._into: dict[Regime, int] = dict.fromkeys(REGIME_ORDER, 0)
        self._history: deque[RegimeDecision] = deque(maxlen=MAX_DECISION_HISTORY)
        self._history_evictions = 0
        self._pressure_demotions = 0
        self._hysteresis_holds = 0
        self._substitutions = 0
        self._unrepairable = 0

    def _entry_for(self, regime: Regime) -> PhenotypeEntry | None:
        if self._catalog is None or regime in self._failed:
            return None
        return self._catalog.for_regime(regime)

    def _resolve(self, target: Regime) -> tuple[Regime, PhenotypeEntry]:
        """The first available, contract-satisfying entry at or below ``target``."""
        for regime in REGIME_ORDER[_RANK[target] :]:
            entry = self._entry_for(regime)
            if entry is not None and self._contract_ok(entry, target):
                return regime, entry
        return Regime.SURVIVAL, self._floor

    @staticmethod
    def _contract_ok(entry: PhenotypeEntry, regime: Regime) -> bool:
        """§57 "contract check": a substitute must fit the budget of the regime it serves."""
        return (
            entry.wu_per_event <= REGIME_WU_CAP[regime]
            and entry.state_bytes <= REGIME_BUDGET_BYTES[regime]
        )

    def _next_target(self, observation: ResourceObservation) -> Regime:
        raw = _supported(observation, 0.0)
        levels = _pressure_levels(observation)
        pressed = _demote(raw, levels)
        if pressed is not raw:
            self._pressure_demotions += 1
        if self._current is None or not self._hysteresis or _RANK[pressed] >= _RANK[self._target]:
            self._streak = 0
            return pressed
        margin = _demote(_supported(observation, HYSTERESIS_MARGIN), levels)
        if _RANK[margin] >= _RANK[self._target]:
            self._streak = 0
            self._hysteresis_holds += 1
            return self._target
        self._streak += 1
        # The move goes only as high as EVERY step of the streak supported.
        self._streak_ceiling = margin if self._streak == 1 else _lower(margin, self._streak_ceiling)
        if self._streak < HYSTERESIS_STEPS:
            self._hysteresis_holds += 1
            return self._target
        self._streak = 0
        return self._streak_ceiling

    def step(self, observation: ResourceObservation) -> RegimeDecision:
        """Choose the phenotype for this observation; see the class docstring for the rules."""
        if not isinstance(observation, ResourceObservation):
            raise ContractError("step takes a ResourceObservation")
        self._target = self._next_target(observation)
        regime, entry = self._resolve(self._target)
        return self._record(regime, entry, substituted=False, basis=observation.basis)

    def report_failure(self, regime: Regime) -> RegimeDecision:
        """Isolate ``regime``'s phenotype and substitute the next lower validated one (§57).

        The Φ-oracle floor is never isolated: a failure reported against it is counted as
        unrepairable and the floor keeps running, because there is nothing validated below it.
        """
        if not isinstance(regime, Regime):
            raise ContractError(f"report_failure takes a Regime, got {regime!r}")
        entry = self._entry_for(regime)
        if entry is None or entry.genome.digest == self._floor.genome.digest:
            self._unrepairable += 1
        else:
            self._failed.add(regime)
        before = None if self._current is None else self._current.genome.digest
        new_regime, new_entry = self._resolve(self._target)
        substituted = before is not None and new_entry.genome.digest != before
        self._substitutions += int(substituted)
        return self._record(new_regime, new_entry, substituted=substituted, basis="FAILURE_REPORT")

    def _record(
        self, regime: Regime, entry: PhenotypeEntry, *, substituted: bool, basis: str
    ) -> RegimeDecision:
        transitioned = self._current_regime is not None and regime is not self._current_regime
        if transitioned:
            self._transitions += 1
            self._into[regime] += 1
        decision = RegimeDecision(
            step=self._decisions,
            regime=regime,
            phenotype_digest=self._phenotype_digests[entry.genome.digest],
            coverage=entry.coverage,
            lost=_lost(self._reference, entry.coverage),
            uncertainty_penalty=_penalty(self._reference, entry),
            transitioned=transitioned,
            substituted=substituted,
            basis=basis,
            genome_digest=entry.genome.digest,
        )
        self._decisions += 1
        self._current, self._current_regime = entry, regime
        if len(self._history) == MAX_DECISION_HISTORY:
            self._history_evictions += 1
        self._history.append(decision)
        return decision

    @property
    def transitions(self) -> int:
        return self._transitions

    @property
    def transitions_into(self) -> Mapping[Regime, int]:
        """Firing count per regime: how many transitions entered it."""
        return MappingProxyType(dict(self._into))

    @property
    def active_entry(self) -> PhenotypeEntry | None:
        return self._current

    @property
    def counters(self) -> Mapping[str, int]:
        """Every mechanism's firing count, so an inert rule is visible (lesson 1)."""
        return MappingProxyType(
            {"decisions": self._decisions, "transitions": self._transitions,
             "pressure_demotions": self._pressure_demotions,
             "hysteresis_holds": self._hysteresis_holds, "substitutions": self._substitutions,
             "unrepairable_failures": self._unrepairable, "isolated_regimes": len(self._failed),
             "history_evictions": self._history_evictions}
        )  # fmt: skip

    def history(self) -> tuple[RegimeDecision, ...]:
        """The most recent :data:`MAX_DECISION_HISTORY` decisions, oldest first."""
        return tuple(self._history)


def drive(
    catalog: PhenotypeCatalog | None,
    trace: Sequence[ResourceObservation],
    *,
    hysteresis: bool = HYSTERESIS_DEFAULT_ENABLED,
) -> tuple[RegimeDecision, ...]:
    """Run a fresh controller over ``trace``; one decision per observation, in order."""
    controller = HomeostaticController(catalog, hysteresis=hysteresis)
    return tuple(controller.step(observation) for observation in trace)


def self_repair_substitutions(catalog: PhenotypeCatalog) -> tuple[RegimeDecision, ...]:
    """S9X-119: for each catalog regime, run it, report it failed, and record the substitute."""
    decisions: list[RegimeDecision] = []
    for regime in REGIME_ORDER:
        if catalog.for_regime(regime) is None:
            continue
        controller = HomeostaticController(catalog)
        controller.step(_observation_for(regime))
        decisions.append(controller.report_failure(regime))
    return tuple(decisions)


# --- simulated traces ---------------------------------------------------------------------------


def _observation_for(regime: Regime) -> ResourceObservation:
    """An observation whose bytes support exactly ``regime`` with the hysteresis margin."""
    return _simulated(int(REGIME_BUDGET_BYTES[regime] * (1.0 + 2.0 * HYSTERESIS_MARGIN)))


#: Parameters of the oscillation trace, fixed before any measurement (chosen, not tuned).
_OSCILLATION_CENTRE_MIB = 250.0
_OSCILLATION_AMPLITUDE_MIB = 100.0
_OSCILLATION_PERIOD_STEPS = 100
_OSCILLATION_NOISE_MIB = 10.0
_DEGRADATION_LEVELS_MIB: tuple[int, ...] = (700, 300, 120, 45, 120, 300, 700)
_DEGRADATION_STEPS_PER_LEVEL = 20


def synthetic_resource_trace(*, steps: int = 400, seed: int = 0) -> tuple[ResourceObservation, ...]:
    """SIMULATED oscillation around the 250 MiB ``REDUCED``/``REFLEX`` boundary, plus noise."""
    if isinstance(steps, bool) or not isinstance(steps, int) or steps < 1:
        raise ContractError("steps must be a positive int")
    rng = random.Random(seed)
    trace: list[ResourceObservation] = []
    for t in range(steps):
        phase = 2.0 * math.pi * t / _OSCILLATION_PERIOD_STEPS
        mib = (
            _OSCILLATION_CENTRE_MIB
            + _OSCILLATION_AMPLITUDE_MIB * math.sin(phase)
            + rng.gauss(0.0, _OSCILLATION_NOISE_MIB)
        )
        trace.append(_simulated(max(0, int(mib * _MIB))))
    return tuple(trace)


def _simulated(available_bytes: int, cpu: float = 0.2, queue: int = 0) -> ResourceObservation:
    return ResourceObservation(
        available_bytes=available_bytes, cpu_share=cpu, queue_depth=queue, basis="SIMULATED"
    )


def degradation_trace() -> tuple[ResourceObservation, ...]:
    """SIMULATED 700 -> 300 -> 120 -> 45 MiB and back up, 20 steps each: visits every regime."""
    return tuple(
        _simulated(mib * _MIB)
        for mib in _DEGRADATION_LEVELS_MIB
        for _ in range(_DEGRADATION_STEPS_PER_LEVEL)
    )


def pressure_trace() -> tuple[ResourceObservation, ...]:
    """SIMULATED CPU and queue pressure at a full 700 MiB: the only trace where those rules fire.

    Ten quiet steps, ten at CPU 0.95, ten at queue depth 4096, ten with both, ten quiet.
    """
    phases = ((0.2, 0), (0.95, 0), (0.2, 4096), (0.95, 4096), (0.2, 0))
    return tuple(_simulated(700 * _MIB, cpu, queue) for cpu, queue in phases for _ in range(10))


# --- the hysteresis verdict ---------------------------------------------------------------------

_MECHANISM = "pocketsec.stage9.runtime.homeostatic:HYSTERESIS_DEFAULT_ENABLED"
#: Spec §4.19: JUSTIFIED iff >= 50% fewer transitions ...
_MIN_TRANSITION_REDUCTION = 0.50
#: ... with <= 10% (of the trace's steps) more time in a lower regime.
_MAX_EXTRA_LOWER_FRACTION = 0.10


def _hysteresis_verdict(reduction: float | None, extra: float) -> MechanismVerdict:
    if reduction is None:
        return MechanismVerdict.NOT_YET_JUSTIFIED  # nothing oscillated, so nothing to damp
    if reduction >= _MIN_TRANSITION_REDUCTION and extra <= _MAX_EXTRA_LOWER_FRACTION:
        return MechanismVerdict.JUSTIFIED
    if extra > _MAX_EXTRA_LOWER_FRACTION:
        return MechanismVerdict.REJECTED  # §68: regime transitions that open detection gaps
    return MechanismVerdict.NOT_YET_JUSTIFIED


def compare_hysteresis(catalog: PhenotypeCatalog) -> DetectorComparison:
    """Hysteresis against none on :func:`synthetic_resource_trace` (SIMULATED).

    ``value`` is the fractional transition reduction (``None`` when the plain controller made
    no transition). "More time in a lower regime" counts the steps where the hysteretic
    controller runs a lower regime than the plain one on the same observation, as a fraction
    of the trace. ``fired`` counts the steps where the two chose differently (0 = INERT).
    """
    trace = synthetic_resource_trace()
    plain = drive(catalog, trace, hysteresis=False)
    damped = drive(catalog, trace, hysteresis=True)
    t_plain = sum(1 for d in plain if d.transitioned)
    t_damped = sum(1 for d in damped if d.transitioned)
    pairs = tuple(zip(plain, damped, strict=True))
    lower = sum(1 for a, b in pairs if _RANK[b.regime] > _RANK[a.regime])
    fired = sum(1 for a, b in pairs if a.regime is not b.regime)
    extra = lower / len(trace)
    reduction = None if t_plain == 0 else 1.0 - t_damped / t_plain
    return DetectorComparison(
        mechanism=_MECHANISM,
        metric="fractional transition reduction on the SIMULATED oscillation trace",
        value=reduction,
        controls=(
            ("no-hysteresis transitions", float(t_plain)),
            ("hysteresis transitions", float(t_damped)),
            ("extra lower-regime fraction", extra),
        ),
        verdict=_hysteresis_verdict(reduction, extra),
        fired=fired,
        detail=(
            f"SIMULATED trace, {len(trace)} steps: transitions {t_plain} -> {t_damped} "
            f"(needs >= {_MIN_TRANSITION_REDUCTION:.0%} fewer); {lower} steps ({extra:.1%}) "
            f"held in a lower regime (allowed <= {_MAX_EXTRA_LOWER_FRACTION:.0%})"
        ),
    )
