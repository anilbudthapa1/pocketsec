"""D9.12 (ONTO-F12, speciation half) — niches, species and morphogenesis against one universal.

Architecture §36-§38 proposes that a universal detector may be wasteful: GENESIS could grow
*species* for host niches, and *morphogenesis* could map (niche, budget, sensors) to a
phenotype. §36 accepts specialisation "only when it improves efficiency without unacceptable
blind spots"; §68 rejects morphogenesis "if configuration complexity outweighs specialization
gains". This module is the measurement of that claim and nothing more.

* :data:`NICHES` binds the architecture's niches to checkable static constraints. Four are
  measurable on this corpus: ``very_low_memory`` (state <= 4096 B), ``reflex`` (<= 4 WU/event),
  ``sensor_limited`` and ``full``. The five host-role niches (desktop, web server, database,
  container host, developer) are ``measurable=False``: the only corpus is one synthetic host
  with no roles, so any figure for them would be a guess.
* :func:`speciate` selects every species **on train** (the elites' records) and only *reports*
  held-out worst-case AP — selecting on held-out would be the Goodhart failure the spec forbids.
  One consequence is structural and stated rather than hidden: where the universal genome is
  admissible, the train argmax over the niche's admissible elites *is* the universal, so a
  species can only differ where the universal cannot run.
* Where the universal cannot run, the spec's "universal inadmissible" clause would make any
  admissible species a win by existence. That has no control, so this module is stricter
  (a recorded deviation): the reference there is the Φ-oracle floor, which the homeostatic
  runtime would run in that niche anyway, and the species must beat it by
  :data:`SPECIES_MARGIN` with **no per-technique recall drop** at a 5% FPR threshold.
* :func:`morphogenesis` is architecture §37's developmental rule D*: it returns the best
  admissible genome *from the pool it is given*, by identity. It never constructs, mutates or
  compiles code — "morphogenesis selects only pre-validated components" — and it returns
  ``None`` for a niche it cannot measure.

:data:`MORPHOGENESIS_DEFAULT_ENABLED` ships ``False`` (the universal phenotype is the control)
until :func:`compare_morphogenesis` returns JUSTIFIED and the integrator cites it.

``sensor_limited`` interpretation (recorded): a host without novelty, temporal or uncertainty
sensing still has state deltas and relations, so its raw inputs are ``DELTA_PHI``,
``STATE_DELTA_MASK``, ``RELATION`` and ``RELATION_FAMILY``, and ``FEATURE`` reads are allowed
only from feature groups other than ``novelty_tensor``, ``novelty_scalars``, ``temporal`` and
``uncertainty``.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, replace
from types import MappingProxyType
from typing import Final

from pocketsec.stage0.benchmark.security_metrics import recall_at_max_fpr
from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage2.dataset import Stage2Dataset
from pocketsec.stage2.encoder.ssir_encoder import FEATURE_WIDTH, GROUP_OFFSETS
from pocketsec.stage6.resources import WorkMeter
from pocketsec.stage9.chemistry.typed_ir import InputSource
from pocketsec.stage9.genome.computational import ComputationalGenomeV1
from pocketsec.stage9.genome.expressibility import phi_oracle_genome
from pocketsec.stage9.ontogenesis.fitness import (
    ABSTAINED_RANK_SCORE,
    EvaluationSuite,
    FitnessRecord,
    evaluate,
    session_scores,
)
from pocketsec.stage9.spec.mssc import DEFAULT_CONSTRAINTS, DetectorComparison, MechanismVerdict

__all__ = [
    "MORPHOGENESIS_DEFAULT_ENABLED",
    "NICHES",
    "RECALL_FPR_BUDGET",
    "SPECIATION_VERDICTS",
    "SPECIES_MARGIN",
    "UNMEASURABLE_REASON",
    "NicheSpec",
    "Speciation",
    "admissible",
    "compare_morphogenesis",
    "feature_group",
    "morphogenesis",
    "niche_by_name",
    "speciate",
]

#: Off until :func:`compare_morphogenesis` returns JUSTIFIED and the integrator cites it (§4.22).
MORPHOGENESIS_DEFAULT_ENABLED: bool = False
#: A species must beat its reference by this much held-out worst-case AP (spec §4.21, chosen).
SPECIES_MARGIN: Final = 0.02
#: The FPR budget every decision threshold in Stage 9 is fitted at (spec §4.21).
RECALL_FPR_BUDGET: Final = 0.05
UNMEASURABLE_REASON: Final = "single synthetic corpus with no host roles"
SPECIATION_VERDICTS: Final = (
    "SPECIALIZATION_HELPS",
    "UNIVERSAL_SUFFICES",
    "NO_ADMISSIBLE_SPECIES",
    "UNMEASURED",
)

_ALL_INPUTS: frozenset[InputSource] = frozenset(InputSource)
_SENSOR_LIMITED_INPUTS: frozenset[InputSource] = frozenset(
    {
        InputSource.DELTA_PHI,
        InputSource.STATE_DELTA_MASK,
        InputSource.RELATION,
        InputSource.RELATION_FAMILY,
        InputSource.FEATURE,  # admitted only through the group filter below
    }
)
_ABSENT_SENSOR_GROUPS: frozenset[str] = frozenset(
    {"novelty_tensor", "novelty_scalars", "temporal", "uncertainty"}
)


def feature_group(index: int) -> str:
    """The Stage 2 feature group ``FEATURE[index]`` belongs to, derived from ``GROUP_OFFSETS``."""
    if isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < FEATURE_WIDTH:
        raise ContractError(f"feature index must be an int in [0, {FEATURE_WIDTH}), got {index!r}")
    owner = ""
    for group, offset in sorted(GROUP_OFFSETS.items(), key=lambda item: item[1]):
        if offset <= index:
            owner = group
    return owner


@dataclass(frozen=True, slots=True)
class NicheSpec:
    """One host niche as static admission constraints on a genome."""

    name: str
    ram_bytes_max: int
    wu_per_event_max: int
    allowed_inputs: frozenset[InputSource]
    allowed_feature_groups: frozenset[str] | None  # None = every group
    measurable: bool
    unmeasurable_reason: str

    def __post_init__(self) -> None:
        if not self.name:
            raise ContractError("a niche needs a name")
        if self.ram_bytes_max <= 0 or self.wu_per_event_max <= 0:
            raise ContractError(f"niche {self.name} needs positive byte and WU caps")
        if self.measurable == bool(self.unmeasurable_reason):
            raise ContractError(
                f"niche {self.name}: an unmeasurable niche needs a reason and a measurable "
                "one must not carry one"
            )
        unknown = (self.allowed_feature_groups or frozenset()) - set(GROUP_OFFSETS)
        if unknown:
            raise ContractError(f"niche {self.name}: unknown feature groups {sorted(unknown)}")


def _measurable(name: str, ram: int, wu: int, inputs: frozenset[InputSource],
                groups: frozenset[str] | None = None) -> NicheSpec:  # fmt: skip
    return NicheSpec(name, ram, wu, inputs, groups, True, "")


def _role(name: str) -> NicheSpec:
    return NicheSpec(
        name,
        DEFAULT_CONSTRAINTS.ram_bytes_max,
        DEFAULT_CONSTRAINTS.wu_per_event_max,
        _ALL_INPUTS,
        None,
        False,
        UNMEASURABLE_REASON,
    )


_RAM_MAX = DEFAULT_CONSTRAINTS.ram_bytes_max
_WU_MAX = DEFAULT_CONSTRAINTS.wu_per_event_max

NICHES: tuple[NicheSpec, ...] = (
    _measurable("very_low_memory", 4096, _WU_MAX, _ALL_INPUTS),
    _measurable("reflex", _RAM_MAX, 4, _ALL_INPUTS),
    _measurable(
        "sensor_limited",
        _RAM_MAX,
        _WU_MAX,
        _SENSOR_LIMITED_INPUTS,
        frozenset(GROUP_OFFSETS) - _ABSENT_SENSOR_GROUPS,
    ),
    _measurable("full", _RAM_MAX, _WU_MAX, _ALL_INPUTS),
    _role("desktop"),
    _role("web_server"),
    _role("database"),
    _role("container_host"),
    _role("developer"),
)
_BY_NAME = MappingProxyType({spec.name: spec for spec in NICHES})


def niche_by_name(name: str) -> NicheSpec:
    """Look a niche up by name; an unknown name is a :class:`ContractError`."""
    try:
        return _BY_NAME[name]
    except KeyError:
        raise ContractError(f"unknown niche {name!r}; known: {sorted(_BY_NAME)}") from None


def admissible(genome: ComputationalGenomeV1, niche: NicheSpec) -> bool:
    """Whether ``genome``'s static bounds and inputs fit ``niche``. Static: needs no data."""
    bounds = genome.bounds
    if bounds.session_state_bytes_max > niche.ram_bytes_max:
        return False
    if bounds.update_wu_per_event > niche.wu_per_event_max:
        return False
    for source, index in genome.observation_map:
        if source not in niche.allowed_inputs:
            return False
        groups = niche.allowed_feature_groups
        filtered = source is InputSource.FEATURE and groups is not None
        if filtered and feature_group(index) not in (groups or frozenset()):
            return False
    return True


@dataclass(frozen=True, slots=True)
class Speciation:
    """One niche's species against the universal genome, on held-out data.

    ``reference`` names what the species had to beat: ``"universal"`` where the universal is
    admissible, ``"phi-oracle-floor"`` where it is not, ``""`` when nothing was compared.
    ``technique_recall_drops`` lists techniques whose recall at a 5%-FPR threshold fell
    against the reference; ``None`` when no comparison was made.
    """

    niche: str
    species_digest: str | None
    universal_digest: str
    species_heldout_worst_ap: float | None
    universal_admissible: bool
    universal_heldout_worst_ap: float | None
    verdict: str
    reference: str = ""
    reference_heldout_worst_ap: float | None = None
    gain: float | None = None
    technique_recall_drops: tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        if self.verdict not in SPECIATION_VERDICTS:
            raise ContractError(f"unknown speciation verdict {self.verdict!r}")
        if self.verdict == "SPECIALIZATION_HELPS" and (
            self.gain is None or self.gain < SPECIES_MARGIN or self.technique_recall_drops != ()
        ):
            raise ContractError("SPECIALIZATION_HELPS needs a measured gain and no recall drop")
        if self.verdict == "UNMEASURED" and self.species_heldout_worst_ap is not None:
            raise ContractError("an UNMEASURED speciation carries no species figure")


# --- selection (train) and reporting (held-out) ------------------------------------------------


def _validated(
    pool: Sequence[tuple[ComputationalGenomeV1, FitnessRecord]],
) -> tuple[tuple[ComputationalGenomeV1, FitnessRecord], ...]:
    """Distinct genomes whose record is theirs and whose train worst-case AP was measured."""
    seen: set[str] = set()
    kept: list[tuple[ComputationalGenomeV1, FitnessRecord]] = []
    for genome, record in pool:
        if record.genome_digest != genome.digest:
            raise ContractError(
                f"record {record.genome_digest[:19]} is not genome {genome.digest[:19]}'s"
            )
        if record.worst_case_ap is None or genome.digest in seen:
            continue
        seen.add(genome.digest)
        kept.append((genome, record))
    return tuple(kept)


def _best(
    pool: Sequence[tuple[ComputationalGenomeV1, FitnessRecord]],
) -> tuple[ComputationalGenomeV1, FitnessRecord] | None:
    """Max train worst-case AP; the cheaper genome wins a tie, then the lower digest."""

    def key(item: tuple[ComputationalGenomeV1, FitnessRecord]) -> tuple[float, int, int, str]:
        genome, record = item
        ap = record.worst_case_ap if record.worst_case_ap is not None else -1.0
        bounds = genome.bounds
        return (-ap, bounds.update_wu_per_event, bounds.session_state_bytes_max, genome.digest)

    return min(pool, key=key) if pool else None


class _HeldOut:
    """Held-out evaluations, computed once per genome; bounded by the pool size + 1."""

    def __init__(self, suite: EvaluationSuite) -> None:
        self._suite = suite
        self._records: dict[str, FitnessRecord] = {}
        self._recall: dict[str, dict[str, float]] = {}

    def worst(self, genome: ComputationalGenomeV1) -> float | None:
        if genome.digest not in self._records:
            self._records[genome.digest] = evaluate(genome, self._suite, meter=WorkMeter())
        return self._records[genome.digest].worst_case_ap

    def technique_recall(self, genome: ComputationalGenomeV1) -> dict[str, float]:
        if genome.digest not in self._recall:
            self._recall[genome.digest] = _technique_recall(genome, self._suite.clean.dataset)
        return self._recall[genome.digest]


def _technique_recall(genome: ComputationalGenomeV1, dataset: Stage2Dataset) -> dict[str, float]:
    """Per-technique recall at the threshold that keeps held-out FPR <= 5% for this genome."""
    raw = session_scores(genome, dataset, meter=WorkMeter())
    scores = [ABSTAINED_RANK_SCORE if s is None else s for s in raw]
    labels = list(dataset.labels)
    _, threshold = recall_at_max_fpr(labels, scores, RECALL_FPR_BUDGET)
    if threshold is None:
        return {}
    hits: dict[str, list[int]] = {}
    for sample, score in zip(dataset.samples, scores, strict=True):
        if sample.label == 1:
            technique = sample.technique or "UNKNOWN_TECHNIQUE"
            hits.setdefault(technique, []).append(int(score >= threshold))
    return {t: sum(v) / len(v) for t, v in sorted(hits.items())}


def _drops(species: dict[str, float], reference: dict[str, float]) -> tuple[str, ...]:
    return tuple(t for t in sorted(reference) if species.get(t, 0.0) < reference[t])


def _niche_speciation(
    spec: NicheSpec,
    elites: tuple[tuple[ComputationalGenomeV1, FitnessRecord], ...],
    universal: ComputationalGenomeV1,
    heldout: _HeldOut,
) -> Speciation:
    universal_ok = admissible(universal, spec)
    base = Speciation(
        niche=spec.name, species_digest=None, universal_digest=universal.digest,
        species_heldout_worst_ap=None, universal_admissible=universal_ok,
        universal_heldout_worst_ap=heldout.worst(universal), verdict="UNMEASURED",
    )  # fmt: skip
    if not spec.measurable:
        return base
    best = _best([item for item in elites if admissible(item[0], spec)])
    if best is None:
        return replace(base, verdict="NO_ADMISSIBLE_SPECIES")
    species = best[0]
    reference = universal if universal_ok else phi_oracle_genome()
    species_ap, reference_ap = heldout.worst(species), heldout.worst(reference)
    gain = None if species_ap is None or reference_ap is None else species_ap - reference_ap
    drops = _drops(heldout.technique_recall(species), heldout.technique_recall(reference))
    helps = gain is not None and gain >= SPECIES_MARGIN and drops == ()
    return replace(
        base,
        species_digest=species.digest,
        species_heldout_worst_ap=species_ap,
        verdict="SPECIALIZATION_HELPS" if helps else "UNIVERSAL_SUFFICES",
        reference="universal" if universal_ok else "phi-oracle-floor",
        reference_heldout_worst_ap=reference_ap,
        gain=gain,
        technique_recall_drops=drops,
    )


def speciate(
    elites: Sequence[tuple[ComputationalGenomeV1, FitnessRecord]],
    heldout: EvaluationSuite,
) -> tuple[Speciation, ...]:
    """One :class:`Speciation` per :data:`NICHES` entry, in order.

    ``elites`` carry TRAIN fitness records: selection uses them; ``heldout`` is only reported.
    """
    pool = _validated(elites)
    universal = _best(pool)
    if universal is None:
        raise ContractError("speciate needs at least one elite with a measured train worst-case AP")
    cache = _HeldOut(heldout)
    return tuple(_niche_speciation(spec, pool, universal[0], cache) for spec in NICHES)


def morphogenesis(
    niche: NicheSpec,
    catalog_pool: Sequence[tuple[ComputationalGenomeV1, FitnessRecord]],
) -> ComputationalGenomeV1 | None:
    """Developmental rule D*: the best admissible pre-validated genome, returned by identity.

    Never synthesises code. ``None`` when the niche is unmeasurable (a phenotype chosen for a
    host role nobody observed is a guess) or when no pool genome is admissible there.
    """
    if not niche.measurable:
        return None
    best = _best([item for item in _validated(catalog_pool) if admissible(item[0], niche)])
    return None if best is None else best[0]


_MECHANISM = "pocketsec.stage9.genesis.speciation:MORPHOGENESIS_DEFAULT_ENABLED"


def compare_morphogenesis(speciations: Sequence[Speciation]) -> DetectorComparison:
    """Morphogenesis against one universal phenotype, per measurable niche (spec §4.19, §68).

    JUSTIFIED iff at least one measurable niche's species beats its reference (the universal
    where admissible, the Φ-oracle floor where not) by :data:`SPECIES_MARGIN` with no
    technique recall drop; UNMEASURED if no measurable niche produced a comparison; REJECTED
    otherwise. ``fired`` counts niches where morphogenesis chose a genome other than the
    universal — 0 means it never changed what would run (INERT).
    """
    compared = [s for s in speciations if s.gain is not None]
    fired = sum(
        1 for s in speciations if s.species_digest not in (None, s.universal_digest)
    )
    controls = tuple(
        (f"{s.niche}:{s.reference}", s.reference_heldout_worst_ap) for s in compared
    )
    unmeasured = [s.niche for s in speciations if s.verdict == "UNMEASURED"]
    if not compared:
        verdict, value = MechanismVerdict.UNMEASURED, None
    else:
        value = max(s.gain for s in compared if s.gain is not None)
        helps = any(s.verdict == "SPECIALIZATION_HELPS" for s in compared)
        verdict = MechanismVerdict.JUSTIFIED if helps else MechanismVerdict.REJECTED
    return DetectorComparison(
        mechanism=_MECHANISM,
        metric="max held-out worst-case AP gain of a niche species over its reference",
        value=value,
        controls=controls,
        verdict=verdict,
        fired=fired,
        detail=(
            f"{len(compared)} measurable niches compared; per niche: "
            + ", ".join(f"{s.niche}={s.verdict}" for s in speciations)
            + f". UNMEASURED ({UNMEASURABLE_REASON}): {', '.join(unmeasured) or 'none'}"
        ),
    )
