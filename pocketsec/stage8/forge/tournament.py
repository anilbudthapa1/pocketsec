"""D8.15 / PROM-F18, PROM-F19 — the Representation Tournament, the Discovery Compression
Ratio and the endpoint footprint of what FORGE would ship.

A surviving theory is worth deploying cheaply only if the cheap form still *is* the theory.
The tournament therefore measures every representation the compiler produced — refused ones
included, as refusals — on the REPLICATION split with hard labels, and selects by a rule that
is a **pure function of the recorded measurements** (:func:`reselect` re-derives the
selection from a stored :class:`TournamentResult` alone):

* **eligible** = expressible, every security figure measured (precision, recall, FPR, PR-AUC,
  decision agreement), recall and precision within 0.02 of TYPED_RULE's, FPR no worse than
  TYPED_RULE's (tolerance 0.0), agreement with TYPED_RULE >= 0.98, artifact <= 64 KiB;
* **costs less** = no worse than TYPED_RULE on both work units per event and artifact bytes,
  strictly better on one, AND no slower than TYPED_RULE in wall time measured in the same run
  (:data:`FORGE_WALL_RATIO_MAX`). Work units are what each representation charges itself, so on
  their own they cannot say an entrant is cheaper to run: the review found an FSM 7 % "cheaper"
  in work units that is 1.23-1.26x slower in CPU, and a deliberately 21.6x slower FSM selected as
  deployable (F2, honesty lens). The wall ratio is an interleaved, repeated, within-run
  measurement (:data:`WALL_REPEATS` pairs, median of per-pair ratios); an unmeasured ratio is
  ``cost_unmeasured``, never cheaper. TYPED_RULE's bytes are its **decision-relevant** content
  (mechanism, forbidden predicates, direction), not the whole genome with its metadata, which
  inflated the reference and made "91 % smaller" an artefact of what was serialised;
* the **Pareto front** over eligible-and-cheaper entrants on (work units per event, artifact
  bytes, -robustness); the **selection** is the front's minimum by (work units per event,
  bytes, interpretability, enum order).

No eligible entrant means ``selected=None`` and ``deployable=False`` with every entrant's
first failing check as a reason. TYPED_RULE can never be selected: it cannot cost less than
itself, so "deployable" always means "compressed without measured loss".

Detection figures are **direction-relative**: for a BENIGN-direction theory a "positive" is
a label-0 episode (what a match predicts), as in the holdout vault.

What the tournament refuses to do:

* **Read an absolute time when selecting.** Wall time enters selection only as the recorded
  within-run ratio to TYPED_RULE (interleaved pairs, beside ``/proc/loadavg``), so
  :func:`reselect` stays a pure function of the recorded measurements. This host is shared; an
  absolute microsecond figure here is not a device measurement, and none is recorded.
* **Let the most sophisticated entrant win by default.** Selection is cost-first among
  representations that preserve quality; a student that is 0.97 in agreement loses to the
  theory itself.
* **Report an unmeasured footprint as within budget.** :class:`EndpointFootprint` refuses
  ``within_ceiling`` unless it is exactly the comparison of a measured incremental RSS; an
  unreadable RSS is ``None`` (UNMEASURED), which a gate must treat as a failure.

The §85 conservation checks (:func:`conservation_checks`) are separate from selection: they
ask whether a compressed form still honours the distinctions the theory draws (nuisance
invariance, necessary-event removal, benign doppelgängers), and their failures become the
package's failure conditions.
"""

from __future__ import annotations

import json
import math
import random
import statistics
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from pocketsec.stage0.benchmark.resource_metrics import ResourceSampler
from pocketsec.stage0.benchmark.security_metrics import average_precision
from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage6.resources import WorkMeter, loadavg
from pocketsec.stage8.challenger.adversarial import ChallengeKind
from pocketsec.stage8.challenger.adversarial import challenge as challenge_detector
from pocketsec.stage8.episode import Episode, FitCounts, Split
from pocketsec.stage8.forge.compiler import (
    CompiledDetector,
    GovernedMeter,
    canonical_artifact_bytes,
    load_detector,
)
from pocketsec.stage8.forge.package import (
    DiscoveryPackageV1,
    FailureCondition,
    RepresentationKind,
    RepresentationMeasurement,
    TournamentResult,
    verify_package,
)
from pocketsec.stage8.forge.representations import Detector, TypedRuleDetector
from pocketsec.stage8.genome.hypothesis import Direction, FalsifierKind, HypothesisGenome
from pocketsec.stage8.governor.budget import ResearchGovernor
from pocketsec.stage8.laboratory.metamorphic import (
    DEFAULT_RELATIONS,
    Expectation,
    MetamorphicRelation,
    MetamorphicResult,
    run_metamorphic,
)

__all__ = [
    "DEFAULT_DOPPELGANGER_SHARE",
    "ENDPOINT_ARTIFACT_MAX_BYTES",
    "FORGE_AGREEMENT_MIN",
    "FORGE_FPR_TOLERANCE",
    "FORGE_PRECISION_TOLERANCE",
    "FORGE_RECALL_TOLERANCE",
    "FORGE_WALL_RATIO_MAX",
    "MAX_MEASURE_EPISODES",
    "SECURITY_FIELDS",
    "STAGE8_ENDPOINT_INCREMENTAL_CEILING_BYTES",
    "TOURNAMENT_COMPONENT",
    "WALL_REPEATS",
    "ConservationReport",
    "EndpointFootprint",
    "conservation_checks",
    "costs_less",
    "decision_relevant_bytes",
    "discovery_compression_ratio",
    "measure_endpoint_footprint",
    "research_state_bytes_of",
    "reselect",
    "run_tournament",
]

#: §4.21 — chosen parameters, not measurements.
FORGE_RECALL_TOLERANCE: float = 0.02
FORGE_PRECISION_TOLERANCE: float = 0.02
FORGE_FPR_TOLERANCE: float = 0.0
FORGE_AGREEMENT_MIN: float = 0.98
#: An entrant may be no slower than TYPED_RULE in the same run (median interleaved ratio).
#: Chosen: "costs less" must not mean "runs slower". 1.0 exactly: no tolerance is granted.
FORGE_WALL_RATIO_MAX: float = 1.0
#: Interleaved (reference, entrant) timing pairs per entrant. Chosen: at 5 pairs a MOTIF whose
#: median ratio is ~0.96 read > 1.0 in 1-2 of 20 re-measurements (load ~11); more pairs narrow it.
WALL_REPEATS: int = 9
ENDPOINT_ARTIFACT_MAX_BYTES: int = 65536
#: Architecture §45 "prefer < 20-35 MB" normal endpoint incremental RSS: the lower end.
STAGE8_ENDPOINT_INCREMENTAL_CEILING_BYTES: int = 20 * 1024 * 1024
#: The doppelgänger refutation threshold when the genome declares none (§4.21). Chosen.
DEFAULT_DOPPELGANGER_SHARE: float = 0.05
#: One tournament measures at most this many episodes (the vault's own cap). Chosen.
MAX_MEASURE_EPISODES: int = 2048
TOURNAMENT_COMPONENT = "forge.tournament"
CONSERVATION_COMPONENT = "forge.conservation"
SECURITY_FIELDS: tuple[str, ...] = (
    "precision", "recall", "false_positive_rate", "pr_auc", "decision_agreement")

_ORDER: Mapping[RepresentationKind, int] = {kind: i for i, kind in enumerate(RepresentationKind)}


# --- measuring one entrant -----------------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Run:
    decisions: tuple[bool, ...]
    units: int
    wall: float


def _run(detector: Detector, episodes: Sequence[Episode], governor: ResearchGovernor) -> _Run:
    """Every decision under a private meter (the deployed cost), paid to the governor first."""
    meter = GovernedMeter(governor, TOURNAMENT_COMPONENT)
    start = time.perf_counter()
    decisions = tuple(bool(detector.decide(episode, meter)) for episode in episodes)
    return _Run(decisions, meter.spent, time.perf_counter() - start)


def _counts(decisions: Sequence[bool], targets: Sequence[int | None]) -> FitCounts:
    matched = true = positives = negatives = 0
    for fired, target in zip(decisions, targets, strict=True):
        if target is None:
            continue  # unlabelled: counted nowhere, as fit_counts does
        positives += target
        negatives += 1 - target
        matched += fired
        true += fired and target == 1
    return FitCounts(matched, true, matched - true, positives, negatives)


def _robustness(detector: Detector, kind: RepresentationKind, genome: HypothesisGenome,
                corpus: Mapping[ChallengeKind, tuple[Episode, ...]],
                governor: ResearchGovernor) -> float | None:
    """Minimum recall retained over challenge kinds, capped at 1.0; ``None`` when no kind
    measured one. The challenger's positives are label 1, so a BENIGN-direction theory has
    no robustness figure here (it is not what the challenges attack)."""
    if not corpus or genome.direction is Direction.BENIGN:
        return None
    meter = GovernedMeter(governor, TOURNAMENT_COMPONENT)
    rows = challenge_detector(f"forge-{kind.value}",
                              lambda episode: detector.decide(episode, meter), corpus)
    retained = [row.recall_retained for row in rows if row.recall_retained is not None]
    return min(1.0, min(retained)) if retained else None


@dataclass(frozen=True, slots=True)
class _Setting:
    """What every entrant is measured against: the same episodes, targets and reference."""

    genome: HypothesisGenome
    episodes: tuple[Episode, ...]
    targets: tuple[int | None, ...]
    reference: _Run | None
    challenge: Mapping[ChallengeKind, tuple[Episode, ...]]
    governor: ResearchGovernor
    load: tuple[float, float, float]
    reference_detector: Detector | None = None


def _pass_seconds(detector: Detector, episodes: Sequence[Episode],
                  governor: ResearchGovernor) -> float:
    meter = GovernedMeter(governor, TOURNAMENT_COMPONENT)
    start = time.perf_counter()
    for episode in episodes:
        detector.decide(episode, meter)
    return time.perf_counter() - start


def _wall_ratio(detector: Detector, setting: _Setting) -> float | None:
    """Median over :data:`WALL_REPEATS` interleaved pairs of entrant time / TYPED_RULE time.

    Both passes of a pair run back to back in alternating order, under the same meter kind, so
    host contention hits both alike (lead's standing order: within-run ratios, never an
    absolute figure). ``None`` (UNMEASURED) when no pair had a positive reference time.
    """
    reference = setting.reference_detector
    if reference is None:
        return 1.0   # measuring TYPED_RULE itself: the ratio to itself is 1 by definition
    ratios = []
    for index in range(WALL_REPEATS):
        if index % 2 == 0:
            ref_s = _pass_seconds(reference, setting.episodes, setting.governor)
            own_s = _pass_seconds(detector, setting.episodes, setting.governor)
        else:
            own_s = _pass_seconds(detector, setting.episodes, setting.governor)
            ref_s = _pass_seconds(reference, setting.episodes, setting.governor)
        if ref_s > 0:
            ratios.append(own_s / ref_s)
    return float(statistics.median(ratios)) if ratios else None


def decision_relevant_bytes(genome: HypothesisGenome) -> int:
    """TYPED_RULE's comparable size: what executing the rule needs, canonical JSON.

    The mechanism, the forbidden predicates and the direction decide every TYPED_RULE output;
    the genome's provenance, competing explanations, falsifiers and scope do not, so they are
    not charged to the reference (F2, honesty lens: they made compression look 91 % smaller).
    """
    return len(canonical_artifact_bytes({
        "kind": RepresentationKind.TYPED_RULE.value, "direction": genome.direction.value,
        "mechanism": genome.proposed_mechanism.to_dsl(),
        "forbidden": [p.payload() for p in genome.forbidden_observations],
    }))


def _refused(entrant: CompiledDetector, load: tuple[float, float, float]
             ) -> RepresentationMeasurement:
    return RepresentationMeasurement(
        kind=entrant.kind, expressible=False, refusal=entrant.refusal, precision=None,
        recall=None, false_positive_rate=None, pr_auc=None, decision_agreement=None,
        work_units_per_event=None, artifact_bytes=None, wall_ratio_to_reference=None,
        loadavg=load, robustness_recall=None, interpretability=None)


def _measure(entrant: CompiledDetector, setting: _Setting) -> tuple[RepresentationMeasurement,
                                                                    _Run]:
    detector = load_detector(entrant)
    run = _run(detector, setting.episodes, setting.governor)
    reference = setting.reference or run
    counts = _counts(run.decisions, setting.targets)
    score_meter = GovernedMeter(setting.governor, TOURNAMENT_COMPONENT)
    labelled = [(episode, t) for episode, t in zip(setting.episodes, setting.targets,
                                                    strict=True) if t is not None]
    scores = [detector.score(episode, score_meter) for episode, _ in labelled]
    agreement = sum(a == b for a, b in zip(run.decisions, reference.decisions, strict=True))
    size = (decision_relevant_bytes(setting.genome)
            if entrant.kind is RepresentationKind.TYPED_RULE else entrant.artifact_bytes)
    measurement = RepresentationMeasurement(
        kind=entrant.kind, expressible=True, refusal=None,
        precision=counts.precision, recall=counts.recall,
        false_positive_rate=counts.false_positive_rate,
        pr_auc=average_precision([t for _, t in labelled], scores) if labelled else None,
        decision_agreement=agreement / len(setting.episodes),
        work_units_per_event=run.units / len(setting.episodes),
        artifact_bytes=size,
        wall_ratio_to_reference=_wall_ratio(detector, setting),
        loadavg=setting.load,
        robustness_recall=_robustness(detector, entrant.kind, setting.genome, setting.challenge,
                                      setting.governor),
        interpretability=detector.interpretability(),
    )
    return measurement, run


# --- selection: a pure function of the measurements -----------------------------------


def _security(m: RepresentationMeasurement) -> tuple[float, float, float, float] | None:
    """(recall, precision, FPR, agreement), or ``None`` if any security figure is missing."""
    if any(getattr(m, name) is None for name in SECURITY_FIELDS):
        return None
    return (float(m.recall or 0.0), float(m.precision or 0.0),
            float(m.false_positive_rate or 0.0), float(m.decision_agreement or 0.0))


def _first_failure(m: RepresentationMeasurement, ref: RepresentationMeasurement) -> str | None:
    """The first eligibility check ``m`` fails against the reference, or ``None``."""
    if not m.expressible:
        return f"refused.{m.refusal}"
    mine, theirs = _security(m), _security(ref)
    if mine is None or theirs is None:
        return "security_unmeasured"
    recall, precision, fpr, agreement = mine
    ref_recall, ref_precision, ref_fpr, _ = theirs
    if recall < ref_recall - FORGE_RECALL_TOLERANCE:
        return "recall_below_tolerance"
    if precision < ref_precision - FORGE_PRECISION_TOLERANCE:
        return "precision_below_tolerance"
    if fpr > ref_fpr + FORGE_FPR_TOLERANCE:
        return "fpr_above_tolerance"
    if agreement < FORGE_AGREEMENT_MIN:
        return "agreement_below_min"
    if m.artifact_bytes is None or m.artifact_bytes > ENDPOINT_ARTIFACT_MAX_BYTES:
        return "artifact_too_large"
    return _cost_failure(m, ref)


def _cost_failure(m: RepresentationMeasurement, ref: RepresentationMeasurement) -> str | None:
    """"Costs less": no worse on (work units per event, bytes), strictly better on one, and no
    slower than the reference in the same run. See :func:`costs_less`."""
    units, size = m.work_units_per_event, m.artifact_bytes
    ref_units, ref_size = ref.work_units_per_event, ref.artifact_bytes
    if units is None or size is None or ref_units is None or ref_size is None \
            or m.wall_ratio_to_reference is None:
        return "cost_unmeasured"
    no_worse = units <= ref_units and size <= ref_size
    if not (no_worse and (units < ref_units or size < ref_size)):
        return "not_cheaper_than_reference"
    if m.wall_ratio_to_reference > FORGE_WALL_RATIO_MAX:
        return "slower_than_reference"
    return None


def costs_less(m: RepresentationMeasurement, ref: RepresentationMeasurement) -> bool:
    """The deployability cost rule, shared by the gate's and the sweep's restatements."""
    return _cost_failure(m, ref) is None


def _objectives(m: RepresentationMeasurement) -> tuple[float, float, float]:
    robustness = -m.robustness_recall if m.robustness_recall is not None else math.inf
    return (float(m.work_units_per_event or 0.0), float(m.artifact_bytes or 0), robustness)


def _dominates(a: tuple[float, ...], b: tuple[float, ...]) -> bool:
    return all(x <= y for x, y in zip(a, b, strict=True)) and a != b


def _select(entrants: Sequence[RepresentationMeasurement]
            ) -> tuple[RepresentationKind | None, tuple[RepresentationKind, ...], tuple[str, ...]]:
    """(selected, Pareto front, reasons) from the recorded measurements alone (the wall time it
    reads is the recorded within-run ratio, never a clock)."""
    by_kind = {m.kind: m for m in entrants}
    ref = by_kind.get(RepresentationKind.TYPED_RULE)
    if ref is None:
        raise ContractError("a tournament without its TYPED_RULE reference selects nothing")
    reasons: list[str] = ["TYPED_RULE:reference"]
    candidates: list[RepresentationMeasurement] = []
    for m in sorted(entrants, key=lambda item: _ORDER[item.kind]):
        if m.kind is RepresentationKind.TYPED_RULE:
            continue
        failure = _first_failure(m, ref)
        if failure is None:
            candidates.append(m)
        else:
            reasons.append(f"{m.kind.value}:{failure}")
    front = [m for m in candidates if not any(
        _dominates(_objectives(o), _objectives(m)) for o in candidates if o is not m)]
    front.sort(key=lambda m: _ORDER[m.kind])
    kinds = tuple(m.kind for m in front)
    if not front:
        return None, (), (*reasons, "none_eligible")
    chosen = min(front, key=lambda m: (
        m.work_units_per_event, m.artifact_bytes,
        m.interpretability if m.interpretability is not None else math.inf, _ORDER[m.kind]))
    reasons += [f"{m.kind.value}:off_pareto_front" for m in candidates if m.kind not in kinds]
    reasons += [f"{kind.value}:pareto_not_minimal" for kind in kinds if kind is not chosen.kind]
    return chosen.kind, kinds, (*reasons, f"selected:{chosen.kind.value}")


def reselect(result: TournamentResult
             ) -> tuple[RepresentationKind | None, tuple[RepresentationKind, ...]]:
    """Re-derive (selected, Pareto front) from a recorded tournament's measurements only."""
    if not isinstance(result, TournamentResult):
        raise ContractError(f"reselect reads a TournamentResult, got {type(result).__name__}")
    selected, front, _ = _select(result.entrants)
    return selected, front


def discovery_compression_ratio(discovery_work_units: int,
                                deployed_units_per_event: float | None) -> float | None:
    """DCR = discovery work units / deployed work units per event; ``None`` when nothing is
    deployed or the deployed cost is not positive (a ratio over zero measures nothing)."""
    if isinstance(discovery_work_units, bool) or not isinstance(discovery_work_units, int) \
            or discovery_work_units < 0:
        raise ContractError(f"discovery_work_units must be an int >= 0, got "
                            f"{discovery_work_units!r}")
    if deployed_units_per_event is None or deployed_units_per_event <= 0:
        return None
    return discovery_work_units / deployed_units_per_event


def research_state_bytes_of(genome: HypothesisGenome,
                            records: Sequence[Mapping[str, Any]] = ()) -> int:
    """The research state a discovery cost to hold: the genome plus its ledger entries and
    experiment records, each as canonical JSON (the ``KnowledgeBytesSaved`` numerator)."""
    size = len(genome.canonical_bytes())
    for record in records:
        size += len(json.dumps(record, sort_keys=True, separators=(",", ":"),
                               allow_nan=False, default=str).encode("utf-8"))
    return size


# --- the tournament ------------------------------------------------------------------


def _checked_entrants(genome: HypothesisGenome, compiled: Sequence[CompiledDetector]
                      ) -> dict[RepresentationKind, CompiledDetector]:
    by_kind: dict[RepresentationKind, CompiledDetector] = {}
    for entrant in compiled:
        if not isinstance(entrant, CompiledDetector) or entrant.kind in by_kind:
            raise ContractError("compiled must hold one CompiledDetector per kind")
        by_kind[entrant.kind] = entrant
    if set(by_kind) != set(RepresentationKind):
        missing = sorted(k.value for k in set(RepresentationKind) - set(by_kind))
        raise ContractError(f"every RepresentationKind enters, refused or not; missing {missing}")
    reference = load_detector(by_kind[RepresentationKind.TYPED_RULE])
    if not isinstance(reference, TypedRuleDetector) or \
            reference.genome.hypothesis_id != genome.hypothesis_id:
        raise ContractError("the TYPED_RULE entrant must be this theory's own genome")
    return by_kind


def _checked_episodes(measure_on: Sequence[Episode], direction: Direction
                      ) -> tuple[tuple[Episode, ...], tuple[int | None, ...]]:
    episodes = tuple(measure_on)
    if not episodes or len(episodes) > MAX_MEASURE_EPISODES:
        raise ContractError(f"a tournament measures 1..{MAX_MEASURE_EPISODES} episodes")
    for episode in episodes:
        if not isinstance(episode, Episode) or episode.split is not Split.REPLICATION:
            raise ContractError("the tournament measures REPLICATION episodes only")
    target = 0 if direction is Direction.BENIGN else 1
    targets = tuple(None if e.label is None else int(e.label == target) for e in episodes)
    if all(t is None for t in targets):
        raise ContractError("no labelled REPLICATION episode: nothing could be measured")
    return episodes, targets


def _require_count(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ContractError(f"{field} must be an int >= 0, got {value!r}")
    return value


def run_tournament(
    genome: HypothesisGenome, compiled: Sequence[CompiledDetector], *,
    measure_on: Sequence[Episode], challenge: Mapping[ChallengeKind, tuple[Episode, ...]],
    discovery_work_units: int, research_state_bytes: int, governor: ResearchGovernor,
) -> TournamentResult:
    """Measure every entrant on REPLICATION and select by the rule in the module docstring."""
    if not isinstance(genome, HypothesisGenome):
        raise ContractError("run_tournament measures a HypothesisGenome's representations")
    if not isinstance(governor, ResearchGovernor):
        raise ContractError("run_tournament needs the run's ResearchGovernor")
    _require_count(discovery_work_units, "discovery_work_units")
    _require_count(research_state_bytes, "research_state_bytes")
    by_kind = _checked_entrants(genome, compiled)
    episodes, targets = _checked_episodes(measure_on, genome.direction)
    setting = _Setting(genome, episodes, targets, None, challenge, governor, loadavg())
    reference, ref_run = _measure(by_kind[RepresentationKind.TYPED_RULE], setting)
    setting = _Setting(genome, episodes, targets, ref_run, challenge, governor, setting.load,
                       load_detector(by_kind[RepresentationKind.TYPED_RULE]))
    entrants: list[RepresentationMeasurement] = []
    for kind in RepresentationKind:
        entrant = by_kind[kind]
        if kind is RepresentationKind.TYPED_RULE:
            entrants.append(reference)
        elif not entrant.expressible:
            entrants.append(_refused(entrant, setting.load))
        else:
            entrants.append(_measure(entrant, setting)[0])
    selected, front, reasons = _select(entrants)
    chosen = next((m for m in entrants if m.kind is selected), None)
    deployed = None if chosen is None else chosen.work_units_per_event
    return TournamentResult(
        tournament_id="", hypothesis_id=genome.hypothesis_id, split=Split.REPLICATION,
        entrants=tuple(entrants), pareto_front=front, selected=selected,
        deployable=selected is not None, reasons=reasons,
        discovery_work_units=discovery_work_units, deployed_work_units_per_event=deployed,
        compression_ratio=discovery_compression_ratio(discovery_work_units, deployed),
        knowledge_bytes_saved=None if chosen is None or chosen.artifact_bytes is None
        else research_state_bytes - chosen.artifact_bytes,
        synthetic_data=any(e.context.synthetic for e in episodes),
    )


# --- §85 conservation checks ---------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ConservationReport:
    """Where a compressed form stopped honouring a distinction the theory draws.

    ``checks_run`` counts (entrant, check) pairs that measured something, so a report with
    no failure over zero checks is visibly vacuous; ``unmeasured`` names each check that had
    nothing to run on (``<KIND>:<check>``), never counted as held.
    """

    hypothesis_id: str
    entrants_checked: int
    checks_run: int
    failures: tuple[FailureCondition, ...]
    unmeasured: tuple[str, ...]


def _doppelganger_share(decide: Callable[[Episode], bool],
                        doppelgangers: Sequence[Episode]) -> float | None:
    if not doppelgangers:
        return None
    return sum(bool(decide(episode)) for episode in doppelgangers) / len(doppelgangers)


def _separation_threshold(genome: HypothesisGenome) -> float:
    for falsifier in genome.falsification_tests:
        if falsifier.kind is FalsifierKind.DOPPELGANGER_SEPARATION:
            return falsifier.threshold
    return DEFAULT_DOPPELGANGER_SHARE


def _metamorphic(detector: Detector, lab_pool: Sequence[Episode], seed: int,
                 governor: ResearchGovernor) -> tuple[MetamorphicResult, ...]:
    """Every entrant sees the same transformed worlds: a fresh RNG from one seed each."""
    meter = GovernedMeter(governor, CONSERVATION_COMPONENT)
    return run_metamorphic(lambda episode: detector.decide(episode, meter), lab_pool,
                           DEFAULT_RELATIONS, rng=random.Random(seed), governor=governor)


def _relation_failures(kind: RepresentationKind, mine: Sequence[MetamorphicResult],
                       theirs: Sequence[MetamorphicResult],
                       relations: Sequence[MetamorphicRelation]
                       ) -> tuple[list[FailureCondition], int, list[str]]:
    """Failures where the reference holds a relation and the entrant does not."""
    worst: dict[str, tuple[float | None, list[str]]] = {}
    run, unmeasured = 0, []
    for relation, own, ref in zip(relations, mine, theirs, strict=True):
        if own.holds is None:
            unmeasured.append(f"{kind.value}:{relation.relation_id}")
            continue
        run += 1
        if ref.holds is True and own.holds is False:
            nuisance = relation.expectation is Expectation.INVARIANT
            code = "NUISANCE" if nuisance else "NECESSARY_EVENT"
            fallen = (None if own.support_before == 0 else
                      (own.support_before - own.support_after) / own.support_before)
            rate = own.agreement if nuisance else fallen
            prior = worst.get(code, (rate, []))
            low = rate if prior[0] is None or (rate is not None and rate < prior[0]) else prior[0]
            worst[code] = (low, [*prior[1], relation.relation_id])
    failures = [FailureCondition(f"conservation:{kind.value}_{code}", rate,
                                 ("fails " + ",".join(ids) + " that TYPED_RULE holds")[:160])
                for code, (rate, ids) in sorted(worst.items())]
    return failures, run, unmeasured


def conservation_checks(
    genome: HypothesisGenome, compiled: Sequence[CompiledDetector], *,
    lab_pool: Sequence[Episode], doppelgangers: Sequence[Episode], seed: int,
    governor: ResearchGovernor,
) -> ConservationReport:
    """Architecture §85, per expressible non-reference entrant, judged against TYPED_RULE:
    nuisance invariance and necessary-event removal (the metamorphic laboratory's default
    relations on LAB_POOL) and doppelgänger separation (only where TYPED_RULE separates)."""
    by_kind = _checked_entrants(genome, compiled)
    reference = load_detector(by_kind[RepresentationKind.TYPED_RULE])
    ref_results = _metamorphic(reference, lab_pool, seed, governor)
    threshold = _separation_threshold(genome)
    ref_share = _doppelganger_share(lambda e: reference.decide(e), doppelgangers)
    separates = ref_share is not None and ref_share <= threshold
    failures: list[FailureCondition] = []
    unmeasured: list[str] = []
    checked = run = 0
    for kind in RepresentationKind:
        entrant = by_kind[kind]
        if kind is RepresentationKind.TYPED_RULE or not entrant.expressible:
            continue
        detector = load_detector(entrant)
        checked += 1
        own = _metamorphic(detector, lab_pool, seed, governor)
        found, ran, missing = _relation_failures(kind, own, ref_results, DEFAULT_RELATIONS)
        failures += found
        unmeasured += missing
        run += ran
        if not separates:
            unmeasured.append(f"{kind.value}:doppelganger")
            continue
        run += 1
        share = _doppelganger_share(lambda e, d=detector: d.decide(e), doppelgangers)
        if share is not None and share > threshold:
            failures.append(FailureCondition(
                f"conservation:{kind.value}_DOPPELGANGER", share,
                "matches benign doppelgangers that TYPED_RULE separates"))
    return ConservationReport(genome.hypothesis_id, checked, run, tuple(failures),
                              tuple(unmeasured))


# --- the endpoint footprint ----------------------------------------------------------


@dataclass(frozen=True, slots=True)
class EndpointFootprint:
    """What loading and running the selected artifacts cost this process, in-process.

    ``incremental_rss_bytes`` is the highest RSS observed inside the block (the sampler's
    samples and the end-of-block reading) minus the start RSS, floored at 0; ``None`` when
    RSS is unreadable. ``within_ceiling`` is exactly that figure's comparison with
    :data:`STAGE8_ENDPOINT_INCREMENTAL_CEILING_BYTES`, or ``None`` (UNMEASURED) — never a
    guess. A dev-host figure, not a device measurement.
    """

    detectors: int
    events: int
    incremental_rss_bytes: int | None
    peak_sampled_rss_bytes: int | None
    within_ceiling: bool | None
    work_units_per_event: float | None
    wall_seconds: float
    loadavg: tuple[float, float, float]

    def __post_init__(self) -> None:
        for name in ("detectors", "events"):
            _require_count(getattr(self, name), f"EndpointFootprint.{name}")
        if self.incremental_rss_bytes is None:
            if self.within_ceiling is not None:
                raise ContractError("within_ceiling must be None when RSS is UNMEASURED")
            return
        _require_count(self.incremental_rss_bytes, "incremental_rss_bytes")
        expected = self.incremental_rss_bytes <= STAGE8_ENDPOINT_INCREMENTAL_CEILING_BYTES
        if self.within_ceiling is not expected:
            raise ContractError(
                f"within_ceiling={self.within_ceiling} contradicts {self.incremental_rss_bytes} B "
                f"against the {STAGE8_ENDPOINT_INCREMENTAL_CEILING_BYTES} B ceiling")


def _shipped(packages: Sequence[DiscoveryPackageV1]) -> list[CompiledDetector]:
    out: list[CompiledDetector] = []
    for package in packages:
        if not isinstance(package, DiscoveryPackageV1):
            raise ContractError("measure_endpoint_footprint reads DiscoveryPackageV1 values")
        problems = verify_package(package)
        if problems:
            raise ContractError(f"refusing to measure an unverified package: {problems[0]}")
        if package.selected_representation is None or package.compiled_artifact is None:
            continue  # nothing ships for this package
        artifact = package.compiled_artifact
        out.append(CompiledDetector(package.selected_representation, True, None, artifact,
                                    len(canonical_artifact_bytes(artifact))))
    return out


def measure_endpoint_footprint(packages: Sequence[DiscoveryPackageV1],
                               episodes: Sequence[Episode]) -> EndpointFootprint:
    """Load every selected artifact with :func:`load_detector` and run it over ``episodes``,
    inside Stage 0's ``ResourceSampler`` — the endpoint-side figure of G8.11. The episodes
    are already resident (an endpoint holds its own telemetry); only the detectors are new."""
    shipped = _shipped(packages)
    events = tuple(episodes)
    if any(not isinstance(e, Episode) for e in events):
        raise ContractError("measure_endpoint_footprint runs over Episode values")
    meter = WorkMeter()
    sampler = ResourceSampler()
    with sampler:
        detectors = [load_detector(entry) for entry in shipped]
        for episode in events:
            for detector in detectors:
                detector.decide(episode, meter)
    metrics = sampler.result(events_processed=len(events), startup_seconds=None)
    start = metrics.idle_rss_bytes
    seen = [value for value in (
        metrics.peak_sampled_rss_bytes,
        None if start is None or metrics.delta_rss_bytes is None
        else start + metrics.delta_rss_bytes,
    ) if value is not None]
    peak = max(seen) if seen else None
    incremental = None if start is None or peak is None else max(0, peak - start)
    return EndpointFootprint(
        detectors=len(shipped), events=len(events), incremental_rss_bytes=incremental,
        peak_sampled_rss_bytes=peak,
        within_ceiling=None if incremental is None
        else incremental <= STAGE8_ENDPOINT_INCREMENTAL_CEILING_BYTES,
        work_units_per_event=meter.spent / len(events) if events else None,
        wall_seconds=metrics.wall_seconds, loadavg=loadavg(),
    )
