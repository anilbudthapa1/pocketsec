"""D3.2 — the CRYSTAL candidate loop (architecture §33), in that exact order.

::

    I = DiscoverInvariant(R)
    B = InferBoundary(I, R)
    candidates = SynthesizeOperators(I, B)
    K = CheapestCandidateMeetingInitialConstraints(candidates)
    while budget remains:
        x = BoundaryPressure(K, oracle, security_spec)
        if violates_hard_security_property(K, x):  K = RefineOrFission(K, x); continue
        if security_divergence(K, x) > epsilon(x): K = RefineOrFission(K, x); continue
        if resolution_and_boundary_coverage_sufficient(K): break
    if not qualified(K): return region_to_DTL(R)

Three properties of this module are not negotiable, because in each case the
obvious shortcut would be a security failure.

**:func:`crystallize` never promotes.** It returns a :class:`CrystalRun` and the
caller decides. Promotion needs the assurance pipeline (D3.11), which applies
checks this module does not — notably the guard that ``AssuranceLevel.A5`` may
only be claimed for a property the verifier actually proves. A pipeline that
promoted its own output would route around that guard. ``field`` is read here
for its occupancy and never written.

**Every non-``PROMOTED`` outcome records a counterexample**, including
``RETURNED_TO_LEARNING``. §21 makes counterexamples the regression corpus; a
refusal that left no trace would be re-discovered on every replay.

**UNMEASURED never passes.** A divergence that could not be computed is ``None``
and is treated as *not shown to be below epsilon*, never as zero. The same rule
governs resolution: an unmeasured axis fails its threshold rather than being
skipped.

One limitation, stated because §33's next line invites the mistake: the
pseudocode continues into ``ShadowExecute(K)``, which belongs to the
``lifecycle`` package. ``CrystalRun.shadow`` is therefore always ``None`` here
and the coverage check uses boundary breadth measured by this run.
``PROMOTED`` means *qualified for shadow and promotion*, not promoted.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field as dataclass_field, replace
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    EvidenceRef,
    digest_of_bytes,
)
from pocketsec.stage1.ssir.transition import SSIRTransitionV1
from pocketsec.stage1.state.security_state import StateDelta
from pocketsec.stage3.boundary.index import CellBoundary
from pocketsec.stage3.cells.masks import BoundaryKey
from pocketsec.stage3.boundary.pressure import (
    BoundaryPressureReport,
    Perturbation,
    PressureStrategy,
    apply_boundary_pressure,
)
from pocketsec.stage3.bytecode.vm import CellResult, CellVM
from pocketsec.stage3.cells.frame import CellFrame
from pocketsec.stage3.cells.field import MAX_CELLS, KnowledgeField
from pocketsec.stage3.cells.fission import fission_cell
from pocketsec.stage3.cells.invariant import Invariant, SemanticPredicate
from pocketsec.stage3.cells.operator import OperatorForm, OperatorProgram
from pocketsec.stage3.cells.schema import (
    AssuranceLevel,
    AuditPolicy,
    CellPhase,
    HardConstraint,
    KnowledgeCellV1,
)
from pocketsec.stage3.invariants.discovery import discover_invariants
from pocketsec.stage3.oracles.counterexamples import Counterexample, CounterexampleStore
from pocketsec.stage3.oracles.dual_oracle import DualOracleEvaluator, DualOracleVerdict
from pocketsec.stage3.oracles.teacher import TeacherOracle
from pocketsec.stage3.synthesis.operators import SYNTHESISERS, OperatorSample
from pocketsec.stage3.synthesis.selector import (
    OperatorCandidate,
    admissible_candidates,
    measure_candidate,
    select_operator_form,
)
from pocketsec.stage3.theory import (
    ResolutionState,
    SecurityConsequence,
    consequence_of,
    crystallization_allowed,
)

if TYPE_CHECKING:  # pragma: no cover - annotation only; lifecycle owns ShadowRun
    from pocketsec.stage3.promotion.shadow import ShadowRun

__all__ = [
    "DEFAULT_EPSILON_BY_CONSEQUENCE",
    "DEFAULT_SHADOW_MIN_COVERAGE",
    "MAX_PRESSURE_BUDGET",
    "MAX_REFINEMENTS",
    "CrystalConfig",
    "CrystalOutcome",
    "CrystalRun",
    "RegionSample",
    "crystallize",
]

#: §33 bounds, restated as constants so the config cannot quietly widen them.
MAX_PRESSURE_BUDGET = 4096
MAX_REFINEMENTS = 8

#: Tolerance tightens with consequence; CRITICAL gets none, because the only
#: acceptable disagreement about a critical future is no disagreement.
DEFAULT_EPSILON_BY_CONSEQUENCE: Mapping[SecurityConsequence, float] = {
    SecurityConsequence.ROUTINE: 0.10,
    SecurityConsequence.ELEVATED: 0.05,
    SecurityConsequence.HIGH: 0.01,
    SecurityConsequence.CRITICAL: 0.0,
}

#: Minimum distinct boundary keys before a region may crystallise. Coverage is
#: breadth, never event count (§26).
DEFAULT_SHADOW_MIN_COVERAGE: Mapping[SecurityConsequence, int] = {
    SecurityConsequence.ROUTINE: 1,
    SecurityConsequence.ELEVATED: 2,
    SecurityConsequence.HIGH: 4,
    SecurityConsequence.CRITICAL: 8,
}


class CrystalOutcome(StrEnum):
    """Why the loop stopped.

    ``PROMOTED`` means *qualified for promotion*: this module does not promote.
    """

    PROMOTED = "PROMOTED"
    REFUSED_RESOLUTION = "REFUSED_RESOLUTION"
    REFUSED_HARD_CONSTRAINT = "REFUSED_HARD_CONSTRAINT"
    REFUSED_DIVERGENCE = "REFUSED_DIVERGENCE"
    RETURNED_TO_LEARNING = "RETURNED_TO_LEARNING"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"


@dataclass(frozen=True, slots=True)
class CrystalConfig:
    """Bounds for one crystallisation attempt. Validated, not trusted."""

    seed: int
    pressure_budget: int = 256
    max_refinements: int = 8
    #: Which Boundary Pressure search the loop uses. The default is the strategy
    #: ADR-0026 **retained**, not the one it removed. The loop hard-coded
    #: ``GUIDED`` while the accepted ADR said "random_replay_control is the
    #: retained strategy" and "nothing in the promotion path depends on guided
    #: search"; both were false, and the direction of the error flattered the
    #: cell, because the guided walk breaks out of an axis on its first
    #: divergence while the non-diverging steps before it stay in
    #: ``predictive_stability``'s denominator. Measured strategy-dependence for
    #: the same cell and budget is recorded in ADR-0026's amendment.
    strategy: PressureStrategy = PressureStrategy.RANDOM_REPLAY
    epsilon_by_consequence: Mapping[SecurityConsequence, float] = dataclass_field(
        default_factory=lambda: dict(DEFAULT_EPSILON_BY_CONSEQUENCE)
    )
    shadow_min_coverage: Mapping[SecurityConsequence, int] = dataclass_field(
        default_factory=lambda: dict(DEFAULT_SHADOW_MIN_COVERAGE)
    )

    def __post_init__(self) -> None:
        if not isinstance(self.strategy, PressureStrategy):
            raise ContractError(
                f"CrystalConfig.strategy must be a PressureStrategy, got {self.strategy!r}"
            )
        if not 1 <= self.pressure_budget <= MAX_PRESSURE_BUDGET:
            raise ContractError(f"pressure_budget must be in 1..{MAX_PRESSURE_BUDGET}")
        if not 0 <= self.max_refinements <= MAX_REFINEMENTS:
            raise ContractError(f"max_refinements must be in 0..{MAX_REFINEMENTS}")
        for name, mapping in (
            ("epsilon_by_consequence", self.epsilon_by_consequence),
            ("shadow_min_coverage", self.shadow_min_coverage),
        ):
            missing = set(SecurityConsequence) - set(mapping)
            if missing:
                names = sorted(m.name for m in missing)
                raise ContractError(f"{name} is not closed: missing {names}")


@dataclass(frozen=True, slots=True)
class RegionSample:
    """The unit CRYSTAL tries to compile: one behavioural region plus evidence.

    Defined here because no other Stage 3 package owns it and it is exactly the
    input to this loop. It carries its own evidence and constraints so that a
    cell built from it can never be assembled without lineage.
    """

    region_key: BoundaryKey
    samples: tuple[OperatorSample, ...]
    evidence: tuple[EvidenceRef, ...]
    constraints: tuple[HardConstraint, ...]
    epochs: frozenset[int]
    #: Element type is owned by the ``invariants`` package; passed through
    #: untouched to ``discover_invariants``.
    sessions: tuple[Any, ...] = ()
    transitions: tuple[SSIRTransitionV1, ...] = ()
    source_candidate_id: str | None = None

    def __post_init__(self) -> None:
        if not self.samples:
            raise ContractError("a region with no samples is not a region")
        if not self.evidence:
            raise ContractError("a region with no evidence is not compilable")
        if not self.epochs:
            raise ContractError("a region with no epoch is valid nowhere")
        # KnowledgeCellV1 refuses an unconstrained cell, so a region carrying no
        # hard constraint could only fail later, inside the synthesis loop,
        # where the reason would read as a synthesis failure rather than a
        # missing security contract.
        if not self.constraints:
            raise ContractError(
                "a region with no hard constraint has nothing that could fail it, "
                "which is not the same as safe"
            )
        # A refusal has to be replayable. `Counterexample.transitions` is
        # non-empty by contract, so a region that carries no transitions could
        # only fail silently, and a silent refusal is re-learned forever.
        if not self.transitions:
            raise ContractError(
                "a region with no transitions cannot record a replayable counterexample"
            )

    @property
    def frames(self) -> tuple[CellFrame, ...]:
        return tuple(sample.frame for sample in self.samples)

    @property
    def candidate_id(self) -> str:
        """Identifier-safe join key for this region's counterexamples."""
        if self.source_candidate_id:
            return self.source_candidate_id
        return "region-" + digest_of_bytes(str(self.region_key).encode())[7:31]

    @property
    def consequence(self) -> SecurityConsequence:
        """The worst consequence in the region. A region is as grave as its peak."""
        return max(
            (consequence_of(s.delta, s.frame.state) for s in self.samples),
            default=SecurityConsequence.ROUTINE,
        )


@dataclass(frozen=True, slots=True)
class CrystalRun:
    """One attempt, recorded whether it succeeded or not."""

    region_key: BoundaryKey
    invariant: Invariant | None
    boundary: CellBoundary | None
    candidates_tried: tuple[OperatorForm, ...]
    selected: OperatorCandidate | None
    pressure: BoundaryPressureReport | None
    dual_oracle: DualOracleVerdict | None
    shadow: ShadowRun | None
    outcome: CrystalOutcome
    counterexamples: tuple[Counterexample, ...]
    reason: str
    cell: KnowledgeCellV1 | None = None
    resolution: ResolutionState | None = None

    @property
    def qualified(self) -> bool:
        return self.outcome is CrystalOutcome.PROMOTED


def _abstained(evidence: tuple[EvidenceRef, ...], reason: str) -> CellResult:
    return CellResult(
        abstained=True,
        delta=StateDelta(raised={}),
        evidence=evidence,
        risk=0.0,
        escalation=None,
        steps_taken=0,
        reason=reason,
    )


def _record(
    store: CounterexampleStore,
    region: RegionSample,
    *,
    outcome: CrystalOutcome,
    reason: str,
    seed: int,
    observed: CellResult | None = None,
) -> Counterexample:
    """Persist the refusal. §21: a refusal with no trace is re-learned forever.

    The identity covers the seed as well as the region and the reason, so two
    *different* attempts are two records. Re-running the *same* attempt returns
    the record already held rather than raising: counterexample ids are
    permanent and never reused, so an idempotent replay must find the original,
    not manufacture a second copy of it.
    """
    head = region.samples[0]
    identity = hashlib.sha256(
        f"{region.region_key}|{seed}|{outcome.value}|{reason}".encode()
    ).hexdigest()[:24]
    existing = {cx.counterexample_id: cx for cx in store.for_candidate(region.candidate_id)}
    already = existing.get(f"cx-{identity}")
    if already is not None:
        return already
    counterexample = Counterexample(
        counterexample_id=f"cx-{identity}",
        cell_candidate_id=region.candidate_id,
        transitions=tuple(region.transitions),
        state=head.frame.state,
        epoch_id=head.frame.epoch_id,
        expected=CellResult(
            abstained=head.abstain,
            delta=head.delta,
            evidence=head.frame.evidence,
            risk=head.risk,
            escalation=None,
            steps_taken=0,
            reason="region target",
        ),
        observed=observed or _abstained(region.evidence, reason),
        divergence_type=outcome.value,
        evidence=region.evidence,
        incident_linked=False,
        superseded_by=None,
    )
    store.record(counterexample)
    return counterexample


def _satisfied_predicates(
    region: RegionSample, invariant: Invariant, scaffold: CellBoundary
) -> tuple[SemanticPredicate, ...]:
    """Antecedent terms that hold on *every* frame in the region.

    A predicate the region violates cannot be part of the region's boundary: the
    boundary is what the cell was validated on, and validating a cell on frames
    that sit outside its own boundary is how a rule ends up silently
    extrapolating (§10). Terms are dropped rather than the boundary widened.
    """
    kept: list[SemanticPredicate] = []
    for predicate in invariant.antecedent:
        probe = replace(scaffold, predicates=(predicate,))
        if all(probe.contains(sample.frame) for sample in region.samples):
            kept.append(predicate)
    return tuple(kept)


def _infer_boundary(region: RegionSample, invariant: Invariant) -> CellBoundary:
    """B(K) from the invariant's antecedent and the region's observed extent.

    Returns a boundary whose predicate list may be empty; the caller refuses
    that case, because a boundary with no semantic term claims the whole host.
    """
    phis = [s.frame.phi for s in region.samples]
    dimensions: set[str] = set()
    for sample in region.samples:
        dimensions |= set(sample.delta.dimensions)
    scaffold = CellBoundary(
        predicates=(),
        state_dimensions=frozenset(dimensions) or invariant.consequent.required_dimensions,
        phi_range=(min(phis), max(phis)),
        max_uncertainty=max(s.frame.uncertainty for s in region.samples),
        epochs=region.epochs,
        forbidden_combinations=(),
        unseen_input_behaviour="ABSTAIN",
    )
    return replace(scaffold, predicates=_satisfied_predicates(region, invariant, scaffold))


def _provisional_cell(
    region: RegionSample,
    invariant: Invariant,
    boundary: CellBoundary,
    candidate: OperatorProgram,
) -> KnowledgeCellV1:
    """A cell that exists only to be pressured. It is never inserted anywhere."""
    return KnowledgeCellV1(
        cell_id=f"cand-{hashlib.sha256(candidate.digest.encode()).hexdigest()[:20]}",
        invariant=invariant,
        boundary=boundary,
        operator=candidate,
        resolution=_zero_resolution(),
        confidence=0.0,
        assurance=AssuranceLevel.A0,
        phase=CellPhase.STRUCTURED,
        evidence_lineage=region.evidence,
        constraints=region.constraints,
        epochs=region.epochs,
        audit_policy=AuditPolicy(
            base_rate=0.05, min_rate=0.001, max_rate=1.0, jitter_salt=str(region.region_key)
        ),
        version=1,
        parent_cell_id=None,
        # ``candidate_id`` rather than ``source_candidate_id``: it is the identity
        # ``_record`` files this region's counterexamples under, and carrying it on
        # the cell is what lets ``melting.stress.open_counterexamples`` find them
        # later. When the region came from Stage 2 the two are the same string; when
        # it did not, this is the ``region-<digest>`` key, and storing ``None``
        # instead left 30% of the melt-trigger score structurally zero for every
        # CRYSTAL-built cell.
        source_candidate_id=region.candidate_id,
    )


def _zero_resolution() -> ResolutionState:
    """Resolution before anything is measured — deliberately unqualifying."""
    return ResolutionState(
        predictive_stability=0.0, calibrated_uncertainty=1.0, validated_breadth=0,
        counterfactual_consistency=0.0, evidence_agreement=0.0, drift_stability=0,
        measured_by="pocketsec.stage3.crystal.pipeline:_zero_resolution",
    )


def _synthesize(region: RegionSample) -> tuple[tuple[OperatorForm, OperatorProgram], ...]:
    """Run every bounded synthesiser. A refusal is a ``None`` and is dropped."""
    produced: list[tuple[OperatorForm, OperatorProgram]] = []
    for form, synthesiser in SYNTHESISERS:
        program = synthesiser(region.samples)
        if program is not None:
            produced.append((form, program))
    return tuple(produced)


def _measure_all(
    region: RegionSample,
    invariant: Invariant,
    boundary: CellBoundary,
    programs: Sequence[tuple[OperatorForm, OperatorProgram]],
    evaluator: DualOracleEvaluator,
    vm: CellVM,
) -> tuple[OperatorCandidate, ...]:
    candidates: list[OperatorCandidate] = []
    for _form, program in programs:
        cell = _provisional_cell(region, invariant, boundary, program)
        verdict = evaluator.evaluate(cell, region.frames)
        candidates.append(
            measure_candidate(program, region.frames, equivalence=verdict, vm=vm)
        )
    return tuple(candidates)


def _resolution_from_run(
    region: RegionSample,
    report: BoundaryPressureReport | None,
    verdict: DualOracleVerdict,
    *,
    substituted: float,
) -> ResolutionState:
    """Every term below is produced by this run; nothing is defaulted upward.

    ``substituted`` is passed in rather than computed here because it can be
    UNMEASURED, and ``ResolutionState`` holds floats: the caller refuses before
    building a state rather than substituting a number for "not probed".
    """
    probes = report.probes_run if report else 0
    divergences = len(report.divergences) if report else 0
    stability = 1.0 - (divergences / probes) if probes else 0.0
    covered = {
        (int(s.frame.relation_family), s.frame.actor_properties, s.delta.bitmask())
        for s in region.samples
    }
    # E comes from Oracle B's own evidence-requirement divergence rather than
    # from a recount here: a second definition of "the evidence agreed" would
    # drift from the one the dual oracle actually enforces.
    agreement = 1.0 - min(1.0, max(0.0, verdict.divergence.d_evidence_requirement))
    return ResolutionState(
        predictive_stability=max(0.0, min(1.0, stability)),
        calibrated_uncertainty=max(s.frame.uncertainty for s in region.samples),
        validated_breadth=len(covered),
        counterfactual_consistency=substituted,
        evidence_agreement=agreement,
        drift_stability=len(region.epochs),
        measured_by="pocketsec.stage3.crystal.pipeline:crystallize",
    )


def _substitution_consistency(report: BoundaryPressureReport | None) -> float | None:
    """Fraction of actor-substitution probes that did *not* diverge, or UNMEASURED.

    ``None`` when no probe moved along that axis — which is routine, because
    ACTOR_SUBSTITUTION is sixth of the seven in ``AXIS_ORDER`` and a
    budget-limited guided walk never reaches it. ``None`` propagates as a refusal
    in :func:`_resolution_round`; it is never a number.

    The denominator is the probes that actually moved *this* axis, from
    ``BoundaryPressureReport.probes_on``. It used to be ``report.probes_run`` —
    the total over all seven axes — which diluted the term by the ratio of total
    probes to actor probes: a region whose outcome depends entirely on which
    actor acted, with its single actor probe diverging, read 0.98 instead of 0.0
    and cleared the ELEVATED bar. §9's prohibition on a cell learning an identity
    rather than a property is the one thing this term exists to catch.

    The old early return also tested ``report.probes_run``, so an unprobed actor
    axis returned exactly the 1.0 the docstring called dishonest.
    """
    if report is None:
        return None
    probes = report.probes_on(Perturbation.ACTOR_SUBSTITUTION)
    if not probes:
        return None
    diverged = report.divergences_on(Perturbation.ACTOR_SUBSTITUTION)
    return max(0.0, min(1.0, 1.0 - diverged / probes))


def _refine_or_fission(
    cell: KnowledgeCellV1,
    report: BoundaryPressureReport | None,
    *,
    region: RegionSample,
    field: KnowledgeField,
    depth: int,
    counterexamples: Sequence[Counterexample],
) -> tuple[KnowledgeCellV1 | None, int, str]:
    """Split if a heterogeneous region is identifiable; otherwise tighten.

    Tightening narrows the Φ range and the uncertainty ceiling toward the probes
    that agreed. It never widens anything: a refinement that enlarged the
    boundary would be answering the counterexample by claiming more ground.
    """
    if counterexamples:
        outcome = fission_cell(cell, counterexamples, depth=depth, field=field)
        if outcome.stable is not None:
            return outcome.stable, depth + 1, f"fission: {outcome.reason}"
    if report is not None and report.near_boundary_errors:
        low, high = cell.boundary.phi_range
        margin = (high - low) * 0.25
        tightened = replace(
            cell.boundary,
            phi_range=(low + margin, high - margin),
            max_uncertainty=cell.boundary.max_uncertainty * 0.5,
        )
        if tightened.phi_range[0] > tightened.phi_range[1] or tightened.is_empty:
            return None, depth, "refinement collapsed the boundary to nothing"
        return replace(cell, boundary=tightened, version=cell.version + 1), depth, "tightened"
    return None, depth, "no refinement available for this divergence"


def _discover_and_bound(attempt: _Attempt) -> _Attempt | CrystalRun:
    """§33 steps 1-2: DiscoverInvariant then InferBoundary, or the refusal."""
    region = attempt.region
    invariants = discover_invariants(region.sessions) if region.sessions else ()
    if not invariants:
        return _finish(
            attempt, CrystalOutcome.RETURNED_TO_LEARNING,
            "NO_INVARIANT: discovery found nothing to compile",
        )
    invariant = invariants[0]
    boundary = _infer_boundary(region, invariant)
    found = replace(attempt, invariant=invariant, boundary=boundary)
    if boundary.is_empty:
        return _finish(
            replace(found, boundary=None), CrystalOutcome.RETURNED_TO_LEARNING,
            "EMPTY_BOUNDARY: the inferred boundary contains nothing",
        )
    if not boundary.predicates:
        # No antecedent term survived the region, so the invariant does not
        # describe it. A boundary with no semantic term claims the whole host.
        return _finish(
            found, CrystalOutcome.RETURNED_TO_LEARNING,
            "NO_SATISFIED_PREDICATE: the invariant does not describe this region",
        )
    return found


def crystallize(
    region: RegionSample,
    *,
    config: CrystalConfig,
    teacher: TeacherOracle,
    field: KnowledgeField,
    store: CounterexampleStore,
) -> CrystalRun:
    """Run §33 over one region. Returns a run; the caller decides what to do."""
    attempt = _Attempt(
        region=region, store=store, config=config,
        consequence=region.consequence, field=field,
    )
    if len(field.cells()) >= MAX_CELLS:
        reason = f"FIELD_FULL: {len(field.cells())} of {MAX_CELLS} cells"
        return _finish(attempt, CrystalOutcome.RETURNED_TO_LEARNING, reason)

    discovered = _discover_and_bound(attempt)
    if isinstance(discovered, CrystalRun):
        return discovered
    attempt = discovered

    programs = _synthesize(region)
    attempt = replace(attempt, tried=tuple(form for form, _ in programs))
    if not programs:
        return _finish(
            attempt, CrystalOutcome.RETURNED_TO_LEARNING,
            "NO_OPERATOR: every bounded synthesiser refused this region",
        )

    vm = CellVM()
    attempt = replace(attempt, evaluator=DualOracleEvaluator(teacher=teacher, vm=vm))
    assert attempt.evaluator is not None and attempt.invariant is not None
    assert attempt.boundary is not None
    candidates = _measure_all(
        region, attempt.invariant, attempt.boundary, programs, attempt.evaluator, vm
    )
    selected = select_operator_form(candidates, constraints=region.constraints)
    if selected is None:
        return _rejected_selection(attempt, candidates)
    return _pressure_loop(replace(attempt, selected=selected))


def _rejected_selection(
    attempt: _Attempt, candidates: tuple[OperatorCandidate, ...]
) -> CrystalRun:
    """Distinguish "violated an invariant" from "was never measured"."""
    admissible = admissible_candidates(candidates, constraints=attempt.region.constraints)
    if not admissible:
        outcome = CrystalOutcome.REFUSED_HARD_CONSTRAINT
        reason = "HARD_VIOLATION: every candidate violated a hard security constraint"
    else:
        outcome = CrystalOutcome.REFUSED_RESOLUTION
        reason = "UNMEASURED: no admissible candidate carried a measured cost"
    verdict = candidates[0].equivalence if candidates else None
    return _finish(attempt, outcome, reason, verdict=verdict)


@dataclass(frozen=True, slots=True)
class _Attempt:
    """What the pressure loop needs and never changes between rounds.

    Bundled so the terminal assembler takes four arguments instead of twelve: a
    long positional call list is where ``report`` silently becomes ``verdict``.
    """

    region: RegionSample
    store: CounterexampleStore
    config: CrystalConfig
    consequence: SecurityConsequence
    field: KnowledgeField
    #: Filled in as §33 proceeds, so a refusal at any step assembles the same way.
    invariant: Invariant | None = None
    boundary: CellBoundary | None = None
    tried: tuple[OperatorForm, ...] = ()
    selected: OperatorCandidate | None = None
    evaluator: DualOracleEvaluator | None = None


@dataclass(frozen=True, slots=True)
class _Round:
    """One pressure round's outcome: either terminal, or a refined cell."""

    run: CrystalRun | None
    cell: KnowledgeCellV1 | None
    report: BoundaryPressureReport | None
    verdict: DualOracleVerdict | None
    resolution: ResolutionState | None
    remaining: int
    depth: int


def _finish(
    attempt: _Attempt,
    outcome: CrystalOutcome,
    reason: str,
    *,
    report: BoundaryPressureReport | None = None,
    verdict: DualOracleVerdict | None = None,
    resolution: ResolutionState | None = None,
    cell: KnowledgeCellV1 | None = None,
) -> CrystalRun:
    """Assemble the run, recording a counterexample unless it qualified."""
    recorded: tuple[Counterexample, ...] = ()
    if outcome is not CrystalOutcome.PROMOTED:
        recorded = (
            _record(
                attempt.store, attempt.region,
                outcome=outcome, reason=reason, seed=attempt.config.seed,
            ),
        )
    return CrystalRun(
        region_key=attempt.region.region_key,
        invariant=attempt.invariant,
        boundary=attempt.boundary,
        candidates_tried=attempt.tried,
        selected=attempt.selected,
        pressure=report,
        dual_oracle=verdict,
        shadow=None,
        outcome=outcome,
        counterexamples=recorded,
        reason=reason,
        cell=cell,
        resolution=resolution,
    )


def _refined(
    attempt: _Attempt,
    cell: KnowledgeCellV1,
    report: BoundaryPressureReport | None,
    depth: int,
    *,
    outcome: CrystalOutcome,
    reason: str,
    verdict: DualOracleVerdict | None,
    resolution: ResolutionState | None = None,
) -> _Round:
    """RefineOrFission, or the terminal run when nothing can be refined."""
    # Keyed on the region, which is the identity ``_record`` files every
    # counterexample under. Looking them up by ``cell.cell_id`` — the provisional
    # ``cand-<sha256(program.digest)[:20]>`` minted in ``_provisional_cell`` —
    # searched a keyspace nothing writes to, so the list was always empty, the
    # ``fission_cell`` branch below was unreachable from ``crystallize``, and a
    # heterogeneous region carrying standing counterexamples was reported as
    # having "no refinement available".
    refined, next_depth, note = _refine_or_fission(
        cell, report, region=attempt.region, field=attempt.field, depth=depth,
        counterexamples=attempt.store.for_candidate(attempt.region.candidate_id),
    )
    if refined is None:
        run = _finish(
            attempt, outcome, f"{reason}; {note}",
            report=report, verdict=verdict, resolution=resolution,
        )
        return _Round(run, None, report, verdict, resolution, 0, next_depth)
    return _Round(None, refined, report, verdict, resolution, 0, next_depth)


def _round(
    attempt: _Attempt, cell: KnowledgeCellV1, *, remaining: int, index: int, depth: int
) -> _Round:
    """One iteration: pressure, then the three §33 checks in order."""
    # Seeds must already be inside the validated region: pressure walks outward
    # from something that held, and a fabricated start would make every
    # divergence a property of the fabrication.
    inside = tuple(f for f in attempt.region.frames if cell.boundary.contains(f))
    if not inside:
        reason = "NO_IN_REGION_SEED: no sample frame lies inside the inferred boundary"
        run = _finish(attempt, CrystalOutcome.REFUSED_RESOLUTION, reason)
        return _Round(run, None, None, None, None, remaining, depth)

    report = apply_boundary_pressure(
        cell, oracle=attempt.evaluator, budget=remaining,
        seed=attempt.config.seed + index, strategy=attempt.config.strategy, seeds=inside,
    )
    left = remaining - max(1, report.probes_run)
    verdict = attempt.evaluator.evaluate(cell, attempt.region.frames)

    if verdict.hard_violations:
        outcome = _refined(
            attempt, cell, report, depth,
            outcome=CrystalOutcome.REFUSED_HARD_CONSTRAINT,
            reason=f"HARD_VIOLATION: {verdict.reason}", verdict=verdict,
        )
        return replace(outcome, remaining=left)

    # UNMEASURED is not "below epsilon". None fails here exactly as a measured
    # value above the tolerance would.
    epsilon = attempt.config.epsilon_by_consequence[attempt.consequence]
    divergence = verdict.divergence.total
    if divergence is None or divergence > epsilon:
        detail = "UNMEASURED" if divergence is None else f"{divergence:.6f} > {epsilon}"
        outcome = _refined(
            attempt, cell, report, depth,
            outcome=CrystalOutcome.REFUSED_DIVERGENCE,
            reason=f"DIVERGENCE: {detail}", verdict=verdict,
        )
        return replace(outcome, remaining=left)

    return replace(_resolution_round(attempt, cell, report, verdict, depth), remaining=left)


def _resolution_round(
    attempt: _Attempt,
    cell: KnowledgeCellV1,
    report: BoundaryPressureReport,
    verdict: DualOracleVerdict,
    depth: int,
) -> _Round:
    """The resolution-and-coverage check, and what happens when it is unmet."""
    substituted = _substitution_consistency(report)
    if substituted is None:
        # UNMEASURED fails, exactly as an unmeasured divergence does. §9's
        # identity-versus-property check cannot be reported as satisfied by a run
        # that never perturbed the actor, and writing a number for it would put a
        # fabricated term into the cell's persisted ResolutionState.
        return _refined(
            attempt, cell, report, depth,
            outcome=CrystalOutcome.REFUSED_RESOLUTION,
            reason=(
                "RESOLUTION: unmet ['counterfactual_consistency: UNMEASURED — no "
                "ACTOR_SUBSTITUTION probe moved this region']"
            ),
            verdict=verdict,
        )
    resolution = _resolution_from_run(
        attempt.region, report, verdict, substituted=substituted
    )
    allowed, unmet = crystallization_allowed(resolution, attempt.consequence)
    minimum = attempt.config.shadow_min_coverage[attempt.consequence]
    if resolution.validated_breadth < minimum:
        allowed = False
        unmet = (*unmet, f"boundary_coverage {resolution.validated_breadth} < {minimum}")
    if allowed:
        run = _finish(
            attempt, CrystalOutcome.PROMOTED,
            "qualified: resolution and boundary coverage sufficient",
            report=report, verdict=verdict, resolution=resolution,
            cell=replace(cell, resolution=resolution),
        )
        return _Round(run, None, report, verdict, resolution, 0, depth)
    return _refined(
        attempt, cell, report, depth,
        outcome=CrystalOutcome.REFUSED_RESOLUTION,
        reason=f"RESOLUTION: unmet {list(unmet)}", verdict=verdict, resolution=resolution,
    )


def _pressure_loop(attempt: _Attempt) -> CrystalRun:
    """The bounded ``while budget remains`` body of §33."""
    assert attempt.invariant is not None and attempt.boundary is not None
    assert attempt.selected is not None and attempt.evaluator is not None
    cell: KnowledgeCellV1 | None = _provisional_cell(
        attempt.region, attempt.invariant, attempt.boundary, attempt.selected.program
    )
    remaining = attempt.config.pressure_budget
    depth = 0
    report: BoundaryPressureReport | None = None
    verdict: DualOracleVerdict | None = None

    for index in range(attempt.config.max_refinements + 1):
        if remaining <= 0 or cell is None:
            break
        outcome = _round(attempt, cell, remaining=remaining, index=index, depth=depth)
        report, verdict = outcome.report, outcome.verdict
        if outcome.run is not None:
            return outcome.run
        cell, remaining, depth = outcome.cell, outcome.remaining, outcome.depth

    if remaining <= 0:
        return _finish(
            attempt, CrystalOutcome.BUDGET_EXHAUSTED,
            f"BUDGET_EXHAUSTED: {attempt.config.pressure_budget} probes spent without qualifying",
            report=report, verdict=verdict,
        )
    return _finish(
        attempt, CrystalOutcome.REFUSED_RESOLUTION,
        f"REFINEMENTS_EXHAUSTED: {attempt.config.max_refinements} refinements did not qualify",
        report=report, verdict=verdict,
    )
