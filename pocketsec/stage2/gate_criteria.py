"""What each Stage 2 gate criterion actually measures.

Split out of ``gate.py`` so that file stays what it claims to be: one context,
thirteen criteria, one verdict each. Everything here returns numbers — a Brier
pair, a coverage figure, an attribution row, a built candidate — and decides
nothing. Read a criterion in ``gate.py``; read how it was measured here.

Stdlib only, like the gate itself: the CI ``gate`` job installs no numpy.
"""

from __future__ import annotations

import ast
import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pocketsec.stage0.contracts.common import ContractError, EvidenceRef
from pocketsec.stage0.experiments.ids import format_experiment_id, parse_experiment_id
from pocketsec.stage1.pipeline import Stage1Pipeline
from pocketsec.stage2.adaptation.epoch_guard import (
    AdaptationPolicy,
    AdaptationRun,
    run_adaptation,
)
from pocketsec.stage2.adaptation.promotion import PromotionController
from pocketsec.stage2.adaptation.quarantine import QuarantineBuffer
from pocketsec.stage2.compile_candidates.candidate import (
    CandidateStability,
    CompileCandidateV1,
    MeasuredCost,
)
from pocketsec.stage2.compile_candidates.phi_oracle_candidate import (
    PHI_ORACLE_SCORER,
    phi_oracle_candidate,
)
from pocketsec.stage2.credit.ledger import CausalCreditLedger, chain_recall, naive_ancestry
from pocketsec.stage2.counterfactual.twin import counterfactual_probe
from pocketsec.stage2.gate_measures import (
    DRIFT_EPOCH_SIGNALS,
    CompiledSplit,
    build_lattice,
    cone_distribution,
    fold_state,
    hazard_base_rates,
    hazard_truth,
    lineage_windows,
    lineage_windows_with_signatures,
    multiclass_brier,
    next_transition,
    positions,
    walk,
)
from pocketsec.stage2.core_ids import ExecutionPath
from pocketsec.stage2.labs.drift_corpus import build_drift_corpus, malicious_lineage
from pocketsec.stage2.lattice.quantizer import BehaviourQuantizer
from pocketsec.stage2.lattice.transitions import TransitionLattice
from pocketsec.stage2.predictors.future_cone import (
    branch_label,
    marginal_cone,
    predict_future_cone,
)
from pocketsec.stage2.predictors.hazard import (
    HORIZONS,
    OUTCOME_DIMENSIONS,
    constant_hazard,
    estimate_security_hazard,
)
from pocketsec.stage2.router.accounting import WorkKind, WorkLedger
from pocketsec.stage2.state.window import WindowStore
from pocketsec.stage2.uncertainty.calibration import expected_calibration_error
from pocketsec.stage2.uncertainty.conformal import SplitConformal

__all__ = [
    "CHEAP_PATHS",
    "EXPENSIVE_PATHS",
    "Adaptation",
    "ConformalCoverage",
    "adaptation_run",
    "adr_naming",
    "attribution_rows",
    "cone_briers",
    "conformal_coverage",
    "hazard_scores",
    "imported_modules",
    "phi_candidate",
    "scorer_microseconds",
    "phi_oracle_scores",
    "rejects_unevidenced_candidates",
    "research_imports",
]

#: Counterfactual probes cost ~1.2 ms each (measured by the credit package), and
#: G2.7 needs sessions, not a sweep. Bounded so the gate stays runnable.
ATTRIBUTION_SESSIONS = 4

#: Refusal reasons that mean "seen often, still not corroborated".
FREQUENCY_REFUSALS = frozenset(
    {"frequency_alone", "insufficient_observations", "not_eligible"}
)

#: G2.5's nominal conformal level, quoted by the gate beside the measured one.
NOMINAL_COVERAGE = 0.9

#: Paths a router would call cheap. Used only to compare a *proposal* with what
#: the ledger proves ran — and, in `runtime_pass`, unreachable by construction:
#: a mandatory WINDOW_UPDATE floors every event at P2_LOCAL (S2-05/S2-FC-06).
CHEAP_PATHS = frozenset(
    {ExecutionPath.P0_COMPILED.value, ExecutionPath.P1_LATTICE.value}
)

#: Paths that mean predictive inference or deeper actually ran. Unlike
#: ``CHEAP_PATHS`` this is reachable, so a fraction taken over it can
#: distinguish a working router from a broken one.
EXPENSIVE_PATHS = frozenset(
    {ExecutionPath.P3_PREDICTIVE.value, ExecutionPath.P4_DEEP.value}
)

#: The drift corpus and poison suite are their own fixtures, run at their own
#: size: they measure a mechanism, not a detection frontier.
ROBUSTNESS_COUNT = 24
TEST_SEED = 11

#: Where a measured rejection is recorded. The gate reads the filename only to
#: confirm the ADR exists beside a measurement it reproduced itself.
ADR_DIR = Path(__file__).resolve().parents[2] / "docs" / "adr"


def _mean(values: list[float]) -> float | None:
    """The mean, or ``None`` when there was nothing to average. Never 0.0."""
    return sum(values) / len(values) if values else None


def phi_oracle_scores(split: CompiledSplit) -> tuple[tuple[int, ...], tuple[float, ...]]:
    """Per session: the Φ-oracle scorer's output and the scenario's own label.

    This is the score Stage 2 *exports* (``PHI_ORACLE_SCORER``, the first
    crystallisation target), so calibrating it calibrates a real Stage 2 output
    rather than a research model's.
    """
    labels: list[int] = []
    scores: list[float] = []
    for label, transitions in split.labelled:
        store = WindowStore()
        best = 0.0
        for transition in transitions:
            window = store.update_multiscale_state(transition)
            best = max(best, PHI_ORACLE_SCORER.evaluate(window))
        labels.append(label)
        scores.append(best)
    return tuple(labels), tuple(scores)


@dataclass(frozen=True, slots=True)
class ConformalCoverage:
    """G2.5's conformal measurement *with* the state of the reservoir it came from.

    ``saturated``, ``evictions`` and ``residuals`` travel beside ``coverage``
    because the reservoir is bounded and a coverage figure measured on a
    subsampled reservoir is an estimate. G2.5 used to receive only
    ``(coverage, radius, samples)``, so the gate could not tell a calibration
    result from an artefact of the bound, and its verdict string blamed the
    predictor for a number the reservoir's own eviction policy produced
    (S2-04).
    """

    coverage: float | None
    radius: float | None
    samples: int
    residuals: int
    observed: int
    evictions: int
    saturated: bool

    def provenance(self) -> str:
        """One clause naming the reservoir the coverage figure was measured on."""
        return (
            f"reservoir held {self.residuals} of {self.observed} residuals, "
            f"{self.evictions} subsampled away, saturated={self.saturated}"
        )


def conformal_coverage(ctx: Stage2GateContext) -> ConformalCoverage:
    """Split conformal over a *continuous* Stage 2 prediction.

    A two-sided interval on a binary label is vacuous by construction (ADR-0117),
    so the target here is the atom's expected ΔΦ against the ΔΦ the next
    transition actually produced. The quantizer keeps adapting while the held-out
    split is walked, which strains the exchangeability conformal assumes; the
    number is reported with that caveat rather than without it.
    """
    quantizer = BehaviourQuantizer()
    residuals = [
        abs(_expected_delta_phi(quantizer, step.previous_atom) - step.transition.delta_phi)
        for step in walk(quantizer, ctx.train.sessions)
        if step.previous_atom is not None
    ]
    conformal = SplitConformal(nominal_coverage=NOMINAL_COVERAGE)
    if not residuals:
        return ConformalCoverage(
            coverage=None,
            radius=None,
            samples=0,
            residuals=0,
            observed=0,
            evictions=0,
            saturated=False,
        )
    conformal.fit(residuals)
    predicted: list[float] = []
    realised: list[float] = []
    for step in walk(quantizer, ctx.test.sessions):
        if step.previous_atom is None:
            continue
        predicted.append(_expected_delta_phi(quantizer, step.previous_atom))
        realised.append(step.transition.delta_phi)
    coverage = conformal.coverage(realised, predicted)  # type: ignore[arg-type]
    radius = conformal.quantile()
    return ConformalCoverage(
        coverage=coverage,
        radius=None if radius is None else round(radius, 6),
        samples=len(predicted),
        residuals=conformal.residual_count(),
        observed=conformal.observed(),
        evictions=conformal.evictions(),
        saturated=conformal.saturated(),
    )


def _expected_delta_phi(quantizer: Any, atom_id: int) -> float:
    atom = quantizer.get(atom_id)
    return 0.0 if atom is None else float(atom.delta_phi_mean)


def cone_briers(ctx: Stage2GateContext) -> tuple[float | None, float | None, int]:
    """Cone branch Brier against the epoch-marginal control, one step ahead."""
    quantizer = BehaviourQuantizer()
    lattice, _ = build_lattice(quantizer, ctx.train.sessions)
    successor = next_transition(ctx.test.sessions)
    cone_scores: list[float] = []
    marginal_scores: list[float] = []
    for step in walk(quantizer, ctx.test.sessions):
        following = successor.get(id(step.transition))
        if following is None:
            continue
        actual = branch_label(step.state, fold_state(step.state, following))
        cone = predict_future_cone(
            lattice,
            quantizer,
            from_atom=step.result.atom_id,
            state=step.state,
            epoch_id=step.transition.epoch_id,
            max_depth=1,
        )
        control = marginal_cone(
            lattice,
            epoch_id=step.transition.epoch_id,
            quantizer=quantizer,
            state=step.state,
        )
        cone_scores.append(multiclass_brier(cone_distribution(cone), actual))
        marginal_scores.append(multiclass_brier(cone_distribution(control), actual))
    return (
        _mean(cone_scores),
        _mean(marginal_scores),
        len(cone_scores),
    )


def hazard_scores(
    ctx: Stage2GateContext,
) -> tuple[float | None, float | None, float | None, float | None, int]:
    """Hazard Brier and ECE against the empirical per-bucket base rate."""
    quantizer = BehaviourQuantizer()
    lattice, _ = build_lattice(quantizer, ctx.train.sessions)
    control = constant_hazard(hazard_base_rates(ctx.train.sessions))
    where = positions(ctx.test.sessions)
    hazard_scores: list[float] = []
    control_scores: list[float] = []
    truths: list[int] = []
    hazard_p: list[float] = []
    control_p: list[float] = []
    for step in walk(quantizer, ctx.test.sessions):
        session, index = where[id(step.transition)]
        cone = predict_future_cone(
            lattice,
            quantizer,
            from_atom=step.result.atom_id,
            state=step.state,
            epoch_id=step.transition.epoch_id,
        )
        report = estimate_security_hazard(cone, lattice, state=step.state)
        for outcome in OUTCOME_DIMENSIONS:
            for horizon in HORIZONS:
                estimate = report.for_outcome(outcome, horizon)
                baseline = control.for_outcome(outcome, horizon)
                if estimate is None or baseline is None:
                    continue
                truth = hazard_truth(session, index, outcome, horizon)
                truths.append(truth)
                hazard_p.append(estimate.probability)
                control_p.append(baseline.probability)
                hazard_scores.append((estimate.probability - truth) ** 2)
                control_scores.append((baseline.probability - truth) ** 2)
    return (
        _mean(hazard_scores),
        _mean(control_scores),
        expected_calibration_error(truths, hazard_p),
        expected_calibration_error(truths, control_p),
        len(hazard_scores),
    )


def attribution_rows() -> list[dict[str, Any]]:
    """Credit spine against naive ancestry on the drift corpus's attack sessions."""
    scenarios = [
        scenario
        for scenario in build_drift_corpus(count=ROBUSTNESS_COUNT, seed=TEST_SEED)
        if malicious_lineage(scenario)
    ][:ATTRIBUTION_SESSIONS]
    rows: list[dict[str, Any]] = []
    for scenario in scenarios:
        pipeline = Stage1Pipeline()
        result = pipeline.run_scenario(scenario, offset=0)
        lineage = malicious_lineage(scenario)
        truth = frozenset(
            t.causal_signature for t in result.transitions if t.actor.identity == lineage
        )
        if not truth:
            continue
        rows.append(_attribute_one_session(pipeline, result.transitions, truth))
    return rows


def _attribute_one_session(
    pipeline: Stage1Pipeline, transitions: tuple[Any, ...], truth: frozenset[str]
) -> dict[str, Any]:
    quantizer = BehaviourQuantizer()
    lattice, _ = build_lattice(quantizer, (transitions,))
    nodes = {node.signature: node for node in naive_ancestry(pipeline.causal)}
    ledger = CausalCreditLedger(probe_budget=len(transitions) + 1)
    for window, signatures in lineage_windows_with_signatures(transitions):
        for index in range(len(window.steps)):
            probe = counterfactual_probe(window, quantizer, lattice, target_index=index)
            # Keyed on the probed transition's real causal signature, NOT on
            # `probe.target_signature`, which is a positional locator
            # (`lineage:index:rN:mM`) that can never equal a 16-hex
            # `CausalNode.signature`. That lookup never matched, so
            # `assign_causal_credit` was never called and the ledger stayed
            # empty for a reason unrelated to divergence (S2-FC-01).
            node = nodes.get(signatures[index])
            if node is not None:
                ledger.assign_causal_credit(probe, node)
    report = ledger.report(pipeline.causal, ground_truth=truth)
    naive_recall = chain_recall(frozenset(nodes), ground_truth=truth)
    return {
        "nodes_inspected": report.nodes_inspected,
        "naive_nodes": report.naive_ancestry_nodes,
        "recall": report.chain_recall,
        "naive_recall": naive_recall,
        "concise_at_equal_recall": bool(
            report.nodes_inspected < report.naive_ancestry_nodes
            and report.chain_recall is not None
            and naive_recall is not None
            and report.chain_recall >= naive_recall
        ),
    }


@dataclass(frozen=True, slots=True)
class Adaptation:
    """One adaptation run with the objects that recorded it, not only its counts."""

    run: AdaptationRun
    buffer: QuarantineBuffer
    controller: PromotionController

    @property
    def refusal_reasons(self) -> dict[str, int]:
        reasons: dict[str, int] = {}
        for record in self.controller.refusals():
            reasons[record.reason] = reasons.get(record.reason, 0) + 1
        return reasons

    @property
    def frequency_alone_refused(self) -> bool:
        """Did the gate actually refuse a pattern for frequency without corroboration?

        Promotion requires distinct corroborated epochs; frequency is explicitly
        insufficient (spec section 37). A refusal counter above zero is the
        evidence the rule fired rather than sitting untested on this corpus.
        """
        return any(
            count > 0
            for reason, count in self.refusal_reasons.items()
            if reason in FREQUENCY_REFUSALS
        )


def adaptation_run(scenarios: Any, attack: Any, policy: AdaptationPolicy) -> Adaptation:
    buffer = QuarantineBuffer()
    controller = PromotionController()
    run = run_adaptation(
        scenarios,
        quantizer=BehaviourQuantizer(),
        epoch_signals=DRIFT_EPOCH_SIGNALS,
        lattice=TransitionLattice(),
        policy=policy,
        buffer=buffer,
        controller=controller,
        attack_lineage=attack,
    )
    return Adaptation(run=run, buffer=buffer, controller=controller)


def scorer_microseconds(ctx: Stage2GateContext, *, repeats: int = 3) -> float | None:
    """Time ``PHI_ORACLE_SCORER`` over the gate's own windows, best of N, PER EVENT.

    The candidate's cost has to be the cost of the artefact being exported, not
    of a research model that happens to compute the same thing. Best-of-N rather
    than the mean: the minimum is the figure least polluted by unrelated load,
    and this host is shared.

    The denominator is the number of scored **steps**, not of windows.
    ``DeterministicScorerSpec.evaluate`` builds a column over every row of
    ``window.features()``, so one evaluation is O(steps in the window); dividing
    the total by ``len(windows)`` produced microseconds per *window* and handed
    it to a field named ``microseconds_per_event``. Measured on the gate's own
    split (292 windows, 4357 steps, 14.92 steps/window): 7.3718 under the old
    denominator against 0.4940 per step — overstated by the mean window length,
    which varies with session length, so the same zero-parameter scorer reported
    a different "cost" on every corpus (S2-FC-05). ``baselines.py`` already
    documents the rule this now follows: per transition, because "events" is the
    unit every other cost figure in this repository uses.
    """
    windows = [
        window
        for _, transitions in ctx.test.labelled
        for window in lineage_windows(transitions)
    ]
    steps = sum(len(window.steps) for window in windows)
    if not windows or steps == 0:
        return None
    best = None
    for _ in range(repeats):
        started = time.perf_counter()
        for window in windows:
            PHI_ORACLE_SCORER.evaluate(window)
        elapsed = time.perf_counter() - started
        best = elapsed if best is None else min(best, elapsed)
    return None if best is None else best / steps * 1e6


def phi_candidate(ctx: Stage2GateContext) -> CompileCandidateV1:
    """The Φ-oracle as a candidate, costed from this run's own measurement."""
    evidence = tuple(
        EvidenceRef(store="stage1.evidence", locator=locator, digest=digest)
        for locator, digest in _gate_evidence(ctx)
    )
    return phi_oracle_candidate(
        cost=MeasuredCost(
            microseconds_per_event=scorer_microseconds(ctx),
            parameters=0,
            bytes_on_disk=len(json.dumps(PHI_ORACLE_SCORER.to_dict()).encode("utf-8")),
            # UNMEASURED, deliberately. This used to carry
            # `ctx.resources["metrics"]["peak_sampled_rss_bytes"]` — the peak RSS
            # of the whole Stage 2 runtime pass, sampled over the process while a
            # WindowStore, a learned BehaviourQuantizer (the layer ADR-0115
            # disabled), a lattice, a cache, cone expansion and uncertainty
            # estimation all ran. None of that is the scorer, which holds four
            # scalars and allocates one list per window. Attributing the stage's
            # footprint to a zero-parameter candidate would be a fabricated
            # measurement in an exported artefact, and unmeasured is not measured
            # (S2-FC-09). Nothing in this repository isolates the scorer's RSS
            # yet, so the field is None until something does.
            peak_rss_bytes=None,
            measured_by="pocketsec.stage2.gate_criteria:scorer_microseconds",
        ),
        experiment_id=_gate_experiment_id(),
        evidence=evidence,
        stability=CandidateStability(
            observations=ctx.cached.events,
            distinct_epochs=len({t.epoch_id for t in ctx.test.flat}) or 1,
            reruns_agreeing=1,
            reruns_total=1,
            drift_invalidations=0,
        ),
        epochs=sorted({t.epoch_id for t in ctx.test.flat}) or [0],
    )


def _gate_evidence(ctx: Stage2GateContext) -> tuple[tuple[str, str], ...]:
    """Evidence refs from the corpus this gate actually ran, never invented."""
    refs: list[tuple[str, str]] = []
    for transition in ctx.test.flat:
        for ref in transition.evidence:
            refs.append((ref.locator, ref.digest))
            if len(refs) >= 4:  # noqa: PLR2004 - a lineage sample, not the whole corpus
                return tuple(refs)
    return tuple(refs)


def _gate_experiment_id() -> str:
    """A well-formed id for the gate's own run. Minted, deliberately not registered.

    ``experiments/registry.jsonl`` is append-only and digest-chained; a gate that
    appended on every invocation would fill the research ledger with duplicate
    runs of the same synthetic corpus. ``python -m pocketsec.stage2.research.cli
    report --register`` records a measured run; the gate only needs an id that
    parses, and G2.12 reads the ledger to see whether one was recorded.
    """
    return format_experiment_id(stage=2, hypothesis="H8", slug="stage2-gate", sequence=7)


def rejects_unevidenced_candidates(candidate: CompileCandidateV1) -> list[str]:
    """A candidate with no evidence or an unparseable experiment id must raise."""
    problems: list[str] = []
    for label, kwargs in (
        ("empty evidence_lineage", {"evidence_lineage": ()}),
        ("unparseable experiment_id", {"experiment_id": "not-an-experiment-id"}),
    ):
        try:
            _replace_candidate(candidate, **kwargs)
        except ContractError:
            continue
        problems.append(f"{label} was accepted; it must be rejectable by construction")
    return problems


def _replace_candidate(candidate: CompileCandidateV1, **overrides: Any) -> CompileCandidateV1:
    fields: dict[str, Any] = {
        "candidate_id": candidate.candidate_id,
        "kind": candidate.kind,
        "boundary": candidate.boundary,
        "evidence_lineage": candidate.evidence_lineage,
        "cost": candidate.cost,
        "experiment_id": candidate.experiment_id,
        "payload": candidate.payload,
        "stability": candidate.stability,
    }
    fields.update(overrides)
    return CompileCandidateV1(**fields)


def imported_modules(node: ast.AST, path: Path) -> list[str]:
    """Every module an import node names, as an ABSOLUTE dotted path.

    The single implementation of import resolution for every boundary checker in
    this repository — the G2.13 seam check below and the structural tests in
    ``tests/test_repository_structure.py`` both call it, so the hole cannot be
    closed in one and left open in the other.

    That hole was real (S2-AUTH-01). Every checker matched on ``node.module``
    verbatim, which is the *relative* name for a relative import: a runtime
    module writing ``from .research import dtl`` yields ``node.module ==
    "research"``, which matches neither ``pocketsec.stage2.research`` nor
    ``.research``; and ``from . import research`` yields ``node.module is None``
    with the name on the alias, which the ``and node.module`` guard dropped
    entirely. numpy and the offline research code could therefore reach the
    endpoint runtime through the back door with CI green and G2.13 reporting
    zero offenders. ``node.level`` and the file's own position under
    ``pocketsec/`` are what resolve it, so both are used here.
    """
    if isinstance(node, ast.Import):
        return [alias.name for alias in node.names]
    if not isinstance(node, ast.ImportFrom):
        return []
    if node.level == 0:
        return [node.module] if node.module else []
    package = _package_of(path, node.level)
    if package is None:  # pragma: no cover - a file outside pocketsec/
        return [node.module] if node.module else [a.name for a in node.names]
    if node.module:
        return [f"{package}.{node.module}" if package else node.module]
    # `from . import x` / `from .. import x`: the names are the modules.
    return [f"{package}.{alias.name}" if package else alias.name for alias in node.names]


def _package_of(path: Path, level: int) -> str | None:
    """The absolute package a ``level``-deep relative import resolves against."""
    parts = path.resolve().parts
    if "pocketsec" not in parts:
        return None
    root = len(parts) - 1 - parts[::-1].index("pocketsec")
    # The containing package, then one step up per extra dot.
    package = list(parts[root:-1])
    climb = level - 1
    if climb > len(package):
        return None
    return ".".join(package[: len(package) - climb])


def research_imports(package: Path) -> list[str]:
    """AST seam check: nothing under ``package`` may import research code."""
    offenders: list[str] = []
    for path in sorted(package.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            modules = imported_modules(node, path)
            if any(
                module == "research" or ".research." in f"{module}." for module in modules
            ):
                offenders.append(f"{path.name}:{node.lineno}")
    return offenders


def adr_naming(token: str) -> str:
    """The ADR filename recording a measured decision about ``token``, if any."""
    for path in sorted(ADR_DIR.glob("*.md")):
        if token in path.name and "rejected" in path.name:
            return path.name
    return ""


# --- the gate's own measurement helpers --------------------------------------
#
# Moved here from `gate.py` because this module's docstring is the rule: "Read a
# criterion in gate.py; read how it was measured here." Every function below
# returns a number, a fraction or a reason string and decides nothing. `gate.py`
# re-exports them, so a caller or a test may reach them by either name.


def _pct(value: float | None) -> str:
    """A fraction, or the word UNMEASURED. Never a plausible-looking stand-in."""
    return "UNMEASURED" if value is None else f"{value:.4f}"


def _us(value: float | None) -> str:
    return "UNMEASURED" if value is None else f"{value:.2f}"


def _cheap_fraction(paths: Any) -> float | None:
    total = sum(paths.values())
    if total == 0:
        return None
    return sum(count for name, count in paths.items() if name in CHEAP_PATHS) / total


def _expensive_fraction(paths: Any) -> float | None:
    """Events whose derived path was predictive or deeper. Never pinned.

    The complement of this is NOT ``_cheap_fraction``: P2_LOCAL sits between
    them, and the mandatory window update puts every event there at minimum.
    Keeping the two separate is what stops a reader treating "0.0000 cheap" as
    "nothing was avoided".
    """
    total = sum(paths.values())
    if total == 0:
        return None
    return sum(count for name, count in paths.items() if name in EXPENSIVE_PATHS) / total


def _skipped_inference_fraction(ledger: WorkLedger) -> float | None:
    """Events for which the ledger proves the core inference did not run.

    Proven, not claimed: an account counts only when it holds a skipped
    ``CORE_INFERENCE`` record and no performed one, which is the same condition
    ``assert_no_phantom_savings`` refuses the inverse of.
    """
    accounts = ledger.accounts()
    if not accounts:
        return None
    skipped = 0
    for account in accounts:
        kinds_performed = {r.kind for r in account.work if r.performed}
        kinds_skipped = {r.kind for r in account.work if not r.performed}
        if (
            WorkKind.CORE_INFERENCE in kinds_skipped
            and WorkKind.CORE_INFERENCE not in kinds_performed
        ):
            skipped += 1
    return skipped / len(accounts)


def _phantom_savings_reason(ledger: WorkLedger) -> str:
    """Empty string when the ledger proves no skip was banked over real work."""
    try:
        ledger.assert_no_phantom_savings()
    except (ContractError, AssertionError, ValueError) as exc:
        return f"PHANTOM SAVINGS: {exc}"
    return ""


def _phantom_check_refuses_a_fake() -> bool:
    """The criterion says a bad number may pass but a *fakeable* one may not.

    So the gate fabricates exactly the ADR-0010 defect — a path reported skipped
    while the work ran — and requires the ledger to refuse it. A check that only
    ran the honest path could not tell an honest ledger from a credulous one.
    """
    ledger = WorkLedger()
    ledger.begin("fabricated")
    ledger.record(WorkKind.CORE_INFERENCE, performed=False, units=0.0, detail="claimed skip")
    ledger.record(WorkKind.CORE_INFERENCE, performed=True, units=40.0, detail="but it ran")
    ledger.close()
    return _phantom_savings_reason(ledger) != ""


def _sequence_of(experiment_id: str) -> int:
    """The trailing counter of a registered experiment id, or -1 if it will not parse."""
    try:
        return parse_experiment_id(experiment_id).sequence
    except (ValueError, ContractError):
        return -1


def _round(value: float | None, digits: int = 6) -> float | str:
    """A measured figure, or the word UNMEASURED. Never a plausible stand-in."""
    return "UNMEASURED" if value is None else round(value, digits)
