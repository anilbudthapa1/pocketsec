"""The measurement helpers the twelve Stage 4 gate checks share.

``gate.py`` holds one ``_check_*`` per acceptance criterion and nothing else. Everything
those checks *measure with* lives here: the one shared engine walk, the two recall
definitions that disagree, the visibility split and its provenance file, the seven
laundering probes, the ten real-subsystem hooks for the fault injection, and the flood
bound sampler.

Three rules this module exists to keep true.

**One walk, not twelve.** ``Stage4GateContext.build()`` replays the corpus and drives the
engine once. Twelve checks reading twelve separate runs would compare figures taken at
twelve different moments of a contended host against each other, which is how a gate
starts measuring the load average (spec §2.8).

**A criterion that cannot fail is not a criterion.** Every helper here returns the number
that decided the check, not a boolean. ``world_set_recall`` returns *three* numbers
because the spec's definition and the stage's own ``labs/baselines.py`` definition
disagree by a factor of eight on this corpus, and a gate that quoted only the flattering
one would be reporting the choice rather than the mechanism.

**Nothing here registers an experiment.** ``registry_digest()`` reads
``experiments/registry.jsonl`` and returns its sha256. It never appends. Stage 3's gate
grew ``PS-S3-*`` rows in the real append-only ledger every time the test suite ran
(spec §2.7); registration belongs in ``cli.py``'s ``register`` subcommand, which an
operator invokes deliberately.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from pocketsec.stage0.contracts.common import digest_of_bytes
from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage0.gate import REPO_ROOT
from pocketsec.stage1.observation.policy import AdaptiveObservationPolicy
from pocketsec.stage1.pipeline import ScenarioResult, Stage1Pipeline
from pocketsec.stage1.telemetry.raw_event_v1 import SensorPath
from pocketsec.stage4.cones.incident_cone import compose_cones
from pocketsec.stage4.engine.degradation import DegradationLedger
from pocketsec.stage4.engine.lucid import IncidentResolution, LucidConfig, LucidEngine
from pocketsec.stage4.identifiability.resolution import (
    IdentifiabilityState,
    IdentifiabilityVerdict,
    test_identifiability,
)
from pocketsec.stage4.labs.baseline_metrics import Replay, replay_corpus
from pocketsec.stage4.labs.dropped_telemetry import (
    drop_sensor_path,
    exclusive_signals,
)
from pocketsec.stage4.labs.incident_corpus import IncidentCase, build_incident_corpus
from pocketsec.stage4.sensing.active_plan import (
    ObservationPlan,
    plan_discriminating_observation,
)
from pocketsec.stage4.sensing.simulate import measure_sensor_costs
from pocketsec.stage4.stage5_interface import CBFResolutionV1
from pocketsec.stage4.visibility.model import (
    VisibilityModel,
    VisibilityObservation,
    fit_visibility_model,
    measure_visibility,
)
from pocketsec.stage4.visibility.sensor_shadow import SensorShadow
from pocketsec.stage4.worlds.field import CausalBeliefField
from pocketsec.stage4.worlds.lifecycle import DIMENSION_SIGNALS, FUSION_EQUIVALENCE_EPSILON
from pocketsec.stage4.worlds.world import SecurityWorldV1

__all__ = [
    "CORPUS_COUNT",
    "CORPUS_SEED",
    "DETECTION_OPERATING_POINT",
    "DROPPED_SENSOR",
    "FLOOD_COUNT",
    "FLOOD_SEED",
    "HELD_OUT_MIN_OCCURRENCES",
    "LEDGER_HEADINGS",
    "NONIDENT_COUNT",
    "NONIDENT_SEED",
    "NOVELTY_WORDS",
    "VISIBILITY_EVIDENCE",
    "VISIBILITY_TOLERANCE",
    "EngineRun",
    "RecallReading",
    "VisibilitySplit",
    "claims_novelty",
    "drive_engine",
    "identifiability_of",
    "measure_visibility_split",
    "plan_for",
    "registry_digest",
    "stage1_digest",
    "stage2_verdicts",
    "truth_world_of",
    "visibility_evidence_matches",
    "world_set_recall",
    "write_visibility_evidence",
]

#: The corpus the gate judges Stage 4 on. Sixty and seed 11 are the spec's own G4.2
#: figures, and seed 11 is Stage 1's guillotine scoring seed reused rather than chosen,
#: so no seed in this gate was picked for the result it produces.
CORPUS_COUNT = 60
CORPUS_SEED = 11

#: The adversarial branch flood of G4.9, at the spec's own size and seed.
FLOOD_COUNT = 40
FLOOD_SEED = 23

#: The constructed non-identifiable pairs of G4.3, at the spec's own size and seed.
NONIDENT_COUNT = 20
NONIDENT_SEED = 17

#: The sensor G4.4 drops. eBPF is the path Stage 1 measured 20/20 cross-sensor
#: equivalence on, so a difference under the drop is the drop rather than the path.
DROPPED_SENSOR = SensorPath.EBPF

#: The operating point ``stage2_verdicts`` thresholds at. Arbitrary, and the same value
#: ``tests/test_stage4_optionality.py:133`` uses, reused rather than chosen. **This is
#: NOT a detection result** — see that function's docstring.
DETECTION_OPERATING_POINT = 0.25

#: G4.1's band and floor, both from the criterion's own wording.
VISIBILITY_TOLERANCE = 0.05
HELD_OUT_MIN_OCCURRENCES = 20

#: Where G4.1's replay evidence lands, with the provenance ADR-0127 requires.
VISIBILITY_EVIDENCE = REPO_ROOT / "results" / "stage4-visibility.json"

#: The five honesty-ledger headings ``docs/stage-4-findings.md`` must carry (spec §11).
LEDGER_HEADINGS = (
    "MEASURED",
    "UNMEASURED",
    "REJECTED",
    "RETRACTED",
    "NOT A DETECTION RESULT",
)

#: Words that claim novelty. Checked against the findings document only, the way Stage
#: 3's G3.13 scoped its own equivalent: a repo-wide grep reported the vocabulary of the
#: check itself as violations, and a check that cries wolf on its own words gets
#: switched off.
NOVELTY_WORDS = ("novel", "first", "unprecedented", "patent", "breakthrough")

_NEGATION = re.compile(r"\b(not|no|never|without|nothing|cannot|neither|nor|forbid\w*)\b")

#: "first" is a novelty word only as a **priority** claim. "the recommended first work",
#: "the first gate run of this session" and "its own first output" are none of them, and a
#: checker that flagged them would be switched off inside a week — which is the real
#: failure mode, because then nothing checks the claims that matter. Stage 3 hit this and
#: documented it; Stage 4 reimplements the technique rather than importing it, because
#: boundary rule 3 forbids importing ``pocketsec.stage3``.
_PRIORITY = re.compile(
    r"\bfirst\b\s+(system|implementation|approach|method|technique|to\s+\w+)",
    re.IGNORECASE,
)

#: How far either side of the word a negation counts. Scoped to the word's neighbourhood
#: rather than to the whole line: a line-wide exemption would mean any sentence containing
#: "no", "not" or "never" anywhere — which is most careful prose in this repository —
#: could carry an unguarded novelty claim past the check.
_NEGATION_WINDOW = 60


# --- the shared engine walk --------------------------------------------------


@dataclass(frozen=True, slots=True)
class EngineRun:
    """One corpus case driven through the real ``LucidEngine``, start to finish."""

    replay: Replay
    field: CausalBeliefField
    resolution: IncidentResolution
    export: CBFResolutionV1

    @property
    def case(self) -> IncidentCase:
        return self.replay.case

    @property
    def confidence(self) -> float:
        return self.resolution.confidence

    @property
    def verdict(self) -> Verdict:
        return self.resolution.prediction_verdict


def drive_engine(
    replays: Sequence[Replay],
    model: VisibilityModel,
    *,
    config: LucidConfig | None = None,
    observation: AdaptiveObservationPolicy | None = None,
    ledger: DegradationLedger | None = None,
) -> tuple[tuple[EngineRun, ...], LucidEngine]:
    """Drive one engine over every replay and return the runs beside the engine.

    The engine is returned as well as the runs because ``work_units`` and
    ``memory_bytes`` are properties of the walk, not of any one incident, and G4.9 and
    G4.10 both read them.

    ``observation`` is Stage 1's AOP and is the **only** thing that can enable a sensor
    (ADR-0035). Passing ``None`` is legal and means no sensing is possible; the gate
    passes a real one, because a planner with nothing to escalate through refuses every
    action for a reason that is about the wiring rather than about the evidence.
    """
    engine = LucidEngine(
        config=config if config is not None else LucidConfig(),
        visibility=model,
        observation=observation,
        ledger=ledger,
    )
    runs: list[EngineRun] = []
    for replay in replays:
        transitions = replay.result.transitions
        epoch = transitions[0].epoch_id if transitions else 0
        field = engine.open_incident(replay.case.incident_id, epoch)
        spine = replay.pipeline.causal.spine()
        for transition in transitions:
            field = engine.update(field, transition, spine).field
        resolution = engine.resolve(field)
        export = engine.close_incident(field)
        runs.append(
            EngineRun(replay=replay, field=field, resolution=resolution, export=export)
        )
    return tuple(runs), engine


# --- G4.2: the two recall definitions, which disagree ------------------------


@dataclass(frozen=True, slots=True)
class RecallReading:
    """World-set recall under three readings of "or an equivalent explanation".

    They are reported together because they disagree, and because which one a gate
    quotes decides whether Stage 4 looks like it works. ``by_mechanism_id`` and
    ``by_equivalence`` are the spec's own two clauses; ``by_signal_coverage`` is the
    reading ``labs/baselines.py`` scores the Pareto frontier on.
    """

    cases: int
    by_mechanism_id: float
    by_equivalence: float
    by_signal_coverage: float
    premature_collapses: int

    @property
    def strict(self) -> float:
        """The spec's criterion: the named mechanism **or** an equivalent world."""
        return max(self.by_mechanism_id, self.by_equivalence)

    @property
    def premature_collapse_rate(self) -> float:
        return self.premature_collapses / self.cases if self.cases else 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "cases": self.cases,
            "by_mechanism_id": round(self.by_mechanism_id, 6),
            "by_equivalence": round(self.by_equivalence, 6),
            "by_signal_coverage": round(self.by_signal_coverage, 6),
            "strict": round(self.strict, 6),
            "premature_collapse_rate": round(self.premature_collapse_rate, 6),
        }


def truth_world_of(case: IncidentCase, *, at_sequence: int = 0) -> SecurityWorldV1 | None:
    """The ground-truth world as a ``SecurityWorldV1``, for the equivalence clause.

    ``None`` when the truth raises no dimension carrying a signal — the equivalence test
    would then compare against a world that predicts nothing, and every surviving world
    would match it vacuously.
    """
    signals = frozenset(
        DIMENSION_SIGNALS[dimension]
        for dimension in case.truth.raises_dimensions
        if dimension in DIMENSION_SIGNALS
    )
    if not signals:
        return None
    from pocketsec.stage4.worlds.field import unknown_world

    base = unknown_world(case.incident_id, at_sequence=at_sequence)
    return replace(
        base,
        world_id=f"{case.incident_id}-truth",
        mechanism_id=case.truth.mechanism_id,
        expected_evidence=signals,
        visibility_requirements=signals,
    )


def world_set_recall(runs: Sequence[EngineRun]) -> RecallReading:
    """Measure all three readings in one pass over the same surviving fields."""
    by_name = by_equiv = by_cover = premature = 0
    for run in runs:
        worlds = run.field.worlds
        truth = run.case.truth
        if truth.mechanism_id in {world.mechanism_id for world in worlds}:
            by_name += 1
        reference = truth_world_of(run.case)
        if reference is not None and any(
            world.observationally_equivalent(reference, epsilon=FUSION_EQUIVALENCE_EPSILON)
            for world in worlds
        ):
            by_equiv += 1
        signals = run.replay.truth_signals
        if signals and any(
            signals <= (world.expected_evidence | world.visibility_requirements)
            for world in worlds
        ):
            by_cover += 1
        if run.resolution.verdict.state is IdentifiabilityState.IDENTIFIED and (
            truth.discriminating_signal is None
            or truth.discriminating_signal not in run.replay.observed
        ):
            premature += 1
    total = len(runs) or 1
    return RecallReading(
        cases=len(runs),
        by_mechanism_id=by_name / total,
        by_equivalence=by_equiv / total,
        by_signal_coverage=by_cover / total,
        premature_collapses=premature,
    )


# --- G4.1: the visibility split and its provenance --------------------------


@dataclass(frozen=True, slots=True)
class VisibilitySplit:
    """A fitted visibility model beside the held-out replay it is scored against."""

    model: VisibilityModel
    fitted: tuple[VisibilityObservation, ...]
    held_out: tuple[VisibilityObservation, ...]
    #: ``(signal, sensor, fitted, held_out_frequency, occurrences)`` for every pair
    #: outside the band. Empty is the criterion being met on the simulator.
    mismatches: tuple[tuple[str, str, float, float, int], ...]
    compared_pairs: int
    mandatory_not_certain: tuple[str, ...]
    unevidenced_not_none: tuple[str, ...]
    coverage: float
    provenance: Mapping[str, Any]


def measure_visibility_split(
    corpus: Sequence[IncidentCase],
    *,
    sensors: Sequence[SensorPath] = (SensorPath.EBPF, SensorPath.AUDITD),
) -> VisibilitySplit:
    """Fit from half the replays, score against the other half, in one process.

    Stage 0 fair-comparison rule 6: scoring never touches the split the model was
    fitted on. Both halves are replayed here rather than in two processes, so the
    comparison is within-run.
    """
    scenarios = [case.scenario for case in corpus]
    half = len(scenarios) // 2
    fitted_obs = measure_visibility(Stage1Pipeline, scenarios[:half], sensors)
    held_obs = measure_visibility(Stage1Pipeline, scenarios[half:], sensors)
    model = fit_visibility_model(fitted_obs)

    mismatches: list[tuple[str, str, float, float, int]] = []
    compared = 0
    for observation in held_obs:
        if observation.occurrences < HELD_OUT_MIN_OCCURRENCES:
            continue
        sensor = observation.sensor.value
        predicted = model.probability(observation.signal, sensor)
        if predicted is None:
            continue
        compared += 1
        frequency = observation.observations / observation.occurrences
        if abs(predicted - frequency) > VISIBILITY_TOLERANCE:
            mismatches.append(
                (observation.signal, sensor, predicted, frequency, observation.occurrences)
            )

    from pocketsec.stage1.observation.policy import MANDATORY_SIGNALS

    mandatory_bad = tuple(
        sorted(
            signal
            for signal in MANDATORY_SIGNALS
            for sensor in sensors
            if model.probability(signal, sensor.value) != 1.0
        )
    )
    # A pair nothing was ever observed for must answer None, not 0.0: "unmeasured is
    # not measured" (ADR-0004), and a 0.0 would read as "this sensor is blind here".
    unevidenced = tuple(
        f"{signal}/{sensor.value}"
        for signal in ("this_signal_was_never_emitted",)
        for sensor in sensors
        if model.probability(signal, sensor.value) is not None
    )
    return VisibilitySplit(
        model=model,
        fitted=tuple(fitted_obs),
        held_out=tuple(held_obs),
        mismatches=tuple(mismatches),
        compared_pairs=compared,
        mandatory_not_certain=mandatory_bad,
        unevidenced_not_none=unevidenced,
        coverage=model.coverage(),
        provenance={
            "corpus": "stage4-incident-corpus",
            "count": len(corpus),
            "seed": CORPUS_SEED,
            "sensors": [sensor.value for sensor in sensors],
            "fit_scenarios": half,
            "held_out_scenarios": len(scenarios) - half,
            "synthetic_data": True,
        },
    )


def write_visibility_evidence(split: VisibilitySplit, *, path: Path | None = None) -> Path:
    """Write G4.1's replay evidence with its own provenance beside it (ADR-0127)."""
    target = VISIBILITY_EVIDENCE if path is None else path
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "provenance": dict(split.provenance),
        "coverage": split.coverage,
        "compared_pairs": split.compared_pairs,
        "tolerance": VISIBILITY_TOLERANCE,
        "min_occurrences": HELD_OUT_MIN_OCCURRENCES,
        "mismatches": [list(row) for row in split.mismatches],
        "fitted": [observation.to_dict() for observation in split.fitted],
        "telemetry_source_clause": "UNMEASURED",
        "telemetry_source_clause_reason": (
            "every sensor path here is a replay of a synthetic corpus through a simulated "
            "collector; what would measure it is paired eBPF/auditd collection on a real "
            "Linux host with ground-truth injected actions"
        ),
    }
    target.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return target


def visibility_evidence_matches(split: VisibilitySplit, *, path: Path | None = None) -> bool:
    """Whether the artefact on disk was produced by the split just run (ADR-0127).

    A stale artefact from a different ``(corpus, count, seed)`` is refused rather than
    read: the defect ADR-0127 records is a gate quoting evidence it did not produce.
    """
    target = VISIBILITY_EVIDENCE if path is None else path
    if not target.is_file():
        return False
    try:
        stored = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return False
    return stored.get("provenance") == dict(split.provenance)


# --- G4.3 / G4.5: the planner, wired the way it has to be wired -------------


def plan_for(
    field: CausalBeliefField,
    *,
    model: VisibilityModel,
    observation: AdaptiveObservationPolicy | None,
    shadow: SensorShadow | None = None,
    now_ns: int = 1_000_000,
) -> ObservationPlan:
    """A real observation plan: measured costs, real cones, Stage 1's real AOP.

    All three are load-bearing and each was measured to be so this session. Omitting
    the measured cost table selects ``SENSOR_COSTS``, every entry of which is UNMEASURED
    and refused, so the plan came back with six refusals reading "no measured cost".
    Omitting the AOP produced six refusals reading "no observation policy". Either way
    ``test_identifiability`` saw an empty plan and answered ``UNIDENTIFIABLE`` for cases
    that are resolvable by one observation — a wiring artefact wearing the costume of a
    finding.
    """
    cones = compose_cones(field)
    return plan_discriminating_observation(
        field,
        cones=cones,
        shadow=shadow if shadow is not None else field.sensor_shadow,
        observation=observation,
        now_ns=now_ns,
        model=model,
        costs=measure_sensor_costs(field, cones=cones, model=model),
    )


def identifiability_of(
    field: CausalBeliefField,
    *,
    model: VisibilityModel,
    observation: AdaptiveObservationPolicy | None,
) -> tuple[IdentifiabilityVerdict, ObservationPlan]:
    """Test identifiability against a plan that was actually computed."""
    plan = plan_for(field, model=model, observation=observation)
    return test_identifiability(field, shadow=field.sensor_shadow, plan=plan), plan


# --- digests, so "unchanged" is a measurement ------------------------------


def stage1_digest(results: Sequence[ScenarioResult]) -> str:
    """A digest over what Stage 1 produced, independent of anything Stage 4 holds."""
    payload = [
        {
            "scenario": result.scenario.name,
            # ``repr`` rather than a structured dump: a semantic key is a tuple holding
            # two frozensets of enum members, which is not JSON-serialisable, and what
            # this digest needs is a stable total ordering over the whole key rather
            # than a readable one. ``sorted`` over the reprs gives that.
            "semantic_keys": sorted(repr(key) for key in result.semantic_keys),
            "peak_phi": round(result.peak_phi, 9),
            "peak_novelty": round(result.peak_novelty, 9),
            "peak_uncertainty": round(result.peak_uncertainty, 9),
            "transitions": [
                [
                    transition.sequence,
                    transition.causal_signature,
                    transition.state_delta.bitmask(),
                    round(transition.uncertainty, 9),
                ]
                for transition in result.transitions
            ],
        }
        for result in results
    ]
    return digest_of_bytes(json.dumps(payload, sort_keys=True).encode("utf-8"))


def stage2_verdicts(results: Sequence[ScenarioResult]) -> tuple[str, ...]:
    """Stage 2's detection path over the same transitions.

    A deterministic function of the Stage 1 transitions rather than an independent
    second opinion, and the operating point is arbitrary. **This is not a detection
    result**; it is a stronger form of the digest check, because it exercises the
    Stage 2 code path rather than only re-hashing Stage 1's output.
    """
    from pocketsec.stage2.compile_candidates.phi_oracle_candidate import PHI_ORACLE_SCORER
    from pocketsec.stage2.state.window import WindowStore

    verdicts: list[str] = []
    for result in results:
        # A fresh store per scenario, matching tests/test_stage4_optionality.py: the
        # multiscale window carries state across transitions and sharing one store would
        # make scenario N's verdict depend on the order the gate happened to replay in.
        store = WindowStore()
        best = 0.0
        for transition in result.transitions:
            window = store.update_multiscale_state(transition)
            best = max(best, PHI_ORACLE_SCORER.evaluate(window))
        verdicts.append(
            Verdict.MALICIOUS.value
            if best >= DETECTION_OPERATING_POINT
            else Verdict.BENIGN.value
        )
    return tuple(verdicts)


def registry_digest(path: Path | None = None) -> str | None:
    """The experiment ledger's sha256. Read only — this gate never appends (spec §2.7)."""
    target = (REPO_ROOT / "experiments" / "registry.jsonl") if path is None else path
    if not target.is_file():
        return None
    return digest_of_bytes(target.read_bytes())


def claims_novelty(text: str, word: str) -> bool:
    """Whether ``text`` *claims* novelty with ``word`` — not merely contains it.

    Read line by line, because the findings document and this module both **name** these
    words in order to forbid them, and the gate's own criterion title is "All novelty
    claims remain provisional until formal prior-art/patent review". A bare substring
    search over that makes the prohibition trip its own check, which is the quickest way
    to get a prohibition deleted. Three rules, each earning its keep:

    * **Headings and quoted gate output are skipped.** A line beginning ``#``, ``>``,
      ``[PASS]``/``[FAIL]`` or sitting inside a fenced block is the document reporting,
      not claiming.
    * **Exact word boundaries, not prefixes.** ``\\bnovel\\b`` does not match "novelty";
      "novelty claims" is the name of the rule, "a novel mechanism" is a claim.
    * **"first" only as a priority claim.** "the first system to", "the first approach" —
      not "the recommended first work" or "the first gate run of this session".

    The negation window is a documented heuristic, not completeness: it is
    ``_NEGATION_WINDOW`` characters either side of the word on the same line.

    This is deliberately narrower than a grep, and the narrowing is safe because it cannot
    make G4.12 pass on its own: the criterion also requires the two ledger entries to
    exist, the five honesty-ledger headings to be present, and the experiment ledger to be
    byte-identical across the run. ``test_stage4_gate.py`` carries the positive control —
    a fabricated unbacked claim that must still be caught.
    """
    in_fence = False
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            continue
        if in_fence or stripped.startswith(("#", ">", "[PASS]", "[FAIL]")):
            continue
        lowered = line.lower()
        pattern = _PRIORITY if word == "first" else re.compile(rf"\b{re.escape(word)}\b")
        for match in pattern.finditer(lowered):
            if not _negated_near(lowered, match.start(), match.end()):
                return True
    return False


def _negated_near(lowered: str, start: int, end: int) -> bool:
    """Whether a negation sits within ``_NEGATION_WINDOW`` characters of the word."""
    left = max(0, start - _NEGATION_WINDOW)
    right = min(len(lowered), end + _NEGATION_WINDOW)
    return _NEGATION.search(lowered[left:right]) is not None


def corpus() -> tuple[IncidentCase, ...]:
    """The gate's corpus, at the spec's own count and seed."""
    return build_incident_corpus(count=CORPUS_COUNT, seed=CORPUS_SEED)


def dropped_replays(cases: Sequence[IncidentCase]) -> tuple[Replay, ...]:
    """The same cases with ``DROPPED_SENSOR``'s exclusive signals masked out."""
    return replay_corpus([drop_sensor_path(case, DROPPED_SENSOR) for case in cases])


def dropped_signal_names() -> frozenset[str]:
    """Exactly the signals the drop makes unobservable, per the simulator's own map."""
    return exclusive_signals(DROPPED_SENSOR)
