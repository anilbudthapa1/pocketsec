"""B2 through B8 — §7's baselines that use no belief field at all.

Split from ``labs/baselines.py`` on the line that matters: these seven use **no
world, no claim graph and no LUCID loop**, so they are the controls for whether any
of that machinery is needed. B1 and the mechanism live beside each other in
``labs/baselines.py`` because B1 *is* the mechanism with ``max_worlds=1``, and that
identity is only credible if it is literally the same code path.

All stdlib, all scoring the same :class:`~pocketsec.stage4.labs.baseline_metrics.Replay`
bundles in the same process, with ``/proc/loadavg`` recorded on every outcome. Two of
§42's named baselines (a DBN and a tiny GNN) cannot be built under ADR-0030 and are
declared in ``labs/baselines.py``'s ``UNBUILDABLE_BASELINES`` rather than faked: a slow
or wrong baseline flatters the mechanism, which is how Stage 2's detached projection
scored 0.55 before it was fixed to 0.94.
"""

from __future__ import annotations

import math
import time
from collections.abc import Mapping, Sequence
from typing import Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.state.potential import phi
from pocketsec.stage4.engine.lucid import LucidConfig, LucidEngine
from pocketsec.stage4.labs.baseline_metrics import (
    HMM_STATES,
    PHI_TREE,
    WINDOW_BUCKET,
    BaselineOutcome,
    Replay,
    accuracy_of,
    efficiency_of,
    loadavg,
    predicted_label,
)
from pocketsec.stage4.sensing.active_plan import SensorAction
from pocketsec.stage4.sensing.simulate import signal_discrimination, signal_payload_bytes
from pocketsec.stage4.visibility.model import DIMENSION_SIGNALS, VisibilityModel

__all__ = [
    "always_on_rich_telemetry",
    "fixed_window_correlation",
    "information_gain_planner",
    "naive_ancestry",
    "no_stage4",
    "phi_threshold_playbook",
    "two_state_hmm",
]


# --- B2 ----------------------------------------------------------------------


def naive_ancestry(replays: Sequence[Replay], _model: VisibilityModel, **_: Any) -> BaselineOutcome:
    """B2 — every ancestor of the highest-ΔΦ node, unweighted, no interventions.

    Judged on *chain recall at nodes inspected*. Stage 2's measured precedent is the
    bar and the warning: the causal spine reached 5.0 nodes at chain recall 0.3611
    against naive ancestry's 19.75 at 1.0 — concision bought with recall, which did
    **not** meet the criterion (ADR-0122). Responsibility Flux must beat that trade,
    not repeat it.
    """
    started = time.process_time()
    inspected = 0
    recalled = 0
    total = 0
    detect_hits = 0
    for replay in replays:
        spine = replay.pipeline.causal.spine()
        if not spine:
            continue
        total += 1
        peak = max(spine, key=lambda node: float(node.delta_phi))
        index = {node.signature: node for node in spine}
        chain: list[str] = []
        cursor: Any = peak
        while cursor is not None and cursor.signature not in chain:
            chain.append(cursor.signature)
            cursor = index.get(cursor.parent_signature)
        inspected += len(chain)
        # Recall against the transitions that actually raised a truth dimension: a
        # chain is "recalled" when it contains a node whose mask is non-zero, which
        # is the weakest honest reading and deliberately generous to the baseline.
        if any(index[sig].state_delta_mask for sig in chain):
            recalled += 1
        if int(float(peak.delta_phi) > 0.0) == replay.case.label:
            detect_hits += 1
    cpu = time.process_time() - started
    return BaselineOutcome(
        baseline_id="B2_NaiveAncestryAttribution",
        world_set_recall=None,
        premature_collapse_rate=None,
        nonidentifiability_accuracy=None,
        unsupported_claim_count=0,
        telemetry_bytes=0,
        cpu_units=cpu,
        work_units=inspected,
        resolution_efficiency=efficiency_of(
            detect_hits, cpu=cpu, telemetry=0, claims=inspected
        ),
        detection_accuracy=accuracy_of(detect_hits, total),
        chain_recall=accuracy_of(recalled, total),
        nodes_inspected=inspected,
        loadavg=loadavg(),
    )


# --- B3 ----------------------------------------------------------------------


def always_on_rich_telemetry(
    replays: Sequence[Replay], _model: VisibilityModel, **_: Any
) -> BaselineOutcome:
    """B3 — collect every optional signal for every lineage, for the whole incident.

    Literally "turn everything on all the time", which is the control the
    architecture's low-overhead claim rests on (G4.5). It reaches perfect coverage of
    every signal *by definition*, so its ``world_set_recall`` is 1.0 and the question
    is only what it cost.
    """
    started = time.process_time()
    telemetry = 0
    detect_hits = 0
    reachable = sorted(
        {signal for action in SensorAction for signal in _action_signals(action)}
        | set(DIMENSION_SIGNALS.values())
    )
    for replay in replays:
        telemetry += signal_payload_bytes(reachable)
        if int(bool(replay.observed & set(DIMENSION_SIGNALS.values()))) == replay.case.label:
            detect_hits += 1
    cpu = time.process_time() - started
    total = len(replays)
    return BaselineOutcome(
        baseline_id="B3_AlwaysOnRichTelemetry",
        world_set_recall=1.0,
        premature_collapse_rate=None,
        nonidentifiability_accuracy=None,
        unsupported_claim_count=0,
        telemetry_bytes=telemetry,
        cpu_units=cpu,
        work_units=total * len(reachable),
        resolution_efficiency=efficiency_of(
            detect_hits, cpu=cpu, telemetry=telemetry, claims=0
        ),
        detection_accuracy=accuracy_of(detect_hits, total),
        loadavg=loadavg(),
    )


def _action_signals(action: SensorAction) -> frozenset[str]:
    from pocketsec.stage4.sensing.active_plan import ACTION_SIGNALS

    return frozenset(ACTION_SIGNALS.get(action, frozenset()))


# --- B4 ----------------------------------------------------------------------

#: B4's decision tree, depth 4. Fixed thresholds over ``phi(state).total``: the point
#: of the baseline is that it has near-zero cost, so CBF/LUCID must beat a table.
PHI_TREE: tuple[tuple[float, str], ...] = (
    (8.0, "resolve_malicious"),
    (4.0, "escalate"),
    (1.0, "watch"),
    (0.0, "ignore"),
)


def phi_threshold_playbook(
    replays: Sequence[Replay], _model: VisibilityModel, **_: Any
) -> BaselineOutcome:
    """B4 — a fixed decision tree over Φ and ΔS bitmask. No worlds, no claims."""
    started = time.process_time()
    detect_hits = 0
    correct_abstain = 0
    unidentifiable_total = 0
    for replay in replays:
        total_phi = phi(replay.result.final_state).total
        decision = next(name for threshold, name in PHI_TREE if total_phi >= threshold)
        if int(decision in {"resolve_malicious", "escalate"}) == replay.case.label:
            detect_hits += 1
        if replay.expects_unidentifiable:
            unidentifiable_total += 1
            # A playbook has no notion of non-identifiability. "escalate" is the
            # closest thing to an abstention it can express, and crediting it with
            # anything more would be inventing a capability it does not have.
            if decision == "escalate":
                correct_abstain += 1
    cpu = time.process_time() - started
    total = len(replays)
    return BaselineOutcome(
        baseline_id="B4_PhiThresholdPlaybook",
        world_set_recall=None,
        premature_collapse_rate=None,
        nonidentifiability_accuracy=accuracy_of(correct_abstain, unidentifiable_total),
        unsupported_claim_count=0,
        telemetry_bytes=0,
        cpu_units=cpu,
        work_units=total * len(PHI_TREE),
        resolution_efficiency=efficiency_of(detect_hits, cpu=cpu, telemetry=0, claims=1),
        detection_accuracy=accuracy_of(detect_hits, total),
        loadavg=loadavg(),
    )


# --- B5 ----------------------------------------------------------------------


def fixed_window_correlation(
    replays: Sequence[Replay], _model: VisibilityModel, **_: Any
) -> BaselineOutcome:
    """B5 — group transitions in a 60 s window per lineage; score by count and max ΔΦ.

    The control for the claim that incident understanding needs latent state at all. A
    new window opens whenever the actor's gap bucket reaches
    :data:`WINDOW_BUCKET`, because Stage 1 records bucketed gaps rather than absolute
    timestamps.
    """
    started = time.process_time()
    detect_hits = 0
    groups = 0
    for replay in replays:
        buckets: dict[tuple[str, int], list[float]] = {}
        window: dict[str, int] = {}
        for transition in replay.result.transitions:
            actor = transition.actor.identity
            if transition.temporal.since_actor_bucket >= WINDOW_BUCKET:
                window[actor] = window.get(actor, 0) + 1
            key = (actor, window.setdefault(actor, 0))
            buckets.setdefault(key, []).append(float(transition.delta_phi))
        groups += len(buckets)
        score = max(
            (len(values) * max(values) for values in buckets.values()),
            default=0.0,
        )
        if int(score > 1.0) == replay.case.label:
            detect_hits += 1
    cpu = time.process_time() - started
    total = len(replays)
    return BaselineOutcome(
        baseline_id="B5_FixedWindowCorrelation",
        world_set_recall=None,
        premature_collapse_rate=None,
        nonidentifiability_accuracy=None,
        unsupported_claim_count=0,
        telemetry_bytes=0,
        cpu_units=cpu,
        work_units=groups,
        resolution_efficiency=efficiency_of(detect_hits, cpu=cpu, telemetry=0, claims=groups),
        detection_accuracy=accuracy_of(detect_hits, total),
        loadavg=loadavg(),
    )


# --- B6, §46's falsifier 1 by name -------------------------------------------


def _hmm_tables(
    train: Sequence[Replay],
) -> tuple[dict[str, dict[str, float]], dict[str, dict[str, float]], dict[str, float]]:
    """Count transition and emission tables from the training split. Laplace-smoothed.

    Smoothing is named because it is a choice: without it an operation absent from one
    class's training data gives that class probability zero and the forward pass
    collapses, which would make the control fail for a reason that is about the
    counting rather than about the model.
    """
    vocabulary = {
        transition.relation.name.lower()
        for replay in train
        for transition in replay.result.transitions
    } or {"unknown"}
    emission: dict[str, dict[str, float]] = {
        state: dict.fromkeys(vocabulary, 1.0) for state in HMM_STATES
    }
    for replay in train:
        state = HMM_STATES[1] if replay.case.label else HMM_STATES[0]
        for transition in replay.result.transitions:
            emission[state][transition.relation.name.lower()] += 1.0
    for state in HMM_STATES:
        total = sum(emission[state].values())
        emission[state] = {word: count / total for word, count in emission[state].items()}
    # Self-persistent chain: a compromise does not flicker back and forth between
    # transitions, and a near-uniform transition matrix would make the hidden state
    # carry no information and hand the comparison to the mechanism.
    transitions = {
        HMM_STATES[0]: {HMM_STATES[0]: 0.95, HMM_STATES[1]: 0.05},
        HMM_STATES[1]: {HMM_STATES[0]: 0.02, HMM_STATES[1]: 0.98},
    }
    prior = {HMM_STATES[0]: 0.9, HMM_STATES[1]: 0.1}
    return transitions, emission, prior


def _forward(
    words: Sequence[str],
    transitions: Mapping[str, Mapping[str, float]],
    emission: Mapping[str, Mapping[str, float]],
    prior: Mapping[str, float],
) -> float:
    """Pure-Python forward algorithm; returns P(compromised at the last step).

    Rescaled each step rather than run in log space, because the quantity wanted is a
    normalised filtered posterior and rescaling gives it directly. Underflow cannot
    occur: the alphas are renormalised to sum to 1 at every step.
    """
    if not words:
        return prior[HMM_STATES[1]]
    floor = 1e-12
    alpha = {
        state: prior[state] * max(emission[state].get(words[0], floor), floor)
        for state in HMM_STATES
    }
    for word in words[1:]:
        nxt: dict[str, float] = {}
        for state in HMM_STATES:
            inflow = math.fsum(alpha[prev] * transitions[prev][state] for prev in HMM_STATES)
            nxt[state] = inflow * max(emission[state].get(word, floor), floor)
        total = math.fsum(nxt.values()) or floor
        alpha = {state: value / total for state, value in nxt.items()}
    total = math.fsum(alpha.values()) or floor
    return alpha[HMM_STATES[1]] / total


def two_state_hmm(
    replays: Sequence[Replay],
    _model: VisibilityModel,
    *,
    train: Sequence[Replay] = (),
    **_: Any,
) -> BaselineOutcome:
    """B6 — a 2-state HMM over the operation vocabulary. The most important baseline.

    §46's falsifier 1 names it: if B6 reaches equivalent incident quality and
    attribution at materially lower cost, **CBF/LUCID is rejected** and ADR-0036
    recommends reducing Stage 4 to B6 plus the typed claim graph — the one component
    with independent value.

    ``train`` must be a *different* split. Fitting and scoring on the same replays
    would measure memorisation, and the comparison would flatter the control exactly
    as badly as a leak flatters a mechanism.
    """
    if not train:
        raise ContractError(
            "two_state_hmm needs a separate training split; fitting and scoring on the "
            "same replays measures memorisation, not a latent-state estimator"
        )
    started = time.process_time()
    transitions, emission, prior = _hmm_tables(train)
    detect_hits = 0
    steps = 0
    for replay in replays:
        words = [t.relation.name.lower() for t in replay.result.transitions]
        steps += len(words)
        posterior = _forward(words, transitions, emission, prior)
        if int(posterior >= 0.5) == replay.case.label:
            detect_hits += 1
    cpu = time.process_time() - started
    total = len(replays)
    return BaselineOutcome(
        baseline_id="B6_TwoStateHMM",
        world_set_recall=None,
        premature_collapse_rate=None,
        nonidentifiability_accuracy=None,
        unsupported_claim_count=0,
        telemetry_bytes=0,
        cpu_units=cpu,
        work_units=steps * len(HMM_STATES) * len(HMM_STATES),
        resolution_efficiency=efficiency_of(detect_hits, cpu=cpu, telemetry=0, claims=1),
        detection_accuracy=accuracy_of(detect_hits, total),
        loadavg=loadavg(),
    )


# --- B7 ----------------------------------------------------------------------


def information_gain_planner(
    replays: Sequence[Replay], model: VisibilityModel, **_: Any
) -> BaselineOutcome:
    """B7 — pick the observation with maximum expected entropy reduction.

    Ignores consequence and ignores cost, which is the whole point: it is the control
    for §16's Utility formula and for §18's free-energy objective. §18 is explicit —
    if the objective does not outperform simpler information-gain planning it is
    removed — so ``enable_free_energy`` stays off until it beats this (ADR-0038).
    """
    engine = LucidEngine(
        config=LucidConfig(enable_active_sensing=False), visibility=model
    )
    started = time.process_time()
    telemetry = 0
    detect_hits = 0
    committed = 0
    planned = 0
    for replay in replays:
        case = replay.case
        epoch = replay.result.transitions[0].epoch_id if replay.result.transitions else 0
        field = engine.open_incident(case.incident_id, epoch)
        spine = replay.pipeline.causal.spine()
        for transition in replay.result.transitions:
            field = engine.update(field, transition, spine).field
        best: tuple[float, str] | None = None
        for signal in sorted(DIMENSION_SIGNALS.values()):
            gain = signal_discrimination(field, signal, model=model)
            planned += 1
            if best is None or gain > best[0]:
                best = (gain, signal)
        if best is not None and best[0] > 0.0:
            telemetry += signal_payload_bytes([best[1]])
        resolution = engine.resolve(field)
        engine.close_incident(field)
        predicted = predicted_label(resolution.prediction_verdict)
        committed += predicted is not None
        if predicted is not None and predicted == case.label:
            detect_hits += 1
    cpu = time.process_time() - started
    total = len(replays)
    return BaselineOutcome(
        baseline_id="B7_InformationGainPlanner",
        world_set_recall=None,
        premature_collapse_rate=None,
        nonidentifiability_accuracy=None,
        unsupported_claim_count=0,
        telemetry_bytes=telemetry,
        cpu_units=cpu,
        work_units=engine.work_units + planned,
        resolution_efficiency=efficiency_of(
            detect_hits, cpu=cpu, telemetry=telemetry, claims=0
        ),
        detection_accuracy=accuracy_of(detect_hits, total),
        detection_coverage=accuracy_of(committed, total),
        loadavg=loadavg(),
    )


# --- B8 ----------------------------------------------------------------------


def no_stage4(replays: Sequence[Replay], _model: VisibilityModel, **_: Any) -> BaselineOutcome:
    """B8 — Stage 1's Φ path alone. Zero worlds, zero claims, zero sensing.

    §42's "pure DTL" row is **void**: DTL is rejected (ADR-0010) and beating a
    22.3 µs/event rejected model proves nothing. The honest control is Stage 1, whose
    Φ-oracle reached 0.7484 PR-AUC with zero parameters (cited, not measured here).
    Stage 4 must add measurable resolution quality over this or it reduces to Stage 1
    plus bookkeeping.
    """
    started = time.process_time()
    detect_hits = 0
    for replay in replays:
        if int(replay.result.peak_phi >= 1.0) == replay.case.label:
            detect_hits += 1
    cpu = time.process_time() - started
    total = len(replays)
    return BaselineOutcome(
        baseline_id="B8_NoStage4",
        world_set_recall=None,
        premature_collapse_rate=None,
        nonidentifiability_accuracy=None,
        unsupported_claim_count=0,
        telemetry_bytes=0,
        cpu_units=cpu,
        work_units=total,
        resolution_efficiency=efficiency_of(detect_hits, cpu=cpu, telemetry=0, claims=0),
        detection_accuracy=accuracy_of(detect_hits, total),
        loadavg=loadavg(),
    )
