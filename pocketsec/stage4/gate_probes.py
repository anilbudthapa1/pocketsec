"""The Stage 4 gate's constructed probes: fixtures, fault injection, bound sampling.

Split out of ``gate_criteria.py``, which reached 1200 lines — ``pocketsec/stage3/`` set the
precedent with ``gate_criteria.py`` beside ``gate_probes.py``. The division is by *kind*
rather than by size: ``gate_criteria.py`` holds the shared measurement of a real corpus
walk, and this module holds everything the gate has to **construct** in order to measure
anything — a decoy world pair the corpus labelled but the engine cannot name, seven
laundering attempts that must be refused, material for all eight adversarial
perturbations, a bound sampler for the flood, and the ten real-subsystem hooks the fault
injection raises inside.

Every probe here is committed rather than described, for the reason
``tests/test_repository_structure.py`` states about its own negative fixture: a rule that
cannot catch its own counterexample is not enforcing anything.
"""

from __future__ import annotations

import hashlib
from functools import partial
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any

from pocketsec.stage0.contracts.common import EvidenceRef
from pocketsec.stage1.observation.policy import AdaptiveObservationPolicy
from pocketsec.stage1.ssir.transition import SSIRTransitionV1
from pocketsec.stage1.telemetry.raw_event_v1 import SensorPath
from pocketsec.stage4.claims.graph import EMPTY_CLAIM_GRAPH, LaunderingAttempt
from pocketsec.stage4.claims.typed_claim import (
    DerivedClaim,
    ExternalClaim,
    InferredClaim,
    ObservedClaim,
)
from pocketsec.stage4.engine.degradation import Subsystem
from pocketsec.stage4.engine.integrator import IncidentEvidence
from pocketsec.stage4.engine.lucid import LucidConfig, LucidEngine
from pocketsec.stage4.gate_criteria import (
    EngineRun,
    dropped_signal_names,
    plan_for,
    truth_world_of,
)
from pocketsec.stage4.labs.baseline_metrics import Replay
from pocketsec.stage4.labs.incident_corpus import IncidentCase
from pocketsec.stage4.visibility.model import VisibilityModel, signals_of_transition
from pocketsec.stage4.worlds.field import CausalBeliefField
from pocketsec.stage4.worlds.world import SecurityWorldV1

__all__ = [
    "BoundSample",
    "decoy_field",
    "flood_bounds",
    "laundering_probes",
    "observed_signals",
    "real_subsystem_hooks",
    "refused",
    "stress_material",
    "with_fault",
]

# --- G4.6: the predefined spurious explanation, read off the corpus ---------


def decoy_field(
    case: IncidentCase, replay: Replay, *, epoch_id: int = 1
) -> tuple[CausalBeliefField, str, str] | None:
    """A field holding the case's true world beside its **predefined** spurious one.

    The two worlds are read off the corpus — ``case.truth.mechanism_id`` against
    ``case.spurious_mechanism_id``, and the decoy's own identity against the true
    chain's — rather than proposed by the engine, because the engine's own mechanism
    vocabulary is ``unresolved_novel_mechanism`` for every world it spawns and a field
    of identical unknowns cannot carry a spurious explanation to detect. What the gate
    supplies is the *labelling*; what the mechanism has to supply is the discrimination.

    ``None`` when the case carries no decoy, so a caller cannot mistake an absent
    construction for a passed one.
    """
    if not case.spurious_mechanism_id or case.decoy_identity is None:
        return None
    reference = truth_world_of(case, at_sequence=0)
    if reference is None:
        # A case whose ground truth raises no signal-bearing dimension — the novel
        # unresolved world — has no true world to contrast a decoy against. Returning
        # None rather than a half-built field is what lets the check report "four of
        # five constructible" instead of silently scoring four as five.
        return None
    # The spurious world expects what the *decoy* raised and the true chain did not.
    # Derived from the replay rather than chosen, so REMOVE_CRITICAL_EVENT has a real
    # event to remove: a spurious world expecting the same signals as the true one is
    # not a spurious explanation, it is a duplicate.
    spurious_signals = frozenset(observed_signals(replay)) - reference.expected_evidence
    if not spurious_signals:
        return None
    spurious = replace(
        reference,
        world_id=f"{case.incident_id}-spurious",
        mechanism_id=case.spurious_mechanism_id,
        expected_evidence=spurious_signals,
        visibility_requirements=spurious_signals,
    )
    field = CausalBeliefField(
        incident_id=case.incident_id,
        epoch_id=epoch_id,
        worlds=(reference, spurious),
        max_worlds=8,
        claim_graph=EMPTY_CLAIM_GRAPH,
    )
    return field, reference.world_id, spurious.world_id


# --- G4.7: the seven laundering attempts, as runnable probes ---------------


def stress_material(case: IncidentCase, replay: Replay) -> Any:
    """Material for all eight §25 perturbations, taken from the case and its replay.

    Every field is filled. A ``StressMaterial`` missing a field makes that perturbation
    report ``NO_MATERIAL`` and ``conclusion_survived=False``, so a partially filled
    material turns "the stress found nothing" into "the stress never ran" — and
    ``stresses_actually_run`` would quote two of eight while the check read it as eight
    passes. The gate fills all eight and reports the count.
    """
    from pocketsec.stage4.counterfactual.stress import StressMaterial
    from pocketsec.stage4.labs.incident_corpus import RENAME_MAP

    spine = tuple(replay.pipeline.causal.spine())
    observed = observed_signals(replay)
    # ``CausalNode.actor_identity`` is Stage 1's lineage key, ``proc:<boot>:<pid>:<pid>``,
    # while the corpus records the decoy and the chain owner as the bare ``(pid, pid)``
    # pair. Matching on the suffix rather than on equality: a naive ``==`` found neither
    # node, INJECT_DECOY_ANCESTRY reported NO_MATERIAL, and the stress suite then quoted
    # seven of eight while the perturbation the criterion is *about* had not run.
    def _node_for(identity: tuple[str, str] | None) -> Any:
        if identity is None:
            return None
        suffix = f":{identity[0]}:{identity[1]}"
        return next((node for node in spine if node.actor_identity.endswith(suffix)), None)

    decoy = _node_for(case.decoy_identity)
    chain_node = _node_for(case.chain_identity)
    critical = chain_node.signature if chain_node is not None else ""
    if not critical and spine:
        critical = spine[0].signature
    return StressMaterial(
        observed_signals=observed,
        spine=spine,
        # A benign signal the incident did not raise: inserting a signal it *did* raise
        # would be a no-op dressed as a perturbation.
        benign_signals=frozenset({"read"}) - observed or frozenset({"accept"}),
        critical_signature=critical,
        decoy=decoy,
        # The drop the rest of the gate uses, so G4.4 and G4.6 perturb the same thing.
        dropped_signals=dropped_signal_names() & observed,
        identity_renames={
            node.actor_identity: RENAME_MAP.get(node.actor_identity, f"/renamed/{node.signature}")
            for node in spine
        },
        ioc_equivalents={node.signature: f"{node.signature[::-1]}" for node in spine},
        delay_steps=1,
        epoch_shift=1,
    )


def observed_signals(replay: Replay) -> frozenset[str]:
    """Every signal the replay actually emitted, from the visibility vocabulary."""
    seen: set[str] = set()
    for transition in replay.result.transitions:
        seen |= signals_of_transition(transition)
    return frozenset(seen)


def _digest(text: str) -> str:
    return f"sha256:{hashlib.sha256(text.encode('utf-8')).hexdigest()}"


def _good_evidence(locator: str = "e0") -> EvidenceRef:
    return EvidenceRef(store="raw.ebpf", locator=locator, digest=_digest(locator))


def _observed(claim_id: str = "c-obs") -> ObservedClaim:
    return ObservedClaim(
        claim_id=claim_id,
        subject="process/1001",
        text="credential_access observed",
        evidence=(_good_evidence(claim_id),),
        sensor=SensorPath.EBPF,
        at_sequence=1,
    )


def _inferred(claim_id: str = "c-inf", premises: tuple[str, ...] = ("c-obs",)) -> InferredClaim:
    return InferredClaim(
        claim_id=claim_id,
        subject="world/w-0",
        text="possible credential access",
        premises=premises,
        world_id="w-0",
        support=0.5,
        shadow_penalty=0.0,
    )


def _observed_with_empty_evidence() -> None:
    ObservedClaim(
        claim_id="c-empty",
        subject="process/1001",
        text="credential_access observed",
        evidence=(),
        sensor=SensorPath.EBPF,
        at_sequence=1,
    )


def _observed_with_malformed_digest() -> None:
    ObservedClaim(
        claim_id="c-forged",
        subject="world/w-0",
        text="possible credential access",
        evidence=(EvidenceRef(store="raw.ebpf", locator="e1", digest="sha256:deadbeef"),),
        sensor=SensorPath.EBPF,
        at_sequence=1,
    )


def _derived_from_inference() -> None:
    graph = EMPTY_CLAIM_GRAPH.insert(_observed()).insert(_inferred())
    graph.insert(
        DerivedClaim(
            claim_id="c-der",
            subject="process/1001",
            text="credential material was read",
            premises=("c-inf",),
            rule_id="rule-0",
        )
    )


def _inference_marked_authoritative() -> None:
    graph = EMPTY_CLAIM_GRAPH.insert(_observed())
    graph.insert(_inferred(), authoritative=True)


def _derived_cycle() -> None:
    graph = EMPTY_CLAIM_GRAPH.insert(_observed())
    graph = graph.insert(
        DerivedClaim(
            claim_id="c-a",
            subject="process/1001",
            text="credential material was read",
            premises=("c-obs", "c-b"),
            rule_id="rule-0",
        )
    )
    graph.insert(
        DerivedClaim(
            claim_id="c-b",
            subject="process/1001",
            text="credential material was read twice",
            premises=("c-a",),
            rule_id="rule-1",
        )
    )


def _external_without_source_version_authoritative() -> None:
    graph = EMPTY_CLAIM_GRAPH.insert(_observed())
    graph.insert(
        ExternalClaim(
            claim_id="c-ext",
            subject="technique/T1003",
            text="attack technique T1003",
            premises=("c-obs",),
            knowledge_source="attack",
            source_version="",
            rationale="matches the observed read of credential material",
        ),
        authoritative=True,
    )


def _second_der_over_an_inference_authoritative() -> None:
    graph = EMPTY_CLAIM_GRAPH.insert(_observed())
    graph = graph.insert(
        DerivedClaim(
            claim_id="c-der1",
            subject="process/1001",
            text="credential material was read",
            premises=("c-obs",),
            rule_id="rule-0",
        )
    )
    graph = graph.insert(_inferred(claim_id="c-inf", premises=("c-der1",)))
    graph.insert(
        DerivedClaim(
            claim_id="c-der2",
            subject="process/1001",
            text="credential material was read again",
            premises=("c-inf",),
            rule_id="rule-1",
        ),
        authoritative=True,
    )


def laundering_probes() -> tuple[tuple[str, Callable[[], None]], ...]:
    """The spec's seven (a)-(g) attempts to launder an inference into an observation.

    Each must raise. They are probes rather than assertions so the gate can report
    *which* one failed to refuse, and so that the same seven are exercised identically
    by ``tests/test_stage4_claims.py`` and by the gate.
    """
    return (
        ("a_observed_claim_with_empty_evidence", _observed_with_empty_evidence),
        ("b_observed_claim_with_malformed_digest", _observed_with_malformed_digest),
        ("c_derived_claim_resting_on_an_inference", _derived_from_inference),
        ("d_inference_inserted_as_authoritative", _inference_marked_authoritative),
        ("e_derivation_cycle", _derived_cycle),
        ("f_external_without_source_version_authoritative",
         _external_without_source_version_authoritative),
        ("g_obs_der_inf_der_with_the_second_der_authoritative",
         _second_der_over_an_inference_authoritative),
    )


def refused(probe: Callable[[], None]) -> str | None:
    """``None`` when the probe was refused; the defect otherwise.

    ``LaunderingAttempt`` subclasses ``ContractError`` subclasses ``ValueError``, and
    the constructor-level refusals (a) and (b) raise ``ContractError`` rather than
    ``LaunderingAttempt`` because a malformed digest is refused before any graph sees
    it. Both are refusals; what would be a defect is the call *succeeding*.
    """
    try:
        probe()
    except (LaunderingAttempt, ValueError):
        return None
    except Exception as exc:  # noqa: BLE001 - an unexpected type is itself the finding
        return f"raised {type(exc).__name__} rather than a refusal: {exc}"
    return "was accepted"


# --- G4.8: claim support against the telemetry that actually arrived --------


def telemetry_digests(replay: Replay) -> frozenset[str]:
    """Every evidence digest the replay's Stage 1 transitions carried."""
    return frozenset(
        ref.digest for transition in replay.result.transitions for ref in transition.evidence
    )


def claim_support_audit(graph: Any, known_digests: frozenset[str]) -> dict[str, tuple[str, ...]]:
    """G4.8's non-structural half: fabricated digests and uncatalogued derivations.

    ``unsupported_authoritative`` checks a digest's SHAPE, so a compiler that invented a
    sha256-shaped reference, or asserted a root cause as free DER text, passed it
    (S4-FC-02). This audit is the part that can fail on those.
    """
    from pocketsec.stage4.claims.compiler import DERIVATION_RULE_CATALOGUE

    return {
        "unanchored": graph.unanchored_observations(known_digests),
        "uncatalogued": graph.uncatalogued_derivations(DERIVATION_RULE_CATALOGUE),
    }


# --- G4.9: the flood bound sampler -----------------------------------------


@dataclass(frozen=True, slots=True)
class BoundSample:
    """The worst value each bounded quantity reached, and whether losses were recorded."""

    steps: int
    worst_worlds: int
    worst_graph_nodes: int
    worst_graph_edges: int
    worst_claims: int
    worst_state_bytes: int
    worst_reasoning_units: int
    truncations: int
    bounds_reached: tuple[str, ...]
    #: Truncations whose ``what`` is ``"world"``: the only ones that can show a world
    #: lost AT the world bound. The total above is met by graph-edge noise, so it
    #: cannot stand in for this (S4-FC-05 / S4-RES-02).
    world_truncations: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "steps": self.steps,
            "worst_worlds": self.worst_worlds,
            "worst_graph_nodes": self.worst_graph_nodes,
            "worst_graph_edges": self.worst_graph_edges,
            "worst_claims": self.worst_claims,
            "worst_state_bytes": self.worst_state_bytes,
            "worst_reasoning_units": self.worst_reasoning_units,
            "truncations": self.truncations,
            "world_truncations": self.world_truncations,
            "bounds_reached": list(self.bounds_reached),
        }


def flood_bounds(
    replays: Sequence[Replay], model: VisibilityModel, *, config: LucidConfig | None = None
) -> tuple[BoundSample, tuple[EngineRun, ...]]:
    """Sample every bound at every step of the flood, not just at the end.

    Sampling only the final field would miss a bound that was exceeded mid-incident and
    then pruned back under it, which is the shape an attacker who can make the system
    branch would aim for.
    """
    settings = config if config is not None else LucidConfig()
    # With Stage 1's AOP, as every production path should be: without one the planner
    # refused every discriminating action for "no observation policy" and the flood's
    # incidents were certified UNIDENTIFIABLE for a wiring reason (S4-REV-03).
    engine = LucidEngine(
        config=settings, visibility=model, observation=AdaptiveObservationPolicy()
    )
    worst = dict.fromkeys(
        ("worlds", "nodes", "edges", "claims", "bytes", "units"), 0
    )
    truncations = 0
    world_truncations = 0
    steps = 0
    runs: list[EngineRun] = []
    for replay in replays:
        transitions = replay.result.transitions
        epoch = transitions[0].epoch_id if transitions else 0
        field = engine.open_incident(replay.case.incident_id, epoch)
        spine = replay.pipeline.causal.spine()
        incident_units = 0
        for transition in transitions:
            outcome = engine.update(field, transition, spine)
            field = outcome.field
            steps += 1
            truncations += len(outcome.truncations)
            world_truncations += sum(1 for item in outcome.truncations if item.what == "world")
            report = field.graph.report()
            worst["worlds"] = max(worst["worlds"], len(field.worlds))
            worst["nodes"] = max(worst["nodes"], int(report["nodes"]))
            worst["edges"] = max(worst["edges"], int(report["edges"]))
            # No per-step claims sample: the field carries no compiled graph during
            # update (it is compiled at resolve), so a per-step read measured the empty
            # sentinel every time (S4-FC-10). The claims bound is read off the resolution.
            worst["bytes"] = max(worst["bytes"], field.state_bytes())
            # Per-incident, not cumulative. ``engine.work_units`` counts the whole walk
            # and ``max_reasoning_units`` is an incident budget; comparing them reported
            # 106035 against 4096 and called a held bound a violation. The per-update sum
            # equals the controller's own ``spend_report()["reasoning_units"]`` exactly —
            # measured at 2558 against 2558 on the first flood case this session — and it
            # is reachable without touching the engine's private incident state.
            incident_units += outcome.work_units
        resolution = engine.resolve(field)
        incident_units += resolution.work_units
        worst["claims"] = max(worst["claims"], len(resolution.claim_graph.claims))
        worst["units"] = max(worst["units"], incident_units)
        export = engine.close_incident(field)
        runs.append(
            EngineRun(replay=replay, field=field, resolution=resolution, export=export)
        )

    from pocketsec.stage4.claims.graph import MAX_CLAIMS_PER_GRAPH
    from pocketsec.stage4.graph.sparse_world_graph import MAX_GRAPH_EDGES, MAX_GRAPH_NODES

    reached = tuple(
        name
        for name, value, bound in (
            ("worlds", worst["worlds"], settings.max_worlds),
            ("graph_nodes", worst["nodes"], MAX_GRAPH_NODES),
            ("graph_edges", worst["edges"], MAX_GRAPH_EDGES),
            ("claims", worst["claims"], MAX_CLAIMS_PER_GRAPH),
            ("reasoning_units", worst["units"], settings.budget.max_reasoning_units),
        )
        if value >= bound
    )
    return (
        BoundSample(
            steps=steps,
            worst_worlds=worst["worlds"],
            worst_graph_nodes=worst["nodes"],
            worst_graph_edges=worst["edges"],
            worst_claims=worst["claims"],
            worst_state_bytes=worst["bytes"],
            worst_reasoning_units=worst["units"],
            truncations=truncations,
            bounds_reached=reached,
            world_truncations=world_truncations,
        ),
        tuple(runs),
    )


# --- G4.11: the ten real subsystems, as attachment hooks -------------------


# Each of the ten hooks is a module-level function taking ``model`` (and, for the one that
# plans, ``observation``) as its first argument, bound with ``functools.partial`` in
# :func:`real_subsystem_hooks`. They were closures in a single 175-line function until the
# integrator split them: ten nested definitions sharing captured state is a function nobody
# reads, and the repository's guidance is ~50 lines. Nothing about the behaviour changed —
# what changed is that each hook can now be read, and tested, on its own.


def _a_world(evidence: IncidentEvidence, transition: SSIRTransitionV1) -> SecurityWorldV1:
    """The bounded UNKNOWN world, which is the only kind the engine ever spawns."""
    from pocketsec.stage4.worlds.field import unknown_world

    return unknown_world(evidence.incident_id, at_sequence=transition.sequence)


def _single_world_field(
    evidence: IncidentEvidence, transition: SSIRTransitionV1
) -> CausalBeliefField:
    """A one-world field, for the hooks that need a field rather than a world."""
    return CausalBeliefField(
        incident_id=evidence.incident_id,
        epoch_id=evidence.epoch_id,
        worlds=(_a_world(evidence, transition),),
        max_worlds=8,
        claim_graph=EMPTY_CLAIM_GRAPH,
    )


def _shadow_for(
    model: VisibilityModel, transition: SSIRTransitionV1, expected: Sequence[str]
) -> Any:
    from pocketsec.stage4.visibility.sensor_shadow import estimate_sensor_shadow

    return estimate_sensor_shadow(model, expected=list(expected), transitions=(transition,))


def _hook_world_lifecycle(
    model: VisibilityModel, evidence: IncidentEvidence, transition: SSIRTransitionV1
) -> object:
    """CBF-F02's birth gate: the real residual over the real shadow."""
    from pocketsec.stage4.worlds.lifecycle import residual_from_transition

    shadow = _shadow_for(model, transition, sorted(signals_of_transition(transition)))
    return residual_from_transition(transition, (), shadow=shadow).signals


def _hook_claim_compiler(
    model: VisibilityModel, evidence: IncidentEvidence, transition: SSIRTransitionV1
) -> object:
    """CBF-F18: compile a real typed claim graph from a real field."""
    from pocketsec.stage4.claims.compiler import compile_typed_claim_graph

    graph, compiled = compile_typed_claim_graph(_single_world_field(evidence, transition))
    return (len(graph.claims), len(compiled))


def _hook_active_sensing(
    model: VisibilityModel,
    observation: AdaptiveObservationPolicy | None,
    evidence: IncidentEvidence,
    transition: SSIRTransitionV1,
) -> object:
    """CBF-F13/F14 through the real planner, measured costs and Stage 1's real AOP."""
    plan = plan_for(
        _single_world_field(evidence, transition), model=model, observation=observation
    )
    return (len(plan.requests), len(plan.refused))


def _hook_counterfactual(
    model: VisibilityModel, evidence: IncidentEvidence, transition: SSIRTransitionV1
) -> object:
    """CBF-F10 over the incident's real causal spine."""
    from pocketsec.stage4.counterfactual.intervention import calculate_responsibility_flux

    return len(
        calculate_responsibility_flux(
            _single_world_field(evidence, transition),
            evidence.spine,
            at_sequence=transition.sequence,
        )
    )


def _hook_calibration(
    model: VisibilityModel, evidence: IncidentEvidence, transition: SSIRTransitionV1
) -> object:
    """A real ``EpochCalibration`` sample.

    The first draft called ``epoch_key(evidence.epoch_id)``, which raises: ``epoch_key``
    takes a Stage 1 ``Epoch`` object and ``epoch_id`` is an ``int``. Because every hook runs
    inside ``guarded``, that broken call was caught and recorded **exactly like an injected
    fault**, so G4.11's CALIBRATION row measured a defect in this file rather than the
    isolation of the subsystem. ``tests/test_stage4_gate.py``'s "every hook actually
    computes" assertion found it, and that is why the assertion exists.
    """
    from pocketsec.stage4.evidence.calibration import EpochCalibration

    book = EpochCalibration()
    book.observe(
        epoch_id=evidence.epoch_id,
        confidence=1.0 - transition.uncertainty,
        correct=transition.is_high_consequence,
    )
    return book.samples(evidence.epoch_id)


def _hook_external_knowledge(
    model: VisibilityModel, evidence: IncidentEvidence, transition: SSIRTransitionV1
) -> object:
    """The Stage 3 seam, read as plain JSON and never imported."""
    return len(evidence.knowledge.cell_ids())


def _hook_verbalizer(
    model: VisibilityModel, evidence: IncidentEvidence, transition: SSIRTransitionV1
) -> object:
    """D4.15's guard, fed a text that asserts more than the claim it compresses.

    Deliberately a text the guard must **refuse**: a hook that only ever passed a faithful
    sentence would leave the half that matters for hallucination cost untouched.
    """
    from pocketsec.stage4.claims.compiler import compile_typed_claim_graph
    from pocketsec.stage4.claims.verbalizer import validate_verbalization

    _graph, compiled = compile_typed_claim_graph(_single_world_field(evidence, transition))
    if not compiled:
        return "no_compiled_claim"
    return validate_verbalization(compiled[0], "credentials were definitely stolen")


def _hook_crystal_handoff(
    model: VisibilityModel, evidence: IncidentEvidence, transition: SSIRTransitionV1
) -> object:
    return evidence.knowledge.is_empty


def _hook_sequential_evidence(
    model: VisibilityModel, evidence: IncidentEvidence, transition: SSIRTransitionV1
) -> object:
    """§31's e-process, restricted to the null's own closed vocabulary.

    The restriction is not tidiness. ``benign_null_likelihood_ratio`` refuses a signal
    outside ``SIGNAL_VOCABULARY``; a first draft passed the transition's raw signals, which
    include relation-family names like ``connect``, and it raised. Widening the vocabulary to
    whatever telemetry arrived is exactly what would void the anytime-validity claim while
    leaving the flag reading True.
    """
    from pocketsec.stage4.evidence.sequential import (
        SIGNAL_VOCABULARY,
        benign_null_likelihood_ratio,
        start_benign_null_evidence,
    )

    signals = signals_of_transition(transition) & SIGNAL_VOCABULARY
    accumulator = start_benign_null_evidence(f"{evidence.incident_id}-w0")
    return accumulator.update(
        benign_null_likelihood_ratio(
            sorted(signals), expected=frozenset(signals), forbidden=frozenset()
        )
    ).e_value


def _hook_world_graph(
    model: VisibilityModel, evidence: IncidentEvidence, transition: SSIRTransitionV1
) -> object:
    """A real ``WorldGraphNode`` through the real bounded graph.

    ``SparseWorldGraph.add`` takes a node and returns the truncations the insert cost — the
    graph mutates in place and the return value is the loss record. A first draft guessed a
    ``(graph, truncations)`` pair over keyword arguments and raised.
    """
    from pocketsec.stage4.graph.sparse_world_graph import SparseWorldGraph, WorldGraphNode

    graph = SparseWorldGraph()
    truncations = graph.add(
        WorldGraphNode(
            signature=transition.causal_signature,
            causal_credit=1.0,
            contradiction_value=0.0,
            discrimination_value=0.0,
            mandatory=transition.is_high_consequence,
            state_delta_mask=transition.state_delta.bitmask(),
        )
    )
    return (len(graph.nodes()), len(truncations))


def _hook_evidence_tension(
    model: VisibilityModel, evidence: IncidentEvidence, transition: SSIRTransitionV1
) -> object:
    """CBF-F07. It has no ``Subsystem`` of its own — the enum is closed at ten and evidence
    tension is part of the world lifecycle — so it is bound there, alongside the birth gate,
    rather than left unexercised."""
    from pocketsec.stage4.tension.evidence_tension import calculate_evidence_tension

    world = _a_world(evidence, transition)
    shadow = _shadow_for(model, transition, sorted(world.expected_evidence))
    # ``history`` is keyword-only and required, with no default: a tension recomputed
    # without its own history is a first sample, and the sustained-tension death rule
    # needs to be able to tell a first sample from a persistent one. ``None`` is the
    # honest value for a single-transition probe; a default would have let a caller lose
    # the history silently.
    return calculate_evidence_tension(
        world,
        transition,
        shadow=shadow,
        model=model,
        history=None,
        observed=signals_of_transition(transition),
    ).total


def real_subsystem_hooks(
    model: VisibilityModel, *, observation: AdaptiveObservationPolicy | None = None
) -> dict[Subsystem, Callable[[IncidentEvidence, SSIRTransitionV1], object]]:
    """Bind each of the ten ``Subsystem`` members to the **real** Stage 4 code.

    ``tests/test_stage4_optionality.py`` had to use stand-in hooks: package 2 was the gate
    the other six packages waited on, so the real subsystems did not exist when it was
    written. They exist now, and a fault injected into a stand-in proves the *harness* is
    isolated rather than the subsystem.

    ``WORLD_LIFECYCLE`` runs the birth gate **and** evidence tension, because CBF-F07 has no
    Subsystem of its own and an unexercised subsystem call is a hole in the injection.
    """

    def lifecycle(evidence: IncidentEvidence, transition: SSIRTransitionV1) -> object:
        return (
            _hook_world_lifecycle(model, evidence, transition),
            _hook_evidence_tension(model, evidence, transition),
        )

    return {
        Subsystem.WORLD_LIFECYCLE: lifecycle,
        Subsystem.CLAIM_COMPILER: partial(_hook_claim_compiler, model),
        Subsystem.ACTIVE_SENSING: partial(_hook_active_sensing, model, observation),
        Subsystem.COUNTERFACTUAL: partial(_hook_counterfactual, model),
        Subsystem.CALIBRATION: partial(_hook_calibration, model),
        Subsystem.EXTERNAL_KNOWLEDGE: partial(_hook_external_knowledge, model),
        Subsystem.VERBALIZER: partial(_hook_verbalizer, model),
        Subsystem.CRYSTAL_HANDOFF: partial(_hook_crystal_handoff, model),
        Subsystem.SEQUENTIAL_EVIDENCE: partial(_hook_sequential_evidence, model),
        Subsystem.WORLD_GRAPH: partial(_hook_world_graph, model),
    }


def with_fault(
    hooks: Mapping[Subsystem, Callable[[IncidentEvidence, SSIRTransitionV1], object]],
    subsystem: Subsystem,
    exception: type[BaseException] = RuntimeError,
) -> dict[Subsystem, Callable[[IncidentEvidence, SSIRTransitionV1], object]]:
    """One hook that raises **mid-incident**, at the middle transition and nowhere else.

    Mid-incident and not at the start: a subsystem that fails on its first call never
    held any state, and the property being tested is that live Stage 1 state sitting
    next to a half-built Stage 4 reasoning state survives.
    """
    healthy = hooks[subsystem]
    faulted = dict(hooks)

    def faulty(evidence: IncidentEvidence, transition: SSIRTransitionV1) -> object:
        if transition.sequence == evidence.middle_sequence:
            raise exception(f"injected {subsystem.value} failure at {transition.sequence}")
        return healthy(evidence, transition)

    faulted[subsystem] = faulty
    return faulted


