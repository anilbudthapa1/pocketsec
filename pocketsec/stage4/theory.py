"""D4.1 — the Causal Belief Field formal specification, as an executable table.

Every construct the architecture document defines gets one :class:`Definition`
row: the section it comes from, the document's own expression, the Python symbol
that realises it, the function whose output measures it, and — the row that
matters most — the observation that would falsify it.

**The deliverable is :func:`unbound_terms`, not the table.** It resolves each
``bound_to`` with ``importlib`` and ``getattr`` and returns the terms that do not
exist yet. A definition table nobody can execute is prose, and prose has already
cost this project real wrong answers: Stage 2's ADR-0116 declared two mechanisms
"default off" while no constant in the code said so, and the cone kept running.
G4.7's structural half is ``unbound_terms() == ()``.

The table refuses to do two things. It states no threshold, so nothing can read a
decision out of it; and it never records a term as bound because a document says
so. ``unbound_terms()`` imports the module and looks the attribute up, every call.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import ContractError

if TYPE_CHECKING:  # pragma: no cover - typing only
    from collections.abc import Mapping

__all__ = [
    "CBF_THEORY_VERSION",
    "DEFINITIONS",
    "DEFINITIONS_BY_TERM",
    "Definition",
    "MAX_DEFINITIONS",
    "definition",
    "resolve_binding",
    "unbound_terms",
]

CBF_THEORY_VERSION = "stage4-cbf-theory-v1.0.0"

#: Spec bound. A table that grows without limit stops being auditable by reading.
MAX_DEFINITIONS = 40


@dataclass(frozen=True, slots=True)
class Definition:
    """One architecture construct, bound to code and to a falsification."""

    term: str
    #: Traceability to the source document, so a reader can check the wording.
    architecture_section: str
    #: The document's own expression. Quoted, not paraphrased.
    formula: str
    #: Dotted path to the symbol that realises it.
    bound_to: str
    #: The exact function whose output realises the quantity.
    measurable_as: str
    #: The observation that would refute the construct. A definition with no
    #: falsifier is a name, and §51 is explicit that a new name proves nothing.
    falsified_if: str

    def __post_init__(self) -> None:
        for name in ("term", "architecture_section", "formula", "bound_to"):
            if not getattr(self, name):
                raise ContractError(f"Definition.{name} must be non-empty for {self.term!r}")
        if not self.falsified_if:
            raise ContractError(
                f"definition {self.term!r} names no falsifier; an unfalsifiable "
                "construct is a label, not a theory (§51)"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "term": self.term,
            "architecture_section": self.architecture_section,
            "formula": self.formula,
            "bound_to": self.bound_to,
            "measurable_as": self.measurable_as,
            "falsified_if": self.falsified_if,
        }


_W = "pocketsec.stage4.worlds"
_C = "pocketsec.stage4.counterfactual"

DEFINITIONS: tuple[Definition, ...] = (
    Definition(
        "causal_belief_field",
        "§2/§3",
        "CBF_t = { (W_i, support_i) } for i = 1..K, with K hard-bounded",
        f"{_W}.field.CausalBeliefField",
        "CausalBeliefField.support_vector() over a bounded world tuple",
        "a single-world MAP field reaches equal incident quality at lower cost",
    ),
    Definition(
        "latent_security_state",
        "§5",
        "X_(t+1) ~ Transition(X_t, event); O_t ~ Observation(X_t, A_t, V_t)",
        f"{_W}.world.LatentSecurityState",
        "LatentSecurityState.consequence, checked equal to phi(state).total",
        "a world's asserted dimensions can exceed what its latent state holds",
    ),
    Definition(
        "sensor_shadow",
        "§6",
        "Shadow_t = PotentialSecurityEvidence - ObservableEvidence(A_t, kernel, "
        "privileges, dropped_events)",
        "pocketsec.stage4.visibility.sensor_shadow.SensorShadow",
        "estimate_sensor_shadow(...).confidence_penalty()",
        "dropping a sensor path does not lower confidence on the affected cases",
    ),
    Definition(
        "evidence_tension",
        "§7",
        "Tension(W) = unexpected_observation_cost + missing_expected_evidence_cost + "
        "causal_inconsistency + temporal_inconsistency + security_state_inconsistency + "
        "visibility_adjusted_contradiction",
        "pocketsec.stage4.tension.evidence_tension.EvidenceTension",
        "calculate_evidence_tension(...).total, with all six terms attached",
        "an incorrect world accumulates no more tension than the correct one",
    ),
    Definition(
        "negative_evidence",
        "§8",
        "absence is informative iff P(observe e | e occurred, A_t, V_t) is high "
        "AND W strongly predicts e AND e is absent; otherwise UNKNOWN",
        "pocketsec.stage4.tension.negative_evidence.classify_absence",
        "classify_absence(...) returning INFORMATIVE_ABSENCE vs UNKNOWN_ABSENCE",
        "a world killed by absence under full visibility also dies under a dropped sensor",
    ),
    Definition(
        "causal_intervention",
        "§9",
        "do(remove E17); do(replace actor semantic class); do(suppress escalation); "
        "measure change in predicted outcome, world support and future evidence",
        f"{_C}.intervention.counterfactual_intervene",
        "the support_distance between the field before and after the intervention",
        "interventions do not improve attribution or sensor planning over ancestry",
    ),
    Definition(
        "responsibility_flux",
        "§10",
        "RF(E_j,t) = change in security-world distribution when E_j is "
        "counterfactually perturbed",
        f"{_C}.intervention.calculate_responsibility_flux",
        "the per-event flux vector over the causal spine",
        "flux ranks events no better than Stage 1 lineage cumulative responsibility",
    ),
    Definition(
        "belief_geometry",
        "§11",
        "representations benchmarked: calibrated probabilities, log-odds/energy, "
        "evidence intervals, conformal sets, e-values",
        f"{_W}.world.BeliefGeometry",
        "WorldSupport.as_probability() returning None for every non-normalising geometry",
        "a log-odds is read as a probability anywhere in the emitted output",
    ),
    Definition(
        "world_birth",
        "§12",
        "Residual = ObservedEvidence - BestExplainedEvidence; spawn a bounded "
        "UNKNOWN world only if the residual is security-relevant, persistent, not a "
        "visibility artifact and not explainable by existing worlds",
        f"{_W}.lifecycle.spawn_world",
        "the spawn/refusal counts under benign novelty",
        "benign novelty causes hypothesis explosion instead of one UNKNOWN world",
    ),
    Definition(
        "world_death",
        "§13",
        "kill on hard contradiction OR sustained tension OR domination by a simpler "
        "world OR epoch invalidation OR assurance below threshold",
        f"{_W}.lifecycle.kill_world",
        "the death cause distribution and the tombstone ledger",
        "the ground-truth world dies while an incorrect world survives",
    ),
    Definition(
        "world_fission",
        "§14",
        "one world predicts incompatible evidence regimes: W -> W_a + W_b",
        f"{_W}.lifecycle.fission_world",
        "world-set recall with enable_fission_fusion on versus off",
        "fission adds no recall over a fixed world set at equal cost",
    ),
    Definition(
        "world_fusion",
        "§14",
        "two worlds become observationally/security equivalent: W_a + W_b -> W*",
        f"{_W}.lifecycle.fuse_worlds",
        "world count per incident with fusion on versus off",
        "fusion merges two worlds that later evidence would have separated",
    ),
    Definition(
        "incident_future_cone",
        "§15",
        "compose local future cones into bounded incident-level counterfactual "
        "futures; observed next evidence collapses branches and worlds",
        "pocketsec.stage4.cones.incident_cone.IncidentFutureCone",
        "the branch count retained per world and the collapse rate on observation",
        "branch composition adds nothing over each world's expected-evidence set",
    ),
    Definition(
        "discrimination",
        "§16",
        "Discrimination(o) = expected distance between posterior world fields after "
        "possible outcomes of o; Utility(o) = Discrimination * SecurityConsequence / cost",
        "pocketsec.stage4.cones.incident_cone.IncidentFutureCone.discriminating_signals",
        "the symmetric difference of two worlds' predicted signal sets",
        "a discrimination-ranked observation resolves no faster than a fixed order",
    ),
    Definition(
        "counterfactual_sensor_planning",
        "§17",
        "if predicted outcomes are nearly identical across worlds, do NOT spend the "
        "telemetry budget",
        "pocketsec.stage4.sensing.simulate.simulate_sensor_value",
        "telemetry bytes and cpu units versus always-on rich telemetry, same run",
        "targeted sensing does not reduce bytes and CPU at comparable resolution quality",
    ),
    Definition(
        "security_free_energy",
        "§18",
        "F_security = unresolved_world_uncertainty + evidence_prediction_error + "
        "consequence_weighted_unknownness + sensing_cost",
        "pocketsec.stage4.engine.lucid.LucidConfig",
        "the LucidConfig.enable_free_energy flag's measured delta against information gain",
        "the objective does not outperform simpler information-gain planning (§18 then removes it)",
    ),
    Definition(
        "incident_identifiability",
        "§19",
        "Identifiable(H) iff available/affordable observations can distinguish H from "
        "material alternatives within required error bounds",
        "pocketsec.stage4.identifiability.resolution.test_identifiability",
        "non-identifiability accuracy on constructed non-identifiable pairs",
        "constructed non-identifiable cases are resolved to a single named world",
    ),
    Definition(
        "resolution_horizon",
        "§20",
        "max time / evidence / compute budget before resolve, escalate, preserve "
        "unresolved, or request a higher observation tier",
        "pocketsec.stage4.identifiability.horizon.ResolutionHorizon",
        "ResolutionHorizon.outcome(verdict) over exhausted incidents",
        "horizon exhaustion produces a benign resolution",
    ),
    Definition(
        "semantic_conservation",
        "§21",
        "read of CREDENTIAL_MATERIAL may license 'possible credential access' and "
        "may NOT license 'password stolen'",
        "pocketsec.stage4.claims.compiler.amplification_violations",
        "amplification_violations(claims) over every emitted claim",
        "an authoritative claim states more than its premise chain evidences",
    ),
    Definition(
        "epistemic_type_system",
        "§22",
        "OBS direct observation; DER deterministic derivation; INF model inference; "
        "CF counterfactual; EXT external mapping; UNK unknown/unobserved",
        "pocketsec.stage4.claims.typed_claim.ClaimKind",
        "ClaimGraph.kinds_present() and unsupported_authoritative()",
        "an INF or CF claim can be emitted as authoritative",
    ),
    Definition(
        "claim_compiler",
        "§23",
        "claim template: headline / because / against / unknown, compiled from typed "
        "evidence rather than generated freely",
        "pocketsec.stage4.claims.compiler.compile_typed_claim_graph",
        "CompiledClaim.render() determinism and the unsupported-claim count",
        "a rendered claim contains a proposition absent from the typed graph",
    ),
    Definition(
        "self_questioning",
        "§24",
        "for every high-consequence world: what would falsify it, what else explains "
        "the evidence, which claim depends on missing visibility, which event carries "
        "too much responsibility",
        f"{_C}.questions.self_question_world",
        "the count of real defects the questions catch beyond ordinary validation",
        "self-questioning catches nothing ordinary validation would not have caught",
    ),
    Definition(
        "adversarial_belief_stress",
        "§25",
        "insert benign context, remove one critical event, rename while preserving "
        "semantics, delay steps, inject decoys, drop telemetry, replace IOCs",
        f"{_C}.stress.stress_world_adversarially",
        "spurious-explanation detection rate on the decoy corpus",
        "a semantics-preserving rename changes the support vector",
    ),
    Definition(
        "sparse_world_graph",
        "§28",
        "node retained if causal_credit > theta OR contradiction_value > theta OR "
        "discrimination_value > theta OR mandatory evidence retention",
        "pocketsec.stage4.graph.sparse_world_graph.SparseWorldGraph",
        "retained nodes and edges per incident against the hard bounds",
        "the sparse graph drops a node the resolution later needed",
    ),
    Definition(
        "incident_entropy_budget",
        "§29",
        "Budget_I = { max_worlds, max_edges, max_counterfactuals, "
        "max_sensor_escalations, max_reasoning_units, max_memory_bytes }",
        "pocketsec.stage4.graph.entropy_budget.EntropyBudget",
        "BudgetController.spend_report() under the adversarial world flood",
        "budget exhaustion silently simplifies an unresolved field into benign",
    ),
    Definition(
        "world_dominance",
        "§30",
        "W_a dominates W_b if it explains >= critical evidence, has <= contradictions, "
        "requires <= unsupported assumptions, costs <= budget, and no "
        "security-critical future unique to W_b is lost",
        f"{_W}.lifecycle.prune_dominated_worlds",
        "world count before and after pruning, with the fifth clause's veto rate",
        "pruning removes the only world predicting a security-critical future",
    ),
    Definition(
        "sequential_evidence",
        "§31",
        "Evidence_t(W) updated per relevant observation; stop on sufficient support, "
        "sufficient contradiction, resolution horizon, or non-identifiability",
        "pocketsec.stage4.evidence.sequential.SequentialEvidence",
        "the e-value trajectory and its anytime_valid flag",
        "the accumulator resolves no earlier than a fixed-window count at equal error",
    ),
    Definition(
        "calibration_under_drift",
        "§32",
        "if calibration_error(epoch) rises: widen uncertainty, increase abstention, "
        "raise audit rate, reduce crystallization trust",
        "pocketsec.stage4.evidence.calibration.EpochCalibration",
        "EpochCalibration.report(epoch).ece, which is None when under-sampled",
        "rising calibration error does not widen uncertainty or raise abstention",
    ),
)

DEFINITIONS_BY_TERM: Mapping[str, Definition] = MappingProxyType(
    {entry.term: entry for entry in DEFINITIONS}
)


def definition(term: str) -> Definition:
    """One definition by term, failing loudly on an unknown one."""
    try:
        return DEFINITIONS_BY_TERM[term]
    except KeyError as exc:
        raise ContractError(f"no Stage 4 definition for term {term!r}") from exc


def resolve_binding(bound_to: str) -> object:
    """Resolve a dotted ``bound_to`` path to the live object, or raise.

    Tries the longest importable module prefix first, then walks the remaining
    parts with ``getattr``, so both ``module.Class`` and ``module.Class.member``
    resolve. Raising rather than returning ``None`` keeps "missing" and "bound to
    None" distinguishable.
    """
    parts = bound_to.split(".")
    for split in range(len(parts) - 1, 0, -1):
        module_name = ".".join(parts[:split])
        try:
            module = importlib.import_module(module_name)
        except ImportError:
            continue
        target: object = module
        for attribute in parts[split:]:
            target = getattr(target, attribute)
        return target
    raise ImportError(f"no importable module prefix in {bound_to!r}")


def unbound_terms() -> tuple[str, ...]:
    """Terms whose ``bound_to`` does not resolve, in table order.

    This is the deliverable. G4.7 asserts it is empty; while Stage 4 is being
    built it is the honest list of what the theory table promises and the code
    does not yet provide.
    """
    missing: list[str] = []
    for entry in DEFINITIONS:
        try:
            resolve_binding(entry.bound_to)
        except (ImportError, AttributeError):
            missing.append(entry.term)
    return tuple(missing)


assert len(DEFINITIONS) <= MAX_DEFINITIONS, "the definition table is bounded"
assert len(DEFINITIONS_BY_TERM) == len(DEFINITIONS), "definition terms must be unique"
assert len(DEFINITIONS) >= 20, "D4.1 requires at least twenty architecture constructs"
