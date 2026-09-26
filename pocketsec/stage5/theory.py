"""D5.18 — the formal statement of architecture §§3, 7, 10, 11, 23 and 26, every term bound.

Each construct the architecture defines gets one :class:`Definition` row: the section it
comes from, the document's own expression quoted rather than paraphrased, the Python
symbol that realises it, the function whose output measures it, and — the column that
matters most — the observation that would falsify it.

**The deliverable is :func:`unbound_terms`, not the table.** It resolves every
``bound_to`` through ``importlib`` and ``getattr`` and returns the terms that do not
exist. A definition table nobody can execute is prose, and prose has already cost this
project real wrong answers: Stage 2's ADR-0116 declared two mechanisms "default off"
while no constant in the code said so, and the cone kept running on every deep event.
Stage 4's ``theory.py`` is the precedent and G4.7 asserted its result was empty.

The table refuses to do two things. It states **no threshold**, so nothing can read a
decision out of it; and it never records a term as bound because a document says so —
``unbound_terms()`` imports the module and looks the attribute up, every call.

**Section 11's six terms, and the one sentence this module exists to make unavoidable.**
§11 writes Minimum Effective Intervention as a minimisation of
``scope + irreversibility + collateral + evidence_loss + ActionShadow +
operational_cost``. Each of those six is bound below to a field of
:class:`~pocketsec.stage5.safe.action_field.CandidateAction`. **Those six numbers are
never summed anywhere in this codebase**, because §12 says AEGIS removes dominated
actions *first* and only then applies a policy order: a scalarisation would hide exactly
the trade-off the frontier exists to expose, and ``aegis/pareto.py``'s
``DEFAULT_WEIGHTS`` exists only to make the B6 control runnable and says so itself.
:func:`mei_terms_summed` is the AST check that keeps that claim true, so the sentence
above is a testable statement about the package rather than an intention.
"""

from __future__ import annotations

import ast
import importlib
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

from pocketsec.stage0.contracts.common import ContractError

__all__ = [
    "DEFINITIONS",
    "DEFINITIONS_BY_TERM",
    "MAX_DEFINITIONS",
    "MEI_TERM_ATTRIBUTES",
    "MIN_MEI_ATTRIBUTES_IN_A_SUM",
    "SAFE_THEORY_VERSION",
    "Definition",
    "definition",
    "mei_terms_summed",
    "resolve_binding",
    "sections_covered",
    "unbound_terms",
]

SAFE_THEORY_VERSION = "stage5-safe-theory-v1.0.0"

#: Spec bound. A table that grows without limit stops being auditable by reading.
MAX_DEFINITIONS = 64

#: The six §11 terms, as the ``CandidateAction`` attribute each is bound to.
#: :func:`mei_terms_summed` looks for an expression that adds two or more of these.
MEI_TERM_ATTRIBUTES: tuple[str, ...] = (
    "scope_size",
    "reversibility",
    "expected_operational_delta",
    "evidence_loss",
    "shadow",
    "lease_ttl_seconds",
)

#: Two is enough to be a scalarisation. Requiring three would let a partial sum through,
#: and a partial sum of the objective vector is the same defect at a smaller size.
MIN_MEI_ATTRIBUTES_IN_A_SUM: int = 2


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
    #: The exact function or field whose value realises the quantity.
    measurable_as: str
    #: The observation that would refute the construct. A definition with no falsifier is
    #: a name, and §49 is explicit that a new name proves nothing.
    falsified_if: str

    def __post_init__(self) -> None:
        for name in ("term", "architecture_section", "formula", "bound_to", "measurable_as"):
            if not str(getattr(self, name)).strip():
                raise ContractError(f"Definition.{name} must be non-empty for {self.term!r}")
        if not self.falsified_if.strip():
            raise ContractError(
                f"definition {self.term!r} names no falsifier; an unfalsifiable construct is a "
                "label, not a theory (§49)"
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


_F = "pocketsec.stage5.safe.action_field"
_T = "pocketsec.stage5.twin.response_twin"
_C = "pocketsec.stage5.aegis.cone"
_S = "pocketsec.stage5.aegis.shadow"
_P = "pocketsec.stage5.aegis.pareto"
_R = "pocketsec.stage5.recovery.safe_state"
_A = "pocketsec.stage5.operators.algebra"

DEFINITIONS: tuple[Definition, ...] = (
    # --- §3, the SAFE Action Field -------------------------------------------
    Definition(
        "safe_action_field",
        "§3",
        "A_j = (operator, target_scope, preconditions, world_applicability, "
        "expected_security_delta, expected_operational_delta, evidence_effect, "
        "reversibility, rollback_plan, authority_class, verification_predicates, lease, "
        "uncertainty, action_shadow)",
        f"{_F}.CandidateAction",
        "generate_action_field(...).candidates, bounded at MAX_CANDIDATES",
        "a field bounded at one candidate reaches equal collateral and containment, so "
        "enumerating alternatives bought nothing",
    ),
    Definition(
        "action_field_operator",
        "§3",
        "A_j.operator — the typed defensive operator, never a string",
        f"{_A}.DefensiveOperator",
        "CandidateAction.operator, whose spec must be a CATALOG member by identity",
        "a structurally equal forged OperatorSpec is accepted by the executor",
    ),
    Definition(
        "action_field_target_scope",
        "§3",
        "A_j.target_scope",
        f"{_A}.TargetScope",
        "CandidateAction.operator.target.scope, host_local enforced",
        "a non-host-local scope reaches a host call",
    ),
    Definition(
        "action_field_preconditions",
        "§3",
        "A_j.preconditions",
        f"{_A}.PreconditionKind",
        "OperatorSpec.preconditions, checked by SentinelKernel's preconditions check",
        "an action commits with a declared precondition unchecked",
    ),
    Definition(
        "world_applicability",
        "§3",
        "A_j.world_applicability — the mechanism ids this candidate addresses",
        f"{_F}.CandidateAction.world_applicability",
        "the mechanism ids surviving RULED_OUT_SUPPORT with reconstructible evidence",
        "restricting a candidate to the leading world alone changes no decision",
    ),
    Definition(
        "expected_security_delta",
        "§3",
        "A_j.expected_security_delta",
        f"{_F}.CandidateAction.expected_security_delta",
        "the measured effect rate where effectiveness memory has samples, else a class prior",
        "the prior and the measured rate rank candidates identically on every case",
    ),
    Definition(
        "expected_operational_delta",
        "§3",
        "A_j.expected_operational_delta",
        f"{_F}.CandidateAction.expected_operational_delta",
        "reversibility cost weighted against a bounded scope term",
        "operational delta does not correlate with observed collateral",
    ),
    Definition(
        "evidence_effect",
        "§3",
        "A_j.evidence_effect",
        f"{_A}.EvidenceEffect",
        "OperatorSpec.evidence_effect, read by the preservation gate before COMMIT",
        "an operator declared PRESERVES loses a signal the gate required",
    ),
    Definition(
        "reversibility",
        "§3",
        "A_j.reversibility",
        f"{_A}.Reversibility",
        "OperatorSpec.reversibility, ordered by REVERSIBILITY_ORDER",
        "an IRREVERSIBLE operator is carried under an autonomous authority class",
    ),
    Definition(
        "rollback_plan",
        "§3",
        "A_j.rollback_plan",
        f"{_A}.DefensiveOperator.rollback",
        "spec.rollback_operator_id resolved back through the catalog",
        "a leased restriction has no rollback operator and is still granted",
    ),
    Definition(
        "authority_class",
        "§3/§14",
        "A_j.authority_class",
        "pocketsec.stage5.constitution.invariants.AuthorityClass",
        "required_authority(spec), total over OperatorClass",
        "an operator's authority class differs from its class's mapping",
    ),
    Definition(
        "verification_predicates",
        "§3/§20",
        "A_j.verification_predicates",
        "pocketsec.stage5.executor.verify.PostconditionKind",
        "PostconditionProbe.probe(...) results, one per declared predicate",
        "a candidate with no verification predicate is generated",
    ),
    Definition(
        "action_lease",
        "§3/§18",
        "A_j.lease",
        "pocketsec.stage5.executor.lease.Lease",
        "Lease.expired(now), a pure function of the lease's frozen fields",
        "a lease is not expired until something happens to call the registry",
    ),
    Definition(
        "action_uncertainty",
        "§3",
        "A_j.uncertainty — carried from the resolution, never converted into authority",
        f"{_F}.CandidateAction.uncertainty",
        "CBFResolutionV1.uncertainty as it reaches the candidate",
        "two resolutions differing only in uncertainty reach different authority decisions",
    ),
    # --- §7, response identifiability ----------------------------------------
    Definition(
        "response_identifiability",
        "§7",
        "ActionIdentifiable(A) iff for every material Stage-4 world W where A causes "
        "unacceptable harm, W has been sufficiently ruled out OR explicit policy accepts "
        "that residual risk",
        f"{_F}.check_response_identifiability",
        "ResponseIdentifiability.outcome over the resolution's hypotheses",
        "the check never returns NOT_IDENTIFIABLE on a corpus of indistinguishable pairs",
    ),
    Definition(
        "unacceptable_harm",
        "§7",
        "the (world, action) pairs where A causes unacceptable harm",
        f"{_F}.HarmModel",
        "HarmModel.harms(mechanism_id, spec), an authored or invariant-derived table",
        "the harm table is derived from a model score rather than from policy",
    ),
    Definition(
        "sufficiently_ruled_out",
        "§7",
        "W has been sufficiently ruled out",
        f"{_F}.RULED_OUT_SUPPORT",
        "hypothesis support <= RULED_OUT_SUPPORT",
        "a world at the threshold is treated as ruled out on one path and not on another",
    ),
    Definition(
        "accepted_residual_risk",
        "§7",
        "OR explicit policy accepts that residual risk",
        f"{_F}.RiskAcceptancePolicy",
        "RiskAcceptancePolicy.accepted_operator_classes, {O0, O1} by default",
        "a class above O1 is accepted as residual risk without a human grant",
    ),
    # --- §10, Action Shadow --------------------------------------------------
    Definition(
        "action_shadow",
        "§10",
        "AS(A) = unmodelled dependencies + uncertain side effects + unobservable "
        "post-action effects",
        f"{_S}.ActionShadow",
        "estimate_action_shadow(...).score, decomposable into its three counted terms",
        "shadow does not rank-correlate with measured intervention residual, so it "
        "cannot gate autonomy on evidence (falsifier F3)",
    ),
    Definition(
        "unmodelled_dependencies",
        "§10",
        "AS(A) term 1 — unmodelled dependencies",
        f"{_T}.ResponseTwin.unknown_dependencies",
        "TwinPrediction.unknown_dependencies, counted into ActionShadow",
        "adding an unknown dependency does not raise shadow",
    ),
    Definition(
        "shadow_autonomy_gate",
        "§10",
        "high Action Shadow pushes the action toward observe/defer/human approval even "
        "when predicted security benefit is large",
        f"{_S}.shadow_gate",
        "AutonomyEligibility from shadow alone; the function takes no benefit argument",
        "a benefit term can be passed to the gate, so benefit can override shadow",
    ),
    # --- §11, minimum effective intervention ---------------------------------
    Definition(
        "minimum_effective_intervention",
        "§11",
        "minimize: scope(A) + irreversibility(A) + collateral(A) + evidence_loss(A) + "
        "ActionShadow(A) + operational_cost(A) subject to required_security_risk_reduction, "
        "hard safety invariants, authority, verification, rollback/expiry policy",
        f"{_P}.ObjectiveVector",
        "score(candidate, ...).objectives, compared component-wise and never summed",
        "a scalarisation over these six terms selects the same action as the frontier on "
        "every case, so §12's argument for removing dominated actions first is unsupported "
        "(falsifier F4)",
    ),
    Definition(
        "mei_scope",
        "§11",
        "scope(A) — processes, services and sessions the action touches",
        f"{_F}.CandidateAction.scope_size",
        "CandidateAction.scope_size, counted from the snapshot without twin steps",
        "scope_size is constant across candidates, so the term cannot discriminate",
    ),
    Definition(
        "mei_irreversibility",
        "§11",
        "irreversibility(A)",
        f"{_F}.CandidateAction.reversibility",
        "IRREVERSIBILITY_SCALE[candidate.reversibility]",
        "an irreversible candidate scores no worse than a fully reversible one",
    ),
    Definition(
        "mei_collateral",
        "§11",
        "collateral(A) — the operational harm the action is predicted to cause",
        f"{_F}.CandidateAction.expected_operational_delta",
        "CandidateAction.expected_operational_delta",
        "predicted collateral does not order candidates by observed collateral",
    ),
    Definition(
        "mei_evidence_loss",
        "§11",
        "evidence_loss(A)",
        f"{_F}.CandidateAction.evidence_loss",
        "the volatile signals the declared evidence effect costs",
        "an operator that loses a uniquely necessary signal scores no worse than one "
        "that loses none",
    ),
    Definition(
        "mei_action_shadow",
        "§11",
        "ActionShadow(A) as a term of the objective",
        f"{_F}.CandidateAction.shadow",
        "CandidateAction.shadow.score",
        "the shadow term is identical for every candidate in a field",
    ),
    Definition(
        "mei_operational_cost",
        "§11",
        "operational_cost(A) — the downtime the action commits the host to",
        f"{_F}.CandidateAction.lease_ttl_seconds",
        "CandidateAction.lease_ttl_seconds, bounded by the operator's max duration",
        "lease length does not correlate with operational cost",
    ),
    Definition(
        "required_risk_reduction",
        "§11",
        "subject to: required_security_risk_reduction",
        "pocketsec.stage5.aegis.planner.PlannerConfig",
        "PlannerConfig.required_risk_reduction as a hard constraint on ACT",
        "an action below the required reduction is still chosen",
    ),
    Definition(
        "hard_safety_invariants",
        "§11/§24",
        "subject to: hard safety invariants",
        "pocketsec.stage5.constitution.schema.MissionInvariantSet",
        "MissionInvariantSet.violations(...), a total match over InvariantKind",
        "an invariant violation is reported after an action rather than before it",
    ),
    # --- §23, the safe-state manifold ---------------------------------------
    Definition(
        "safe_state_manifold",
        "§23",
        "M_safe = { x : critical invariants hold, known malicious trajectory "
        "blocked/reduced, recovery path exists, observation remains sufficient }",
        f"{_R}.SafeStateManifold",
        "in_manifold(snapshot, manifold, leases=...).status",
        "every snapshot is inside the manifold, so the predicate is not a predicate",
    ),
    Definition(
        "manifold_recovery_path",
        "§23",
        "M_safe term 3 — a recovery path exists",
        f"{_R}.ManifoldStatus",
        "ManifoldVerdict.recovery_path_exists, with OUTSIDE_UNRECOVERABLE reachable",
        "OUTSIDE_UNRECOVERABLE never fires, so the planner always finds a path",
    ),
    Definition(
        "manifold_observation_sufficiency",
        "§23",
        "M_safe term 4 — observation remains sufficient",
        f"{_R}.SafeStateManifold.required_observation",
        "ManifoldVerdict.missing_observation",
        "losing a required signal does not move the host outside the manifold",
    ),
    # --- §26, defensive regret ----------------------------------------------
    Definition(
        "defensive_regret",
        "§26",
        "Regret(A,W) = Loss(A,W) - Loss(best admissible action in hindsight, W)",
        f"{_P}.regret",
        "regret(candidate, world_id=..., all_candidates=...)",
        "per-world regret orders candidates identically to expected loss, so the "
        "hindsight benchmark adds nothing",
    ),
    Definition(
        "admissible_action",
        "§26",
        "'admissible' — passes the constitution, the invariants and the shadow gate for "
        "that world; an inadmissible action is not a hindsight benchmark",
        f"{_P}.admissible_in_world",
        "admissible_in_world(...) as the filter on the hindsight set",
        "an inadmissible action is used as the hindsight benchmark",
    ),
    Definition(
        "minimax_regret",
        "§26",
        "minimax-regret is particularly useful when Stage 4 cannot distinguish a benign "
        "administrative world from a compromised one",
        f"{_P}.minimax_regret",
        "minimax_regret(scored, world_ids)",
        "on indistinguishable pairs minimax regret selects the same action as the "
        "leading-world choice",
    ),
    Definition(
        "intervention_residual",
        "§21/§26",
        "IR(A) = distance(predicted post-action state, observed post-action state)",
        "pocketsec.stage5.executor.residual.intervention_residual",
        "InterventionResidual.distance, normalised to [0,1] over six components",
        "the residual decomposition always finds a cause, so it explains noise "
        "(UNATTRIBUTABLE is unreachable)",
    ),
)

DEFINITIONS_BY_TERM = MappingProxyType({entry.term: entry for entry in DEFINITIONS})


def definition(term: str) -> Definition:
    """One definition by term, failing loudly on an unknown one."""
    try:
        return DEFINITIONS_BY_TERM[term]
    except KeyError as exc:
        raise ContractError(f"no Stage 5 definition for term {term!r}") from exc


def sections_covered() -> tuple[str, ...]:
    """Every architecture section the table cites, sorted. Six are required."""
    return tuple(sorted({entry.architecture_section for entry in DEFINITIONS}))


def resolve_binding(bound_to: str) -> object:
    """Resolve a dotted ``bound_to`` path to the live object, or raise.

    Tries the longest importable module prefix first, then walks the remaining parts with
    ``getattr``, so both ``module.Class`` and ``module.Class.member`` resolve. Raising
    rather than returning ``None`` keeps "missing" and "bound to None" distinguishable.
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
    """Terms whose ``bound_to`` does not resolve, in table order. **The deliverable.**

    While Stage 5 is being built this is the honest list of what the theory table promises
    and the code does not yet provide. The gate asserts it is empty.
    """
    missing: list[str] = []
    for entry in DEFINITIONS:
        try:
            resolve_binding(entry.bound_to)
        except (ImportError, AttributeError):
            missing.append(entry.term)
    return tuple(missing)


def mei_terms_summed(package_root: Path) -> tuple[str, ...]:
    """``path:lineno`` for every expression that adds two or more §11 terms together.

    The AST check behind this module's central claim. Walks every module under
    ``package_root`` and reports an addition chain, a ``sum(...)`` call or an augmented
    assignment whose operands read at least :data:`MIN_MEI_ATTRIBUTES_IN_A_SUM` distinct
    :data:`MEI_TERM_ATTRIBUTES`. ``()`` is the property.

    It looks at *attribute names*, not at types, so it is deliberately over-broad: a
    module that happens to add ``scope_size`` to ``lease_ttl_seconds`` for an unrelated
    reason is reported and has to be rewritten or the claim withdrawn. That is the right
    direction for a check whose whole value is that it cannot be satisfied by intent.
    """
    offenders: list[str] = []
    for path in sorted(package_root.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):  # pragma: no cover - a module mid-edit
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.BinOp, ast.AugAssign, ast.Call)):
                continue
            if isinstance(node, ast.BinOp) and not isinstance(node.op, ast.Add):
                continue
            if isinstance(node, ast.AugAssign) and not isinstance(node.op, ast.Add):
                continue
            if isinstance(node, ast.Call) and _call_name(node) != "sum":
                continue
            if len(_mei_attributes(node)) >= MIN_MEI_ATTRIBUTES_IN_A_SUM:
                offenders.append(f"{path}:{node.lineno}")
    return tuple(offenders)


def _call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return ""


def _mei_attributes(node: ast.AST) -> frozenset[str]:
    """The distinct §11 term attribute names read anywhere inside ``node``."""
    return frozenset(
        child.attr
        for child in ast.walk(node)
        if isinstance(child, ast.Attribute) and child.attr in MEI_TERM_ATTRIBUTES
    )


def _required_sections() -> Sequence[str]:
    return ("§3", "§7", "§10", "§11", "§23", "§26")


assert len(DEFINITIONS) <= MAX_DEFINITIONS, "the definition table is bounded"
assert len(DEFINITIONS_BY_TERM) == len(DEFINITIONS), "definition terms must be unique"
assert all(
    any(section in cited for cited in sections_covered()) for section in _required_sections()
), "the table must cover §§3, 7, 10, 11, 23 and 26"
assert len(MEI_TERM_ATTRIBUTES) == 6, "§11 states exactly six terms"
