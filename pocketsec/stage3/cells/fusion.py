"""D3.10 (part) — cell fusion (§23): merge two cells that agree about the future.

§23 permits a merge only when *"SecurityFuture(K_i) ≈ SecurityFuture(K_j) AND
boundary union remains validated"*, and requires that *"fusion is reversible and
must pass the same shadow/stress process as a newly synthesized cell."* Both
clauses are enforced here rather than described.

What this module refuses to do, and why each refusal is load-bearing:

* **It never fuses across incompatible epochs.** Two cells whose epoch sets are
  disjoint were validated in configurations that never coexisted; their union
  would claim validity in a world no evidence covers. That is the §39
  epoch-manipulation path, and it is closed by construction.
* **It never fuses cells with different operators.** Fusing programs would mean
  synthesising a third one, which is crystallisation, not fusion — and it would
  be crystallisation with no boundary pressure and no dual-oracle check behind
  it. Same operator digest, or no fusion.
* **It never loosens a bound in the union.** ``max_uncertainty`` takes the
  *tighter* of the two ceilings and ``forbidden_combinations`` takes the union,
  so a combination either parent forbade stays forbidden. A union that relaxed
  its parents' limits would let fusion launder an un-validated region.
* **It never produces a crystallized cell.** The fused cell re-enters shadow at
  ``AssuranceLevel.A0`` with both parents named in ``parent_cell_id``, so the
  merge is reversible and has to earn its assurance again from zero.

:func:`fuse_cells` returns ``None`` on every refusal, per the D3.10 contract.
:func:`fusion_refusal` exposes *why*, so an auditor is not left guessing.
"""

from __future__ import annotations

import hashlib
from dataclasses import replace

from pocketsec.stage0.contracts.common import ContractError, EvidenceRef
from pocketsec.stage3.boundary.index import MAX_KEYS_PER_CELL, CellBoundary
from pocketsec.stage3.cells.schema import (
    AssuranceLevel,
    CellPhase,
    HardConstraint,
    KnowledgeCellV1,
)
from pocketsec.stage3.theory import ResolutionState

__all__ = [
    "FUSED_PARENT_PREFIX",
    "FUSED_PARENT_SEPARATOR",
    "fuse_cells",
    "fusion_refusal",
]

#: ``parent_cell_id`` is a single string in the v1 schema, so a fused cell
#: encodes both parents in it. The prefix makes the encoding greppable and
#: keeps rollback mechanical rather than a matter of convention. The separator
#: is ``:`` because the whole string must still pass ``require_identifier``.
FUSED_PARENT_PREFIX = "fused:"
FUSED_PARENT_SEPARATOR = ":"


def _security_future_equivalent(a: KnowledgeCellV1, b: KnowledgeCellV1) -> bool:
    """Same consequent spec and the same hard-constraint set.

    Equivalence is judged on what the cells *promise about the future*, not on
    how they compute it: same required dimensions, same ΔΦ floor, same required
    evidence kinds, same consequence level, same constraint kinds.
    """
    if a.invariant.consequent != b.invariant.consequent:
        return False
    return {c.kind for c in a.constraints} == {c.kind for c in b.constraints}


def _union_boundary(a: CellBoundary, b: CellBoundary) -> CellBoundary:
    """The conservative union: wider where it must be, tighter where it can be."""
    return replace(
        a,
        predicates=tuple(dict.fromkeys((*a.predicates, *b.predicates))),
        state_dimensions=a.state_dimensions | b.state_dimensions,
        phi_range=(min(a.phi_range[0], b.phi_range[0]), max(a.phi_range[1], b.phi_range[1])),
        max_uncertainty=min(a.max_uncertainty, b.max_uncertainty),
        epochs=a.epochs | b.epochs,
        forbidden_combinations=tuple(
            dict.fromkeys((*a.forbidden_combinations, *b.forbidden_combinations))
        ),
    )


def _union_validated(union: CellBoundary) -> str:
    """Empty string when the union is still a usable boundary."""
    if union.is_empty:
        return "UNION_EMPTY: the merged boundary contains nothing"
    if union.unseen_input_behaviour != "ABSTAIN":
        return "UNION_NOT_ABSTAINING: unseen input must abstain"
    required: set[object] = set()
    forbidden: set[object] = set()
    for predicate in union.predicates:
        required |= set(predicate.required_properties)
        forbidden |= set(predicate.forbidden_properties)
    if required & forbidden:
        return "UNION_CONTRADICTORY: a property is both required and forbidden"
    try:
        keys = union.keys()
    except ContractError as exc:
        return f"UNION_KEY_EXPANSION: {exc}"
    if len(keys) > MAX_KEYS_PER_CELL:
        return f"UNION_KEY_EXPANSION: {len(keys)} keys > {MAX_KEYS_PER_CELL}"
    return ""


def fusion_refusal(a: KnowledgeCellV1, b: KnowledgeCellV1) -> str:
    """The reason these two cells may not fuse; empty string when they may."""
    if a.cell_id == b.cell_id:
        return "SAME_CELL: a cell cannot fuse with itself"
    if a.epochs.isdisjoint(b.epochs) or a.boundary.epochs.isdisjoint(b.boundary.epochs):
        return "INCOMPATIBLE_EPOCHS: the two cells share no validated epoch"
    if a.operator.digest != b.operator.digest:
        return "OPERATOR_MISMATCH: fusing programs would be re-synthesis, not fusion"
    if not _security_future_equivalent(a, b):
        return "SECURITY_FUTURE_DIVERGES: consequent specs or constraints differ"
    return _union_validated(_union_boundary(a.boundary, b.boundary))


def _fused_id(a: KnowledgeCellV1, b: KnowledgeCellV1) -> str:
    left, right = sorted((a.cell_id, b.cell_id))
    return "fuse-" + hashlib.sha256(f"{left}|{right}".encode()).hexdigest()[:24]


def _merged_constraints(
    a: KnowledgeCellV1, b: KnowledgeCellV1
) -> tuple[HardConstraint, ...]:
    merged: dict[str, HardConstraint] = {}
    for constraint in (*a.constraints, *b.constraints):
        merged.setdefault(constraint.constraint_id, constraint)
    return tuple(merged.values())


def _merged_evidence(a: KnowledgeCellV1, b: KnowledgeCellV1) -> tuple[EvidenceRef, ...]:
    return tuple(dict.fromkeys((*a.evidence_lineage, *b.evidence_lineage)))


def _weaker_resolution(a: KnowledgeCellV1, b: KnowledgeCellV1) -> ResolutionState:
    """Take the worse value on every axis — a merge cannot invent resolution."""
    left, right = a.resolution, b.resolution
    return replace(
        left,
        predictive_stability=min(left.predictive_stability, right.predictive_stability),
        calibrated_uncertainty=max(left.calibrated_uncertainty, right.calibrated_uncertainty),
        validated_breadth=min(left.validated_breadth, right.validated_breadth),
        counterfactual_consistency=min(
            left.counterfactual_consistency, right.counterfactual_consistency
        ),
        evidence_agreement=min(left.evidence_agreement, right.evidence_agreement),
        drift_stability=min(left.drift_stability, right.drift_stability),
        measured_by="pocketsec.stage3.cells.fusion:fuse_cells",
    )


def fuse_cells(a: KnowledgeCellV1, b: KnowledgeCellV1) -> KnowledgeCellV1 | None:
    """Merge two equivalent cells, or return ``None`` with no side effects."""
    if fusion_refusal(a, b):
        return None
    invariant = replace(
        a.invariant,
        invariant_id=f"{a.invariant.invariant_id}:{b.invariant.invariant_id}"[:128],
        # Support counts distinct lineages. The two parents may have witnessed
        # the same ones, so the merged support is the minimum, never the sum:
        # fusion must not manufacture corroboration (ADR-0007).
        support=min(a.invariant.support, b.invariant.support),
        contradictions=a.invariant.contradictions + b.invariant.contradictions,
        epochs=a.invariant.epochs | b.invariant.epochs,
        evidence=tuple(dict.fromkeys((*a.invariant.evidence, *b.invariant.evidence))),
    )
    return replace(
        a,
        cell_id=_fused_id(a, b),
        invariant=invariant,
        boundary=_union_boundary(a.boundary, b.boundary),
        resolution=_weaker_resolution(a, b),
        confidence=min(a.confidence, b.confidence),
        assurance=AssuranceLevel.A0,
        phase=CellPhase.STRUCTURED,
        evidence_lineage=_merged_evidence(a, b),
        constraints=_merged_constraints(a, b),
        epochs=a.epochs | b.epochs,
        version=max(a.version, b.version) + 1,
        parent_cell_id=(
            f"{FUSED_PARENT_PREFIX}{a.cell_id}{FUSED_PARENT_SEPARATOR}{b.cell_id}"
        ),
    )
