"""The constructed probes and region builders three gate criteria need.

Split out of ``gate.py`` for one reason: that file holds the thirteen criteria and
the shared corpus walk, and it is already long. What lives here is the *apparatus*
each criterion needs in order to assert something rather than nothing — the
regions ``crystallize`` and ``recrystallize`` are given, the frame G3.7 pushes
through the index before and after a melt, the ``RETURN_RISK`` program G3.8
measures, and the two small readers G3.9 and G3.12 use to say which branch
produced a result.

Every probe here is **constructed and says so**. G3.7's drift probe takes a real
corpus frame and replaces two of its fields, because no corpus frame carries
INTERPRETER in the NETWORK family; G3.8's program is written here rather than
synthesised, because no synthesiser emits ``RETURN_RISK``. A criterion asserting
something about a fabricated input is honest exactly as long as the fabrication is
stated, and the alternative in both cases was an assertion that could not fail.

The gate's context is taken as ``Any`` so the import stays one-way: ``gate.py``
imports this module, never the reverse.
"""

from __future__ import annotations

import collections
from collections.abc import Sequence
from dataclasses import replace
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.ssir.relations import RelationFamily
from pocketsec.stage3.boundary.index import BoundaryIndex
from pocketsec.stage3.bytecode.verifier import verify
from pocketsec.stage3.cells.field import KnowledgeField
from pocketsec.stage3.cells.frame import boundary_key_of
from pocketsec.stage3.cells.schema import ConstraintKind, HardConstraint, KnowledgeCellV1
from pocketsec.stage3.crystal.pipeline import RegionSample
from pocketsec.stage3.labs.cell_path import phi_oracle_cell
from pocketsec.stage3.labs.crystal_corpus import session_frames
from pocketsec.stage3.oracles.teacher import phi_oracle_score
from pocketsec.stage3.promotion.assurance import (
    AssuranceState,
    PromotionOutcome,
    promote_cell,
)
from pocketsec.stage3.synthesis.operators import OperatorSample

if TYPE_CHECKING:  # pragma: no cover - typing only
    from pocketsec.stage3.cells.frame import CellFrame

__all__ = [
    "drift_probe",
    "guard_outcome",
    "lifecycle_region",
    "ratio_band",
    "region_sample",
    "regions_of",
    "return_risk_evidence_probe",
]


def regions_of(
    frames: tuple[CellFrame, ...],
) -> list[tuple[tuple[int, int, int], list[CellFrame]]]:
    buckets: dict[tuple[int, int, int], list[CellFrame]] = collections.defaultdict(list)
    for frame in frames:
        buckets[boundary_key_of(frame)].append(frame)
    return sorted(buckets.items(), key=lambda item: -len(item[1]))



def region_sample(
    key: tuple[int, int, int],
    frames: Sequence[CellFrame],
    *,
    sessions: tuple[Any, ...],
    transitions: tuple[Any, ...],
) -> RegionSample:
    """One region, assembled the same way wherever the gate needs one."""
    rows = tuple(
        OperatorSample(frame=f, risk=phi_oracle_score(f.delta_phi), delta=f.delta)
        for f in frames[:24]
    )
    return RegionSample(
        region_key=key,
        samples=rows,
        evidence=frames[0].evidence,
        constraints=(
            HardConstraint(
                constraint_id="Q1",
                kind=ConstraintKind.NEVER_LOWER_PHI,
                detail="phi is monotone under a crystallised answer",
            ),
        ),
        epochs=frozenset(f.epoch_id for f in frames[:24]),
        sessions=sessions,
        transitions=transitions,
    )



def lifecycle_region(ctx: Any) -> RegionSample | None:
    """A region from the **fit** split, for the recrystallise step.

    Deliberately not the region whose frames drove the melt: ``recrystallize``
    refuses to recompile from the samples that drifted, because reconstructing the
    failure and calling it a repair is the one thing that step may not do. The fit
    corpus is a genuinely separate draw (Stage 0 fair-comparison rule 6), so it is
    the honest stand-in for "a fresh observation since the melt" that this gate can
    obtain without inventing data.
    """
    frames = tuple(frame for session in ctx.fit.sessions for frame in session_frames(session))
    regions = regions_of(frames)
    if not regions:
        return None
    key, bucket = regions[0]
    return region_sample(
        key,
        bucket,
        sessions=ctx.fit.sessions,
        transitions=ctx.fit.sessions[0].transitions[:3],
    )



def drift_probe(ctx: Any, drifted: Any) -> CellFrame | None:
    """A frame inside ``drifted``, built from a corpus frame rather than invented.

    Everything except the relation family and the actor mask comes from real
    corpus telemetry; those two are replaced so the frame satisfies the drifted
    region's ACTOR predicate. Returns ``None`` rather than a frame the region does
    not contain, so a caller cannot mistake a failed construction for a pass.
    """
    from pocketsec.stage3.boundary.index import boundary_property_mask
    from pocketsec.stage1.ssir.entities import SemanticProperty

    if not ctx.frames:
        return None
    required = 0
    for predicate in drifted.predicates:
        required |= boundary_property_mask(predicate.required_properties)
    families = drifted.relation_families()
    probe = replace(
        ctx.frames[0],
        relation_family=RelationFamily(families[0]),
        actor_properties=required | boundary_property_mask({SemanticProperty.INTERPRETER}),
    )
    return probe if drifted.contains(probe) else None



def return_risk_evidence_probe(
    ctx: Any, frame: CellFrame
) -> dict[str, Any]:
    """Run a verified ``RETURN_RISK`` program and report what it carries.

    Exists so G3.8 states a measured fact rather than a generalisation. The check
    above only ever exercised ``phi_oracle_cell``, whose program ends in
    RETURN_STATE, so the third answering terminator was never measured while the
    detail string called non-suppression structural.
    """
    from pocketsec.stage3.bytecode.isa import DELTA_SLOTS, Instruction, Op, encode
    from pocketsec.stage3.cells.operator import OperatorForm, OperatorProgram

    program = OperatorProgram(
        form=OperatorForm.BYTECODE,
        words=encode(
            (
                Instruction(Op.LOAD_DELTA, DELTA_SLOTS.index("delta_phi")),
                Instruction(Op.RETURN_RISK, 0),
            )
        ),
        table={},
        max_steps=4,
        max_state_bytes=320,
    )
    report = verify(program)
    result = ctx.vm.run(program, frame)
    cell = replace(phi_oracle_cell(cell_id="cell-return-risk"), operator=program)
    verdict = ctx.oracle.evaluate(cell, (frame,))
    return {
        "verifies": report.ok,
        "abstained": result.abstained,
        "evidence_count": len(result.evidence),
        "d_causal_attribution": verdict.divergence.d_causal_attribution,
        "d_evidence_requirement": verdict.divergence.d_evidence_requirement,
    }



def ratio_band(
    numerator: tuple[float, float] | None, denominator: tuple[float, float] | None
) -> tuple[float, float] | None:
    """Widest and narrowest ratio the two measured spreads admit, or ``None``."""
    if numerator is None or denominator is None:
        return None
    lows, highs = numerator, denominator
    if not highs[0] or not highs[1]:
        return None
    return (lows[0] / highs[1], lows[1] / highs[0])



def guard_outcome(cell: KnowledgeCellV1, state: AssuranceState) -> str:
    """Which branch of ``promote_cell`` decided: the G3.12 guard, or something else."""
    try:
        verdict = promote_cell(cell, state, field=KnowledgeField(), index=BoundaryIndex())
    except ContractError:
        return "GUARD"
    return (
        "PROMOTED" if verdict.outcome is PromotionOutcome.PROMOTED else "REFUSED-ELSEWHERE"
    )

