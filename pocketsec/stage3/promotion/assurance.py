"""D3.11 (part) — the assurance ladder and the one gate onto the cheap path.

Architecture §25 grades what is actually *known* about a cell, A0 to A5.
:func:`promote_cell` is the only function in Stage 3 that puts a cell where it
can answer, so it is where the acceptance gate's hardest criterion becomes
mechanical:

> G3.12 — all claims of formal verification are limited to properties actually
> proven.

A5 means "formally verified property set, **if actually proven**". This module
refuses to take that on trust. An A5 claim with no named prover, or naming a
property that is not in the verifier's by-construction set, **raises** — it is
not a refusal verdict, because a refusal can be logged and ignored, and an
unfounded verification claim is not a policy decision, it is a false statement
about the system. Everything in ``TESTED_ONLY_PROPERTIES`` is an empirical
claim; a cell whose safety rests on "no test broke it" is at A4 at best.

:class:`AssuranceState` deliberately does **not** enforce that guard at
construction. It is a record of what is *claimed*, including a claim that is
wrong; if it refused to hold an unfounded claim, the unfounded claim would never
reach the check that rejects it, and Stage 10 — which extends this type — would
have no way to represent an assurance state under review.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage3.boundary.index import BoundaryIndexFull
from pocketsec.stage3.bytecode.verifier import (
    ALL_PROVEN_PROPERTIES,
    TESTED_ONLY_PROPERTIES,
    verify,
)
from pocketsec.stage3.cells.field import FieldFull
from pocketsec.stage3.cells.schema import AssuranceLevel, CellPhase

if TYPE_CHECKING:  # pragma: no cover - import-time cost, not behaviour
    from pocketsec.stage3.boundary.index import BoundaryIndex
    from pocketsec.stage3.boundary.pressure import BoundaryPressureReport
    from pocketsec.stage3.cells.field import KnowledgeField
    from pocketsec.stage3.cells.schema import KnowledgeCellV1
    from pocketsec.stage3.promotion.shadow import ShadowRun

__all__ = [
    "ASSURANCE_EVIDENCE",
    "AssuranceState",
    "MIN_PROMOTABLE_ASSURANCE",
    "PROMOTABLE_PHASES",
    "PromotionOutcome",
    "PromotionVerdict",
    "promote_cell",
]

#: ``module:function`` — the same shape ``ResolutionState.measured_by`` demands,
#: so "who proved this" is answerable by opening a file rather than by asking.
_PROVER_RE = re.compile(r"^[A-Za-z_][\w.]*:[A-Za-z_]\w*$")

#: Which :class:`AssuranceState` field must be present for each rung. Cumulative:
#: claiming A3 requires A1's replay and A2's pressure too, because the ladder is
#: a ladder — a cell that shadowed well but was never pressure-tested has not
#: been shown to abstain off its boundary.
ASSURANCE_EVIDENCE: Mapping[AssuranceLevel, tuple[str, ...]] = MappingProxyType(
    {
        AssuranceLevel.A0: (),
        AssuranceLevel.A1: ("replay",),
        AssuranceLevel.A2: ("replay", "pressure"),
        AssuranceLevel.A3: ("replay", "pressure", "shadow"),
        AssuranceLevel.A4: ("replay", "pressure", "shadow", "exhaustive_domain"),
        AssuranceLevel.A5: (
            "replay",
            "pressure",
            "shadow",
            "exhaustive_domain",
            "proven_properties",
            "prover",
        ),
    }
)

#: A melted cell has already been shown to be wrong somewhere; promoting one
#: without recrystallising it would reinstate the knowledge that failed.
PROMOTABLE_PHASES: frozenset[CellPhase] = frozenset(
    {CellPhase.STRUCTURED, CellPhase.CRYSTALLIZED}
)

#: The lowest rung that may reach the answering path. ``ASSURANCE_EVIDENCE[A0]``
#: is the empty tuple, so ``missing_evidence()`` is empty at A0 and the assurance
#: check was vacuous exactly where §25 calls a cell "candidate only": a cell that
#: had never been replayed, pressured or shadowed passed the gate and began
#: emitting committal SUSPICIOUS/BENIGN verdicts on ``CHEAP_TRANSITION``. A0 is
#: also the only level the repository's own cell producers emit — ``crystallize``
#: builds at A0 and ``fuse_cells`` demotes to A0 "so it re-enters shadow", which
#: is a rule with no mechanism behind it unless promotion refuses the rung.
MIN_PROMOTABLE_ASSURANCE = AssuranceLevel.A1


@dataclass(frozen=True, slots=True)
class AssuranceState:
    """What is claimed about a cell, and on what evidence (§25).

    **Stage 10 extends this type; it must not fork it.** The field names are the
    seam, so they are spelled here exactly as the build contract assigns them.
    """

    level: AssuranceLevel
    replay: ShadowRun | None
    pressure: BoundaryPressureReport | None
    shadow: ShadowRun | None
    exhaustive_domain: str | None
    proven_properties: tuple[str, ...]
    prover: str | None
    counterexamples_open: int

    def __post_init__(self) -> None:
        if not isinstance(self.level, AssuranceLevel):
            raise ContractError(f"AssuranceState.level must be an AssuranceLevel, got {self.level!r}")
        if not isinstance(self.proven_properties, tuple) or any(
            not isinstance(item, str) or not item.strip() for item in self.proven_properties
        ):
            raise ContractError(
                "AssuranceState.proven_properties must be a tuple of non-empty property "
                "statements; membership is checked at promotion, not here"
            )
        if self.prover is not None and not _PROVER_RE.fullmatch(self.prover):
            raise ContractError(
                f"AssuranceState.prover must be 'module:function', got {self.prover!r}; "
                "a prover nobody can open is not a prover"
            )
        if self.exhaustive_domain is not None and not self.exhaustive_domain.strip():
            raise ContractError(
                "AssuranceState.exhaustive_domain must name the bounded domain actually "
                "enumerated, or be None"
            )
        if (
            isinstance(self.counterexamples_open, bool)
            or not isinstance(self.counterexamples_open, int)
            or self.counterexamples_open < 0
        ):
            raise ContractError(
                f"AssuranceState.counterexamples_open must be >= 0, got "
                f"{self.counterexamples_open!r}"
            )

    def missing_evidence(self) -> tuple[str, ...]:
        """Fields the claimed level requires that are absent or empty."""
        missing: list[str] = []
        for name in ASSURANCE_EVIDENCE[self.level]:
            value = getattr(self, name)
            if value is None or (isinstance(value, tuple) and not value):
                missing.append(name)
        return tuple(missing)

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level.value,
            "replay": None if self.replay is None else self.replay.to_dict(),
            "pressure": None if self.pressure is None else self.pressure.to_dict(),
            "shadow": None if self.shadow is None else self.shadow.to_dict(),
            "exhaustive_domain": self.exhaustive_domain,
            "proven_properties": list(self.proven_properties),
            "prover": self.prover,
            "counterexamples_open": self.counterexamples_open,
        }


class PromotionOutcome(StrEnum):
    """Why a cell did or did not reach the cheap path."""

    PROMOTED = "PROMOTED"
    REFUSED_ASSURANCE = "REFUSED_ASSURANCE"
    REFUSED_COVERAGE = "REFUSED_COVERAGE"
    REFUSED_HARD_CONSTRAINT = "REFUSED_HARD_CONSTRAINT"
    REFUSED_FIELD_FULL = "REFUSED_FIELD_FULL"
    REFUSED_OPEN_COUNTEREXAMPLE = "REFUSED_OPEN_COUNTEREXAMPLE"


@dataclass(frozen=True, slots=True)
class PromotionVerdict:
    """The outcome, the cell if it was admitted, and the sentence explaining it."""

    outcome: PromotionOutcome
    cell: KnowledgeCellV1 | None
    reason: str

    def __post_init__(self) -> None:
        if not isinstance(self.outcome, PromotionOutcome):
            raise ContractError("PromotionVerdict.outcome must be a PromotionOutcome")
        if not isinstance(self.reason, str) or not self.reason.strip():
            raise ContractError("PromotionVerdict.reason must be a non-empty explanation")
        if (self.outcome is PromotionOutcome.PROMOTED) != (self.cell is not None):
            raise ContractError(
                "PromotionVerdict carries a cell exactly when it promoted one; a refusal "
                "that still hands back a cell invites the caller to use it anyway"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "cell_id": None if self.cell is None else self.cell.cell_id,
            "reason": self.reason,
        }


def _guard_verification_claims(state: AssuranceState) -> None:
    """The G3.12 guard. Raises rather than refusing — see the module docstring."""
    unfounded = tuple(
        claim for claim in state.proven_properties if claim not in ALL_PROVEN_PROPERTIES
    )
    if unfounded:
        empirical = tuple(claim for claim in unfounded if claim in TESTED_ONLY_PROPERTIES)
        detail = (
            " These are in TESTED_ONLY_PROPERTIES: they are empirical claims and may never "
            "be presented as proven."
            if empirical
            else ""
        )
        raise ContractError(
            f"AssuranceState claims {len(unfounded)} propert(ies) the verifier does not "
            f"prove by construction: {list(unfounded)}.{detail} All claims of formal "
            "verification are limited to properties actually proven (G3.12)."
        )
    if state.level is not AssuranceLevel.A5:
        return
    if state.prover is None:
        raise ContractError(
            "AssuranceState claims A5 with prover=None. A5 means 'formally verified "
            "property set, if actually proven'; without a named prover module there is "
            "nothing that proved it, and the honest level is A4."
        )
    if not state.proven_properties:
        raise ContractError(
            "AssuranceState claims A5 with no proven_properties. An empty proof set is not "
            "a verified property set, it is an unverified one with a higher label."
        )


def _refuse(outcome: PromotionOutcome, reason: str) -> PromotionVerdict:
    return PromotionVerdict(outcome=outcome, cell=None, reason=reason)


def _rung(level: AssuranceLevel) -> int:
    """Position on the ladder. Declaration order is the ladder (A0 … A5)."""
    return tuple(AssuranceLevel).index(level)


def _pre_insertion_refusal(
    cell: KnowledgeCellV1, state: AssuranceState
) -> PromotionVerdict | None:
    """Every reason to refuse that does not depend on the field's capacity."""
    if state.counterexamples_open > 0:
        return _refuse(
            PromotionOutcome.REFUSED_OPEN_COUNTEREXAMPLE,
            f"{state.counterexamples_open} counterexample(s) stand unsuperseded against "
            f"{cell.cell_id!r}; a known-wrong cell does not reach the cheap path",
        )
    if cell.phase not in PROMOTABLE_PHASES:
        return _refuse(
            PromotionOutcome.REFUSED_HARD_CONSTRAINT,
            f"cell {cell.cell_id!r} is in phase {cell.phase.value}; only "
            f"{sorted(p.value for p in PROMOTABLE_PHASES)} may be promoted, and a melted "
            "cell must be recrystallised rather than reinstated",
        )
    if _rung(state.level) < _rung(MIN_PROMOTABLE_ASSURANCE):
        return _refuse(
            PromotionOutcome.REFUSED_ASSURANCE,
            f"cell {cell.cell_id!r} claims {state.level.value}, below "
            f"{MIN_PROMOTABLE_ASSURANCE.value}: §25 calls that level candidate-only and "
            f"{list(ASSURANCE_EVIDENCE[state.level])} is the evidence it requires, so the "
            "assurance check would pass on nothing at all. Shadow it and claim A1",
        )
    if cell.assurance is not state.level:
        return _refuse(
            PromotionOutcome.REFUSED_ASSURANCE,
            f"cell {cell.cell_id!r} carries assurance {cell.assurance.value} but the state "
            f"claims {state.level.value}; the cell and its evidence must agree",
        )
    report = verify(cell.operator)
    if not report.ok:
        return _refuse(
            PromotionOutcome.REFUSED_HARD_CONSTRAINT,
            f"operator of {cell.cell_id!r} does not verify: {list(report.failures)}; an "
            "unverified program abstains at runtime, so promoting it would put a guaranteed "
            "abstention on the cheap path",
        )
    missing = state.missing_evidence()
    if missing:
        return _refuse(
            PromotionOutcome.REFUSED_ASSURANCE,
            f"assurance {state.level.value} requires {list(ASSURANCE_EVIDENCE[state.level])}; "
            f"missing {list(missing)}",
        )
    if state.shadow is not None and not state.shadow.coverage_met:
        return _refuse(PromotionOutcome.REFUSED_COVERAGE, state.shadow.reason)
    if state.shadow is not None and state.shadow.divergences:
        return _refuse(
            PromotionOutcome.REFUSED_HARD_CONSTRAINT,
            f"shadow run recorded {len(state.shadow.divergences)} divergence(s) from the "
            "dual oracle; the candidate is not security-equivalent to what it replaces",
        )
    return None


def promote_cell(
    cell: KnowledgeCellV1,
    state: AssuranceState,
    *,
    field: KnowledgeField,
    index: BoundaryIndex,
) -> PromotionVerdict:
    """Admit a cell to the field and the index, or say why not.

    All-or-nothing: if the index refuses the cell after the field accepted it,
    the field insertion is rolled back. A cell present in one and not the other
    would answer through one door and be invisible to melting through the other,
    and nothing downstream could tell.
    """
    _guard_verification_claims(state)
    refusal = _pre_insertion_refusal(cell, state)
    if refusal is not None:
        return refusal
    try:
        field.insert(cell)
    except FieldFull as exc:
        return _refuse(PromotionOutcome.REFUSED_FIELD_FULL, f"knowledge field full: {exc}")
    except ContractError as exc:
        return _refuse(PromotionOutcome.REFUSED_HARD_CONSTRAINT, f"field refused cell: {exc}")
    try:
        index.insert(cell)
    except BoundaryIndexFull as exc:
        field.remove(cell.cell_id)
        return _refuse(PromotionOutcome.REFUSED_FIELD_FULL, f"boundary index full: {exc}")
    except ContractError as exc:
        field.remove(cell.cell_id)
        return _refuse(
            PromotionOutcome.REFUSED_HARD_CONSTRAINT, f"boundary index refused cell: {exc}"
        )
    return PromotionVerdict(
        outcome=PromotionOutcome.PROMOTED,
        cell=cell,
        reason=f"promoted at {state.level.value} with {len(index.keys_for(cell.cell_id))} keys",
    )


def _assert_ladder_is_closed_and_cumulative() -> None:
    levels = tuple(AssuranceLevel)
    if set(ASSURANCE_EVIDENCE) != set(levels):
        raise ContractError(
            "ASSURANCE_EVIDENCE must cover every AssuranceLevel; an unlisted rung would "
            "promote on no evidence at all"
        )
    previous: tuple[str, ...] = ()
    for level in levels:
        required = ASSURANCE_EVIDENCE[level]
        if not set(previous) <= set(required):
            raise ContractError(
                f"assurance ladder is not cumulative at {level.value}: {list(required)} "
                f"drops evidence required by the rung below ({list(previous)})"
            )
        previous = required
    if ASSURANCE_EVIDENCE[MIN_PROMOTABLE_ASSURANCE] == ():
        raise ContractError(
            f"MIN_PROMOTABLE_ASSURANCE={MIN_PROMOTABLE_ASSURANCE.value} requires no "
            "evidence, so the promotion assurance check would be vacuous at the lowest "
            "promotable rung"
        )
    if not set(TESTED_ONLY_PROPERTIES).isdisjoint(ALL_PROVEN_PROPERTIES):
        raise ContractError(
            "a property appears in both TESTED_ONLY_PROPERTIES and the proven set; the "
            "distinction between proven and empirical is the whole of G3.12"
        )


_assert_ladder_is_closed_and_cumulative()
