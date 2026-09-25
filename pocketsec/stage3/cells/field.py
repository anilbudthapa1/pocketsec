"""D3.5 — the Knowledge Field and its composition algebra (architecture §15, §16).

The field is a bounded container of promoted cells and the place where several
cells that all claim a frame are reconciled. Its two load-bearing behaviours:

**It refuses rather than evicts.** ``insert`` raises ``FieldFull`` at
``MAX_CELLS`` or ``MAX_FIELD_BYTES``. Silent eviction would make the field's
answer depend on insertion order and would delete crystallised knowledge with no
melt record — and rollback/reconstruction paths are a first-class requirement.
Forgetting is a *decision*, made by the intelligence GC (D3.14) with a recorded
reason, never a side effect of running out of room.

**It abstains rather than picks a winner.** Composition implements the seven §16
rules, and four of the five outcomes are abstentions. A field that resolved
contradictions by taking the most confident cell would be a voting scheme
dressed as a proof, and confidence is not authority (MEMORY.md).

Composition never *manufactures* anything. It unions the evidence its inputs
already required, forwards the strongest escalation the AOP already decided, and
joins state deltas under Stage 1's own lattice. If the join is not monotone it
abstains, because a non-monotone composed delta contradicts the state calculus
(ADR-0005) and the calculus wins.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    EvidenceRef,
    require_finite_unit_interval,
    require_identifier,
)
from pocketsec.stage1.observation.policy import EscalationDecision, ObservationLevel
from pocketsec.stage1.state.security_state import DIMENSIONS, SecurityStateV1, StateDelta
from pocketsec.stage3.cells.schema import KnowledgeCellV1
from pocketsec.stage3.theory import SecurityConsequence

__all__ = [
    "CellActivation",
    "CompositionOutcome",
    "CompositionVerdict",
    "FieldFull",
    "KnowledgeField",
    "MAX_CELLS",
    "MAX_COMPOSITION_DEPTH",
    "MAX_FIELD_BYTES",
]

MAX_CELLS = 512
#: Architecture §38: "Knowledge Cells + metadata < 5-20 MB bounded". The upper
#: end of the declared band, on a 2 GB host target.
MAX_FIELD_BYTES = 20 * 1024 * 1024
#: Beyond four composed cells the result is a rule explosion, not an answer.
MAX_COMPOSITION_DEPTH = 4

#: Escalation strength order, so "compose by maximum requested level" is a
#: defined operation rather than an enum-ordering accident.
_ESCALATION_RANK: dict[ObservationLevel, int] = {
    ObservationLevel.BASELINE: 0,
    ObservationLevel.ELEVATED: 1,
    ObservationLevel.HIGH_RESOLUTION: 2,
}


class FieldFull(ContractError):
    """The field is at its declared bound and will not silently make room."""


@dataclass(frozen=True, slots=True)
class CellActivation:
    """What one cell claims about one frame, before composition."""

    cell_id: str
    delta: StateDelta
    risk: float
    evidence_required: tuple[EvidenceRef, ...]
    escalation: EscalationDecision | None
    consequence: SecurityConsequence
    confidence: float
    epochs: frozenset[int]

    def __post_init__(self) -> None:
        require_identifier(self.cell_id, "CellActivation.cell_id")
        if not isinstance(self.delta, StateDelta):
            raise ContractError("CellActivation.delta must be a StateDelta")
        require_finite_unit_interval(self.risk, "CellActivation.risk")
        if not isinstance(self.evidence_required, tuple):
            raise ContractError("CellActivation.evidence_required must be a tuple")
        for ref in self.evidence_required:
            if not isinstance(ref, EvidenceRef):
                raise ContractError(
                    f"CellActivation.evidence_required entries must be EvidenceRef, "
                    f"got {type(ref).__name__}"
                )
        if self.escalation is not None and not isinstance(self.escalation, EscalationDecision):
            raise ContractError(
                "CellActivation.escalation must be an EscalationDecision or None; Stage 3 "
                "forwards an AOP decision and never defines a second escalation type"
            )
        if not isinstance(self.consequence, SecurityConsequence):
            raise ContractError("CellActivation.consequence must be a SecurityConsequence")
        require_finite_unit_interval(self.confidence, "CellActivation.confidence")
        if not isinstance(self.epochs, frozenset) or not self.epochs:
            raise ContractError(
                "CellActivation.epochs must be non-empty: an activation valid in no epoch "
                "cannot compose with anything"
            )


class CompositionOutcome(StrEnum):
    """Four of these five are abstentions. That is the design, not a shortfall."""

    RESOLVED = "RESOLVED"
    ABSTAINED_CONTRADICTION = "ABSTAINED_CONTRADICTION"
    ABSTAINED_EPOCH_INCOMPATIBLE = "ABSTAINED_EPOCH_INCOMPATIBLE"
    ABSTAINED_DEPTH = "ABSTAINED_DEPTH"
    ABSTAINED_NO_CELL = "ABSTAINED_NO_CELL"


@dataclass(frozen=True, slots=True)
class CompositionVerdict:
    """The field's answer, including on abstention.

    ``evidence`` is the **union** of every input's requirement and is returned on
    every outcome. Abstaining is not a reason to drop evidence: the learned path
    that takes over still needs the bytes, and an abstention that quietly shed a
    ``MANDATORY_SIGNALS`` requirement would be a suppression channel.
    """

    outcome: CompositionOutcome
    delta: StateDelta
    risk: float
    evidence: tuple[EvidenceRef, ...]
    escalation: EscalationDecision | None
    contributing: tuple[str, ...]
    reason: str

    @property
    def resolved(self) -> bool:
        return self.outcome is CompositionOutcome.RESOLVED

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "delta": self.delta.to_dict(),
            "risk": self.risk,
            "evidence": [ref.to_dict() for ref in self.evidence],
            "escalation": None if self.escalation is None else self.escalation.to_dict(),
            "contributing": list(self.contributing),
            "reason": self.reason,
        }


class KnowledgeField:
    """``F`` — the bounded set of cells currently allowed to answer (§15)."""

    def __init__(self, *, max_cells: int = MAX_CELLS, max_bytes: int = MAX_FIELD_BYTES) -> None:
        if max_cells < 1 or max_bytes < 1:
            raise ContractError("KnowledgeField bounds must be positive")
        self._max_cells = max_cells
        self._max_bytes = max_bytes
        self._cells: dict[str, KnowledgeCellV1] = {}
        self._bytes = 0

    # --- container -----------------------------------------------------------

    def insert(self, cell: KnowledgeCellV1) -> None:
        """Add a cell, or raise. Never evicts.

        A duplicate ``cell_id`` is refused rather than replaced: silently
        overwriting a promoted cell would lose the version lineage that rollback
        depends on. Replacing is ``remove`` then ``insert``, which is visible.
        """
        if not isinstance(cell, KnowledgeCellV1):
            raise ContractError(
                f"KnowledgeField.insert expects a KnowledgeCellV1, got {type(cell).__name__}"
            )
        if cell.cell_id in self._cells:
            raise ContractError(
                f"KnowledgeField already holds cell {cell.cell_id!r}; replacing a promoted "
                "cell in place would erase the version lineage rollback needs"
            )
        if len(self._cells) >= self._max_cells:
            raise FieldFull(
                f"KnowledgeField holds {len(self._cells)} cells, at its bound of "
                f"{self._max_cells}; forgetting is a GC decision with a recorded reason, "
                "never a side effect of insertion"
            )
        size = cell.size_bytes()
        if self._bytes + size > self._max_bytes:
            raise FieldFull(
                f"KnowledgeField would grow to {self._bytes + size} bytes, above its bound "
                f"of {self._max_bytes}; endpoint state is bounded by construction"
            )
        self._cells[cell.cell_id] = cell
        self._bytes += size

    def remove(self, cell_id: str) -> bool:
        """Remove a cell, returning whether it was there. The only exit path."""
        cell = self._cells.pop(cell_id, None)
        if cell is None:
            return False
        self._bytes -= cell.size_bytes()
        return True

    def get(self, cell_id: str) -> KnowledgeCellV1 | None:
        return self._cells.get(cell_id)

    def cells(self) -> tuple[KnowledgeCellV1, ...]:
        """Insertion-ordered snapshot, so a field walk is reproducible."""
        return tuple(self._cells.values())

    def memory_bytes(self) -> int:
        """Measured from the cells' own canonical bytes, not estimated."""
        return self._bytes

    def __len__(self) -> int:
        return len(self._cells)

    # --- composition ---------------------------------------------------------

    def compose(self, activations: Sequence[CellActivation]) -> CompositionVerdict:
        """Reconcile several cells claiming the same frame (architecture §16).

        The rules, in the order they are applied, each with the failure it
        prevents:

        1. no activation -> ``ABSTAINED_NO_CELL``; the learned path answers.
        2. depth above ``MAX_COMPOSITION_DEPTH`` -> ``ABSTAINED_DEPTH``.
        3. an activation naming a cell this field does not hold -> abstain; a
           field must not answer for knowledge it cannot show.
        4. epoch-incompatible activations cannot compose.
        5. contradictory activations -> ``ABSTAINED_CONTRADICTION``, never an
           arbitrary winner.
        6. the composed delta must satisfy ``SecurityStateV1.join`` monotonicity.
        7. the evidence union is monotone and escalation composes by maximum.

        Rule 7 holds on *every* path, including the abstentions.
        """
        evidence = _evidence_union(activations)
        escalation = _strongest_escalation(activations)
        contributing = tuple(activation.cell_id for activation in activations)

        guard = self._guard(activations)
        if guard is not None:
            outcome, reason = guard
            return CompositionVerdict(
                outcome=outcome,
                delta=StateDelta({}),
                risk=0.0,
                evidence=evidence,
                escalation=escalation,
                contributing=contributing,
                reason=reason,
            )

        conflict = _contradiction(activations)
        if conflict is not None:
            return CompositionVerdict(
                outcome=CompositionOutcome.ABSTAINED_CONTRADICTION,
                delta=StateDelta({}),
                risk=0.0,
                evidence=evidence,
                escalation=escalation,
                contributing=contributing,
                reason=conflict,
            )

        joined = _join_deltas(activations)
        if isinstance(joined, str):
            return CompositionVerdict(
                outcome=CompositionOutcome.ABSTAINED_CONTRADICTION,
                delta=StateDelta({}),
                risk=0.0,
                evidence=evidence,
                escalation=escalation,
                contributing=contributing,
                reason=joined,
            )

        consequence = max(activation.consequence for activation in activations)
        # Rule 2: risk is taken from the activations at the *highest* consequence
        # only. A low-confidence ROUTINE cell reporting risk 0.0 must not be able
        # to average down a CRITICAL cell's answer.
        risk = max(
            activation.risk
            for activation in activations
            if activation.consequence is consequence
        )
        return CompositionVerdict(
            outcome=CompositionOutcome.RESOLVED,
            delta=joined,
            risk=risk,
            evidence=evidence,
            escalation=escalation,
            contributing=contributing,
            reason=f"resolved at {consequence.name} over {len(activations)} cell(s)",
        )

    def _guard(
        self, activations: Sequence[CellActivation]
    ) -> tuple[CompositionOutcome, str] | None:
        if not isinstance(activations, Sequence):
            raise ContractError("KnowledgeField.compose expects a sequence of CellActivation")
        for activation in activations:
            if not isinstance(activation, CellActivation):
                raise ContractError(
                    f"KnowledgeField.compose expects CellActivation, "
                    f"got {type(activation).__name__}"
                )
        if not activations:
            return (CompositionOutcome.ABSTAINED_NO_CELL, "no cell claimed this frame")
        if len(activations) > MAX_COMPOSITION_DEPTH:
            return (
                CompositionOutcome.ABSTAINED_DEPTH,
                f"{len(activations)} activations exceed MAX_COMPOSITION_DEPTH="
                f"{MAX_COMPOSITION_DEPTH}",
            )
        missing = [a.cell_id for a in activations if a.cell_id not in self._cells]
        if missing:
            return (
                CompositionOutcome.ABSTAINED_NO_CELL,
                f"activations name cells this field does not hold: {sorted(missing)}",
            )
        shared = frozenset.intersection(*(a.epochs for a in activations))
        if not shared:
            return (
                CompositionOutcome.ABSTAINED_EPOCH_INCOMPATIBLE,
                "activations share no epoch; knowledge from two regimes does not compose",
            )
        return None


def _evidence_union(activations: Sequence[CellActivation]) -> tuple[EvidenceRef, ...]:
    """Union by digest, first-appearance order.

    Order-stable so a verdict is reproducible; deduplicated by digest because
    two cells citing the same bytes cite one piece of evidence, not two.
    """
    seen: dict[str, EvidenceRef] = {}
    for activation in activations:
        for ref in activation.evidence_required:
            seen.setdefault(ref.digest, ref)
    return tuple(seen.values())


def _strongest_escalation(
    activations: Sequence[CellActivation],
) -> EscalationDecision | None:
    """Compose escalation by maximum requested level (§16 rule 3).

    Stage 3 never mints an ``EscalationDecision``; it forwards the strongest one
    the AOP already made, so the AOP's budget remains the only thing that decides
    whether observation actually rises.
    """
    decisions = [a.escalation for a in activations if a.escalation is not None]
    if not decisions:
        return None
    return max(decisions, key=lambda decision: _ESCALATION_RANK[decision.level])


def _contradiction(activations: Sequence[CellActivation]) -> str | None:
    """Two cells raising the same dimension to different levels contradict.

    Silence is not contradiction: a cell that says nothing about a dimension has
    not disagreed with one that does. Only a differing *target* level is a
    genuine conflict, and it abstains rather than choosing.
    """
    claimed: dict[str, tuple[str, int]] = {}
    for activation in activations:
        for name, (_before, after) in activation.delta.raised.items():
            previous = claimed.get(name)
            if previous is not None and previous[1] != after:
                return (
                    f"cells {previous[0]!r} and {activation.cell_id!r} disagree on "
                    f"{name}: {previous[1]} vs {after}"
                )
            claimed[name] = (activation.cell_id, after)
    return None


def _join_deltas(activations: Sequence[CellActivation]) -> StateDelta | str:
    """Join the activations' deltas, or return the reason they cannot be joined.

    Verified through ``SecurityStateV1.join`` itself rather than by reimplementing
    the lattice: the composed "after" state must be the join of "before" and
    "after", which is exactly Stage 1's monotonicity property (ADR-0005). A level
    outside its dimension's lattice fails here too, which is how an adversarial
    or corrupted delta is caught before it reaches the hub.
    """
    raised: dict[str, tuple[int, int]] = {}
    for activation in activations:
        for name, (before, after) in activation.delta.raised.items():
            if name not in DIMENSIONS:
                return f"unknown state dimension {name!r} in cell {activation.cell_id!r}"
            existing = raised.get(name)
            if existing is None:
                raised[name] = (before, after)
            else:
                raised[name] = (min(existing[0], before), max(existing[1], after))

    if not raised:
        return StateDelta({})

    try:
        before_state = _state_from_levels({name: pair[0] for name, pair in raised.items()})
        after_state = _state_from_levels({name: pair[1] for name, pair in raised.items()})
    except (ContractError, ValueError) as exc:
        return f"composed delta is not a valid security state: {exc}"

    if SecurityStateV1.join(before_state, after_state) != after_state:
        return (
            "composed delta is not monotone under SecurityStateV1.join; capability does "
            "not decay within a lineage (ADR-0005)"
        )
    return StateDelta(raised)


def _state_from_levels(levels: dict[str, int]) -> SecurityStateV1:
    """Build a state from raw dimension levels, raising on an off-lattice value."""
    lattice_values = {name: DIMENSIONS[name](level) for name, level in levels.items()}
    return SecurityStateV1(**lattice_values)  # type: ignore[arg-type]
