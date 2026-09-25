"""D3.6 — the PCB interpreter: the only thing a crystallised cell may do.

This module exists so that executable knowledge on an endpoint has a ceiling.
A :class:`CellVM` reads a :class:`CellFrame` — normalised Stage 1 data and
nothing else — and returns a :class:`CellResult`. What it *refuses* to do is
the point:

* It refuses to execute an unverified program. :func:`~pocketsec.stage3.
  bytecode.verifier.verify` runs first, on every call, and any failure produces
  an abstention rather than a partial execution or a repaired program.
* It refuses to touch the host. There is no file, socket, subprocess, dynamic
  import, ``eval`` or ``getattr`` path in this module. The nine state accessors
  are bound once at import time to a closed, pinned tuple of field names, so
  even attribute access here is static.
* It refuses to lower security state. ``TRANSITION`` can raise a lattice
  dimension by one step and clamps at the top; there is no opcode that lowers
  one. ``UPDATE_PHI`` accumulates only non-negative contributions.
* It refuses to drop evidence. ``PRESERVE_EVIDENCE`` unions the frame's
  evidence into the result; :func:`_union_evidence` can only add. The ISA makes
  this structural: ``RETURN_STATE`` pops an ``EVIDENCE`` handle, so a program
  that changes security state must have preserved evidence first.
* It refuses to grant its own escalation. ``RAISE_OBSERVATION`` emits a Stage 1
  :class:`~pocketsec.stage1.observation.policy.EscalationDecision` marked *not
  escalated*, because only the Adaptive Observation Policy holds the budget. A
  cell requests; it does not decide. There is deliberately no second escalation
  type in Stage 3.

Allocation is bounded by construction: the value stack is allocated once per
:class:`CellVM` and reused, the program is straight-line, and nothing in the
hot path builds a string or grows a dictionary. That the *observed* peak stays
flat across ten thousand frames is an empirical claim, checked in
``tests/test_stage3_bytecode.py``; that it *cannot* grow is the verifier's
``no dynamic allocation`` property, which is proven from the absence of an
allocation opcode.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from operator import and_, attrgetter, eq, gt, lt, ne, or_
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import ContractError, EvidenceRef
from pocketsec.stage1.observation.policy import EscalationDecision, ObservationLevel
from pocketsec.stage1.ssir.relations import RelationFamily
from pocketsec.stage1.state.security_state import (
    DIMENSIONS,
    SecurityStateV1,
    StateDelta,
)
from pocketsec.stage3.bytecode.isa import (
    MAX_INSTRUCTIONS,
    MAX_STACK,
    STATE_SLOTS,
    TERMINATORS,
    Instruction,
    Op,
)
from pocketsec.stage3.bytecode.verifier import (
    BYTECODE_FORM_NAME,
    VerifiedProgram,
    verify_and_decode,
)

# Imported, never redefined. ``CellFrame`` is the join key between a frame and
# the frozen teacher snapshot (Oracle A, D3.8) and it lives in `foundation`,
# which `bytecode` depends on (spec §5). A second dataclass with identical
# fields would still be an unequal class, so every snapshot written with one and
# read with the other would join on nothing and report TEACHER_UNAVAILABLE
# rather than failing loudly. Re-exported here because spec §4 D3.6 names this
# module as the import path.
from pocketsec.stage3.cells.frame import CellFrame

if TYPE_CHECKING:  # pragma: no cover - typing only
    from pocketsec.stage3.cells.operator import OperatorProgram

__all__ = [
    "CellFrame",
    "CellResult",
    "CellVM",
    "MAX_CELL_STEPS",
    "REASON_ABSTAIN",
    "REASON_NOT_EXECUTABLE_FORM",
    "REASON_RETURN_RISK",
    "REASON_RETURN_STATE",
    "REASON_STEP_BUDGET",
    "REASON_UNVERIFIED_PREFIX",
]

#: A cell may execute at most one instruction per declared step, and a program
#: may hold at most ``MAX_INSTRUCTIONS`` instructions, so the two are the same
#: number by construction rather than by coincidence.
MAX_CELL_STEPS = MAX_INSTRUCTIONS

REASON_RETURN_STATE = "RETURN_STATE"
REASON_RETURN_RISK = "RETURN_RISK"
REASON_ABSTAIN = "ABSTAIN"
REASON_NOT_EXECUTABLE_FORM = "NOT_EXECUTABLE_FORM"
REASON_STEP_BUDGET = "STEP_BUDGET_EXCEEDED"
REASON_UNVERIFIED_PREFIX = "UNVERIFIED:"

#: The cell names itself as the escalation target. A constant, because building
#: a target string per event would be allocation in the hot path.
_ESCALATION_TARGET = "crystal-cell"

#: A cell requests escalation; the Adaptive Observation Policy grants it. The
#: decision leaves the VM un-granted so no cell can widen its own telemetry.
_ESCALATION_PENDING = "REQUESTED_BY_CELL_PENDING_AOP"

#: ``RAISE_OBSERVATION`` operand -> level, in ascending order so "maximum
#: requested level" is an integer comparison.
_OBSERVATION_LEVELS: tuple[ObservationLevel, ...] = (
    ObservationLevel.BASELINE,
    ObservationLevel.ELEVATED,
    ObservationLevel.HIGH_RESOLUTION,
)

#: Bound once, to a closed tuple of field names pinned by ``STATE_SLOTS``.
#: An ``attrgetter`` built at import is not a dynamic attribute path: the names
#: cannot be influenced by a program, a frame or an operand.
_STATE_GETTERS: tuple[Callable[[SecurityStateV1], Any], ...] = tuple(
    attrgetter(name) for name in STATE_SLOTS
)

#: Top of each dimension's lattice, so ``TRANSITION`` clamps instead of running
#: off the end of the enum.
_MAX_LEVELS: tuple[int, ...] = tuple(
    max(int(member) for member in DIMENSIONS[name]) for name in STATE_SLOTS
)

_BINARY_OPS: Mapping[Op, Callable[[Any, Any], Any]] = {
    Op.EQ: eq,
    Op.NE: ne,
    Op.LT: lt,
    Op.GT: gt,
    Op.AND: and_,
    Op.OR: or_,
}

#: Marker pushed by ``PRESERVE_EVIDENCE`` and popped by ``RETURN_STATE``. It is
#: a sentinel, not data: the evidence itself never rides the stack, so a
#: program cannot reshape or drop it.
_EVIDENCE_MARKER = object()

_EMPTY_DELTA_FIELDS: dict[str, tuple[int, int]] = {}


@dataclass(frozen=True, slots=True)
class CellResult:
    """One cell execution. ``delta`` and ``evidence`` are the plan's bound seam."""

    abstained: bool
    delta: StateDelta
    evidence: tuple[EvidenceRef, ...]
    risk: float
    escalation: EscalationDecision | None
    steps_taken: int
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "abstained": self.abstained,
            "delta": self.delta.to_dict(),
            "evidence": [ref.to_dict() for ref in self.evidence],
            "risk": round(self.risk, 6),
            "escalation": self.escalation.to_dict() if self.escalation else None,
            "steps_taken": self.steps_taken,
            "reason": self.reason,
        }


def _union_evidence(
    existing: tuple[EvidenceRef, ...], incoming: Sequence[EvidenceRef]
) -> tuple[EvidenceRef, ...]:
    """Add evidence, never remove it.

    The result is always a superset of ``existing``. This is the only path by
    which ``CellResult.evidence`` changes, so "a cell cannot suppress evidence"
    is a property of one small function rather than of a review convention.
    """
    if not incoming:
        return existing
    if not existing:
        return tuple(incoming)
    seen = {(ref.store, ref.locator, ref.digest) for ref in existing}
    added = [ref for ref in incoming if (ref.store, ref.locator, ref.digest) not in seen]
    if not added:
        return existing
    return existing + tuple(added)


class CellVM:
    """A straight-line interpreter for verified PCB programs.

    One instance holds one reusable value stack. Instances are not thread-safe
    on purpose: sharing a stack across threads would be shared mutable state in
    the one place this design refuses to have any.
    """

    __slots__ = ("_max_steps", "_stack")

    def __init__(self, *, max_steps: int = MAX_CELL_STEPS) -> None:
        if max_steps < 0 or max_steps > MAX_CELL_STEPS:
            raise ContractError(f"max_steps must be within [0, {MAX_CELL_STEPS}]")
        self._max_steps = max_steps
        # Allocated once. The verifier proves no program can exceed MAX_STACK,
        # so this list never needs to grow and never does.
        self._stack: list[Any] = [None] * MAX_STACK

    @property
    def max_steps(self) -> int:
        return self._max_steps

    def run(self, program: OperatorProgram, frame: CellFrame) -> CellResult:
        """Verify, then execute. An unverified program abstains without running."""
        verified: VerifiedProgram = verify_and_decode(program)
        report = verified.report
        if not report.ok:
            return _abstained(REASON_UNVERIFIED_PREFIX + report.failures[0][0])
        if str(program.form) != BYTECODE_FORM_NAME:
            # Structurally sound, but this VM executes instructions and a table
            # is not instructions. Abstaining is honest; guessing is not.
            return _abstained(REASON_NOT_EXECUTABLE_FORM)
        if report.instruction_count > self._max_steps:
            return _abstained(REASON_STEP_BUDGET)
        return self._execute(
            verified.instructions, frame, verified.constants, verified.sets
        )

    def _execute(
        self,
        instructions: tuple[Instruction, ...],
        frame: CellFrame,
        constants: tuple[float, ...],
        sets: tuple[frozenset[int], ...],
    ) -> CellResult:
        """The one path. Effects and terminators here; stack algebra delegated."""
        stack = self._stack
        levels = tuple(int(getter(frame.state)) for getter in _STATE_GETTERS)
        raised: dict[str, tuple[int, int]] = {}
        evidence: tuple[EvidenceRef, ...] = ()
        phi_gain = 0.0
        level_index = -1
        sp = 0
        steps = 0
        for instruction in instructions:
            op = instruction.op
            operand = instruction.operand
            steps += 1
            if op in TERMINATORS:
                risk = phi_gain
                if op is Op.RETURN_RISK:
                    sp -= 1
                    risk = stack[sp]
                elif op is Op.RETURN_STATE:
                    sp -= 1  # the EVIDENCE handle PRESERVE_EVIDENCE pushed
                return _finish(op, raised, evidence, risk, level_index, frame, steps)
            if op is Op.PRESERVE_EVIDENCE:
                evidence = _union_evidence(evidence, frame.evidence)
                stack[sp] = _EVIDENCE_MARKER
                sp += 1
            elif op is Op.TRANSITION:
                sp -= 1
                if stack[sp]:
                    _raise_dimension(raised, levels, operand)
            elif op is Op.UPDATE_PHI:
                sp -= 1
                value = stack[sp]
                if value > 0.0:
                    phi_gain += value
            elif op is Op.RAISE_OBSERVATION:
                sp -= 1
                if stack[sp] and operand > level_index:
                    level_index = operand
            else:
                sp = _apply_stack_op(op, operand, stack, sp, frame, levels, constants, sets)
        # Unreachable for a verified program (the verifier refuses a missing
        # terminator). Kept so a future ISA change fails closed.
        return _abstained(REASON_UNVERIFIED_PREFIX + "no_terminator")


def _finish(
    op: Op,
    raised: dict[str, tuple[int, int]],
    evidence: tuple[EvidenceRef, ...],
    risk: float,
    level_index: int,
    frame: CellFrame,
    steps: int,
) -> CellResult:
    """Build the single result this program produces.

    ``ABSTAIN`` yields no verdict at all: no delta, no risk, no escalation.
    Abstention is a first-class output here, not a failure code — a cell that
    does not know is required to say so rather than to guess.
    """
    if op is Op.ABSTAIN:
        return CellResult(
            True, StateDelta(raised=_EMPTY_DELTA_FIELDS), evidence, 0.0, None, steps,
            REASON_ABSTAIN,
        )
    if op is Op.RETURN_STATE:
        delta = StateDelta(raised=raised)
        reason = REASON_RETURN_STATE
    else:
        delta = StateDelta(raised=_EMPTY_DELTA_FIELDS)
        reason = REASON_RETURN_RISK
    return CellResult(
        False, delta, evidence, _clamp01(risk), _escalation(level_index, frame), steps, reason,
    )


def _apply_stack_op(
    op: Op,
    operand: int,
    stack: list[Any],
    sp: int,
    frame: CellFrame,
    levels: tuple[int, ...],
    constants: tuple[float, ...],
    sets: tuple[frozenset[int], ...],
) -> int:
    """Loads, comparisons and boolean algebra. Touches nothing but the stack."""
    if op is Op.LOAD_STATE:
        stack[sp] = float(levels[operand])
        return sp + 1
    if op is Op.LOAD_SEM:
        stack[sp] = frame.actor_properties if operand == 0 else frame.object_properties
        return sp + 1
    if op is Op.LOAD_REL:
        stack[sp] = _load_rel(frame, operand)
        return sp + 1
    if op is Op.LOAD_DELTA:
        stack[sp] = _load_delta(frame, operand)
        return sp + 1
    if op is Op.LOAD_CONST:
        stack[sp] = constants[operand]
        return sp + 1
    if op is Op.COUNT_WINDOW:
        stack[sp] = float(frame.window_counts.get(operand, 0))
        return sp + 1
    if op is Op.SEEN_WITHIN:
        stack[sp] = frame.window_counts.get(operand, 0) > 0
        return sp + 1
    if op is Op.IN_SET:
        stack[sp - 1] = stack[sp - 1] in sets[operand]
        return sp
    if op is Op.NOT:
        stack[sp - 1] = not stack[sp - 1]
        return sp
    stack[sp - 2] = _BINARY_OPS[op](stack[sp - 2], stack[sp - 1])
    return sp - 1


def _load_rel(frame: CellFrame, operand: int) -> int:
    if operand == 0:
        return int(frame.relation_family)
    if operand == 1:
        return frame.epoch_id
    return frame.delta.bitmask()


def _load_delta(frame: CellFrame, operand: int) -> float:
    if operand == 0:
        return float(frame.delta.magnitude)
    if operand == 1:
        return float(len(frame.delta.raised))
    if operand == 2:
        return frame.phi
    if operand == 3:
        return frame.delta_phi
    return frame.uncertainty


def _raise_dimension(
    raised: dict[str, tuple[int, int]], levels: tuple[int, ...], operand: int
) -> None:
    """Raise one dimension by one step, clamped at the top of its lattice.

    Monotone by construction: ``after`` is never below ``before``, and a
    dimension already raised by this program is left alone so a long program
    cannot ratchet a lineage to root one instruction at a time.
    """
    name = STATE_SLOTS[operand]
    if name in raised:
        return
    before = levels[operand]
    after = before + 1
    if after > _MAX_LEVELS[operand]:
        after = _MAX_LEVELS[operand]
    if after > before:
        raised[name] = (before, after)


def _escalation(level_index: int, frame: CellFrame) -> EscalationDecision | None:
    """Emit a Stage 1 escalation *request*, never a grant."""
    if level_index < 0:
        return None
    return EscalationDecision(
        target=_ESCALATION_TARGET,
        level=_OBSERVATION_LEVELS[level_index],
        budget_score=_clamp01(frame.uncertainty),
        escalated=False,
        refused_reason=_ESCALATION_PENDING,
    )


def _clamp01(value: float) -> float:
    if value < 0.0:
        return 0.0
    if value > 1.0:
        return 1.0
    return float(value)


def _abstained(reason: str) -> CellResult:
    return CellResult(
        abstained=True,
        delta=StateDelta(raised=_EMPTY_DELTA_FIELDS),
        evidence=(),
        risk=0.0,
        escalation=None,
        steps_taken=0,
        reason=reason,
    )
