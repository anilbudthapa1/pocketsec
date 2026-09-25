"""D3.6 — the PocketSec Cell Bytecode (PCB) instruction set (architecture section 14).

This module exists so that a crystallised Knowledge Cell can carry *executable*
knowledge onto an endpoint without carrying the ability to do anything except
read a fixed frame and emit a bounded security verdict.

**The termination argument is an absence, not a check.** The ISA defines no
jump, no branch, no call, no loop, no allocation, no indirect load and no
syscall opcode. There is therefore no opcode that can move the program counter
backwards or sideways: every PCB program is straight-line, it has exactly one
execution path, and it executes exactly ``len(instructions)`` steps. Combined
with the static ``instruction_count <= MAX_INSTRUCTIONS`` check in
:mod:`pocketsec.stage3.bytecode.verifier`, that absence is what the verifier
reports as *proven by construction* rather than as *not yet observed to fail*.
Adding a single program-counter-moving opcode to :class:`Op` would delete that
proof, which is why ``tests/test_stage3_bytecode.py`` asserts over the members
of :class:`Op` rather than over any particular program.

Two consequences of that design are worth stating plainly, because they look
like limitations and are actually the point:

* There is no conditional jump, so a program cannot *branch*. Conditional
  behaviour is expressed by guarding an effect (``TRANSITION``,
  ``RAISE_OBSERVATION``) with a boolean it pops. Every instruction still runs.
* A terminator may appear only as the final instruction. Allowing an early
  ``RETURN_*`` would make every following instruction dead code, which is a
  second path in all but name, and dead code in a security operator is a place
  for a later contributor to hide behaviour.

Values are typed. The numeric domain is split deliberately: ``FLOAT`` carries
magnitudes that get compared against thresholds, ``INT`` carries masks and
enum identifiers that get tested for set membership. Keeping them apart is what
lets :data:`STACK_EFFECT` declare exactly one type per stack slot, which is
what makes the verifier's type check a decision rather than a heuristic.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import IntEnum, StrEnum

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.state.security_state import DIMENSIONS
# Imported and re-exported, never redefined. ``cells/operator.py`` enforces that
# a BYTECODE program's table holds nothing but these two pools, and it must
# spell the prefixes the same way this module reads them or the constant pool
# loads empty while looking correct. Foundation owns the shared vocabulary; the
# §5 package order has bytecode depending on it, exactly as with MAX_CELL_STEPS.
from pocketsec.stage3.cells.operator import (
    CONSTANT_KEY_PREFIX,
    MAX_CELL_STEPS,
    SET_KEY_PREFIX,
)

__all__ = [
    "CONSTANT_KEY_PREFIX",
    "CellISA",
    "DELTA_SLOTS",
    "FRAME_OVERHEAD_BYTES",
    "Instruction",
    "MAX_CONSTANTS",
    "MAX_INSTRUCTIONS",
    "MAX_OPERAND",
    "MAX_SETS",
    "MAX_SET_MEMBERS",
    "MAX_STACK",
    "MAX_STATE_BYTES",
    "MAX_TABLE_ENTRIES",
    "MAX_WINDOW_KEYS",
    "OPERAND_ARITY",
    "OPERAND_BITS",
    "OPERAND_RANGE",
    "Op",
    "PCB_VERSION",
    "REL_SLOTS",
    "SEM_SLOTS",
    "SET_KEY_PREFIX",
    "SLOT_BYTES",
    "STACK_EFFECT",
    "STATE_SLOTS",
    "TERMINATORS",
    "ValueType",
    "constant_key",
    "decode",
    "encode",
    "instruction_names",
    "load_constants",
    "load_sets",
    "set_key",
    "state_bytes_for_depth",
]

PCB_VERSION = "pocketsec-cell-bytecode.1.0.0"

#: Static program bounds. Every one of these is checked by the verifier before
#: a program is allowed to execute, so they are bounds rather than hopes.
# Imported rather than restated: ``cells/operator.py`` caps every operator's
# declared steps at the same number, and two independent 64s would drift.
MAX_INSTRUCTIONS = MAX_CELL_STEPS
MAX_STACK = 16
MAX_CONSTANTS = 32
MAX_SET_MEMBERS = 32

#: Distinct set literals a single program may carry. Not named by the
#: architecture; bounded here because an unbounded number of 32-member sets is
#: an unbounded operator, and "bounded operator form" is what G3.3 checks.
MAX_SETS = 8

#: Distinct sliding-window counters a program may read. The frame supplies the
#: counts; the program may only index into that fixed set.
MAX_WINDOW_KEYS = 16

#: Entries a non-BYTECODE operator's plain table may hold. A LOOKUP_TABLE that
#: grows without limit is the "knowledge explosion" threat wearing a table.
MAX_TABLE_ENTRIES = 1024

#: Word layout: one int per instruction, opcode in the high bits.
OPCODE_BITS = 8
OPERAND_BITS = 16
MAX_OPERAND = (1 << OPERAND_BITS) - 1
MAX_WORD = (1 << (OPCODE_BITS + OPERAND_BITS)) - 1

#: Bytes attributed to one occupied stack slot (a CPython object pointer) and
#: to the interpreter's fixed per-run bookkeeping. Used to compute an exact
#: static upper bound on VM working state, which is what makes
#: ``OperatorProgram.max_state_bytes`` a checkable declaration.
SLOT_BYTES = 8
FRAME_OVERHEAD_BYTES = 256
MAX_STATE_BYTES = MAX_STACK * SLOT_BYTES + FRAME_OVERHEAD_BYTES


class Op(IntEnum):
    """The complete PCB opcode set — architecture section 14's candidate list.

    There is deliberately no ``JUMP``, ``BRANCH``, ``CALL``, ``LOOP``,
    ``ALLOC``, ``LOAD_INDIRECT`` or ``SYSCALL`` member. That absence is the
    termination argument and the bounded-memory argument; see the module
    docstring.
    """

    LOAD_STATE = 0
    LOAD_SEM = 1
    LOAD_REL = 2
    LOAD_DELTA = 3
    LOAD_CONST = 4
    EQ = 5
    NE = 6
    LT = 7
    GT = 8
    IN_SET = 9
    AND = 10
    OR = 11
    NOT = 12
    COUNT_WINDOW = 13
    SEEN_WITHIN = 14
    TRANSITION = 15
    UPDATE_PHI = 16
    RAISE_OBSERVATION = 17
    PRESERVE_EVIDENCE = 18
    RETURN_STATE = 19
    RETURN_RISK = 20
    ABSTAIN = 21


class ValueType(StrEnum):
    BOOL = "BOOL"
    INT = "INT"
    FLOAT = "FLOAT"
    SET = "SET"
    EVIDENCE = "EVIDENCE"


#: Instructions that end a program. Exactly one of these must be the final
#: instruction, and none may appear anywhere else.
TERMINATORS: frozenset[Op] = frozenset({Op.RETURN_STATE, Op.RETURN_RISK, Op.ABSTAIN})


# --- frame slots -------------------------------------------------------------
# Every LOAD_* operand indexes one of these fixed tuples. The tuples are closed
# and pinned: index order is a wire commitment, because a program encoded under
# one order and decoded under another would read a different frame field while
# still verifying. Appending a slot is backward-compatible; reordering is not.

#: ``LOAD_STATE`` — one lattice level per Stage 1 state dimension, as FLOAT so
#: it can be compared against a threshold constant.
STATE_SLOTS: tuple[str, ...] = tuple(DIMENSIONS)

#: ``LOAD_SEM`` — semantic property masks, as INT so they can be set-tested.
SEM_SLOTS: tuple[str, ...] = ("actor_properties", "object_properties")

#: ``LOAD_REL`` — relation/epoch identifiers and the packed state-delta mask.
REL_SLOTS: tuple[str, ...] = ("relation_family", "epoch_id", "state_delta_bitmask")

#: ``LOAD_DELTA`` — magnitudes derived from the transition, as FLOAT.
DELTA_SLOTS: tuple[str, ...] = (
    "magnitude",
    "dimension_count",
    "phi",
    "delta_phi",
    "uncertainty",
)


# --- operand and stack contracts ---------------------------------------------

#: How many immediate operands an opcode consumes: 1 or 0. An opcode with arity
#: 0 must carry operand 0, so there is exactly one encoding per instruction and
#: a spare operand field cannot smuggle data past the verifier.
OPERAND_ARITY: Mapping[Op, int] = {
    Op.LOAD_STATE: 1,
    Op.LOAD_SEM: 1,
    Op.LOAD_REL: 1,
    Op.LOAD_DELTA: 1,
    Op.LOAD_CONST: 1,
    Op.EQ: 0,
    Op.NE: 0,
    Op.LT: 0,
    Op.GT: 0,
    Op.IN_SET: 1,
    Op.AND: 0,
    Op.OR: 0,
    Op.NOT: 0,
    Op.COUNT_WINDOW: 1,
    Op.SEEN_WITHIN: 1,
    Op.TRANSITION: 1,
    Op.UPDATE_PHI: 0,
    Op.RAISE_OBSERVATION: 1,
    Op.PRESERVE_EVIDENCE: 0,
    Op.RETURN_STATE: 0,
    Op.RETURN_RISK: 0,
    Op.ABSTAIN: 0,
}

#: Exclusive upper bound on each opcode's operand. An arity-0 opcode gets 1,
#: which admits only operand 0. These bounds are what "bounded state access"
#: means: a LOAD_* operand is range-checked against a fixed slot count at
#: verification time, and there is no opcode that computes an index.
OPERAND_RANGE: Mapping[Op, int] = {
    Op.LOAD_STATE: len(STATE_SLOTS),
    Op.LOAD_SEM: len(SEM_SLOTS),
    Op.LOAD_REL: len(REL_SLOTS),
    Op.LOAD_DELTA: len(DELTA_SLOTS),
    Op.LOAD_CONST: MAX_CONSTANTS,
    Op.EQ: 1,
    Op.NE: 1,
    Op.LT: 1,
    Op.GT: 1,
    Op.IN_SET: MAX_SETS,
    Op.AND: 1,
    Op.OR: 1,
    Op.NOT: 1,
    Op.COUNT_WINDOW: MAX_WINDOW_KEYS,
    Op.SEEN_WITHIN: MAX_WINDOW_KEYS,
    Op.TRANSITION: len(STATE_SLOTS),
    Op.UPDATE_PHI: 1,
    Op.RAISE_OBSERVATION: 3,  # len(ObservationLevel); see vm._OBSERVATION_LEVELS
    Op.PRESERVE_EVIDENCE: 1,
    Op.RETURN_STATE: 1,
    Op.RETURN_RISK: 1,
    Op.ABSTAIN: 1,
}

_B = ValueType.BOOL
_I = ValueType.INT
_F = ValueType.FLOAT
_E = ValueType.EVIDENCE

#: ``op -> (popped types, pushed types)``, bottom-of-pop first.
#:
#: ``RETURN_STATE`` pops an ``EVIDENCE`` handle on purpose. A program cannot
#: return a state change without having executed ``PRESERVE_EVIDENCE`` first,
#: so "a cell that changes security state carries evidence" is enforced by the
#: type system rather than by a reviewer noticing.
STACK_EFFECT: Mapping[Op, tuple[tuple[ValueType, ...], tuple[ValueType, ...]]] = {
    Op.LOAD_STATE: ((), (_F,)),
    Op.LOAD_SEM: ((), (_I,)),
    Op.LOAD_REL: ((), (_I,)),
    Op.LOAD_DELTA: ((), (_F,)),
    Op.LOAD_CONST: ((), (_F,)),
    Op.EQ: ((_F, _F), (_B,)),
    Op.NE: ((_F, _F), (_B,)),
    Op.LT: ((_F, _F), (_B,)),
    Op.GT: ((_F, _F), (_B,)),
    Op.IN_SET: ((_I,), (_B,)),
    Op.AND: ((_B, _B), (_B,)),
    Op.OR: ((_B, _B), (_B,)),
    Op.NOT: ((_B,), (_B,)),
    Op.COUNT_WINDOW: ((), (_F,)),
    Op.SEEN_WITHIN: ((), (_B,)),
    Op.TRANSITION: ((_B,), ()),
    Op.UPDATE_PHI: ((_F,), ()),
    Op.RAISE_OBSERVATION: ((_B,), ()),
    Op.PRESERVE_EVIDENCE: ((), (_E,)),
    Op.RETURN_STATE: ((_E,), ()),
    Op.RETURN_RISK: ((_F,), ()),
    Op.ABSTAIN: ((), ()),
}


def _assert_tables_are_closed() -> None:
    """Refuse to import with a half-added opcode.

    A plain ``assert`` would vanish under ``python -O``, and an opcode with no
    declared stack effect is precisely the hole the verifier cannot see. This
    is the one place where the cost of a real check at import time is obviously
    worth paying.
    """
    members = set(Op)
    for name, table in (
        ("OPERAND_ARITY", OPERAND_ARITY),
        ("OPERAND_RANGE", OPERAND_RANGE),
        ("STACK_EFFECT", STACK_EFFECT),
    ):
        missing = members - set(table)
        extra = set(table) - members
        if missing or extra:
            raise ContractError(
                f"{name} must cover exactly Op; missing={sorted(m.name for m in missing)} "
                f"extra={sorted(str(e) for e in extra)}"
            )
    for op, arity in OPERAND_ARITY.items():
        if arity == 0 and OPERAND_RANGE[op] != 1:
            raise ContractError(f"{op.name} takes no operand but declares a range > 1")
    if max(Op) >= (1 << OPCODE_BITS):
        raise ContractError("opcodes must fit in OPCODE_BITS")


_assert_tables_are_closed()


@dataclass(frozen=True, slots=True)
class Instruction:
    """One decoded PCB instruction. Immutable, so a verified program stays verified."""

    op: Op
    operand: int

    def to_dict(self) -> dict[str, int | str]:
        return {"op": self.op.name, "operand": self.operand}


def encode(instructions: Sequence[Instruction]) -> tuple[int, ...]:
    """Pack instructions into one non-negative int each.

    Encoding refuses a malformed instruction here rather than letting it reach
    the verifier as a plausible-looking word, because a word that decodes
    cleanly to the wrong opcode is worse than one that fails to decode.
    """
    words: list[int] = []
    for index, instruction in enumerate(instructions):
        op = instruction.op
        if not isinstance(op, Op):
            raise ContractError(f"instruction {index}: {op!r} is not a PCB opcode")
        operand = instruction.operand
        if not isinstance(operand, int) or isinstance(operand, bool):
            raise ContractError(f"instruction {index}: operand must be an int")
        if operand < 0 or operand > MAX_OPERAND:
            raise ContractError(
                f"instruction {index}: operand {operand} outside [0, {MAX_OPERAND}]"
            )
        if OPERAND_ARITY[op] == 0 and operand != 0:
            raise ContractError(f"instruction {index}: {op.name} takes no operand")
        words.append((int(op) << OPERAND_BITS) | operand)
    return tuple(words)


def decode(words: Sequence[int]) -> tuple[Instruction, ...]:
    """Unpack words into instructions, refusing anything the ISA does not define.

    An unknown opcode is refused rather than skipped. Skipping would let a
    program mean one thing to the verifier and another to a future VM that
    happened to define the opcode.
    """
    instructions: list[Instruction] = []
    for index, word in enumerate(words):
        if not isinstance(word, int) or isinstance(word, bool):
            raise ContractError(f"word {index}: {word!r} is not an int")
        if word < 0 or word > MAX_WORD:
            raise ContractError(f"word {index}: {word} outside [0, {MAX_WORD}]")
        opcode = word >> OPERAND_BITS
        operand = word & MAX_OPERAND
        try:
            op = Op(opcode)
        except ValueError as exc:
            raise ContractError(f"word {index}: unknown opcode {opcode}") from exc
        if OPERAND_ARITY[op] == 0 and operand != 0:
            raise ContractError(
                f"word {index}: {op.name} takes no operand, got {operand}"
            )
        instructions.append(Instruction(op=op, operand=operand))
    return tuple(instructions)


# --- the operator table as a constant/set pool -------------------------------
# ``OperatorProgram.table`` is a plain ``Mapping[str, float]`` so a cell stays
# JSON. Constants and set literals therefore live in that flat mapping under
# reserved key prefixes, which keeps the wire format free of nested structures
# a future reader could interpret differently.




def constant_key(index: int) -> str:
    return f"{CONSTANT_KEY_PREFIX}{index}"


def set_key(index: int, member: int) -> str:
    return f"{SET_KEY_PREFIX}{index}.{member}"


def load_constants(table: Mapping[str, float]) -> tuple[float, ...]:
    """Read the dense constant pool out of an operator table.

    Dense on purpose: ``const.0 … const.n-1`` with no gaps, so ``LOAD_CONST``'s
    range check against the pool length is exact.
    """
    found: dict[int, float] = {}
    for key, value in table.items():
        if not key.startswith(CONSTANT_KEY_PREFIX):
            continue
        index = _positive_index(key[len(CONSTANT_KEY_PREFIX) :], key)
        if index >= MAX_CONSTANTS:
            raise ContractError(f"constant index {index} exceeds MAX_CONSTANTS")
        found[index] = float(value)
    if found and sorted(found) != list(range(len(found))):
        raise ContractError(f"constant pool is not dense: {sorted(found)}")
    return tuple(found[index] for index in range(len(found)))


def load_sets(table: Mapping[str, float]) -> tuple[frozenset[int], ...]:
    """Read the dense set-literal pool out of an operator table.

    A member is present when its value is non-zero. Storing membership as a
    float keeps the table a flat ``Mapping[str, float]``; it is never arithmetic.
    """
    found: dict[int, set[int]] = {}
    for key, value in table.items():
        if not key.startswith(SET_KEY_PREFIX):
            continue
        body = key[len(SET_KEY_PREFIX) :]
        head, _, tail = body.partition(".")
        if not tail:
            raise ContractError(f"malformed set key {key!r}")
        index = _positive_index(head, key)
        member = _positive_index(tail, key)
        if index >= MAX_SETS:
            raise ContractError(f"set index {index} exceeds MAX_SETS")
        if value:
            found.setdefault(index, set()).add(member)
    for index, members in found.items():
        if len(members) > MAX_SET_MEMBERS:
            raise ContractError(f"set {index} has {len(members)} members > MAX_SET_MEMBERS")
    if found and sorted(found) != list(range(len(found))):
        raise ContractError(f"set pool is not dense: {sorted(found)}")
    return tuple(frozenset(found[index]) for index in range(len(found)))


def _positive_index(text: str, key: str) -> int:
    """Parse one pool index, refusing any non-canonical spelling of it.

    ``isdigit()`` alone accepted ``const.0`` and ``const.00`` as the same index,
    so one of the two values silently won on the normalised table's iteration
    order and the other was dropped — while the density check
    ``sorted(found) == range(len(found))`` still passed, leaving ``LOAD_CONST``'s
    range check exact against a pool that had lost an entry. ``isdigit()`` also
    accepts non-ASCII decimal digits, which ``int()`` then converts to an index
    nobody wrote.
    """
    if not text or not text.isascii() or not text.isdigit():
        raise ContractError(f"malformed pool key {key!r}")
    if text != str(int(text)):
        raise ContractError(
            f"pool key {key!r} spells its index non-canonically; 'const.0' and 'const.00' "
            "would name one slot and one of the two values would be dropped silently"
        )
    return int(text)


def state_bytes_for_depth(max_stack_depth: int) -> int:
    """Exact static upper bound on VM working state for a given stack depth.

    Exact because the stack is the only per-run storage a PCB program can
    reach: there is no allocation opcode, and the depth is computed by the
    verifier rather than observed at runtime. A synthesiser declares
    ``OperatorProgram.max_state_bytes`` from this, and the verifier refuses a
    declaration smaller than the bound it computes itself.
    """
    if max_stack_depth < 0:
        raise ContractError("max_stack_depth must be non-negative")
    return max_stack_depth * SLOT_BYTES + FRAME_OVERHEAD_BYTES


def instruction_names(ops: Iterable[Op]) -> tuple[str, ...]:
    """Names of a program's opcodes — for reports and ADRs, never the hot path."""
    return tuple(op.name for op in ops)


#: Integration plan section 3.2 names the ISA ``CellISA``. Same object, so a
#: consumer that imports either name gets the same closed opcode set.
CellISA = Op
