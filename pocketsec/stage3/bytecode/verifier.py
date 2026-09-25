"""D3.6 — the PCB verifier: what it proves, and what it merely tests.

This module exists to answer one question before a Knowledge Cell's operator is
allowed to run on an endpoint: *is there any input for which this program does
not terminate, overruns its stack, reads outside its frame, or applies an
operation to the wrong type?* For PCB the answer is decidable, and it is
decidable for a boring reason: a PCB program is straight-line, so it has
exactly one execution path, so abstract interpretation over it is **exact**
rather than an over-approximation.

**The discipline this module exists to hold.** A property may appear in
:data:`PROVEN_PROPERTIES` only if its proof is one sentence about the ISA
itself. "No test has broken it" is not a proof and never earns a place there;
such claims live in :data:`TESTED_ONLY_PROPERTIES` and must be worded as
empirical claims everywhere they appear — spec, ADR, findings document and
docstring alike. ``AssuranceLevel.A5`` may be assigned only for a property in
:data:`PROVEN_PROPERTIES`; a VM that is "safe" because nothing has broken it is
at A4 at best.

The verifier refuses rather than repairs. A program that fails any check is not
rewritten, clamped or partially accepted: :class:`VerificationReport` comes back
with ``ok=False`` and the :class:`~pocketsec.stage3.bytecode.vm.CellVM` abstains
without executing a single instruction.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage3.bytecode.isa import (
    MAX_INSTRUCTIONS,
    MAX_STACK,
    MAX_STATE_BYTES,
    MAX_TABLE_ENTRIES,
    OPERAND_RANGE,
    STACK_EFFECT,
    TERMINATORS,
    Instruction,
    Op,
    ValueType,
    decode,
    load_constants,
    load_sets,
    state_bytes_for_depth,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from pocketsec.stage3.cells.operator import OperatorProgram

__all__ = [
    "ALL_PROVEN_PROPERTIES",
    "BYTECODE_FORM_NAME",
    "CellVerifier",
    "PROVEN_PROPERTIES",
    "STRUCTURAL_PROVEN_PROPERTIES",
    "TESTED_ONLY_PROPERTIES",
    "VerifiedProgram",
    "VerificationReport",
    "verify",
    "verify_and_decode",
]

#: ``OperatorForm.BYTECODE`` compared as a string. ``OperatorForm`` is a
#: ``StrEnum`` owned by the cells package (D3.5), so comparing by value keeps
#: the verifier usable without a runtime import of a package it does not need.
BYTECODE_FORM_NAME = "BYTECODE"

PROVEN_PROPERTIES: tuple[str, ...] = (
    "termination: the program is straight-line; the ISA defines no jump, branch or call "
    "opcode, and instruction_count <= MAX_INSTRUCTIONS is checked statically",
    "no unbounded loop: by the same absence — there is no opcode that can move the program "
    "counter backwards",
    "no dynamic allocation: max_stack_depth is computed exactly by abstract interpretation "
    "over a straight-line program and checked against MAX_STACK",
    "operand-type safety: abstract stack typing over a straight-line program is exact, not "
    "an approximation, so a type error is a decision rather than a heuristic",
    "bounded state access: every LOAD_* operand indexes a fixed-size CellFrame and is "
    "range-checked at verification time; there is no indirect load",
)

TESTED_ONLY_PROPERTIES: tuple[str, ...] = (
    "the VM does not corrupt interpreter or host state — no test has observed it; empirical",
    "decode(encode(p)) == p for the generated program corpus — empirical over that corpus",
    "no verified program has exceeded its declared max_steps in any run — empirical",
    "resistance to adversarially-crafted operand values beyond the range check — empirical, "
    "exercised by labs/boundary_evasion.py",
)

#: Reported for a non-BYTECODE operator form, which carries no program at all.
#: Kept separate from :data:`PROVEN_PROPERTIES` because those five are
#: statements about the ISA, and a lookup table has no ISA. Vacuous truth is
#: still truth, but a report that claimed "abstract interpretation found depth
#: 0" for a program that does not exist would read as a stronger claim than the
#: one actually made.
STRUCTURAL_PROVEN_PROPERTIES: tuple[str, ...] = (
    "bounded table size: the operator carries a plain mapping whose entry count is counted "
    "statically and checked against MAX_TABLE_ENTRIES; it holds no opcode and no program "
    "counter, so there is nothing to bound dynamically",
)

#: The full set a downstream assurance check may accept as *proven*. Stage 3's
#: promotion path (D3.11) checks membership against this, so a structural
#: operator cannot claim an ISA property and an ISA operator cannot claim a
#: table property.
ALL_PROVEN_PROPERTIES: tuple[str, ...] = PROVEN_PROPERTIES + STRUCTURAL_PROVEN_PROPERTIES


@dataclass(frozen=True, slots=True)
class VerificationReport:
    """The verdict, and an explicit split between proof and observation."""

    ok: bool
    proven: tuple[str, ...]
    tested_only: tuple[str, ...]
    failures: tuple[tuple[str, str], ...]
    instruction_count: int
    max_stack_depth: int
    max_state_bytes: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "proven": list(self.proven),
            "tested_only": list(self.tested_only),
            "failures": [{"code": code, "detail": detail} for code, detail in self.failures],
            "instruction_count": self.instruction_count,
            "max_stack_depth": self.max_stack_depth,
            "max_state_bytes": self.max_state_bytes,
        }


@dataclass(frozen=True, slots=True)
class VerifiedProgram:
    """A report plus the decoded form the verifier already had to build.

    This exists for one measured reason. Decoding the words and parsing the
    constant/set pools costs about as much as executing the program, and
    ``CellVM.run`` was paying for it twice: once inside ``verify`` and once
    again on its own. Measured as within-run ratios against ``_execute`` in the
    same process (absolute microseconds are not reported, because this host is
    contended): ``run()`` cost 10.18x ``_execute()`` while it decoded twice
    (loadavg 16.59/22.01/21.79) and 2.93x once it stopped (loadavg
    18.12/20.70/21.33).

    The contract is unchanged, and that is the point of returning the decoding
    rather than caching a "already verified" flag: verification still runs in
    full on every call, and ``instructions`` is empty whenever ``report.ok`` is
    false, so a refused program hands back nothing that could be executed.
    """

    report: VerificationReport
    instructions: tuple[Instruction, ...]
    constants: tuple[float, ...]
    sets: tuple[frozenset[int], ...]


def verify(program: OperatorProgram) -> VerificationReport:
    """Decide whether ``program`` may execute, and say why on both answers."""
    return verify_and_decode(program).report


def verify_and_decode(program: OperatorProgram) -> VerifiedProgram:
    """Verify, and hand back the decoding the verification already produced."""
    if str(program.form) != BYTECODE_FORM_NAME:
        return VerifiedProgram(_verify_structural(program), (), (), ())
    return _verify_bytecode(program)


def _verify_structural(program: OperatorProgram) -> VerificationReport:
    """Bounds for an operator form that carries data instead of instructions."""
    failures: list[tuple[str, str]] = []
    if tuple(program.words):
        failures.append(("unexpected_words", f"{str(program.form)} carries bytecode words"))
    entries = len(program.table)
    if entries > MAX_TABLE_ENTRIES:
        failures.append(("table_too_large", f"{entries} entries > {MAX_TABLE_ENTRIES}"))
    failures.extend(_check_declared_bounds(program, computed_state_bytes=0))
    ok = not failures
    return VerificationReport(
        ok=ok,
        proven=STRUCTURAL_PROVEN_PROPERTIES if ok else (),
        tested_only=TESTED_ONLY_PROPERTIES if ok else (),
        failures=tuple(failures),
        instruction_count=0,
        max_stack_depth=0,
        max_state_bytes=int(program.max_state_bytes),
    )


def _verify_bytecode(program: OperatorProgram) -> VerifiedProgram:
    """The five static checks, in the order that makes each one meaningful."""
    try:
        instructions = decode(program.words)
        constants = load_constants(program.table)
        sets = load_sets(program.table)
    except ContractError as exc:
        return VerifiedProgram(_refused("decode", str(exc)), (), (), ())

    count = len(instructions)
    failures: list[tuple[str, str]] = []
    if count > MAX_INSTRUCTIONS:
        failures.append(("too_many_instructions", f"{count} > {MAX_INSTRUCTIONS}"))
    failures.extend(_check_terminator(instructions))
    failures.extend(_check_operands(instructions, len(constants), len(sets)))
    depth, type_failures = _abstract_interpret(instructions)
    failures.extend(type_failures)
    computed = state_bytes_for_depth(depth)
    failures.extend(_check_declared_bounds(program, computed_state_bytes=computed))
    if program.max_steps < count:
        failures.append(("declared_steps_too_small", f"{program.max_steps} < {count}"))

    ok = not failures
    report = VerificationReport(
        ok=ok,
        proven=PROVEN_PROPERTIES if ok else (),
        tested_only=TESTED_ONLY_PROPERTIES if ok else (),
        failures=tuple(failures),
        instruction_count=count,
        max_stack_depth=depth,
        max_state_bytes=computed,
    )
    # A refused program hands back no decoding: there is nothing to execute,
    # and an executable artefact attached to a failed report is an invitation.
    if not ok:
        return VerifiedProgram(report, (), (), ())
    return VerifiedProgram(report, instructions, constants, sets)


def _refused(code: str, detail: str) -> VerificationReport:
    return VerificationReport(
        ok=False,
        proven=(),
        tested_only=(),
        failures=((code, detail),),
        instruction_count=0,
        max_stack_depth=0,
        max_state_bytes=0,
    )


def _check_terminator(instructions: tuple[Instruction, ...]) -> list[tuple[str, str]]:
    """A terminator must be last, and may be nowhere else.

    An early terminator would make everything after it dead code, which is a
    second execution path in all but name — and the one-path property is what
    makes the stack analysis exact rather than approximate.
    """
    if not instructions:
        return [("no_terminator", "empty program cannot terminate in a verdict")]
    if instructions[-1].op not in TERMINATORS:
        return [("no_terminator", f"program ends with {instructions[-1].op.name}")]
    early = [
        index
        for index, instruction in enumerate(instructions[:-1])
        if instruction.op in TERMINATORS
    ]
    if early:
        return [("terminator_not_final", f"terminators at {early}")]
    return []


def _check_operands(
    instructions: tuple[Instruction, ...], constant_count: int, set_count: int
) -> list[tuple[str, str]]:
    """Range-check every operand against a fixed, statically known bound."""
    failures: list[tuple[str, str]] = []
    for index, instruction in enumerate(instructions):
        op = instruction.op
        limit = OPERAND_RANGE[op]
        if op is Op.LOAD_CONST:
            limit = min(limit, constant_count)
        elif op is Op.IN_SET:
            limit = min(limit, set_count)
        if instruction.operand >= limit:
            failures.append(
                (
                    "operand_out_of_range",
                    f"instruction {index} {op.name} operand {instruction.operand} >= {limit}",
                )
            )
    return failures


def _abstract_interpret(
    instructions: tuple[Instruction, ...],
) -> tuple[int, list[tuple[str, str]]]:
    """Walk the one path this program has, tracking the typed stack exactly.

    Exact, not conservative: there is no branch to merge and no loop to widen,
    so the abstract stack at instruction *i* is the concrete stack shape at
    instruction *i* for every input. That is why a type mismatch reported here
    is a decision about the program and not a warning about a possibility.
    """
    stack: list[ValueType] = []
    failures: list[tuple[str, str]] = []
    depth = 0
    for index, instruction in enumerate(instructions):
        popped, pushed = STACK_EFFECT[instruction.op]
        if len(stack) < len(popped):
            failures.append(
                ("stack_underflow", f"instruction {index} {instruction.op.name} underflows")
            )
            return depth, failures
        actual = tuple(stack[len(stack) - len(popped) :]) if popped else ()
        if actual != popped:
            failures.append(
                (
                    "type_mismatch",
                    f"instruction {index} {instruction.op.name} wants "
                    f"{[t.value for t in popped]}, stack holds {[t.value for t in actual]}",
                )
            )
            return depth, failures
        del stack[len(stack) - len(popped) :]
        stack.extend(pushed)
        depth = max(depth, len(stack))
        if depth > MAX_STACK:
            failures.append(("stack_overflow", f"depth {depth} > {MAX_STACK}"))
            return depth, failures
    return depth, failures


def _check_declared_bounds(
    program: OperatorProgram, *, computed_state_bytes: int
) -> list[tuple[str, str]]:
    """The operator's own declared bounds must be honest and within the caps."""
    failures: list[tuple[str, str]] = []
    declared_steps = int(program.max_steps)
    if declared_steps < 0 or declared_steps > MAX_INSTRUCTIONS:
        failures.append(
            ("declared_steps_out_of_range", f"{declared_steps} outside [0, {MAX_INSTRUCTIONS}]")
        )
    declared_bytes = int(program.max_state_bytes)
    if declared_bytes < 0 or declared_bytes > MAX_STATE_BYTES:
        failures.append(
            ("declared_state_out_of_range", f"{declared_bytes} outside [0, {MAX_STATE_BYTES}]")
        )
    elif declared_bytes < computed_state_bytes:
        failures.append(
            (
                "declared_state_too_small",
                f"declared {declared_bytes} < computed {computed_state_bytes}",
            )
        )
    return failures


#: Integration plan section 3.2 names the verifier ``CellVerifier``.
CellVerifier = verify
