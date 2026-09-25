"""D3.6 — PCB ISA, verifier and VM: bounds that bound, refusals that refuse.

Tests are named after the property they defend, not after the function they
call, because the point of this file is that someone who weakens an invariant
has to delete a test whose name says what they are deleting.

The split this file exists to hold:

* Every string in ``verifier.PROVEN_PROPERTIES`` is defended by at least one
  test that would fail if the ISA gained the corresponding capability. Those
  tests assert over the members of ``Op`` and over the verifier's static
  decisions — never over "no run happened to break it".
* Every string in ``verifier.TESTED_ONLY_PROPERTIES`` is an **empirical**
  claim about the corpus or the runs in this file. The round-trip test is
  named to say so out loud.
"""

from __future__ import annotations

import gc
import tracemalloc
from dataclasses import dataclass
from typing import Any

import pytest

from pocketsec.stage0.contracts.common import ContractError, EvidenceRef
from pocketsec.stage1.observation.policy import EscalationDecision, ObservationLevel
from pocketsec.stage1.ssir.relations import RelationFamily
from pocketsec.stage1.state.security_state import (
    DIMENSIONS,
    Privilege,
    SecurityStateV1,
    StateDelta,
)
from pocketsec.stage3.bytecode import isa, verifier, vm
from pocketsec.stage3.bytecode.isa import (
    MAX_CONSTANTS,
    MAX_INSTRUCTIONS,
    MAX_OPERAND,
    MAX_SETS,
    MAX_STACK,
    MAX_STATE_BYTES,
    MAX_WINDOW_KEYS,
    OPERAND_ARITY,
    OPERAND_RANGE,
    PCB_VERSION,
    STACK_EFFECT,
    STATE_SLOTS,
    TERMINATORS,
    CellISA,
    Instruction,
    Op,
    ValueType,
    constant_key,
    decode,
    encode,
    set_key,
    state_bytes_for_depth,
)
from pocketsec.stage3.bytecode.vm import CellFrame, CellResult, CellVM
from pocketsec.stage3.bytecode.verifier import (
    ALL_PROVEN_PROPERTIES,
    PROVEN_PROPERTIES,
    STRUCTURAL_PROVEN_PROPERTIES,
    TESTED_ONLY_PROPERTIES,
    CellVerifier,
    verify,
    verify_and_decode,
)

# --- the operator-program seam -----------------------------------------------
# ``OperatorProgram`` (D3.5) is owned by the `foundation` work package and is
# being written concurrently. This file therefore constructs programs through a
# local test double whose field names are exactly the five attributes the
# verifier and VM read. ``test_operator_program_seam_fields_are_the_ones_read``
# checks the real class against the same tuple as soon as it exists, so the
# double cannot drift into a weaker contract than the real type.

#: The attributes this package reads off an ``OperatorProgram``. Nothing else.
REQUIRED_PROGRAM_FIELDS = ("form", "words", "table", "max_steps", "max_state_bytes")


@dataclass(frozen=True, slots=True)
class _Program:
    """Test double for ``pocketsec.stage3.cells.operator.OperatorProgram``."""

    form: str
    words: tuple[int, ...]
    table: dict[str, float]
    max_steps: int
    max_state_bytes: int


def _program(
    instructions: list[Instruction] | tuple[Instruction, ...] = (),
    *,
    form: str = "BYTECODE",
    table: dict[str, float] | None = None,
    words: tuple[int, ...] | None = None,
    max_steps: int | None = None,
    max_state_bytes: int = MAX_STATE_BYTES,
) -> Any:
    encoded = encode(instructions) if words is None else words
    return _Program(
        form=form,
        words=encoded,
        table={} if table is None else table,
        max_steps=MAX_INSTRUCTIONS if max_steps is None else max_steps,
        max_state_bytes=max_state_bytes,
    )


def _evidence(n: int = 2) -> tuple[EvidenceRef, ...]:
    return tuple(
        EvidenceRef(store="stage1", locator=f"evt-{i}", digest="sha256:" + f"{i:064x}")
        for i in range(n)
    )


def _frame(
    *,
    state: SecurityStateV1 | None = None,
    phi: float = 0.4,
    delta_phi: float = 0.1,
    uncertainty: float = 0.6,
    epoch_id: int = 0,
    window_counts: dict[int, int] | None = None,
    evidence: tuple[EvidenceRef, ...] | None = None,
) -> CellFrame:
    return CellFrame(
        state=state or SecurityStateV1(),
        delta=StateDelta(raised={"privilege": (0, 1)}),
        actor_properties=0b1010,
        object_properties=0b0110,
        relation_family=RelationFamily.EXECUTION,
        phi=phi,
        delta_phi=delta_phi,
        uncertainty=uncertainty,
        epoch_id=epoch_id,
        window_counts={0: 3, 1: 0} if window_counts is None else window_counts,
        evidence=_evidence() if evidence is None else evidence,
        encoder_version="ssir-encoder.1",
    )


#: A minimal program that terminates in a state change with preserved evidence.
def _state_program() -> Any:
    return _program(
        [
            Instruction(Op.LOAD_DELTA, 2),  # phi           -> FLOAT
            Instruction(Op.LOAD_CONST, 0),  # threshold     -> FLOAT
            Instruction(Op.GT, 0),  # phi > threshold       -> BOOL
            Instruction(Op.TRANSITION, 0),  # raise privilege
            Instruction(Op.LOAD_DELTA, 3),  # delta_phi     -> FLOAT
            Instruction(Op.UPDATE_PHI, 0),
            Instruction(Op.PRESERVE_EVIDENCE, 0),  #        -> EVIDENCE
            Instruction(Op.RETURN_STATE, 0),
        ],
        table={constant_key(0): 0.2},
    )


# --- PROVEN: termination, and no unbounded loop ------------------------------

#: Anything that could move the program counter anywhere but forward by one.
FORBIDDEN_OPCODE_TOKENS = (
    "JUMP",
    "BRANCH",
    "CALL",
    "LOOP",
    "GOTO",
    "REPEAT",
    "WHILE",
    "ALLOC",
    "SYSCALL",
    "INVOKE",
    "INDIRECT",
    "EVAL",
    "IMPORT",
    "YIELD",
)

#: The ISA, member for member. Adding an opcode without amending this tuple is
#: a test failure, which is the point: a new opcode must be argued for.
EXPECTED_OPS = (
    "LOAD_STATE",
    "LOAD_SEM",
    "LOAD_REL",
    "LOAD_DELTA",
    "LOAD_CONST",
    "EQ",
    "NE",
    "LT",
    "GT",
    "IN_SET",
    "AND",
    "OR",
    "NOT",
    "COUNT_WINDOW",
    "SEEN_WITHIN",
    "TRANSITION",
    "UPDATE_PHI",
    "RAISE_OBSERVATION",
    "PRESERVE_EVIDENCE",
    "RETURN_STATE",
    "RETURN_RISK",
    "ABSTAIN",
)


def test_isa_defines_no_opcode_that_moves_the_program_counter_backwards() -> None:
    """The termination proof is this absence. Adding JUMP deletes the proof."""
    names = tuple(op.name for op in Op)
    assert names == EXPECTED_OPS
    for name in names:
        for token in FORBIDDEN_OPCODE_TOKENS:
            assert token not in name, f"{name} looks like control flow"


def test_isa_defines_no_opcode_that_allocates_or_reaches_the_host() -> None:
    """Bounded memory and bounded state access rest on the same absence."""
    assert not {"ALLOC", "NEW", "STORE_STATE", "WRITE", "OPEN", "EXEC"} & {op.name for op in Op}


def test_every_opcode_has_a_declared_arity_range_and_stack_effect() -> None:
    """A half-added opcode is a hole the verifier cannot see, so import refuses."""
    assert set(OPERAND_ARITY) == set(Op)
    assert set(OPERAND_RANGE) == set(Op)
    assert set(STACK_EFFECT) == set(Op)
    for op, arity in OPERAND_ARITY.items():
        assert arity in (0, 1)
        if arity == 0:
            assert OPERAND_RANGE[op] == 1


def test_a_program_of_65_instructions_is_refused() -> None:
    body = [Instruction(Op.LOAD_DELTA, 2), Instruction(Op.UPDATE_PHI, 0)] * 32
    program = _program([*body, Instruction(Op.ABSTAIN, 0)])
    report = verify(program)
    assert len(program.words) == MAX_INSTRUCTIONS + 1
    assert not report.ok
    assert "too_many_instructions" in _codes(report)


def test_a_program_at_exactly_64_instructions_is_accepted() -> None:
    """The bound is a bound, not a margin: 64 passes, 65 does not."""
    body = [Instruction(Op.LOAD_DELTA, 2), Instruction(Op.UPDATE_PHI, 0)] * 31
    tail = [Instruction(Op.PRESERVE_EVIDENCE, 0), Instruction(Op.RETURN_STATE, 0)]
    program = _program([*body, *tail])
    report = verify(program)
    assert report.instruction_count == MAX_INSTRUCTIONS
    assert report.ok, report.failures


# --- PROVEN: no dynamic allocation (max_stack_depth exact, checked) ----------


def test_a_program_whose_abstract_stack_exceeds_16_is_refused() -> None:
    pushes = [Instruction(Op.LOAD_DELTA, 2)] * (MAX_STACK + 1)
    report = verify(_program([*pushes, Instruction(Op.ABSTAIN, 0)]))
    assert not report.ok
    assert "stack_overflow" in _codes(report)


def test_a_program_at_exactly_stack_depth_16_is_accepted() -> None:
    pushes = [Instruction(Op.LOAD_DELTA, 2)] * MAX_STACK
    report = verify(_program([*pushes, Instruction(Op.ABSTAIN, 0)]))
    assert report.ok, report.failures
    assert report.max_stack_depth == MAX_STACK


@pytest.mark.parametrize(
    ("program_factory", "expected_depth"),
    [
        (_state_program, 2),
        (lambda: _program([Instruction(Op.ABSTAIN, 0)]), 0),
        (
            lambda: _program(
                [Instruction(Op.LOAD_DELTA, 2)] * 5 + [Instruction(Op.ABSTAIN, 0)]
            ),
            5,
        ),
    ],
)
def test_abstract_stack_depth_equals_the_depth_the_vm_actually_reaches(
    program_factory: Any, expected_depth: int
) -> None:
    """Exact, not conservative — a straight-line program has one path.

    The VM's stack is allocated once and reused, so a slot the interpreter
    never pushed to is still the sentinel this test planted. If the analysis
    were an over-approximation, a slot above ``max_stack_depth`` would have
    been written and ``no dynamic allocation`` would be a guess.
    """
    program = program_factory()
    report = verify(program)
    assert report.ok, report.failures
    assert report.max_stack_depth == expected_depth
    assert report.max_state_bytes == state_bytes_for_depth(expected_depth)

    machine = CellVM()
    sentinel = object()
    machine._stack[:] = [sentinel] * MAX_STACK
    machine.run(program, _frame())
    untouched = [i for i in range(MAX_STACK) if machine._stack[i] is sentinel]
    assert min(untouched, default=MAX_STACK) >= report.max_stack_depth
    assert len(untouched) == MAX_STACK - report.max_stack_depth


def test_declared_state_bytes_smaller_than_the_computed_bound_is_refused() -> None:
    report = verify(_program([Instruction(Op.ABSTAIN, 0)], max_state_bytes=0))
    assert not report.ok
    assert "declared_state_too_small" in _codes(report)


def test_declared_state_bytes_above_the_cap_is_refused() -> None:
    report = verify(
        _program([Instruction(Op.ABSTAIN, 0)], max_state_bytes=MAX_STATE_BYTES + 1)
    )
    assert not report.ok
    assert "declared_state_out_of_range" in _codes(report)


def test_the_vm_peak_allocation_does_not_grow_with_the_number_of_events() -> None:
    """Empirical: 10k frames through one VM, peak measured with tracemalloc.

    This is an observation about this run, not a proof. The *proof* that peak
    memory cannot grow is the ISA's lack of an allocation opcode, defended by
    ``test_isa_defines_no_opcode_that_allocates_or_reaches_the_host``.
    """
    machine = CellVM()
    program = _state_program()
    frame = _frame()
    for _ in range(200):  # warm up: import-time and first-call allocations
        machine.run(program, frame)
    gc.collect()
    tracemalloc.start()
    baseline = tracemalloc.get_traced_memory()[0]
    for _ in range(10_000):
        machine.run(program, frame)
    gc.collect()
    current, _peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    growth = current - baseline
    assert growth < 64 * 1024, f"traced memory grew {growth} bytes over 10k frames"


# --- PROVEN: operand-type safety ---------------------------------------------


def test_a_type_mismatched_program_is_refused() -> None:
    """AND wants two BOOLs; handing it FLOATs is a decision, not a warning."""
    report = verify(
        _program(
            [
                Instruction(Op.LOAD_DELTA, 2),
                Instruction(Op.LOAD_DELTA, 3),
                Instruction(Op.AND, 0),
                Instruction(Op.ABSTAIN, 0),
            ]
        )
    )
    assert not report.ok
    assert "type_mismatch" in _codes(report)


def test_return_state_without_a_preserved_evidence_handle_is_refused() -> None:
    """The ISA makes evidence structural: RETURN_STATE pops an EVIDENCE value."""
    report = verify(_program([Instruction(Op.RETURN_STATE, 0)]))
    assert not report.ok
    assert "stack_underflow" in _codes(report)


def test_in_set_refuses_a_float_operand_stack() -> None:
    report = verify(
        _program(
            [
                Instruction(Op.LOAD_DELTA, 2),  # FLOAT
                Instruction(Op.IN_SET, 0),  # wants INT
                Instruction(Op.ABSTAIN, 0),
            ],
            table={set_key(0, 3): 1.0},
        )
    )
    assert not report.ok
    assert "type_mismatch" in _codes(report)


def test_stack_underflow_is_refused() -> None:
    report = verify(_program([Instruction(Op.NOT, 0), Instruction(Op.ABSTAIN, 0)]))
    assert not report.ok
    assert "stack_underflow" in _codes(report)


# --- PROVEN: bounded state access --------------------------------------------


def test_an_out_of_range_load_operand_is_refused() -> None:
    """LOAD_STATE indexes a fixed nine-slot frame; slot 9 does not exist."""
    assert len(STATE_SLOTS) == len(DIMENSIONS) == 9
    report = verify(
        _program([Instruction(Op.LOAD_STATE, len(STATE_SLOTS)), Instruction(Op.ABSTAIN, 0)])
    )
    assert not report.ok
    assert "operand_out_of_range" in _codes(report)


@pytest.mark.parametrize(
    ("op", "operand"),
    [
        (Op.LOAD_SEM, 2),
        (Op.LOAD_REL, 3),
        (Op.LOAD_DELTA, 5),
        (Op.COUNT_WINDOW, MAX_WINDOW_KEYS),
        (Op.SEEN_WITHIN, MAX_WINDOW_KEYS),
        (Op.TRANSITION, 9),
        (Op.RAISE_OBSERVATION, 3),
        (Op.IN_SET, MAX_SETS),
        (Op.LOAD_CONST, MAX_CONSTANTS),
    ],
)
def test_every_indexed_opcode_range_checks_its_operand(op: Op, operand: int) -> None:
    prefix: list[Instruction] = []
    if op in (Op.TRANSITION, Op.RAISE_OBSERVATION):
        prefix = [Instruction(Op.SEEN_WITHIN, 0)]
    elif op is Op.IN_SET:
        prefix = [Instruction(Op.LOAD_SEM, 0)]
    report = verify(
        _program([*prefix, Instruction(op, operand), Instruction(Op.ABSTAIN, 0)])
    )
    assert not report.ok
    assert "operand_out_of_range" in _codes(report), report.failures


def test_load_const_beyond_the_declared_pool_is_refused() -> None:
    """The range is the *pool*, not the cap: an undeclared constant is refused."""
    report = verify(
        _program(
            [Instruction(Op.LOAD_CONST, 1), Instruction(Op.ABSTAIN, 0)],
            table={constant_key(0): 0.5},
        )
    )
    assert not report.ok
    assert "operand_out_of_range" in _codes(report)


def test_a_sparse_constant_pool_is_refused() -> None:
    report = verify(
        _program([Instruction(Op.ABSTAIN, 0)], table={constant_key(0): 1.0, constant_key(2): 1.0})
    )
    assert not report.ok
    assert "decode" in _codes(report)


# --- terminators --------------------------------------------------------------


def test_a_program_with_no_terminator_is_refused() -> None:
    report = verify(_program([Instruction(Op.LOAD_DELTA, 2), Instruction(Op.UPDATE_PHI, 0)]))
    assert not report.ok
    assert "no_terminator" in _codes(report)


def test_an_empty_program_is_refused() -> None:
    report = verify(_program([]))
    assert not report.ok
    assert "no_terminator" in _codes(report)


def test_a_terminator_before_the_end_is_refused_so_there_is_no_dead_code() -> None:
    report = verify(
        _program([Instruction(Op.ABSTAIN, 0), Instruction(Op.ABSTAIN, 0)])
    )
    assert not report.ok
    assert "terminator_not_final" in _codes(report)


def test_every_terminator_is_accepted_as_the_final_instruction() -> None:
    assert TERMINATORS == {Op.RETURN_STATE, Op.RETURN_RISK, Op.ABSTAIN}
    assert verify(_program([Instruction(Op.ABSTAIN, 0)])).ok
    assert verify(
        _program([Instruction(Op.LOAD_DELTA, 2), Instruction(Op.RETURN_RISK, 0)])
    ).ok
    assert verify(_state_program()).ok


# --- encode / decode ----------------------------------------------------------


def test_decode_encode_roundtrip_holds_over_this_generated_corpus_empirically() -> None:
    """EMPIRICAL over the corpus built here — this is not a proof of totality.

    The corpus is every opcode at every legal operand value up to a cap, which
    is a large sample of the encoding space and still only a sample.
    """
    corpus: list[Instruction] = []
    for op in Op:
        limit = min(OPERAND_RANGE[op], 64)
        corpus.extend(Instruction(op, operand) for operand in range(limit))
    assert len(corpus) > 100
    assert decode(encode(corpus)) == tuple(corpus)


def test_encode_refuses_an_operand_on_an_opcode_that_takes_none() -> None:
    with pytest.raises(ContractError):
        encode([Instruction(Op.ABSTAIN, 1)])


def test_encode_refuses_an_out_of_range_operand() -> None:
    with pytest.raises(ContractError):
        encode([Instruction(Op.LOAD_CONST, MAX_OPERAND + 1)])
    with pytest.raises(ContractError):
        encode([Instruction(Op.LOAD_CONST, -1)])


def test_decode_refuses_an_unknown_opcode() -> None:
    unknown = (len(Op) << isa.OPERAND_BITS) | 0
    with pytest.raises(ContractError):
        decode([unknown])


def test_decode_refuses_a_negative_or_oversized_word() -> None:
    with pytest.raises(ContractError):
        decode([-1])
    with pytest.raises(ContractError):
        decode([1 << 40])


def test_decode_refuses_a_bool_masquerading_as_a_word() -> None:
    """``True == 1`` in Python; a bool word would silently decode as LOAD_SEM."""
    with pytest.raises(ContractError):
        decode([True])


def test_a_program_whose_words_do_not_decode_is_refused_not_repaired() -> None:
    report = verify(_program(words=(1 << 40,)))
    assert not report.ok
    assert _codes(report) == ("decode",)
    assert report.proven == ()


# --- VM behaviour and refusals -----------------------------------------------


def test_an_unverified_program_abstains_rather_than_running() -> None:
    machine = CellVM()
    result = machine.run(_program([Instruction(Op.LOAD_DELTA, 2)]), _frame())
    assert result.abstained
    assert result.steps_taken == 0
    assert result.reason.startswith(vm.REASON_UNVERIFIED_PREFIX)
    assert result.evidence == ()
    assert not result.delta


def test_a_non_bytecode_operator_form_verifies_structurally_but_does_not_execute() -> None:
    table = {"key": 1.0}
    program = _program(form="LOOKUP_TABLE", table=table, max_steps=1, max_state_bytes=0)
    report = verify(program)
    assert report.ok, report.failures
    assert report.proven == STRUCTURAL_PROVEN_PROPERTIES
    assert report.instruction_count == 0
    result = CellVM().run(program, _frame())
    assert result.abstained
    assert result.reason == vm.REASON_NOT_EXECUTABLE_FORM


def test_an_oversized_lookup_table_is_refused() -> None:
    table = {f"k{i}": 1.0 for i in range(isa.MAX_TABLE_ENTRIES + 1)}
    report = verify(_program(form="LOOKUP_TABLE", table=table, max_steps=1, max_state_bytes=0))
    assert not report.ok
    assert "table_too_large" in _codes(report)


def test_a_vm_with_a_smaller_step_budget_refuses_a_longer_program() -> None:
    machine = CellVM(max_steps=4)
    result = machine.run(_state_program(), _frame())
    assert result.abstained
    assert result.reason == vm.REASON_STEP_BUDGET


def test_the_vm_refuses_a_step_budget_outside_the_isa_bound() -> None:
    with pytest.raises(ContractError):
        CellVM(max_steps=MAX_INSTRUCTIONS + 1)


def test_abstain_reaches_the_abstention_path_with_no_state_change() -> None:
    result = CellVM().run(_program([Instruction(Op.ABSTAIN, 0)]), _frame())
    assert result.abstained
    assert result.reason == vm.REASON_ABSTAIN
    assert result.risk == 0.0
    assert result.delta.raised == {}
    assert result.escalation is None


def test_return_state_emits_a_raised_dimension_and_preserved_evidence() -> None:
    frame = _frame(phi=0.9)
    result = CellVM().run(_state_program(), frame)
    assert not result.abstained
    assert result.reason == vm.REASON_RETURN_STATE
    assert result.delta.raised == {"privilege": (0, 1)}
    assert set(result.evidence) == set(frame.evidence)
    assert result.steps_taken == 8


def test_a_false_guard_leaves_state_untouched() -> None:
    result = CellVM().run(_state_program(), _frame(phi=0.0))
    assert not result.abstained
    assert result.delta.raised == {}


def test_transition_cannot_lower_state_and_clamps_at_the_top_of_the_lattice() -> None:
    """Monotone by construction: there is no opcode that lowers a dimension."""
    at_root = SecurityStateV1(privilege=Privilege.ROOT)
    result = CellVM().run(_state_program(), _frame(state=at_root, phi=0.9))
    assert result.delta.raised == {}, "raising a saturated dimension must be a no-op"
    fresh = CellVM().run(_state_program(), _frame(phi=0.9))
    before, after = fresh.delta.raised["privilege"]
    assert after == before + 1


def test_update_phi_never_accumulates_a_negative_contribution() -> None:
    """NEVER_LOWER_PHI, at the instruction level rather than the policy level."""
    program = _program(
        [
            Instruction(Op.LOAD_DELTA, 3),
            Instruction(Op.UPDATE_PHI, 0),
            Instruction(Op.PRESERVE_EVIDENCE, 0),
            Instruction(Op.RETURN_STATE, 0),
        ]
    )
    negative = CellVM().run(program, _frame(delta_phi=-0.9))
    assert negative.risk == 0.0
    positive = CellVM().run(program, _frame(delta_phi=0.25))
    assert positive.risk == pytest.approx(0.25)


def test_return_risk_is_clamped_into_the_unit_interval() -> None:
    program = _program(
        [Instruction(Op.LOAD_CONST, 0), Instruction(Op.RETURN_RISK, 0)],
        table={constant_key(0): 42.0},
    )
    assert CellVM().run(program, _frame()).risk == 1.0
    low = _program(
        [Instruction(Op.LOAD_CONST, 0), Instruction(Op.RETURN_RISK, 0)],
        table={constant_key(0): -7.0},
    )
    assert CellVM().run(low, _frame()).risk == 0.0


def test_preserve_evidence_cannot_shrink_the_evidence_tuple() -> None:
    """The only path that changes result evidence can only add to it."""
    existing = _evidence(3)
    assert vm._union_evidence(existing, ()) == existing
    assert vm._union_evidence(existing, existing) == existing
    assert len(vm._union_evidence(existing, _evidence(5))) == 5
    assert set(existing) <= set(vm._union_evidence(existing, _evidence(5)))
    assert vm._union_evidence((), existing) == existing


def test_repeated_preserve_evidence_never_yields_fewer_refs_than_one() -> None:
    once = _program(
        [Instruction(Op.PRESERVE_EVIDENCE, 0), Instruction(Op.RETURN_STATE, 0)]
    )
    twice = _program(
        [
            Instruction(Op.PRESERVE_EVIDENCE, 0),
            Instruction(Op.PRESERVE_EVIDENCE, 0),
            Instruction(Op.RETURN_STATE, 0),
        ]
    )
    assert verify(twice).ok, verify(twice).failures
    frame = _frame(evidence=_evidence(4))
    machine = CellVM()
    first = machine.run(once, frame)
    second = machine.run(twice, frame)
    assert len(second.evidence) >= len(first.evidence) == 4
    assert set(frame.evidence) <= set(first.evidence)


def test_a_program_that_never_preserves_evidence_returns_no_evidence() -> None:
    """Silence, not fabrication: the VM never invents an evidence reference."""
    program = _program([Instruction(Op.LOAD_DELTA, 2), Instruction(Op.RETURN_RISK, 0)])
    assert CellVM().run(program, _frame()).evidence == ()


def test_raise_observation_emits_a_stage1_escalation_decision_not_a_new_type() -> None:
    program = _program(
        [
            Instruction(Op.SEEN_WITHIN, 0),
            Instruction(Op.RAISE_OBSERVATION, 2),
            Instruction(Op.LOAD_DELTA, 2),
            Instruction(Op.RETURN_RISK, 0),
        ]
    )
    result = CellVM().run(program, _frame())
    assert isinstance(result.escalation, EscalationDecision)
    assert result.escalation.level is ObservationLevel.HIGH_RESOLUTION
    assert result.escalation.escalated is False, "a cell requests; AOP grants"


def test_raise_observation_composes_by_maximum_requested_level() -> None:
    program = _program(
        [
            Instruction(Op.SEEN_WITHIN, 0),
            Instruction(Op.RAISE_OBSERVATION, 2),
            Instruction(Op.SEEN_WITHIN, 0),
            Instruction(Op.RAISE_OBSERVATION, 0),
            Instruction(Op.LOAD_DELTA, 2),
            Instruction(Op.RETURN_RISK, 0),
        ]
    )
    result = CellVM().run(program, _frame())
    assert result.escalation is not None
    assert result.escalation.level is ObservationLevel.HIGH_RESOLUTION


def test_a_false_guard_requests_no_escalation() -> None:
    program = _program(
        [
            Instruction(Op.SEEN_WITHIN, 1),  # window key 1 has count 0
            Instruction(Op.RAISE_OBSERVATION, 2),
            Instruction(Op.LOAD_DELTA, 2),
            Instruction(Op.RETURN_RISK, 0),
        ]
    )
    assert CellVM().run(program, _frame()).escalation is None


def test_in_set_reads_the_declared_set_literal() -> None:
    program = _program(
        [
            Instruction(Op.LOAD_REL, 0),  # relation_family -> INT
            Instruction(Op.IN_SET, 0),
            Instruction(Op.RETURN_RISK, 0),
        ],
        table={set_key(0, int(RelationFamily.EXECUTION)): 1.0},
    )
    report = verify(program)
    assert not report.ok, "RETURN_RISK wants FLOAT; IN_SET leaves a BOOL"
    assert "type_mismatch" in _codes(report)


def test_set_membership_drives_a_transition() -> None:
    program = _program(
        [
            Instruction(Op.LOAD_REL, 0),
            Instruction(Op.IN_SET, 0),
            Instruction(Op.TRANSITION, 1),  # trust
            Instruction(Op.PRESERVE_EVIDENCE, 0),
            Instruction(Op.RETURN_STATE, 0),
        ],
        table={set_key(0, int(RelationFamily.EXECUTION)): 1.0},
    )
    assert verify(program).ok, verify(program).failures
    result = CellVM().run(program, _frame())
    assert result.delta.raised == {"trust": (0, 1)}


def test_a_set_larger_than_max_set_members_is_refused() -> None:
    table = {set_key(0, member): 1.0 for member in range(isa.MAX_SET_MEMBERS + 1)}
    report = verify(_program([Instruction(Op.ABSTAIN, 0)], table=table))
    assert not report.ok
    assert "decode" in _codes(report)


# --- adversarial input --------------------------------------------------------


@pytest.mark.parametrize("word", [-1, 1 << 40, (len(Op) << 16), (Op.ABSTAIN << 16) | 7])
def test_adversarial_words_abstain_instead_of_executing(word: int) -> None:
    result = CellVM().run(_program(words=(word,)), _frame())
    assert result.abstained
    assert result.steps_taken == 0


def test_a_frame_with_a_missing_window_key_reads_zero_rather_than_raising() -> None:
    program = _program(
        [Instruction(Op.COUNT_WINDOW, 15), Instruction(Op.RETURN_RISK, 0)]
    )
    result = CellVM().run(program, _frame(window_counts={}))
    assert result.risk == 0.0
    assert not result.abstained


def test_running_the_same_vm_twice_does_not_leak_state_between_runs() -> None:
    machine = CellVM()
    raised = machine.run(_state_program(), _frame(phi=0.9))
    quiet = machine.run(_state_program(), _frame(phi=0.0))
    assert raised.delta.raised == {"privilege": (0, 1)}
    assert quiet.delta.raised == {}
    assert quiet.risk == pytest.approx(0.1)


# --- the proven / tested-only discipline -------------------------------------

#: Each PROVEN property, and the tests that would fail if the ISA gained the
#: capability the property denies. This mapping is itself asserted, so a
#: property cannot be added to PROVEN_PROPERTIES without naming its defence.
PROPERTY_DEFENCES: dict[int, tuple[str, ...]] = {
    0: (
        "test_isa_defines_no_opcode_that_moves_the_program_counter_backwards",
        "test_a_program_of_65_instructions_is_refused",
    ),
    1: (
        "test_isa_defines_no_opcode_that_moves_the_program_counter_backwards",
        "test_a_terminator_before_the_end_is_refused_so_there_is_no_dead_code",
    ),
    2: (
        "test_isa_defines_no_opcode_that_allocates_or_reaches_the_host",
        "test_a_program_whose_abstract_stack_exceeds_16_is_refused",
        "test_the_vm_peak_allocation_does_not_grow_with_the_number_of_events",
    ),
    3: (
        "test_a_type_mismatched_program_is_refused",
        "test_abstract_stack_depth_equals_the_depth_the_vm_actually_reaches",
    ),
    4: (
        "test_an_out_of_range_load_operand_is_refused",
        "test_every_indexed_opcode_range_checks_its_operand",
        "test_isa_defines_no_opcode_that_allocates_or_reaches_the_host",
    ),
}


def test_every_proven_property_is_defended_by_a_named_test() -> None:
    assert len(PROVEN_PROPERTIES) == 5
    assert set(PROPERTY_DEFENCES) == set(range(len(PROVEN_PROPERTIES)))
    module = globals()
    for index, names in PROPERTY_DEFENCES.items():
        assert names, f"PROVEN_PROPERTIES[{index}] has no defence"
        for name in names:
            assert callable(module.get(name)), f"missing defending test {name}"


def test_proven_properties_are_worded_as_statements_about_the_isa() -> None:
    """A proof is one sentence about the ISA. "No test broke it" is not one."""
    for text in PROVEN_PROPERTIES:
        lowered = text.lower()
        assert "empirical" not in lowered
        assert "no test" not in lowered
        assert any(
            token in lowered
            for token in (
                " isa ",
                "opcode",
                "statically",
                "straight-line",
                "abstract interpretation",
                "verification time",
            )
        ), text


def test_tested_only_properties_are_worded_as_empirical_claims() -> None:
    assert len(TESTED_ONLY_PROPERTIES) == 4
    for text in TESTED_ONLY_PROPERTIES:
        assert "empirical" in text.lower(), text


def test_proven_and_tested_only_sets_are_disjoint() -> None:
    assert not set(PROVEN_PROPERTIES) & set(TESTED_ONLY_PROPERTIES)
    assert set(ALL_PROVEN_PROPERTIES) == set(PROVEN_PROPERTIES) | set(
        STRUCTURAL_PROVEN_PROPERTIES
    )
    assert not set(STRUCTURAL_PROVEN_PROPERTIES) & set(PROVEN_PROPERTIES)


def test_a_failing_report_claims_nothing_at_all() -> None:
    """A refusal must not leave a proven-property list lying around for A5."""
    report = verify(_program([Instruction(Op.LOAD_DELTA, 2)]))
    assert not report.ok
    assert report.proven == ()
    assert report.tested_only == ()


def test_a_refused_program_hands_back_nothing_executable() -> None:
    """``verify_and_decode`` exists to save a redundant decode, not to leak one.

    If a failed verification still returned decoded instructions, a future
    caller could execute them while believing verification had run.
    """
    refused = verify_and_decode(_program([Instruction(Op.LOAD_DELTA, 2)]))
    assert not refused.report.ok
    assert refused.instructions == ()
    assert refused.constants == ()
    assert refused.sets == ()
    undecodable = verify_and_decode(_program(words=(1 << 40,)))
    assert undecodable.instructions == ()


def test_verify_and_decode_returns_the_same_verdict_as_verify() -> None:
    for program in (
        _state_program(),
        _program([Instruction(Op.LOAD_DELTA, 2)]),
        _program(form="LOOKUP_TABLE", table={"k": 1.0}, max_steps=1, max_state_bytes=0),
    ):
        assert verify_and_decode(program).report == verify(program)


def test_a_bytecode_report_never_claims_the_structural_property() -> None:
    report = verify(_state_program())
    assert report.ok
    assert report.proven == PROVEN_PROPERTIES
    assert set(report.proven).isdisjoint(STRUCTURAL_PROVEN_PROPERTIES)


# --- contract aliases and seam ------------------------------------------------


def test_the_contract_aliases_named_by_the_integration_plan_exist() -> None:
    assert CellISA is Op
    assert CellVerifier is verify
    assert PCB_VERSION == "pocketsec-cell-bytecode.1.0.0"
    assert vm.MAX_CELL_STEPS == MAX_INSTRUCTIONS


def test_cell_result_carries_a_state_delta_and_an_evidence_tuple() -> None:
    """Integration plan section 3.2 binds ``CellVM.run()`` to exactly this pair."""
    result = CellVM().run(_state_program(), _frame(phi=0.9))
    assert isinstance(result, CellResult)
    assert isinstance(result.delta, StateDelta)
    assert isinstance(result.evidence, tuple)
    assert all(isinstance(ref, EvidenceRef) for ref in result.evidence)
    assert isinstance(result.to_dict()["delta"], dict)


def test_operator_program_seam_fields_are_the_ones_read() -> None:
    """The verifier reads five attributes. Check the real type when it lands.

    ``OperatorProgram`` is built by the concurrent `foundation` package. Until
    it exists this asserts the test double; once it exists it asserts the real
    class, so the double cannot drift into a weaker contract.
    """
    try:
        from pocketsec.stage3.cells.operator import OperatorProgram as Real
    except ImportError:
        subject: Any = _Program
    else:
        subject = Real
    fields = set(getattr(subject, "__dataclass_fields__", {}))
    assert set(REQUIRED_PROGRAM_FIELDS) <= fields, sorted(fields)


def test_the_value_types_the_isa_declares_are_exactly_the_five_named() -> None:
    assert tuple(v.value for v in ValueType) == ("BOOL", "INT", "FLOAT", "SET", "EVIDENCE")


def test_state_slots_track_stage1_dimensions_so_an_operand_cannot_drift() -> None:
    assert STATE_SLOTS == tuple(DIMENSIONS)
    assert OPERAND_RANGE[Op.LOAD_STATE] == len(DIMENSIONS)
    assert OPERAND_RANGE[Op.TRANSITION] == len(DIMENSIONS)


def _codes(report: verifier.VerificationReport) -> tuple[str, ...]:
    return tuple(code for code, _detail in report.failures)


def test_a_non_canonical_pool_index_is_refused_rather_than_silently_dropped() -> None:
    """Pins S3-16: ``const.0`` and ``const.00`` resolved to the same slot.

    ``_positive_index`` accepted any digit string, so one of the two values won on
    the normalised table's iteration order and the other was dropped — while the
    density check ``sorted(found) == range(len(found))`` still passed, leaving
    ``LOAD_CONST``'s range check exact against a pool that had lost an entry.
    """
    from pocketsec.stage3.bytecode.isa import load_constants, load_sets

    assert load_constants({"const.0": 1.0, "const.1": 2.0}) == (1.0, 2.0)
    with pytest.raises(ContractError, match="non-canonically"):
        load_constants({"const.0": 1.0, "const.00": 2.0})
    with pytest.raises(ContractError, match="non-canonically"):
        load_sets({"set.0.0": 1.0, "set.00.0": 1.0})
    with pytest.raises(ContractError, match="malformed pool key"):
        load_constants({"const.٠": 1.0})


# --- D3.6 cost split: the producer for the two published ratios ---------------


def test_measure_vm_cost_produces_both_published_ratios() -> None:
    """Pins S3-FC-08: the two ratios had no producer in the repository.

    ``docs/stage-3-findings.md`` published ``run / _execute`` and
    ``run / handwritten`` in prose, cited ``verifier.py`` for a "2.9-4.9x band"
    that file does not report, and its own Corrections table said the fix was to
    land a producer here or withdraw the figures. This test pins the producer's
    contract; it asserts no timing value, because an absolute microsecond figure
    from this contended host is not a device measurement.
    """
    from pocketsec.stage3.bytecode.cost import (
        HANDWRITTEN_CONTROL_SOURCE,
        handwritten_clamp01,
        measure_vm_cost,
        phi_clamp_program,
    )
    from pocketsec.stage3.labs.crystal_corpus import build_crystal_corpus, session_frames

    corpus = build_crystal_corpus(count=8, seed=11)
    frames = tuple(f for s in corpus.sessions for f in session_frames(s))[:16]
    assert frames

    report = measure_vm_cost(frames, repetitions=2)
    payload = report.to_dict()

    assert report.frames == len(frames)
    for value in (report.run_us, report.interpreter_us, report.handwritten_us):
        assert value is not None and value > 0.0
    assert report.run_over_interpreter is not None and report.run_over_interpreter > 0.0
    assert report.run_over_handwritten is not None and report.run_over_handwritten > 0.0
    assert payload["control_source"] == HANDWRITTEN_CONTROL_SOURCE
    assert "not device measurements" in payload["note"]
    assert payload["loadavg"] and len(payload["loadavg"]) == 3

    # The control must compute the answer the program computes, or the ratio is
    # between two different questions.
    vm_answer = CellVM().run(phi_clamp_program(), frames[0])
    assert not vm_answer.abstained
    assert handwritten_clamp01(frames[0].delta_phi) == pytest.approx(float(vm_answer.risk))


def test_measure_vm_cost_refuses_to_time_what_it_cannot_verify() -> None:
    """An UNMEASURED cost is never a small number, and never a timed one."""
    from pocketsec.stage3.bytecode.cost import measure_vm_cost
    from pocketsec.stage3.labs.crystal_corpus import build_crystal_corpus, session_frames
    from pocketsec.stage3.cells.operator import OperatorForm, OperatorProgram

    corpus = build_crystal_corpus(count=8, seed=11)
    frames = tuple(f for s in corpus.sessions for f in session_frames(s))[:4]

    with pytest.raises(ContractError, match="at least one frame"):
        measure_vm_cost(())
    no_terminator = OperatorProgram(
        form=OperatorForm.BYTECODE,
        words=encode((Instruction(Op.LOAD_DELTA, 0),)),
        table={},
        max_steps=4,
        max_state_bytes=320,
    )
    with pytest.raises(ContractError, match="does not verify"):
        measure_vm_cost(frames, program=no_terminator, repetitions=1)
