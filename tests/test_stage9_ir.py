"""Stage 9 `ir` package: the typed IR, the seed alphabet and the phenotype interpreter.

Every test is named after the invariant it protects. The termination, memory and cost
properties are claimed BY CONSTRUCTION (spec §4.3), so these tests attack the constructors:
a loop, a recursion, an unbounded allocation and an understated cost must each be refused
or cut, with the code or the counted bound recorded.
"""

from __future__ import annotations

import ast
import dataclasses
import json
from pathlib import Path

import pytest

from pocketsec.stage1.state.security_state import DIMENSIONS
from pocketsec.stage2.encoder.ssir_encoder import FEATURE_WIDTH, EncodedTransition
from pocketsec.stage6.resources import WorkBudgetExceeded, WorkMeter
from pocketsec.stage9.chemistry.phenotype import (
    MAX_EVIDENCE_EVENTS,
    Phenotype,
    SessionAggregation,
    SessionInterventions,
)
from pocketsec.stage9.chemistry.typed_ir import (
    LINEAGE_OVERHEAD_BYTES,
    MAX_LINEAGES,
    MAX_SESSION_EVENTS,
    SIDE_ENTRY_BYTES,
    SIDE_TABLE_ENTRIES,
    VALUE_BYTES,
    InputSource,
    IRError,
    IRNode,
    IRProgram,
    IRType,
    NodeKind,
    ProgramPhase,
    RegisterSpec,
    quantise,
    static_bounds,
    validate_program,
)
from pocketsec.stage9.foundry.primitives import (
    SEED_ALPHABET,
    STATE_DELTA_BITS,
    MacroBody,
    Primitive,
    PrimitiveAlphabet,
    PrimitiveOrigin,
)

FT, IT, BT = IRType.FLOAT, IRType.INT, IRType.BOOL
REPO = Path(__file__).resolve().parents[1]
IR_MODULES = (
    REPO / "pocketsec/stage9/chemistry/typed_ir.py",
    REPO / "pocketsec/stage9/chemistry/phenotype.py",
    REPO / "pocketsec/stage9/foundry/primitives.py",
)


# --- builders -------------------------------------------------------------------------


def reg(index: int = 0, type_: IRType = FT, lag: int = 0) -> IRNode:
    return IRNode(NodeKind.REG, type_, index=index, lag=lag)


def inp(source: InputSource, index: int = 0) -> IRNode:
    types = {
        InputSource.FEATURE: FT, InputSource.DELTA_PHI: FT, InputSource.LINEAGE_FIRST_EVENT: BT,
    }
    return IRNode(NodeKind.INPUT, types.get(source, IT), source=source, index=index)


def const(value: float | int | bool, type_: IRType = FT) -> IRNode:
    return IRNode(NodeKind.CONST, type_, value=value)


def app(name: str, type_: IRType, *args: int) -> IRNode:
    return IRNode(NodeKind.APPLY, type_, primitive=name, args=args)


def update(*nodes: IRNode, outputs: tuple[int, ...] | None = None) -> IRProgram:
    return IRProgram(ProgramPhase.UPDATE, nodes, outputs or (len(nodes) - 1,))


def readout(*nodes: IRNode) -> IRProgram:
    return IRProgram(ProgramPhase.READOUT, nodes, (len(nodes) - 1,))


def event(slot: int = 0, *, phi: float = 0.0, relation: int = 0, mask: int = 0,
          evidence: tuple[str, ...] = ()) -> EncodedTransition:
    features = [0.0] * FEATURE_WIDTH
    features[73] = phi
    return EncodedTransition(
        features=tuple(features), relation=relation, relation_family=0, state_delta_mask=mask,
        time_bucket=0, delta_phi=phi, object_property_mask=0, epoch_id=0, actor_slot=slot,
        evidence=evidence,
    )


PHI_UPDATE = update(reg(), inp(InputSource.FEATURE, 73), app("MAX", FT, 0, 1))
REG_READOUT = readout(reg())


def phi_phenotype(**kwargs: object) -> Phenotype:
    """The Φ-oracle: per-lineage max of features[73], MAX over lineages (3 WU/event)."""
    options: dict[str, object] = {
        "update": PHI_UPDATE, "readout": REG_READOUT, "registers": (RegisterSpec(FT),),
        "aggregation": SessionAggregation.MAX,
    }
    options.update(kwargs)
    return Phenotype(**options)  # type: ignore[arg-type]


def codes_of(error: pytest.ExceptionInfo[IRError]) -> str:
    return str(error.value.code)


# --- termination: loops and recursion are unconstructible ------------------------------


def test_a_loop_written_as_a_self_reference_is_refused_with_SELF_REFERENCE() -> None:
    with pytest.raises(IRError) as error:
        update(reg(), app("ADD", FT, 0, 1))
    assert codes_of(error) == "SELF_REFERENCE"


def test_a_loop_written_as_a_forward_reference_is_refused_with_FORWARD_REFERENCE() -> None:
    with pytest.raises(IRError) as error:
        update(reg(), app("ADD", FT, 0, 2), const(1.0), outputs=(1,))
    assert codes_of(error) == "FORWARD_REFERENCE"


def test_tampering_a_valid_program_into_a_loop_is_refused_on_replace() -> None:
    program = update(reg(), const(1.0), app("ADD", FT, 0, 1))
    looped = dataclasses.replace(program.nodes[2], args=(0, 2))
    with pytest.raises(IRError) as error:
        dataclasses.replace(program, nodes=(*program.nodes[:2], looped))
    assert codes_of(error) == "SELF_REFERENCE"


def test_node_kinds_have_no_jump_loop_or_call_member() -> None:
    assert {kind.value for kind in NodeKind} == {"INPUT", "CONST", "REG", "APPLY", "PARAM"}


def _add_body(first: str = "ADD") -> MacroBody:
    return MacroBody(
        params=(FT, FT),
        nodes=(IRNode(NodeKind.PARAM, FT, index=0), IRNode(NodeKind.PARAM, FT, index=1),
               app(first, FT, 0, 1)),
        output=2,
    )


def test_a_self_referencing_macro_is_refused_with_MACRO_CYCLE() -> None:
    with pytest.raises(IRError) as error:
        SEED_ALPHABET.with_macro("LOOPY", _add_body("LOOPY"))
    assert codes_of(error) == "MACRO_CYCLE"


def test_a_hand_built_alphabet_cannot_bypass_the_macro_cycle_check() -> None:
    rogue = Primitive(name="LOOPY", arg_types=(FT, FT), result_type=FT, work_units=1,
                      side_table=False, fn=lambda x, y: x, origin=PrimitiveOrigin.PROMOTED,
                      macro=_add_body("LOOPY"))
    with pytest.raises(IRError) as error:
        PrimitiveAlphabet((*SEED_ALPHABET, rogue))
    assert codes_of(error) == "MACRO_CYCLE"


def test_a_macro_nested_beyond_depth_two_is_refused_with_MACRO_DEPTH() -> None:
    depth1 = SEED_ALPHABET.with_macro("M1", _add_body("ADD"))
    depth2 = depth1.with_macro("M2", _add_body("M1"))
    assert (depth2.depth("M1"), depth2.depth("M2")) == (1, 2)
    with pytest.raises(IRError) as error:
        depth2.with_macro("M3", _add_body("M2"))
    assert codes_of(error) == "MACRO_DEPTH"


def test_a_macro_body_above_the_node_cap_is_refused_with_MACRO_SIZE() -> None:
    nodes = (IRNode(NodeKind.PARAM, FT, index=0), *(app("ABS", FT, i) for i in range(8)))
    with pytest.raises(IRError) as error:
        MacroBody(params=(FT,), nodes=nodes, output=8)
    assert codes_of(error) == "MACRO_SIZE"


def test_with_macro_leaves_the_receiver_alphabet_unchanged() -> None:
    before_digest, before_names = SEED_ALPHABET.digest, SEED_ALPHABET.names()
    grown = SEED_ALPHABET.with_macro("M1", _add_body())
    assert SEED_ALPHABET.digest == before_digest
    assert SEED_ALPHABET.names() == before_names and "M1" not in SEED_ALPHABET
    assert grown.digest != before_digest and "M1" in grown
    with pytest.raises(AttributeError):
        SEED_ALPHABET._primitives = {}


def test_expand_inlines_macros_with_identical_semantics_and_cost() -> None:
    grown = SEED_ALPHABET.with_macro("M1", _add_body())
    assert grown.get("M1").work_units == 1 and grown.get("M1").fn(1.5, 2.0) == 3.5
    with_macro = update(reg(), inp(InputSource.FEATURE, 73), app("M1", FT, 0, 1))
    expanded = grown.expand(with_macro)
    assert [n.primitive for n in expanded.nodes if n.kind is NodeKind.APPLY] == ["ADD"]
    macro_run = Phenotype(update=with_macro, readout=REG_READOUT, registers=(RegisterSpec(FT),),
                          aggregation=SessionAggregation.MAX, alphabet=grown)
    seed_run = Phenotype(update=expanded, readout=REG_READOUT, registers=(RegisterSpec(FT),),
                         aggregation=SessionAggregation.MAX)
    session = [event(0, phi=0.25), event(0, phi=0.5)]
    assert macro_run.run_session(session) == seed_run.run_session(session)
    assert macro_run.digest == seed_run.digest
    assert macro_run.bounds == seed_run.bounds


# --- bounded memory ---------------------------------------------------------------------


def test_a_ring_of_a_million_is_refused_with_RING_BOUND() -> None:
    with pytest.raises(IRError) as error:
        RegisterSpec(FT, ring=10**6)
    assert codes_of(error) == "RING_BOUND"


def test_a_64_lineage_session_keeps_at_most_16_lineages_and_counts_48_evictions() -> None:
    phenotype = phi_phenotype()
    # Slot 0 carries the session maximum and is the FIRST lineage evicted: the score is
    # right only if an evicted lineage's readout is folded into the aggregate.
    session = [event(slot, phi=0.9 if slot == 0 else 0.01) for slot in range(64)]
    run = phenotype.run_session(session)
    assert (run.lineages, run.lineage_evictions) == (MAX_LINEAGES, 48)
    assert run.score == 0.9
    bounds = phenotype.bounds
    assert run.work_units == 64 * bounds.update_wu_per_event + 64 * bounds.readout_wu_per_lineage
    assert run.state_bytes_peak <= bounds.session_state_bytes_max
    assert run.state_bytes_peak == MAX_LINEAGES * bounds.state_bytes_per_lineage + 4 * VALUE_BYTES


def test_an_evicted_lineage_restarts_from_init_when_it_reappears() -> None:
    counter = update(reg(), inp(InputSource.LINEAGE_FIRST_EVENT), app("B2F", FT, 1),
                     const(1.0), app("ADD", FT, 0, 3))
    phenotype = Phenotype(update=counter, readout=REG_READOUT, registers=(RegisterSpec(FT),),
                          aggregation=SessionAggregation.SUM)
    session = [event(0), event(0), *(event(s) for s in range(1, 17)), event(0)]
    run = phenotype.run_session(session)
    # folded: slot0=2, slot1=1; live: slots 2..16 (15 x 1) + restarted slot0=1  -> 19.
    # Were state kept across the eviction, slot0 would end at 3 and the sum at 21.
    assert run.lineage_evictions == 2 and run.score == 19.0


def test_side_tables_are_bounded_and_their_evictions_counted() -> None:
    distinct = update(reg(), inp(InputSource.RELATION), app("FIRST_SEEN", BT, 1),
                      app("COUNT", FT, 2, 0))
    phenotype = Phenotype(update=distinct, readout=REG_READOUT, registers=(RegisterSpec(FT),),
                          aggregation=SessionAggregation.MAX)
    run = phenotype.run_session([event(0, relation=r) for r in range(300)] + [event(0, relation=0)])
    # 300 distinct keys overflow 256 slots by 44; key 0 was among them, so it reads as new
    # again and its re-insertion evicts one more. The flood costs recall, never memory.
    assert run.side_table_evictions == 300 - SIDE_TABLE_ENTRIES + 1
    assert run.score == 301.0
    assert run.state_bytes_peak <= phenotype.bounds.session_state_bytes_max
    assert phenotype.bounds.session_state_bytes_max == (
        MAX_LINEAGES * (VALUE_BYTES + LINEAGE_OVERHEAD_BYTES)
        + SIDE_TABLE_ENTRIES * SIDE_ENTRY_BYTES + (4 + 1) * VALUE_BYTES
    )


def test_events_beyond_the_session_cap_are_counted_and_never_processed() -> None:
    """Pins S9-FC-02 / S9-CX-01 / S9-BOUND-01: a session over the cap fails CLOSED.

    It used to score the first MAX_SESSION_EVENTS events and return 0.1 here: 4096 cheap
    events hid the four 0.99 events behind an ordinary, confident score. Now it abstains
    with no work done and the overflow counted, as the successor contract's ABSTAIN_UNKNOWN
    says; a session exactly at the cap is still scored in full.
    """
    session = [event(0, phi=0.1)] * MAX_SESSION_EVENTS + [event(0, phi=0.99)] * 4
    run = phi_phenotype().run_session(session)
    assert run.score is None  # abstained: never a prefix score
    assert (run.events, run.truncated_events, run.work_units) == (0, 4, 0)
    at_cap = [event(0, phi=0.1)] * (MAX_SESSION_EVENTS - 1) + [event(0, phi=0.99)]
    full = phi_phenotype().run_session(at_cap)
    assert full.score == 0.99 and full.truncated_events == 0
    assert (full.events, full.work_units) == (MAX_SESSION_EVENTS, MAX_SESSION_EVENTS * 3 + 1)


# --- exact static cost and the meter ---------------------------------------------------


def test_work_units_equal_the_static_bound_exactly(ambiguous20: object) -> None:
    phenotype = phi_phenotype()
    meter = WorkMeter()
    runs = phenotype.run_dataset(ambiguous20, meter=meter)  # type: ignore[arg-type]
    bounds = phenotype.bounds
    for run in runs:
        readouts = run.lineages + run.lineage_evictions
        assert run.work_units == (
            run.events * bounds.update_wu_per_event + readouts * bounds.readout_wu_per_lineage
        )
        assert run.work_units <= bounds.session_wu_max
        assert run.state_bytes_peak <= bounds.session_state_bytes_max
    assert meter.spent == sum(run.work_units for run in runs)
    assert (bounds.update_wu_per_event, bounds.readout_wu_per_lineage) == (3, 1)


def test_static_bounds_sum_node_work_units_by_kind() -> None:
    program = update(reg(), inp(InputSource.RELATION), app("HASH", IT, 1), app("RARE", FT, 2),
                     const(0.5), app("DECAY", FT, 0, 3, 4))
    bounds = static_bounds(program, REG_READOUT, (RegisterSpec(FT, ring=3),), SEED_ALPHABET)
    assert bounds.update_wu_per_event == 1 + 1 + 2 + 4 + 0 + 2
    assert bounds.max_steps_per_event == 6
    assert bounds.state_bytes_per_lineage == 3 * VALUE_BYTES + LINEAGE_OVERHEAD_BYTES


def test_a_meter_below_the_need_raises_before_any_score_is_produced() -> None:
    phenotype = phi_phenotype()
    session = [event(slot, phi=0.1 * slot) for slot in range(4)]
    need = phenotype.run_session(session).work_units
    starved = WorkMeter(budget=len(session) * 3 - 1)
    with pytest.raises(WorkBudgetExceeded):
        phenotype.run_session(session, meter=starved)
    assert starved.spent == 0  # refused up front: no event was run unpaid
    short_of_one_readout = WorkMeter(budget=need - 1)
    with pytest.raises(WorkBudgetExceeded):
        phenotype.run_session(session, meter=short_of_one_readout)
    assert short_of_one_readout.spent == need - 1
    exact = WorkMeter(budget=need)
    assert phenotype.run_session(session, meter=exact).score == pytest.approx(0.3)


# --- abstention, determinism, precision -----------------------------------------------


def test_a_session_below_min_events_abstains_and_costs_nothing() -> None:
    phenotype = phi_phenotype(min_events_for_score=5)
    meter = WorkMeter()
    run = phenotype.run_session([event(0, phi=0.9)] * 3, meter=meter)
    assert run.score is None and run.work_units == 0 and meter.spent == 0
    assert phenotype.run_session([event(0, phi=0.9)] * 5).score == 0.9
    assert phi_phenotype().run_session([]).score is None


def test_two_runs_produce_byte_identical_outputs(ambiguous20: object) -> None:
    def dump() -> str:
        runs = phi_phenotype().run_dataset(ambiguous20)  # type: ignore[arg-type]
        return json.dumps([dataclasses.asdict(run) for run in runs], sort_keys=True)

    assert dump() == dump()
    assert phi_phenotype().digest == phi_phenotype().digest


def test_quantise_rounds_half_to_even_on_the_significand() -> None:
    assert quantise(1.25, 2) == 1.0 and quantise(1.75, 2) == 2.0  # both ties, to even
    assert quantise(1.3, 2) == 1.5 and quantise(0.1, 64) == 0.1
    assert RegisterSpec(FT, precision_bits=2, init=1.3).init == 1.5


def test_precision_quantisation_reduces_state_distinguishability() -> None:
    sessions = [[event(0, phi=0.5 + 0.01 * k)] for k in range(40)]

    def distinct(bits: int) -> int:
        phenotype = phi_phenotype(registers=(RegisterSpec(FT, precision_bits=bits),))
        return len({phenotype.run_session(s).score for s in sessions})

    counts = {bits: distinct(bits) for bits in (1, 2, 4, 8, 64)}
    assert counts[64] == 40
    assert counts[1] < counts[2] < counts[4] < counts[8] <= counts[64]
    assert counts[1] == 2  # 0.5 and 1.0 are the only one-bit values in [0.5, 0.9)


def test_precision_bits_outside_one_to_64_are_refused() -> None:
    for bits in (0, 65):
        with pytest.raises(IRError) as error:
            RegisterSpec(FT, precision_bits=bits)
        assert codes_of(error) == "PRECISION_BOUND"


# --- lineage semantics: ties, evidence, interventions -----------------------------------


def test_max_ties_go_to_the_lowest_actor_slot_and_evidence_follows_the_winner() -> None:
    session = [event(3, phi=0.5, evidence=("slot3",)), event(1, phi=0.5, evidence=("slot1",))]
    run = phi_phenotype().run_session(session)
    assert run.score == 0.5 and run.evidence == ("slot1",)


def test_evidence_holds_at_most_eight_recent_events_that_changed_the_winner() -> None:
    rising = [event(0, phi=0.05 * k, evidence=(f"e{k}",)) for k in range(1, 13)]
    flat = [event(0, phi=0.01, evidence=("unchanged",))]
    run = phi_phenotype().run_session(rising + flat)
    assert run.evidence == tuple(f"e{k}" for k in range(5, 13))
    assert len(run.evidence) == MAX_EVIDENCE_EVENTS


def test_state_reset_and_forget_interventions_change_the_outcome() -> None:
    session = [event(0, phi=0.9), event(0, phi=0.1), event(1, phi=0.2)]
    phenotype = phi_phenotype()
    assert phenotype.run_session(session).score == 0.9
    reset = SessionInterventions(reset_at=1)
    assert phenotype.run_session(session, interventions=reset).score == 0.2
    forget_zero = SessionInterventions(forget=((1, 0),))
    assert phenotype.run_session(session, interventions=forget_zero).score == 0.2
    forget_all = SessionInterventions(forget=((3, 0), (3, 1)))
    assert phenotype.run_session(session, interventions=forget_all).score is None


# --- the seed alphabet --------------------------------------------------------------------

PINNED_SIGNATURES = {
    "ADD": ("FF", "F", 1), "SUB": ("FF", "F", 1), "MUL": ("FF", "F", 1), "MIN": ("FF", "F", 1),
    "MAX": ("FF", "F", 1), "DIV": ("FF", "F", 2), "ABS": ("F", "F", 1), "CLIP01": ("F", "F", 1),
    "LT": ("FF", "B", 1), "GT": ("FF", "B", 1), "EQ_I": ("II", "B", 1),
    "SELECT": ("BFF", "F", 1), "B2F": ("B", "F", 1), "AND": ("II", "I", 1),
    "OR": ("II", "I", 1), "XOR": ("II", "I", 1), "NOT": ("I", "I", 1), "SHIFT": ("II", "I", 1),
    "POPCOUNT": ("I", "F", 1), "HASH": ("I", "I", 2), "LOOKUP": ("I", "F", 2),
    "COUNT": ("BF", "F", 1), "DECAY": ("FFF", "F", 2), "BIND": ("II", "I", 1),
    "GRAPH_EDGE": ("II", "I", 1), "STATE_DELTA": ("II", "B", 1),
    "TEMPORAL_WITHIN": ("III", "B", 1), "FIRST_SEEN": ("I", "B", 4), "RARE": ("I", "F", 4),
}
_T = {"F": FT, "I": IT, "B": BT}

# (primitive, arguments, expected result): the spec §4.4 semantics table, case by case.
SEMANTICS: tuple[tuple[str, tuple[Literal, ...], Literal], ...] = (
    ("ADD", (1.5, 2.0), 3.5), ("ADD", (9e11, 9e11), 1e12), ("SUB", (1.0, 3.0), -2.0),
    ("MUL", (2.0, -3.0), -6.0), ("MUL", (1e12, -1e12), -1e12), ("MIN", (1.0, -1.0), -1.0),
    ("MAX", (1.0, -1.0), 1.0), ("DIV", (1.0, 4.0), 0.25), ("DIV", (5.0, 0.0), 0.0),
    ("ABS", (-2.5,), 2.5), ("CLIP01", (1.7,), 1.0), ("CLIP01", (-0.3,), 0.0),
    ("CLIP01", (0.4,), 0.4), ("LT", (1.0, 2.0), True), ("GT", (1.0, 2.0), False),
    ("EQ_I", (7, 7), True), ("EQ_I", (7, 8), False), ("SELECT", (True, 1.0, 2.0), 1.0),
    ("SELECT", (False, 1.0, 2.0), 2.0), ("B2F", (True,), 1.0), ("B2F", (False,), 0.0),
    ("AND", (0b1100, 0b1010), 0b1000), ("OR", (0b1100, 0b1010), 0b1110),
    ("XOR", (0b1100, 0b1010), 0b0110), ("NOT", (0,), (1 << 64) - 1),
    ("SHIFT", (1, 65), 2), ("SHIFT", (1 << 63, 1), 0), ("POPCOUNT", (0b1011,), 3.0),
    ("HASH", (1,), 2654435761 & 0xFFFF), ("COUNT", (True, 2.0), 3.0),
    ("COUNT", (False, 2.0), 2.0), ("DECAY", (10.0, 1.0, 0.5), 6.0),
    ("DECAY", (10.0, 1.0, 7.0), 11.0), ("BIND", (0, 1 << 63), 1), ("BIND", (4, 1), 6),
    ("GRAPH_EDGE", (0x1FF, 0x2AB), 0xFFAB), ("STATE_DELTA", (0b10, 10), True),
    ("STATE_DELTA", (0b10, 0), False), ("TEMPORAL_WITHIN", (5, 9, 4), True),
    ("TEMPORAL_WITHIN", (5, 10, 4), False),
)


def test_the_seed_alphabet_is_the_spec_table_exactly_and_has_no_SUPERPOSE() -> None:
    assert "SUPERPOSE" not in SEED_ALPHABET
    # The spec prose says 26; its own table lists these 29. Pinned so a silent add, drop
    # or signature change fails here.
    assert len(SEED_ALPHABET) == 29
    for name, (args, result, wu) in PINNED_SIGNATURES.items():
        primitive = SEED_ALPHABET.get(name)
        assert primitive.arg_types == tuple(_T[c] for c in args), name
        assert (primitive.result_type, primitive.work_units) == (_T[result], wu), name
        assert primitive.side_table == (name in {"FIRST_SEEN", "RARE"}), name
    assert set(SEED_ALPHABET.names()) == set(PINNED_SIGNATURES)
    assert len(DIMENSIONS) == STATE_DELTA_BITS


def test_div_by_zero_returns_zero() -> None:
    div = SEED_ALPHABET.get("DIV").fn
    assert div(3.0, 0.0) == 0.0 and div(-3.0, -0.0) == 0.0 and div(0.0, 0.0) == 0.0
    safe = update(reg(), inp(InputSource.DELTA_PHI), const(0.0), app("DIV", FT, 1, 2))
    phenotype = Phenotype(update=safe, readout=REG_READOUT, registers=(RegisterSpec(FT),),
                          aggregation=SessionAggregation.MAX)
    assert phenotype.run_session([event(0, phi=5.0)]).score == 0.0


Literal = float | int | bool


def _probe(name: str, args: tuple[Literal, ...], expected: Literal) -> float | None:
    """Run one primitive through the interpreter: CONST args -> APPLY -> typed register."""
    primitive = SEED_ALPHABET.get(name)
    nodes = [const(value, type_) for value, type_ in zip(args, primitive.arg_types, strict=True)]
    nodes.append(app(name, primitive.result_type, *range(len(args))))
    result = primitive.result_type
    if result is FT:
        out = readout(reg(0, FT))
    elif result is BT:
        out = readout(reg(0, BT), app("B2F", FT, 0))
    else:
        out = readout(reg(0, IT), const(expected, IT), app("EQ_I", BT, 0, 1), app("B2F", FT, 2))
    phenotype = Phenotype(update=update(*nodes), readout=out, registers=(RegisterSpec(result),),
                          aggregation=SessionAggregation.MAX)
    return phenotype.run_session([event(0)]).score


def _stateful_probes() -> dict[str, float | None]:
    rel = inp(InputSource.RELATION)
    lookup = Phenotype(update=update(reg(), rel, app("LOOKUP", FT, 1)), readout=REG_READOUT,
                       registers=(RegisterSpec(FT),), aggregation=SessionAggregation.MAX,
                       lookup_table=(0.5, 0.25, 0.125))
    rare = Phenotype(update=update(reg(), rel, app("RARE", FT, 1), app("ADD", FT, 0, 2)),
                     readout=REG_READOUT, registers=(RegisterSpec(FT),),
                     aggregation=SessionAggregation.MAX)
    seen = Phenotype(update=update(reg(), rel, app("FIRST_SEEN", BT, 1), app("COUNT", FT, 2, 0)),
                     readout=REG_READOUT, registers=(RegisterSpec(FT),),
                     aggregation=SessionAggregation.MAX)
    return {
        "LOOKUP": lookup.run_session([event(0, relation=4)]).score,
        "RARE": rare.run_session([event(0, relation=5)] * 3).score,
        "FIRST_SEEN": seen.run_session([event(0, relation=r) for r in (7, 7, 3, 7, 3, 9)]).score,
    }


def test_every_seed_primitive_fires_and_matches_its_semantics_table() -> None:
    fired: set[str] = set()
    for name, args, expected in SEMANTICS:
        direct = SEED_ALPHABET.get(name).fn(*args)
        assert direct == expected, (name, args, direct)
        via_interpreter = _probe(name, args, expected)
        wanted = float(expected) if SEED_ALPHABET.get(name).result_type is not IT else 1.0
        assert via_interpreter == wanted, (name, args, via_interpreter)
        fired.add(name)
    stateful = _stateful_probes()
    assert stateful == {"LOOKUP": 0.25, "RARE": 1.0 + 0.5 + 1.0 / 3.0, "FIRST_SEEN": 3.0}
    fired.update(stateful)
    assert SEED_ALPHABET.get("LOOKUP").fn((), 5) == 0.0  # empty table
    assert fired == set(SEED_ALPHABET.names()), sorted(set(SEED_ALPHABET.names()) - fired)


# --- every IR refusal code a constructor or validator can raise --------------------------


def _validate(program: IRProgram, registers: tuple[RegisterSpec, ...] | None = None) -> None:
    validate_program(program, registers or (RegisterSpec(FT),), SEED_ALPHABET)


REFUSALS = (
    ("TYPE_MISMATCH", lambda: _validate(update(reg(), inp(InputSource.RELATION),
                                               app("ADD", FT, 0, 1)))),
    ("UNKNOWN_PRIMITIVE", lambda: _validate(update(reg(), app("SUPERPOSE", FT, 0)))),
    ("ARITY", lambda: _validate(update(reg(), app("ADD", FT, 0)))),
    ("FEATURE_INDEX", lambda: inp(InputSource.FEATURE, FEATURE_WIDTH)),
    ("INPUT_IN_READOUT", lambda: readout(inp(InputSource.DELTA_PHI))),
    ("PARAM_OUTSIDE_MACRO", lambda: update(IRNode(NodeKind.PARAM, FT, index=0))),
    ("NODE_BOUND", lambda: update(*([const(1.0)] * 33))),
    ("REGISTER_BOUND", lambda: _validate(PHI_UPDATE, (RegisterSpec(FT),) * 9)),
    ("OUTPUT_COUNT", lambda: _validate(PHI_UPDATE, (RegisterSpec(FT),) * 2)),
    ("OUTPUT_TYPE", lambda: readout(const(1, IT))),
    ("OUTPUT_TYPE", lambda: _validate(update(inp(InputSource.DELTA_PHI)), (RegisterSpec(IT),))),
    ("TYPE_MISMATCH", lambda: _validate(PHI_UPDATE, (RegisterSpec(IT),))),
    ("LAG_BOUND", lambda: _validate(update(reg(0, FT, lag=1)))),
    ("LOOKUP_BOUND", lambda: phi_phenotype(lookup_table=(0.0,) * 33)),
    ("TYPE_MISMATCH", lambda: const(float("nan"))),
)


@pytest.mark.parametrize(("code", "build"), REFUSALS)
def test_ill_typed_programs_are_refused_with_their_code(code: str, build: object) -> None:
    with pytest.raises(IRError) as error:
        build()  # type: ignore[operator]
    assert codes_of(error) == code


def test_programs_round_trip_through_their_canonical_json() -> None:
    program = update(reg(), inp(InputSource.FEATURE, 73), const(2), app("MAX", FT, 0, 1))
    assert program.nodes[2].value == 2.0 and isinstance(program.nodes[2].value, float)
    assert IRProgram.from_dict(json.loads(json.dumps(program.to_dict()))) == program
    spec = RegisterSpec(FT, ring=3, precision_bits=8, init=0.5)
    assert RegisterSpec.from_dict(spec.to_dict()) == spec
    with pytest.raises(Exception, match="exactly"):
        IRProgram.from_dict({**program.to_dict(), "extra": 1})


def test_the_ir_modules_contain_no_dynamic_execution() -> None:
    banned = {"eval", "exec", "compile", "__import__"}
    for path in IR_MODULES:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
        imported = {
            alias.name for node in ast.walk(tree)
            if isinstance(node, (ast.Import, ast.ImportFrom)) for alias in node.names
        }
        assert not names & banned, (path.name, names & banned)
        assert not imported & {"pickle", "marshal", "subprocess", "socket", "importlib"}
        assert len(path.read_text(encoding="utf-8").splitlines()) < 800


# --- real encodings --------------------------------------------------------------------


@pytest.fixture(scope="module")
def ambiguous20() -> object:
    from pocketsec.stage2.gate_measures import compile_split

    return compile_split("ambiguous", count=20, seed=11).dataset


def test_the_phi_oracle_program_reproduces_max_feature_73_on_a_real_split(
    ambiguous20: object,
) -> None:
    runs = phi_phenotype().run_dataset(ambiguous20)  # type: ignore[arg-type]
    reference = [max(step.features[73] for step in sample.steps)
                 for sample in ambiguous20.samples]  # type: ignore[attr-defined]
    assert [run.score for run in runs] == reference
    assert any(run.evidence for run in runs)
