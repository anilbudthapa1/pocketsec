"""D9.3 (state half) — LAPLACE state discovery: how much state does a genome actually need?

The architecture's state objective (§6) is ``S* = argmin_S Cost(S)`` *subject to predictive
security sufficiency and counterfactual preservation*: a candidate state is rejected if the
compression hides a distinction that changes a security outcome. This module turns that
sentence into four measurements over a genome's registers:

* :func:`state_sufficiency` (S9X-005) freezes each register at its ``init`` value and counts
  the security **decisions** that flip. A register whose freezing flips nothing is not part
  of the sufficient state, whatever its AP delta says.
* :func:`precision_sweep` (S9X-002..004) re-quantises every FLOAT register to 1..64
  significand bits, so binary, integer-like and hybrid precision are all points on one curve.
* :func:`state_dimension_sweep` reads the search records back as "best worst-case AP per
  register count", the empirical answer to "how many dimensions does this job need".
* :func:`discover_minimal_state` greedily removes registers whose removal flips no TRAIN
  decision, then verifies the result on the held-out suite and reports registers whose
  value sequences are identical (S9X-006, identifiability).

A *decision* is ``score >= threshold`` with the threshold fitted ONCE on the full genome's
clean TRAIN scores at a false-positive budget of :data:`DECISION_FPR_BUDGET` (spec §4.21).
It is never re-fitted for the ablated genome: re-fitting would let a register that merely
rescales the score look irrelevant, and the question is whether the same decision rule
still reaches the same outcomes without that state. An abstained score ranks as ``0.0``,
the convention :mod:`pocketsec.stage9.ontogenesis.fitness` uses for AP.

What this module refuses to do: it never edits a genome in place (every ablation is a NEW
genome built through :func:`build_genome`, so it is re-validated against the typed IR), it
never removes a register whose removal flips a train decision, and it never reports a
precision point without the genome that produced it (gate G9.3 runs semantic-conservation
tests on exactly those genomes). The program-surgery helpers here (:func:`freeze_register`,
:func:`remove_register`, :func:`prune_program`) are shared with CHRONOS and the primitive
promotion gate so all three ablate genomes the same way.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace

from pocketsec.stage0.benchmark.security_metrics import average_precision, recall_at_max_fpr
from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage2.dataset import Stage2Dataset
from pocketsec.stage6.resources import WorkMeter
from pocketsec.stage9.chemistry.phenotype import SessionAggregation
from pocketsec.stage9.chemistry.typed_ir import (
    MAX_LINEAGES,
    VALUE_BYTES,
    IRNode,
    IRProgram,
    IRType,
    NodeKind,
    ProgramPhase,
    RegisterSpec,
    coerce_value,
)
from pocketsec.stage9.genome.computational import ComputationalGenomeV1, build_genome
from pocketsec.stage9.ontogenesis.fitness import (
    EvaluationSuite,
    FitnessRecord,
    evaluate,
    session_scores,
)

__all__ = [
    "DECISION_FPR_BUDGET",
    "PRECISION_LEVELS",
    "DiscoveredState",
    "PrecisionPoint",
    "StateAblation",
    "decisions",
    "discover_minimal_state",
    "fit_threshold",
    "freeze_register",
    "packed_state_bytes",
    "precision_sweep",
    "prune_program",
    "rebuild",
    "remove_register",
    "replace_nodes",
    "state_dimension_sweep",
    "state_sufficiency",
    "suite_scores",
]

#: Every decision threshold in Stage 9 is fitted at this false-positive budget on train
#: (spec §4.21). Chosen, not measured.
DECISION_FPR_BUDGET = 0.05

#: The precision levels the sweep visits, in significand bits (spec §4.14).
PRECISION_LEVELS: tuple[int, ...] = (1, 2, 4, 8, 16, 32, 64)

#: A double's sign + exponent bits; a packed FLOAT of ``b`` significand bits needs these too.
_FLOAT_OVERHEAD_BITS = 12
#: A double stores 52 explicit significand bits; more precision than that costs nothing.
_MAX_EXPLICIT_SIGNIFICAND = 52


# --- result types ----------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class StateAblation:
    """One register frozen at ``init``: what it cost in AP and in decisions (S9X-005)."""

    register: int
    ap_full: float | None  # worst-case AP over the suite, full genome
    ap_without: float | None  # worst-case AP with the register frozen at init
    decisions_flipped: int  # sessions (over clean + attacked variants) whose decision changed
    sessions: int  # sessions examined
    unique_utility: float | None  # ap_full - ap_without (architecture §33)


@dataclass(frozen=True, slots=True)
class PrecisionPoint:
    """One precision level. ``genome`` is REQUIRED: gate G9.3 tests this exact abstraction."""

    bits: int
    ap: float | None
    state_bytes: int  # packed session bytes, see :func:`packed_state_bytes`
    genome: ComputationalGenomeV1


@dataclass(frozen=True, slots=True)
class DiscoveredState:
    """The smallest register set that reproduces every train decision, verified held-out."""

    genome_digest: str  # the genome the discovery started from
    minimal_genome: ComputationalGenomeV1
    registers_kept: tuple[int, ...]  # indices into the ORIGINAL genome's registers
    removed: tuple[int, ...]
    state_bytes: int  # minimal_genome.bounds.session_state_bytes_max
    heldout_worst_case_ap: float | None
    redundant_pairs: tuple[tuple[int, int], ...]  # identical value sequences (S9X-006)
    reason: str


# --- decisions -----------------------------------------------------------------------------


def _ranked(scores: Sequence[float | None]) -> list[float]:
    """An abstained score ranks as 0.0 — the fitness convention, so AP and decisions agree."""
    return [0.0 if score is None else float(score) for score in scores]


def fit_threshold(labels: Sequence[int], scores: Sequence[float | None]) -> float:
    """The threshold with the best recall at FPR <= :data:`DECISION_FPR_BUDGET`.

    Raises :class:`ContractError` when the fit is impossible (a single-class split): a
    decision rule that was never fitted must not silently become "decide nothing".
    """
    _recall, threshold = recall_at_max_fpr(list(labels), _ranked(scores), DECISION_FPR_BUDGET)
    if threshold is None:
        raise ContractError("no decision threshold can be fitted: the split has one class only")
    return float(threshold)


def decisions(scores: Sequence[float | None], threshold: float) -> tuple[bool, ...]:
    """``score >= threshold``, with an abstention ranked as 0.0 (as in the fit)."""
    return tuple(value >= threshold for value in _ranked(scores))


def suite_scores(
    genome: ComputationalGenomeV1, suite: EvaluationSuite
) -> tuple[tuple[float | None, ...], ...]:
    """Session scores on every variant of ``suite`` (clean first), unmetered."""
    return tuple(session_scores(genome, variant.dataset) for variant in suite.variants)


def _flips(
    reference: Sequence[Sequence[bool]], candidate: Sequence[Sequence[bool]]
) -> tuple[int, int]:
    """(decisions that differ, decisions examined), aligned variant by variant."""
    flipped = total = 0
    for ref, cand in zip(reference, candidate, strict=True):
        if len(ref) != len(cand):
            raise ContractError("an ablated genome scored a different number of sessions")
        total += len(ref)
        flipped += sum(1 for a, b in zip(ref, cand, strict=True) if a != b)
    return flipped, total


def _suite_decisions(
    scores: Sequence[Sequence[float | None]], threshold: float
) -> tuple[tuple[bool, ...], ...]:
    return tuple(decisions(variant, threshold) for variant in scores)


def _worst_case(genome: ComputationalGenomeV1, suite: EvaluationSuite) -> float | None:
    return evaluate(genome, suite, meter=WorkMeter()).worst_case_ap


# --- program surgery (shared with CHRONOS and the promotion gate) ----------------------------


def replace_nodes(program: IRProgram, replacements: Mapping[int, IRNode]) -> IRProgram:
    """A NEW program with the nodes at the given indices swapped; outputs are unchanged."""
    nodes = tuple(replacements.get(index, node) for index, node in enumerate(program.nodes))
    return IRProgram(phase=program.phase, nodes=nodes, outputs=program.outputs)


def prune_program(program: IRProgram) -> IRProgram:
    """Dead-node elimination: keep only nodes an output depends on, in their original order.

    Dropping a dead side-table node (FIRST_SEEN/RARE) is safe: its table is only observable
    through its own result, and nothing reads that result.
    """
    live: set[int] = set()
    stack = list(program.outputs)
    while stack:
        index = stack.pop()
        if index in live:
            continue
        live.add(index)
        stack.extend(program.nodes[index].args)
    order = sorted(live)
    remap = {old: new for new, old in enumerate(order)}
    nodes = tuple(
        replace(program.nodes[old], args=tuple(remap[a] for a in program.nodes[old].args))
        for old in order
    )
    return IRProgram(
        phase=program.phase,
        nodes=nodes,
        outputs=tuple(remap[index] for index in program.outputs),
    )


def rebuild(
    genome: ComputationalGenomeV1,
    *,
    mutation: str,
    registers: Sequence[RegisterSpec] | None = None,
    update: IRProgram | None = None,
    readout: IRProgram | None = None,
) -> ComputationalGenomeV1:
    """A NEW genome through :func:`build_genome`, so the typed IR re-validates it."""
    return build_genome(
        registers=tuple(genome.registers if registers is None else registers),
        update=genome.update if update is None else update,
        readout=genome.readout if readout is None else readout,
        aggregation=genome.aggregation,
        lookup_table=genome.lookup_table,
        min_events_for_score=genome.min_events_for_score,
        parent_digests=(genome.digest,),
        mutation=mutation,
    )


def _init_const(spec: RegisterSpec) -> IRNode:
    value = coerce_value(spec.init, spec.type, "register init")
    return IRNode(kind=NodeKind.CONST, type=spec.type, value=value)


def _freeze_reads(program: IRProgram, register: int, spec: RegisterSpec) -> IRProgram:
    """Every read of ``register`` (any lag) becomes CONST ``init``: a ring that is never
    written holds ``init`` in every slot, so this IS the frozen register."""
    const = _init_const(spec)
    swaps = {
        index: const
        for index, node in enumerate(program.nodes)
        if node.kind is NodeKind.REG and node.index == register
    }
    return replace_nodes(program, swaps)


def freeze_register(genome: ComputationalGenomeV1, register: int) -> ComputationalGenomeV1:
    """The genome with ``register`` frozen at its init value; the register itself stays."""
    if not 0 <= register < len(genome.registers):
        raise ContractError(f"register {register} outside 0..{len(genome.registers) - 1}")
    spec = genome.registers[register]
    return rebuild(
        genome,
        mutation=f"laplace-freeze-r{register}",
        update=_freeze_reads(genome.update, register, spec),
        readout=_freeze_reads(genome.readout, register, spec),
    )


def _renumber(program: IRProgram, removed: int) -> IRProgram:
    swaps = {
        index: replace(node, index=node.index - 1)
        for index, node in enumerate(program.nodes)
        if node.kind is NodeKind.REG and node.index > removed
    }
    return replace_nodes(program, swaps)


def remove_register(genome: ComputationalGenomeV1, register: int) -> ComputationalGenomeV1:
    """The genome without ``register``: reads frozen to ``init``, its update dropped, the
    remaining registers renumbered and dead nodes pruned. Raises ContractError/IRError if
    the result is not a valid genome (e.g. no register left)."""
    if not 0 <= register < len(genome.registers):
        raise ContractError(f"register {register} outside 0..{len(genome.registers) - 1}")
    spec = genome.registers[register]
    update = _freeze_reads(genome.update, register, spec)
    outputs = tuple(o for index, o in enumerate(update.outputs) if index != register)
    update = IRProgram(phase=update.phase, nodes=update.nodes, outputs=outputs)
    readout = _freeze_reads(genome.readout, register, spec)
    registers = tuple(r for index, r in enumerate(genome.registers) if index != register)
    return rebuild(
        genome,
        mutation=f"laplace-remove-r{register}",
        registers=registers,
        update=prune_program(_renumber(update, register)),
        readout=prune_program(_renumber(readout, register)),
    )


# --- S9X-005: state sufficiency --------------------------------------------------------------


def state_sufficiency(
    genome: ComputationalGenomeV1, suite: EvaluationSuite
) -> tuple[StateAblation, ...]:
    """Freeze each register at init and count the decisions that flip (S9X-005).

    The threshold is fitted once on the full genome's clean scores of ``suite``; flips are
    counted over the clean and every attacked variant, because a register that matters only
    under attack is still part of the sufficient state.
    """
    full_scores = suite_scores(genome, suite)
    threshold = fit_threshold(suite.labels, full_scores[0])
    reference = _suite_decisions(full_scores, threshold)
    ap_full = _worst_case(genome, suite)
    ablations = []
    for register in range(len(genome.registers)):
        frozen = freeze_register(genome, register)
        flipped, total = _flips(reference, _suite_decisions(suite_scores(frozen, suite), threshold))
        ap_without = _worst_case(frozen, suite)
        utility = None if ap_full is None or ap_without is None else ap_full - ap_without
        ablations.append(StateAblation(register, ap_full, ap_without, flipped, total, utility))
    return tuple(ablations)


# --- S9X-002..004: precision -----------------------------------------------------------------


def _packed_float_bytes(bits: int) -> int:
    significand = min(bits, _MAX_EXPLICIT_SIGNIFICAND)
    return min(VALUE_BYTES, math.ceil((significand + _FLOAT_OVERHEAD_BITS) / 8))


def packed_state_bytes(genome: ComputationalGenomeV1) -> int:
    """Session state bytes if each FLOAT register slot were stored packed at its precision.

    The static bound (:attr:`StaticBounds.session_state_bytes_max`) charges every slot
    ``VALUE_BYTES`` whatever its precision, because the interpreter stores Python floats.
    This figure replaces each FLOAT slot's 8 bytes by ``ceil((bits + 12) / 8)`` (sign and
    exponent included), capped at 8. It is ACCOUNTING for a packed backend, not a measured
    RSS; INT and BOOL slots keep ``VALUE_BYTES``.
    """
    saved_per_lineage = sum(
        spec.ring * (VALUE_BYTES - _packed_float_bytes(spec.precision_bits))
        for spec in genome.registers
        if spec.type is IRType.FLOAT
    )
    return genome.bounds.session_state_bytes_max - MAX_LINEAGES * saved_per_lineage


def _clean_ap(genome: ComputationalGenomeV1, dataset: Stage2Dataset) -> float | None:
    return average_precision(list(dataset.labels), _ranked(session_scores(genome, dataset)))


def precision_sweep(
    genome: ComputationalGenomeV1,
    dataset: Stage2Dataset,
    bits: Sequence[int] = PRECISION_LEVELS,
) -> tuple[PrecisionPoint, ...]:
    """Re-quantise every FLOAT register to each precision and measure clean AP (S9X-002..004).

    Points come back sorted by ``bits``. A genome with no FLOAT register yields identical
    points: precision is then not a knob it has, and the sweep says so by not moving.
    """
    levels = sorted(set(bits))
    if not levels or any(isinstance(b, bool) or not isinstance(b, int) for b in levels):
        raise ContractError(f"precision levels must be a non-empty set of ints, got {bits!r}")
    points = []
    for level in levels:
        registers = tuple(
            replace(spec, precision_bits=level) if spec.type is IRType.FLOAT else spec
            for spec in genome.registers
        )
        quantised = rebuild(genome, mutation=f"laplace-precision-{level}", registers=registers)
        points.append(
            PrecisionPoint(
                level, _clean_ap(quantised, dataset), packed_state_bytes(quantised), quantised
            )
        )
    return tuple(points)


# --- state dimension ---------------------------------------------------------------------------


def state_dimension_sweep(
    records: Sequence[FitnessRecord], genomes: Sequence[ComputationalGenomeV1]
) -> tuple[tuple[int, float | None], ...]:
    """Best worst-case AP per register count over index-aligned search records."""
    if len(records) != len(genomes):
        raise ContractError(f"{len(records)} records but {len(genomes)} genomes")
    best: dict[int, float | None] = {}
    for record, genome in zip(records, genomes, strict=True):
        if record.genome_digest != genome.digest:
            raise ContractError("records and genomes are not index-aligned (digest mismatch)")
        count = len(genome.registers)
        current = best.get(count)
        value = record.worst_case_ap
        if count not in best or (value is not None and (current is None or value > current)):
            best[count] = value
    return tuple(sorted(best.items()))


# --- minimal state -----------------------------------------------------------------------------


def _try_removals(
    genome: ComputationalGenomeV1,
    train: EvaluationSuite,
    reference: Sequence[Sequence[bool]],
    threshold: float,
) -> tuple[ComputationalGenomeV1, list[int], list[str]]:
    """Greedy: remove the first register whose removal flips no train decision; repeat.

    Returns the minimal genome, the ORIGINAL indices kept and one note per refused removal.
    """
    current = genome
    kept = list(range(len(genome.registers)))
    notes: list[str] = []
    progress = True
    while progress:
        progress = False
        for position, original in enumerate(kept):
            try:
                candidate = remove_register(current, position)
            except ContractError as error:  # IRError is a ContractError
                notes.append(f"r{original}: unbuildable ({error})")
                continue
            flipped, total = _flips(
                reference, _suite_decisions(suite_scores(candidate, train), threshold)
            )
            if flipped == 0:
                current, progress = candidate, True
                del kept[position]
                break
            notes.append(f"r{original}: kept, removal flips {flipped}/{total} train decisions")
    return current, kept, notes


def discover_minimal_state(
    genome: ComputationalGenomeV1, train: EvaluationSuite, heldout: EvaluationSuite
) -> DiscoveredState:
    """Greedy register removal that flips no TRAIN decision, then verified on held-out.

    The held-out verification re-uses the TRAIN threshold (never re-fitted on held-out) and
    reports how many held-out decisions the minimal genome changes; the reason starts with
    ``HELDOUT_VERIFIED`` when that count is 0 and ``HELDOUT_FLIPS=<k>`` otherwise. A
    removal that verifies badly on held-out is reported, not silently undone.
    """
    full_train = suite_scores(genome, train)
    threshold = fit_threshold(train.labels, full_train[0])
    reference = _suite_decisions(full_train, threshold)
    minimal, kept, notes = _try_removals(genome, train, reference, threshold)
    removed = tuple(i for i in range(len(genome.registers)) if i not in kept)
    held_flips, held_total = _flips(
        _suite_decisions(suite_scores(genome, heldout), threshold),
        _suite_decisions(suite_scores(minimal, heldout), threshold),
    )
    heldout_ap = _worst_case(minimal, heldout)
    status = "HELDOUT_VERIFIED" if held_flips == 0 else f"HELDOUT_FLIPS={held_flips}"
    reason = (
        f"{status}: removed {len(removed)} of {len(genome.registers)} registers with 0 train "
        f"decision flips; held-out flips {held_flips}/{held_total} at the train threshold"
        + ("" if not notes else "; " + "; ".join(notes))
    )
    return DiscoveredState(
        genome_digest=genome.digest,
        minimal_genome=minimal,
        registers_kept=tuple(kept),
        removed=removed,
        state_bytes=minimal.bounds.session_state_bytes_max,
        heldout_worst_case_ap=heldout_ap,
        redundant_pairs=_redundant_pairs(genome, train.clean.dataset),
        reason=reason,
    )


# --- S9X-006: identifiability ------------------------------------------------------------------


def _difference_probe(
    genome: ComputationalGenomeV1, a: int, b: int
) -> ComputationalGenomeV1 | None:
    """A probe genome with one extra register accumulating |new_a - new_b| (FLOAT/BOOL) or
    new_a XOR new_b (INT) over every event of every lineage; readout that register, MAX.

    Its session score is 0 exactly when registers ``a`` and ``b`` were written identical
    values at every event of that session. ``None`` when the pair cannot be compared (type,
    ring or precision differ, so the stored sequences cannot be identical by construction).
    """
    spec_a, spec_b = genome.registers[a], genome.registers[b]
    if (spec_a.type, spec_a.ring, spec_a.precision_bits) != (
        spec_b.type,
        spec_b.ring,
        spec_b.precision_bits,
    ) or spec_a.init != spec_b.init:
        return None
    nodes = list(genome.update.nodes)
    out_a, out_b = genome.update.outputs[a], genome.update.outputs[b]
    probe_index = len(genome.registers)
    builders: Mapping[IRType, Callable[[], None]] = {
        IRType.FLOAT: lambda: _float_diff(nodes, out_a, out_b, probe_index),
        IRType.BOOL: lambda: _bool_diff(nodes, out_a, out_b, probe_index),
        IRType.INT: lambda: _int_diff(nodes, out_a, out_b, probe_index),
    }
    builders[spec_a.type]()
    probe_type = IRType.INT if spec_a.type is IRType.INT else IRType.FLOAT
    registers = (
        *genome.registers,
        RegisterSpec(type=probe_type, init=0 if probe_type is IRType.INT else 0.0),
    )
    update = IRProgram(
        phase=genome.update.phase,
        nodes=tuple(nodes),
        outputs=(*genome.update.outputs, len(nodes) - 1),
    )
    readout = _probe_readout(probe_type, probe_index)
    return build_genome(
        registers=registers,
        update=update,
        readout=readout,
        aggregation=SessionAggregation.MAX,
        lookup_table=genome.lookup_table,
        min_events_for_score=1,
        parent_digests=(genome.digest,),
        mutation=f"laplace-identifiability-r{a}-r{b}",
    )


def _probe_readout(probe_type: IRType, probe_index: int) -> IRProgram:
    """Read the probe register; an INT difference mask is read as its POPCOUNT."""
    nodes = [IRNode(kind=NodeKind.REG, type=probe_type, index=probe_index)]
    if probe_type is IRType.INT:
        nodes.append(
            IRNode(kind=NodeKind.APPLY, type=IRType.FLOAT, primitive="POPCOUNT", args=(0,))
        )
    return IRProgram(phase=ProgramPhase.READOUT, nodes=tuple(nodes), outputs=(len(nodes) - 1,))


def _apply(nodes: list[IRNode], type_: IRType, primitive: str, *args: int) -> int:
    nodes.append(IRNode(kind=NodeKind.APPLY, type=type_, primitive=primitive, args=args))
    return len(nodes) - 1


def _float_diff(nodes: list[IRNode], a: int, b: int, probe: int) -> None:
    diff = _apply(nodes, IRType.FLOAT, "ABS", _apply(nodes, IRType.FLOAT, "SUB", a, b))
    nodes.append(IRNode(kind=NodeKind.REG, type=IRType.FLOAT, index=probe))
    _apply(nodes, IRType.FLOAT, "MAX", len(nodes) - 1, diff)


def _bool_diff(nodes: list[IRNode], a: int, b: int, probe: int) -> None:
    fa = _apply(nodes, IRType.FLOAT, "B2F", a)
    fb = _apply(nodes, IRType.FLOAT, "B2F", b)
    _float_diff(nodes, fa, fb, probe)


def _int_diff(nodes: list[IRNode], a: int, b: int, probe: int) -> None:
    diff = _apply(nodes, IRType.INT, "XOR", a, b)
    nodes.append(IRNode(kind=NodeKind.REG, type=IRType.INT, index=probe))
    _apply(nodes, IRType.INT, "OR", len(nodes) - 1, diff)


def _redundant_pairs(
    genome: ComputationalGenomeV1, dataset: Stage2Dataset
) -> tuple[tuple[int, int], ...]:
    """Register pairs whose written value sequences are identical on every session."""
    pairs = []
    count = len(genome.registers)
    for a in range(count):
        for b in range(a + 1, count):
            try:
                probe = _difference_probe(genome, a, b)
            except ContractError:  # probe exceeds a node/register bound: not measurable
                continue
            if probe is None:
                continue
            scores = session_scores(probe, dataset)
            if all(score is not None and score == 0.0 for score in scores):
                pairs.append((a, b))
    return tuple(pairs)
