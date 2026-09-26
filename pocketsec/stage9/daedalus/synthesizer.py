"""D9.11 — DAEDALUS: turn a searched genome into a checked, specialised, compiled candidate.

Architecture §31 lists the synthesis pipeline: type/resource validation -> IR ->
specialisation -> compilation -> unit and metamorphic tests. This module is that pipeline
and nothing more. ARGUS and hardware-in-loop measurement stay separate stages (spec §4.17),
so a :class:`SynthesizedSystem` is evidence that a genome *compiles and behaves
consistently*, never evidence that it is good or cheap on a device.

What it refuses to do:

* **Change semantics.** :func:`specialize` folds constants and deletes dead nodes, and
  nothing else. It never folds or deletes a side-table primitive (``FIRST_SEEN``/``RARE``):
  those mutate a per-session table, so a node whose *value* is unused still changes what
  a later node reads. :func:`synthesize` then *measures* whether scores stayed identical
  (``specialization_preserves_scores``) instead of trusting the argument.
* **Work around Stage 3.** M0.10: Stage 3's PCB ISA has 22 opcodes and none of them is
  arithmetic, ``MAX``, ``MIN``, ``DIV``, ``POPCOUNT`` or a per-lineage register.
  :func:`lower_to_pcb` names every IR construct that has no PCB counterpart and reports the
  genome NOT expressible. The Φ-oracle is not expressible (its update reads a register and
  applies ``MAX``); that is a Stage 3 seam finding, recorded, not patched around.
* **Overclaim a lowering.** The only fragment PCB can carry is a per-event predicate over
  the Stage 1 state-delta mask. A genome in that fragment has no ``REG`` node, so its
  readout is constant and its session score cannot depend on the events at all: PCB can
  carry the per-event predicate, never the scorer. Every successful lowering says so in
  its ``reason``.
* **Pass vacuously.** :func:`synthesize` refuses an empty sample, and the actor-slot
  permutation check reports ``None`` (not ``True``) when no session has two lineages to
  permute.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.state.security_state import DIMENSIONS
from pocketsec.stage2.dataset import Stage2Dataset, Stage2Sample
from pocketsec.stage3.bytecode.isa import Op
from pocketsec.stage3.bytecode.verifier import verify
from pocketsec.stage3.cells.operator import OperatorForm, OperatorProgram
from pocketsec.stage9.chemistry.phenotype import Phenotype, SessionRun
from pocketsec.stage9.chemistry.typed_ir import (
    INT_MASK,
    InputSource,
    IRNode,
    IRProgram,
    IRType,
    NodeKind,
    StaticBounds,
    clamp_float,
    coerce_value,
    static_bounds,
    validate_program,
)
from pocketsec.stage9.foundry.primitives import SEED_ALPHABET, TABLE_READERS
from pocketsec.stage9.genome.computational import ComputationalGenomeV1, build_genome

__all__ = [
    "PCB_LOWERABLE_INPUTS",
    "PCB_LOWERABLE_PRIMITIVES",
    "PCB_MASK_DOMAIN",
    "PCB_OBSERVATION_OPERAND",
    "SPECIALIZE_MUTATION",
    "MetamorphicReport",
    "PcbLowering",
    "SynthesizedSystem",
    "lower_to_pcb",
    "permute_actor_slots_reversed",
    "specialize",
    "synthesize",
]

#: The ``mutation`` tag :func:`specialize` appends. Lineage fields are excluded from the
#: genome digest, so the tag records what happened without changing identity.
SPECIALIZE_MUTATION = "SPECIALIZE"

#: The IR primitives with an exact PCB rendering (spec §4.17). Everything else is named.
PCB_LOWERABLE_PRIMITIVES: frozenset[str] = frozenset({"STATE_DELTA", "EQ_I", "AND", "OR", "NOT"})

#: The one IR input with a PCB frame slot of identical encoding: ``state_delta_mask`` is
#: Stage 1's ``StateDelta.bitmask()`` (``stage2/encoder/ssir_encoder.py:253``), and PCB's
#: ``LOAD_REL 2`` returns ``frame.delta.bitmask()`` (``stage3/bytecode/vm.py:361``) — the
#: same method, so the same bit order (DIMENSIONS insertion order).
PCB_LOWERABLE_INPUTS: frozenset[InputSource] = frozenset({InputSource.STATE_DELTA_MASK})

#: Every value the state-delta mask can take: one bit per Stage 1 dimension.
PCB_MASK_DOMAIN = 1 << len(DIMENSIONS)

#: ``RAISE_OBSERVATION`` operand for a true predicate: ELEVATED. BASELINE (0) would be a
#: no-op request, making the lowered predicate unobservable. The VM only *requests*
#: escalation; Stage 1's observation policy grants it, so this carries no authority.
PCB_OBSERVATION_OPERAND = 1

# PCB word layout and pool bounds (stage3/bytecode/isa.py). Only ``Op`` is on the §2.3
# allow-list, so these are restated here; ``verify`` re-decodes every word and re-reads
# every set, so a drifted copy is REFUSED by Stage 3, never silently trusted.
_PCB_OPERAND_BITS = 16
_PCB_MAX_SET_MEMBERS = 32
_PCB_MAX_SETS = 8
_PCB_LOAD_REL_DELTA_MASK = 2
# MAX_STACK * SLOT_BYTES + FRAME_OVERHEAD_BYTES: the verifier's ceiling for a PCB frame.
_PCB_DECLARED_STATE_BYTES = 16 * 8 + 256


@dataclass(frozen=True, slots=True)
class MetamorphicReport:
    """Behaviour that must not change under transformations that change nothing."""

    sessions: int
    deterministic: bool
    #: None when no sample session had two lineages to permute (nothing was tested).
    actor_slot_permutation_invariant: bool | None
    specialization_preserves_scores: bool
    #: Sessions whose score changed under the permutation (the firing count).
    permutation_score_changes: int = 0
    #: Sessions whose score differs between the original and the specialised genome.
    specialization_score_changes: int = 0


@dataclass(frozen=True, slots=True)
class PcbLowering:
    """Whether a genome's per-event dataflow has an exact PCB rendering Stage 3 accepts."""

    expressible: bool
    reason: str
    #: Every IR node or construct with no PCB counterpart, named (M0.10).
    unsupported: tuple[str, ...]
    #: ``stage3.bytecode.verifier.verify(...).to_dict()`` when a program was built.
    verifier_report: dict[str, Any] | None
    #: The OperatorProgram handed to Stage 3, when one was built (accepted or not).
    program: OperatorProgram | None = None


@dataclass(frozen=True, slots=True)
class SynthesizedSystem:
    """One genome after DAEDALUS: validated, specialised, compiled and self-tested."""

    genome_digest: str
    specialized: ComputationalGenomeV1
    phenotype_digest: str
    bounds: StaticBounds
    unit_checks: tuple[tuple[str, bool], ...]
    metamorphic: MetamorphicReport
    pcb: PcbLowering

    @property
    def unit_checks_passed(self) -> bool:
        return all(ok for _, ok in self.unit_checks)


# --- specialisation ----------------------------------------------------------------------------


def _foldable(node: IRNode, nodes: Sequence[IRNode]) -> bool:
    if node.kind is not NodeKind.APPLY or not node.args:
        return False
    if SEED_ALPHABET.get(node.primitive).side_table:
        return False
    return all(nodes[arg].kind is NodeKind.CONST for arg in node.args)


def _fold_value(node: IRNode, nodes: Sequence[IRNode], lookup: Sequence[float]) -> object:
    """The value the phenotype would compute for ``node`` from its constant arguments."""
    primitive = SEED_ALPHABET.get(node.primitive)
    args = [nodes[arg].value for arg in node.args]
    raw = primitive.fn(tuple(lookup), *args) if node.primitive in TABLE_READERS \
        else primitive.fn(*args)
    if node.type is IRType.FLOAT:
        return clamp_float(float(raw))
    if node.type is IRType.INT:
        return int(raw) & INT_MASK
    return bool(raw)


def _fold_constants(program: IRProgram, lookup: Sequence[float]) -> tuple[IRNode, ...]:
    folded: list[IRNode] = []
    for node in program.nodes:
        if _foldable(node, folded):
            try:
                value = coerce_value(_fold_value(node, folded, lookup), node.type, "fold")
            except (ContractError, ArithmeticError, TypeError, ValueError):
                # Folding is an optimisation: a value it cannot reproduce stays computed.
                folded.append(node)
                continue
            folded.append(IRNode(kind=NodeKind.CONST, type=node.type, value=value))
        else:
            folded.append(node)
    return tuple(folded)


def _live_nodes(nodes: Sequence[IRNode], outputs: Sequence[int]) -> list[bool]:
    live = [False] * len(nodes)
    for index in outputs:
        live[index] = True
    for index, node in enumerate(nodes):
        # A side-table primitive mutates per-session state other nodes read: always a root.
        if node.kind is NodeKind.APPLY and SEED_ALPHABET.get(node.primitive).side_table:
            live[index] = True
    for index in range(len(nodes) - 1, -1, -1):
        if live[index]:
            for arg in nodes[index].args:
                live[arg] = True
    return live


def _eliminate_dead(nodes: Sequence[IRNode], program: IRProgram) -> IRProgram:
    live = _live_nodes(nodes, program.outputs)
    remap: dict[int, int] = {}
    kept: list[IRNode] = []
    for index, node in enumerate(nodes):
        if live[index]:
            remap[index] = len(kept)
            args = tuple(remap[arg] for arg in node.args)
            kept.append(dataclasses.replace(node, args=args) if node.args else node)
    outputs = tuple(remap[index] for index in program.outputs)
    return IRProgram(phase=program.phase, nodes=tuple(kept), outputs=outputs)


def _specialize_program(program: IRProgram, lookup: Sequence[float], *, fold: bool) -> IRProgram:
    nodes = _fold_constants(program, lookup) if fold else program.nodes
    return _eliminate_dead(nodes, program)


def _rebuild(genome: ComputationalGenomeV1, update: IRProgram,
             readout: IRProgram) -> ComputationalGenomeV1:
    mutation = SPECIALIZE_MUTATION if not genome.mutation \
        else f"{genome.mutation}+{SPECIALIZE_MUTATION}"
    return build_genome(
        registers=genome.registers, update=update, readout=readout,
        aggregation=genome.aggregation, lookup_table=genome.lookup_table,
        min_events_for_score=genome.min_events_for_score,
        parent_digests=(genome.digest,), mutation=mutation,
    )


def specialize(genome: ComputationalGenomeV1) -> ComputationalGenomeV1:
    """Constant-fold and delete dead nodes, re-validated through ``build_genome``.

    Returns ``genome`` itself when nothing changes. If the folded program would break an
    IR bound (a fold can add a constant when its arguments stay live elsewhere), dead-node
    elimination alone is tried, then the original is returned: specialisation never
    refuses a genome the IR already accepted.
    """
    for fold in (True, False):
        update = _specialize_program(genome.update, genome.lookup_table, fold=fold)
        readout = _specialize_program(genome.readout, genome.lookup_table, fold=fold)
        if update == genome.update and readout == genome.readout:
            return genome
        try:
            return _rebuild(genome, update, readout)
        except ContractError:
            continue
    return genome


# --- PCB lowering ------------------------------------------------------------------------------


def _node_label(phase: str, index: int, node: IRNode) -> str:
    if node.kind is NodeKind.REG:
        what = f"REG r{node.index} lag {node.lag} (per-lineage state; PCB has no register)"
    elif node.kind is NodeKind.INPUT:
        source = node.source.value if node.source is not None else "?"
        slot = f"[{node.index}]" if node.source is InputSource.FEATURE else ""
        what = f"INPUT {source}{slot} (no PCB frame slot with the same encoding)"
    elif node.kind is NodeKind.APPLY:
        what = f"{node.primitive} (no PCB opcode: PCB has no arithmetic, MAX, MIN, DIV, " \
            "POPCOUNT or table primitive)"
    else:
        what = f"{node.kind.value} ({node.type.value})"
    return f"{phase} node {index}: {what}"


def _lowerable(node: IRNode) -> bool:
    if node.kind is NodeKind.REG:
        return False
    if node.kind is NodeKind.INPUT:
        return node.source in PCB_LOWERABLE_INPUTS
    if node.kind is NodeKind.APPLY:
        return node.primitive in PCB_LOWERABLE_PRIMITIVES
    return True


def _unsupported_nodes(genome: ComputationalGenomeV1) -> list[str]:
    found = [_node_label("UPDATE", index, node)
             for index, node in enumerate(genome.update.nodes) if not _lowerable(node)]
    for index, node in enumerate(genome.readout.nodes):
        if node.kind is not NodeKind.CONST:
            found.append(_node_label("READOUT", index, node))
    for register, output in enumerate(genome.update.outputs):
        if genome.update.nodes[output].type is not IRType.BOOL:
            found.append(
                f"UPDATE output r{register}: {genome.update.nodes[output].type.value} value "
                "(PCB can only emit a per-event boolean, via RAISE_OBSERVATION)"
            )
    return found


def _evaluate_at(nodes: Sequence[IRNode], output: int, mask: int) -> bool:
    """The per-event value of ``output`` when the state-delta mask is ``mask``."""
    values: list[object] = []
    for node in nodes[: output + 1]:
        if node.kind is NodeKind.INPUT:
            values.append(mask)
        elif node.kind is NodeKind.CONST:
            values.append(node.value)
        else:
            raw = SEED_ALPHABET.get(node.primitive).fn(*(values[a] for a in node.args))
            values.append(bool(raw) if node.type is IRType.BOOL else int(raw) & INT_MASK)
    return bool(values[output])


def _predicate_set(nodes: Sequence[IRNode], output: int) -> frozenset[int] | str:
    """The PCB set literal for one predicate, or why no set literal can carry it.

    AND/OR/NOT act bit by bit, so over one mask input a STATE_DELTA predicate depends on one
    bit and an EQ_I predicate on a conjunction of bits: the predicate holds on a power of two
    masks. A complement-plus-NOT rendering could only help a set of >= 480 of 512, which this
    fragment cannot produce, so it is not built (a branch nothing reaches is not a feature).
    """
    holds = frozenset(m for m in range(PCB_MASK_DOMAIN) if _evaluate_at(nodes, output, m))
    if not holds or len(holds) == PCB_MASK_DOMAIN:
        return "the predicate is constant, so no PCB set literal can carry it"
    if len(holds) <= _PCB_MAX_SET_MEMBERS:
        return holds
    return (
        f"the predicate holds on {len(holds)} of {PCB_MASK_DOMAIN} state-delta masks; a PCB "
        f"IN_SET literal holds at most {_PCB_MAX_SET_MEMBERS}"
    )


def _word(op: Op, operand: int = 0) -> int:
    return (int(op) << _PCB_OPERAND_BITS) | operand


def _pcb_program(sets: Sequence[frozenset[int]]) -> OperatorProgram:
    words: list[int] = []
    table: dict[str, float] = {}
    for index, members in enumerate(sets):
        words += [_word(Op.LOAD_REL, _PCB_LOAD_REL_DELTA_MASK), _word(Op.IN_SET, index),
                  _word(Op.RAISE_OBSERVATION, PCB_OBSERVATION_OPERAND)]
        table.update({f"set.{index}.{member}": 1.0 for member in sorted(members)})
    words.append(_word(Op.ABSTAIN))
    return OperatorProgram(
        form=OperatorForm.BYTECODE, words=tuple(words), table=table,
        max_steps=len(words), max_state_bytes=_PCB_DECLARED_STATE_BYTES,
    )


def lower_to_pcb(genome: ComputationalGenomeV1) -> PcbLowering:
    """Lower the per-event predicate fragment to Stage 3 bytecode, or name why not.

    Every ``REG`` node, every primitive outside :data:`PCB_LOWERABLE_PRIMITIVES` (so
    ``MAX``, ``MIN``, ``DIV``, arithmetic and ``POPCOUNT``) and every input outside
    :data:`PCB_LOWERABLE_INPUTS` is named in ``unsupported``. A genome with none of them
    has a BOOL predicate per register over the 9-bit state-delta mask; each is rendered
    EXACTLY by its truth table over all :data:`PCB_MASK_DOMAIN` masks as an ``IN_SET``
    literal, and the program is handed to Stage 3's
    ``verify``. ``expressible`` is True only if Stage 3 accepts it.
    """
    unsupported = _unsupported_nodes(genome)
    sets: list[frozenset[int]] = []
    if not unsupported:
        for register, output in enumerate(genome.update.outputs):
            rendered = _predicate_set(genome.update.nodes, output)
            if isinstance(rendered, str):
                unsupported.append(f"UPDATE output r{register}: {rendered}")
            else:
                sets.append(rendered)
        if len(sets) > _PCB_MAX_SETS:
            unsupported.append(f"{len(sets)} predicates > {_PCB_MAX_SETS} PCB set literals")
    if unsupported:
        return PcbLowering(False, "not expressible in PCB (M0.10): " + "; ".join(unsupported),
                           tuple(unsupported), None)
    return _verified_lowering(genome, sets)


def _verified_lowering(genome: ComputationalGenomeV1,
                       sets: Sequence[frozenset[int]]) -> PcbLowering:
    try:
        program = _pcb_program(sets)
    except ContractError as exc:
        return PcbLowering(False, f"Stage 3 refused the operator: {exc}", (), None)
    report = verify(program)
    if not report.ok:
        failures = "; ".join(f"{code}: {detail}" for code, detail in report.failures)
        return PcbLowering(False, f"Stage 3's verifier refused the lowering: {failures}", (),
                           report.to_dict(), program)
    constant = genome.readout.nodes[genome.readout.outputs[0]].value
    reason = (
        f"per-event predicates of {len(sets)} register(s) lowered exactly (truth table over "
        f"all {PCB_MASK_DOMAIN} Stage 1 state-delta masks) and accepted by Stage 3's verifier. "
        f"The readout is the constant {constant!r}: this fragment carries no per-lineage "
        "state, so PCB carries the per-event predicate, never a session scorer (M0.10)"
    )
    return PcbLowering(True, reason, (), report.to_dict(), program)


# --- synthesis ---------------------------------------------------------------------------------


def permute_actor_slots_reversed(dataset: Stage2Dataset) -> Stage2Dataset:
    """Relabel lineages inside each session by reversing their slot order.

    ``actor_slot`` is a session-local grouping key (spec §3.2), so a bijective relabelling
    changes who is called what and nothing else: event order, features and labels stay.
    Deterministic, so a failure reproduces.
    """
    samples: list[Stage2Sample] = []
    for sample in dataset.samples:
        slots = sorted({step.actor_slot for step in sample.steps})
        mapping = dict(zip(slots, reversed(slots), strict=True))
        steps = tuple(dataclasses.replace(s, actor_slot=mapping[s.actor_slot])
                      for s in sample.steps)
        samples.append(dataclasses.replace(sample, steps=steps))
    return dataclasses.replace(dataset, samples=tuple(samples))


def _validation_checks(genome: ComputationalGenomeV1) -> list[tuple[str, bool]]:
    checks: list[tuple[str, bool]] = []
    for name, program in (("update", genome.update), ("readout", genome.readout)):
        try:
            validate_program(program, genome.registers, SEED_ALPHABET)
            checks.append((f"ir_valid:{name}", True))
        except ContractError:
            checks.append((f"ir_valid:{name}", False))
    bounds = static_bounds(genome.update, genome.readout, genome.registers, SEED_ALPHABET)
    checks.append(("declared_bounds_cover_static",
                   genome.declared_max_state_bytes >= bounds.session_state_bytes_max
                   and genome.declared_max_steps_per_event >= bounds.max_steps_per_event))
    try:
        again = ComputationalGenomeV1.from_dict(genome.to_dict())
        checks.append(("digest_roundtrip", again.digest == genome.digest))
    except ContractError:
        checks.append(("digest_roundtrip", False))
    return checks


def _run_checks(original: ComputationalGenomeV1, specialized: ComputationalGenomeV1,
                phenotype: Phenotype, runs: Sequence[SessionRun],
                dataset: Stage2Dataset) -> list[tuple[str, bool]]:
    bounds = specialized.bounds
    below_min = phenotype.run_session(
        dataset.samples[0].steps[: specialized.min_events_for_score - 1])
    return [
        ("specialized_not_costlier",
         bounds.update_wu_per_event <= original.bounds.update_wu_per_event
         and bounds.session_state_bytes_max <= original.bounds.session_state_bytes_max),
        ("phenotype_bounds_equal_genome_bounds", phenotype.bounds == bounds),
        ("state_bytes_within_static_bound",
         all(run.state_bytes_peak <= bounds.session_state_bytes_max for run in runs)),
        ("work_units_within_static_bound",
         all(run.work_units <= bounds.session_wu_max for run in runs)),
        ("abstains_below_min_events", below_min.score is None),
    ]


def _differences(a: Sequence[SessionRun], b: Sequence[SessionRun]) -> int:
    return sum(1 for x, y in zip(a, b, strict=True) if x.score != y.score)


def _metamorphic(original: ComputationalGenomeV1, specialized: ComputationalGenomeV1,
                 dataset: Stage2Dataset, runs: Sequence[SessionRun]) -> MetamorphicReport:
    again = specialized.phenotype().run_dataset(dataset)
    deterministic = all(
        (x.score, x.work_units, x.evidence) == (y.score, y.work_units, y.evidence)
        for x, y in zip(runs, again, strict=True)
    )
    multi_lineage = any(len({s.actor_slot for s in sample.steps}) > 1 for sample in dataset)
    permuted = specialized.phenotype().run_dataset(permute_actor_slots_reversed(dataset))
    permutation_changes = _differences(runs, permuted)
    original_runs = original.phenotype().run_dataset(dataset)
    specialization_changes = _differences(original_runs, runs)
    return MetamorphicReport(
        sessions=len(dataset.samples),
        deterministic=deterministic,
        actor_slot_permutation_invariant=(permutation_changes == 0) if multi_lineage else None,
        specialization_preserves_scores=specialization_changes == 0,
        permutation_score_changes=permutation_changes,
        specialization_score_changes=specialization_changes,
    )


def synthesize(genome: ComputationalGenomeV1,
               sample_sessions: Stage2Dataset) -> SynthesizedSystem:
    """Architecture §31: validate -> IR -> specialise -> compile -> unit + metamorphic tests.

    A validation failure raises ``ContractError`` (nothing downstream of an invalid genome
    is meaningful). The run-time and metamorphic checks are *recorded*, never raised, so a
    caller sees exactly which property failed.
    """
    if not sample_sessions.samples:
        raise ContractError("synthesize needs >= 1 sample session: a metamorphic check over "
                            "nothing passes vacuously")
    checks = _validation_checks(genome)
    failed = [name for name, ok in checks if not ok]
    if failed:
        raise ContractError(f"genome {genome.digest} failed validation: {failed}")
    specialized = specialize(genome)
    phenotype = specialized.phenotype()
    runs = phenotype.run_dataset(sample_sessions)
    checks += _run_checks(genome, specialized, phenotype, runs, sample_sessions)
    return SynthesizedSystem(
        genome_digest=genome.digest,
        specialized=specialized,
        phenotype_digest=phenotype.digest,
        bounds=specialized.bounds,
        unit_checks=tuple(checks),
        metamorphic=_metamorphic(genome, specialized, sample_sessions, runs),
        pcb=lower_to_pcb(specialized),
    )
