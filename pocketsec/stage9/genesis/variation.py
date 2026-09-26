"""D9.12 (variation) — GENESIS: the typed variation operators and the one random generator.

A search is only as honest as the moves it may make. This module holds every way Stage 9
proposes a new computation:

* :func:`random_genome` is **the one generator**. Random search and the evolutionary
  search's initial population both call it, so "evolution beat random search" can only mean
  the variation loop helped, never that the arms drew from different languages. It draws
  typed random DAGs over every :class:`InputSource` and all 96 feature indices.
* :func:`mutate` applies one of architecture §32's operators (plus the spec's CROSSOVER and
  MACRO_INSERT); :func:`crossover` exchanges typed subtrees between two register updates.

What this module refuses to do:

* **It never repairs an invalid child.** Every child is built through ``build_genome``, so
  the IR validator decides validity; a refused child comes back as a :class:`Mutation` with
  ``child=None`` and the validator's code, and the search counts it. The only normalisation
  applied to every draft alike is dead-node removal, which preserves meaning.
* **It never invents a backend.** MOVE is refused every time with ``NO_ALTERNATIVE_BACKEND``
  (``DeploymentBackend`` has one member); MOVE is expected to be INERT and is reported so.
* **It never uses a promoted macro unless the alphabet holds one** (``NO_PROMOTED_PRIMITIVE``).
* **It holds no state.** Operator counts live in the caller's :class:`OperatorStats`.

Node indexing for :func:`unique_utility` and :func:`ablate_node` is *flat*: indices
``0 .. len(update.nodes)-1`` name update nodes, and the readout nodes follow.
"""

from __future__ import annotations

import math
import random
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage2.encoder.ssir_encoder import FEATURE_WIDTH
from pocketsec.stage6.resources import WorkMeter
from pocketsec.stage9.chemistry.phenotype import SessionAggregation
from pocketsec.stage9.chemistry.typed_ir import (
    INPUT_TYPES,
    MAX_PROGRAM_NODES,
    MAX_REGISTERS,
    InputSource,
    IRNode,
    IRProgram,
    IRType,
    NodeKind,
    ProgramPhase,
    RegisterSpec,
)
from pocketsec.stage9.foundry.primitives import (
    SEED_ALPHABET,
    Primitive,
    PrimitiveAlphabet,
    PrimitiveOrigin,
)
from pocketsec.stage9.genome.computational import ComputationalGenomeV1, build_genome
from pocketsec.stage9.ontogenesis.fitness import EvaluationSuite, evaluate

__all__ = [
    "REFUSED_NOT_APPLICABLE",
    "REFUSED_NO_BACKEND",
    "REFUSED_NO_CHANGE",
    "REFUSED_NO_MACRO",
    "Mutation",
    "OperatorStats",
    "VariationOperator",
    "ablate_node",
    "crossover",
    "mutate",
    "node_total",
    "random_genome",
    "unique_utility",
]

#: Probability that the generator stops growing and draws a leaf. Chosen, not measured.
_LEAF_PROBABILITY: float = 0.3
#: Nodes kept free under ``MAX_PROGRAM_NODES`` before the generator forces leaves, so a
#: partly grown APPLY chain can still close. Chosen, not measured.
_NODE_RESERVE: int = 8
#: Rejection-sampling attempts before :func:`random_genome` gives up loudly.
_RANDOM_ATTEMPTS: int = 64
_FLOAT_CONSTANTS: tuple[float, ...] = (0.0, 0.5, 1.0, 2.0, 8.0)
_INT_CONSTANT_LIMIT: int = 256
_LOOKUP_ENTRIES_MAX: int = 8

REFUSED_NO_BACKEND = "NO_ALTERNATIVE_BACKEND"
REFUSED_NOT_APPLICABLE = "NOT_APPLICABLE"
REFUSED_NO_CHANGE = "NO_CHANGE"
REFUSED_NO_MACRO = "NO_PROMOTED_PRIMITIVE"


class VariationOperator(StrEnum):
    """Architecture §32's operators, plus CROSSOVER and MACRO_INSERT from the spec (§4.7)."""

    REPLACE = "REPLACE"
    MERGE = "MERGE"
    SPLIT = "SPLIT"
    FACTORIZE = "FACTORIZE"
    SPARSIFY = "SPARSIFY"
    SPECIALIZE = "SPECIALIZE"
    REMOVE = "REMOVE"
    MOVE = "MOVE"
    COMPRESS = "COMPRESS"
    DEVELOPMENTAL = "DEVELOPMENTAL"
    INSERT = "INSERT"
    CROSSOVER = "CROSSOVER"
    MACRO_INSERT = "MACRO_INSERT"


@dataclass(frozen=True, slots=True)
class Mutation:
    """One proposal: a valid child, or the reason there is none. Never both."""

    operator: VariationOperator
    child: ComputationalGenomeV1 | None
    refused_reason: str

    def __post_init__(self) -> None:
        if (self.child is None) == (self.refused_reason == ""):
            raise ContractError("Mutation carries exactly one of a child or a refusal reason")


@dataclass(frozen=True, slots=True)
class OperatorStats:
    """Per-operator firing counts; ``valid == 0`` over a whole search means INERT."""

    operator: VariationOperator
    proposed: int
    valid: int
    improved_archive: int


# --------------------------------------------------------------------------- drafts

_Nodes = tuple[IRNode, ...]
_Outs = tuple[int, ...]


@dataclass(frozen=True, slots=True)
class _Draft:
    """A genome's editable parts. Becomes a genome only through ``build_genome``."""

    registers: tuple[RegisterSpec, ...]
    update: _Nodes
    update_out: _Outs
    readout: _Nodes
    readout_out: _Outs
    aggregation: SessionAggregation
    lookup_table: tuple[float, ...]
    min_events: int

    def program(self, phase: ProgramPhase) -> tuple[_Nodes, _Outs]:
        if phase is ProgramPhase.UPDATE:
            return self.update, self.update_out
        return self.readout, self.readout_out

    def with_program(
        self, phase: ProgramPhase, nodes: Sequence[IRNode], outs: Sequence[int]
    ) -> _Draft:
        kept, kept_outs = _gc(tuple(nodes), tuple(outs))
        if phase is ProgramPhase.UPDATE:
            return replace(self, update=kept, update_out=kept_outs)
        return replace(self, readout=kept, readout_out=kept_outs)

    def with_node(self, phase: ProgramPhase, index: int, node: IRNode) -> _Draft:
        nodes, outs = self.program(phase)
        return self.with_program(phase, (*nodes[:index], node, *nodes[index + 1 :]), outs)


def _draft_of(genome: ComputationalGenomeV1) -> _Draft:
    return _Draft(
        tuple(genome.registers), tuple(genome.update.nodes), tuple(genome.update.outputs),
        tuple(genome.readout.nodes), tuple(genome.readout.outputs), genome.aggregation,
        tuple(genome.lookup_table), genome.min_events_for_score,
    )


def _build(
    draft: _Draft, alphabet: PrimitiveAlphabet, *, parents: tuple[str, ...], label: str
) -> ComputationalGenomeV1:
    """The only construction path: the IR validator, not this module, decides validity."""
    return build_genome(
        registers=draft.registers,
        update=IRProgram(phase=ProgramPhase.UPDATE, nodes=draft.update, outputs=draft.update_out),
        readout=IRProgram(
            phase=ProgramPhase.READOUT, nodes=draft.readout, outputs=draft.readout_out
        ),
        aggregation=draft.aggregation,
        lookup_table=draft.lookup_table,
        alphabet=alphabet,
        min_events_for_score=draft.min_events,
        parent_digests=parents,
        mutation=label,
    )


def _gc(nodes: _Nodes, outs: _Outs) -> tuple[_Nodes, _Outs]:
    """Drop nodes no output reaches. Meaning-preserving; applied to every draft alike."""
    live = [False] * len(nodes)
    stack = list(outs)
    while stack:
        index = stack.pop()
        if not live[index]:
            live[index] = True
            stack.extend(nodes[index].args)
    remap: dict[int, int] = {}
    kept: list[IRNode] = []
    for index, node in enumerate(nodes):
        if live[index]:
            remap[index] = len(kept)
            kept.append(_mapped(node, remap.__getitem__))
    return tuple(kept), tuple(remap[out] for out in outs)


def _mapped(node: IRNode, mapping: Callable[[int], int]) -> IRNode:
    return replace(node, args=tuple(mapping(arg) for arg in node.args)) if node.args else node


def _rewire(
    nodes: Sequence[IRNode], outs: Sequence[int], old: int, new: int
) -> tuple[list[IRNode], list[int]]:
    """Point every use of ``old`` at ``new``; ``new < old`` keeps the DAG backward-only."""
    mapping: Callable[[int], int] = lambda arg: new if arg == old else arg  # noqa: E731
    return [_mapped(node, mapping) for node in nodes], [mapping(out) for out in outs]


def _splice(
    nodes: Sequence[IRNode], outs: Sequence[int], at: int, graft: Sequence[IRNode], *, wrap: bool
) -> tuple[list[IRNode], list[int]]:
    """Insert ``graft`` (absolute indices, root last) at ``at``.

    ``wrap=True`` puts the graft *after* node ``at`` and redirects every later use of ``at``
    to the graft's root (INSERT); ``wrap=False`` *replaces* node ``at`` (crossover).
    """
    root = (at + 1 if wrap else at) + len(graft) - 1
    shift = len(graft) if wrap else len(graft) - 1

    def mapping(arg: int) -> int:
        return root if arg == at else arg + shift if arg > at else arg

    prefix = list(nodes[: at + 1]) if wrap else list(nodes[:at])
    suffix = [_mapped(node, mapping) for node in nodes[at + 1 :]]
    return prefix + list(graft) + suffix, [mapping(out) for out in outs]


def _uses(nodes: Sequence[IRNode], outs: Sequence[int]) -> list[int]:
    counts = [0] * len(nodes)
    for arg in [a for node in nodes for a in node.args] + list(outs):
        counts[arg] += 1
    return counts


def _const(kind: IRType, value: float | int | bool | None = None) -> IRNode:
    """A CONST node; ``value=None`` means the type's zero."""
    if value is None:
        value = 0.0 if kind is IRType.FLOAT else False if kind is IRType.BOOL else 0
    return IRNode(kind=NodeKind.CONST, type=kind, value=value)


def _coerce(kind: IRType, value: object) -> float | int | bool | None:
    """Cast a folded value to the node's type, or ``None`` when it is not representable."""
    if kind is IRType.BOOL:
        return bool(value)
    if not isinstance(value, (int, float)) or not math.isfinite(float(value)):
        return None
    return int(value) if kind is IRType.INT else float(value)


def node_total(genome: ComputationalGenomeV1) -> int:
    """Flat node count (update then readout), the index space of :func:`ablate_node`."""
    return len(genome.update.nodes) + len(genome.readout.nodes)


# --------------------------------------------------------------------------- generator


def _primitives(
    alphabet: PrimitiveAlphabet, origin: PrimitiveOrigin | None
) -> tuple[Primitive, ...]:
    prims = (alphabet.get(name) for name in alphabet.names())
    return tuple(p for p in prims if origin is None or p.origin is origin)


class _Grower:
    """Grows typed expressions into a node list. Hash-consing keeps the DAG small."""

    def __init__(self, rng: random.Random, registers: Sequence[RegisterSpec], phase: ProgramPhase,
                 prims: Sequence[Primitive], *, base: int = 0) -> None:
        self.rng, self.registers, self.phase, self.base = rng, tuple(registers), phase, base
        self.nodes: list[IRNode] = []
        self._seen: dict[IRNode, int] = {}
        self._by_result: dict[IRType, list[Primitive]] = {}
        for prim in prims:
            self._by_result.setdefault(prim.result_type, []).append(prim)
        self._sources: dict[IRType, list[InputSource]] = {}
        for source in InputSource:  # enum order, never mapping order: determinism
            self._sources.setdefault(INPUT_TYPES[source], []).append(source)

    def add(self, node: IRNode) -> int:
        if node not in self._seen:
            self._seen[node] = self.base + len(self.nodes)
            self.nodes.append(node)
        return self._seen[node]

    def leaf(self, want: IRType) -> int:
        """INPUT (update only), else a register of the type, else a CONST."""
        regs = [i for i, spec in enumerate(self.registers) if spec.type is want]
        sources = self._sources.get(want, []) if self.phase is ProgramPhase.UPDATE else []
        draw = self.rng.random()
        if sources and draw < 0.5:
            source = self.rng.choice(sources)
            index = self.rng.randrange(FEATURE_WIDTH) if source is InputSource.FEATURE else 0
            return self.add(IRNode(kind=NodeKind.INPUT, type=want, source=source, index=index))
        if regs and draw < 0.8:
            reg = self.rng.choice(regs)
            lag = self.rng.randrange(self.registers[reg].ring)
            return self.add(IRNode(kind=NodeKind.REG, type=want, index=reg, lag=lag))
        if want is IRType.FLOAT:
            return self.add(_const(want, self.rng.choice(_FLOAT_CONSTANTS)))
        if want is IRType.INT:
            return self.add(_const(want, self.rng.randrange(_INT_CONSTANT_LIMIT)))
        return self.add(_const(want, self.rng.random() < 0.5))

    def grow(self, want: IRType, depth: int) -> int:
        choices = self._by_result.get(want, [])
        full = self.base + len(self.nodes) >= MAX_PROGRAM_NODES - _NODE_RESERVE
        if depth <= 0 or not choices or full or self.rng.random() < _LEAF_PROBABILITY:
            return self.leaf(want)
        prim = self.rng.choice(choices)
        args = tuple(self.grow(kind, depth - 1) for kind in prim.arg_types)
        return self.add(IRNode(kind=NodeKind.APPLY, type=want, primitive=prim.name, args=args))

    def view(self, register: int, depth: int) -> int:
        """A FLOAT reading of one register: the readout a random genome usually wants."""
        spec = self.registers[register]
        reg = self.add(IRNode(kind=NodeKind.REG, type=spec.type, index=register))
        casts = [p for p in self._by_result.get(IRType.FLOAT, []) if p.arg_types == (spec.type,)]
        if spec.type is IRType.FLOAT or not casts:
            return reg if spec.type is IRType.FLOAT else self.grow(IRType.FLOAT, depth)
        name = self.rng.choice(casts).name
        return self.add(IRNode(kind=NodeKind.APPLY, type=IRType.FLOAT, primitive=name, args=(reg,)))


def _random_register(rng: random.Random) -> RegisterSpec:
    draw = rng.random()
    ring = 1 if rng.random() < 0.75 else rng.randint(2, 3)
    if draw < 0.6:
        return RegisterSpec(type=IRType.FLOAT, ring=ring)
    if draw < 0.9:
        return RegisterSpec(type=IRType.INT, ring=ring)
    return RegisterSpec(type=IRType.BOOL, ring=ring, init=False)


def _random_draft(
    rng: random.Random, prims: Sequence[Primitive], registers_max: int, depth: int
) -> _Draft:
    registers = tuple(_random_register(rng) for _ in range(rng.randint(1, registers_max)))
    update = _Grower(rng, registers, ProgramPhase.UPDATE, prims)
    update_out = tuple(update.grow(spec.type, depth) for spec in registers)
    readout = _Grower(rng, registers, ProgramPhase.READOUT, prims)
    if rng.random() < 0.5:
        root = readout.view(rng.randrange(len(registers)), depth)
    else:
        root = readout.grow(IRType.FLOAT, depth)
    lookup: tuple[float, ...] = ()
    if any(n.primitive == "LOOKUP" for n in update.nodes + readout.nodes):
        lookup = tuple(round(rng.random(), 3) for _ in range(rng.randint(1, _LOOKUP_ENTRIES_MAX)))
    aggregation = rng.choice(tuple(SessionAggregation))
    return _Draft(registers, tuple(update.nodes), update_out, tuple(readout.nodes), (root,),
                  aggregation, lookup, 1)


def random_genome(
    rng: random.Random,
    *,
    alphabet: PrimitiveAlphabet = SEED_ALPHABET,
    max_registers: int = 3,
    max_depth: int = 3,
) -> ComputationalGenomeV1:
    """Draw one valid genome by rejection sampling over typed random DAGs.

    Rejection is sampling, not repair: an invalid draft is discarded whole. Failing
    ``_RANDOM_ATTEMPTS`` times in a row raises, because it means the generator and the IR
    disagree about the language — a defect to fix, not to hide.
    """
    if not 1 <= max_registers <= MAX_REGISTERS:
        raise ContractError(f"max_registers must be in [1, {MAX_REGISTERS}], got {max_registers}")
    if max_depth < 0:
        raise ContractError(f"max_depth must be >= 0, got {max_depth}")
    prims = _primitives(alphabet, None)
    last: ContractError | None = None
    for _ in range(_RANDOM_ATTEMPTS):
        try:
            draft = _random_draft(rng, prims, max_registers, max_depth)
            return _build(draft, alphabet, parents=(), label="RANDOM")
        except ContractError as exc:
            last = exc
    raise ContractError(f"random_genome: {_RANDOM_ATTEMPTS} invalid drafts in a row; last: {last}")


# --------------------------------------------------------------------------- operators

_Edit = _Draft | str  # a new draft, or a refusal reason
_BOTH: tuple[ProgramPhase, ...] = (ProgramPhase.UPDATE, ProgramPhase.READOUT)


def _pick(rng: random.Random, draft: _Draft, keep: Callable[[IRNode], bool],
          phases: Sequence[ProgramPhase] = _BOTH) -> tuple[ProgramPhase, int] | None:
    found = [(p, i) for p in phases for i, node in enumerate(draft.program(p)[0]) if keep(node)]
    return rng.choice(found) if found else None


def _op_replace(draft: _Draft, rng: random.Random, alphabet: PrimitiveAlphabet) -> _Edit:
    """Swap a primitive for another SEED primitive with the same signature."""
    seeds = _primitives(alphabet, PrimitiveOrigin.SEED)

    def alternatives(node: IRNode) -> list[Primitive]:
        if node.kind is not NodeKind.APPLY:
            return []
        now = alphabet.get(node.primitive)
        return [p for p in seeds if p.name != now.name and p.arg_types == now.arg_types
                and p.result_type is now.result_type]

    spot = _pick(rng, draft, lambda node: bool(alternatives(node)))
    if spot is None:
        return REFUSED_NOT_APPLICABLE
    phase, index = spot
    node = draft.program(phase)[0][index]
    swapped = replace(node, primitive=rng.choice(alternatives(node)).name)
    return draft.with_node(phase, index, swapped)


def _op_remove(draft: _Draft, rng: random.Random, alphabet: PrimitiveAlphabet) -> _Edit:
    """Subtractive evolution (§33): delete one APPLY node."""
    spot = _pick(rng, draft, lambda node: node.kind is NodeKind.APPLY)
    return REFUSED_NOT_APPLICABLE if spot is None else _delete_node(draft, *spot, rng)


def _delete_node(
    draft: _Draft, phase: ProgramPhase, index: int, rng: random.Random | None
) -> _Draft:
    """Rewire an APPLY's uses to a same-typed argument, else replace it by CONST zero."""
    nodes, outs = draft.program(phase)
    node = nodes[index]
    same = [arg for arg in node.args if nodes[arg].type is node.type]
    if not same:
        return draft.with_node(phase, index, _const(node.type))
    target = rng.choice(same) if rng is not None else same[0]
    return draft.with_program(phase, *_rewire(nodes, outs, index, target))


def _op_insert(draft: _Draft, rng: random.Random, alphabet: PrimitiveAlphabet,
               origin: PrimitiveOrigin = PrimitiveOrigin.SEED,
               phases: Sequence[ProgramPhase] = _BOTH) -> _Edit:
    """Wrap an operand in a new APPLY whose other arguments are fresh typed leaves."""
    prims = _primitives(alphabet, origin)

    def wrappers(kind: IRType) -> list[Primitive]:
        return [p for p in prims if kind in p.arg_types and p.result_type is kind]

    spot = _pick(rng, draft, lambda node: bool(wrappers(node.type)), phases)
    if spot is None:
        return REFUSED_NOT_APPLICABLE
    phase, at = spot
    nodes, outs = draft.program(phase)
    kind = nodes[at].type
    prim = rng.choice(wrappers(kind))
    slot = rng.choice([i for i, arg_type in enumerate(prim.arg_types) if arg_type is kind])
    grower = _Grower(rng, draft.registers, phase, prims, base=at + 1)
    args = tuple(at if i == slot else grower.leaf(t) for i, t in enumerate(prim.arg_types))
    grower.add(IRNode(kind=NodeKind.APPLY, type=kind, primitive=prim.name, args=args))
    return draft.with_program(phase, *_splice(nodes, outs, at, grower.nodes, wrap=True))


def _canonical_keys(nodes: Sequence[IRNode], alias: dict[int, int] | None = None) -> list[object]:
    """Structural identity per node; ``alias`` reads register ``s`` as ``r`` for MERGE."""
    keys: list[object] = []
    for node in nodes:
        index = node.index
        if node.kind is NodeKind.REG:
            index = (alias or {}).get(index, index)
        keys.append((node.kind, node.type, node.primitive, tuple(keys[a] for a in node.args),
                     node.source, index, node.lag, repr(node.value)))
    return keys


def _op_merge(draft: _Draft, rng: random.Random, alphabet: PrimitiveAlphabet) -> _Edit:
    """Common-subexpression merge of identical nodes, or of identical registers."""
    options: list[tuple[ProgramPhase | None, int, int]] = []
    for phase in _BOTH:
        first: dict[object, int] = {}
        for index, key in enumerate(_canonical_keys(draft.program(phase)[0])):
            if key in first:
                options.append((phase, first[key], index))
            first.setdefault(key, index)
    for s in range(len(draft.registers)):
        for r in range(s):
            keys = _canonical_keys(draft.update, {s: r})
            same_output = keys[draft.update_out[r]] == keys[draft.update_out[s]]
            if draft.registers[r] == draft.registers[s] and same_output:
                options.append((None, r, s))
    if not options:
        return REFUSED_NOT_APPLICABLE
    where, keep, drop = rng.choice(options)
    if where is None:
        return _drop_register(draft, keep, drop)
    return draft.with_program(where, *_rewire(*draft.program(where), drop, keep))


def _drop_register(draft: _Draft, keep: int, drop: int) -> _Draft:
    """Remove register ``drop`` (its reads now read ``keep``) and renumber the rest."""

    def renumber(node: IRNode) -> IRNode:
        if node.kind is not NodeKind.REG or node.index < drop:
            return node
        return replace(node, index=keep if node.index == drop else node.index - 1)

    staged = replace(draft, registers=draft.registers[:drop] + draft.registers[drop + 1 :])
    outs = draft.update_out[:drop] + draft.update_out[drop + 1 :]
    staged = staged.with_program(ProgramPhase.UPDATE, [renumber(n) for n in draft.update], outs)
    readout = [renumber(n) for n in draft.readout]
    return staged.with_program(ProgramPhase.READOUT, readout, draft.readout_out)


def _op_split(draft: _Draft, rng: random.Random, alphabet: PrimitiveAlphabet) -> _Edit:
    """Duplicate a shared node so one of its consumers can diverge."""
    shared = [(p, i) for p in _BOTH for i, n in enumerate(_uses(*draft.program(p))) if n >= 2]
    if not shared:
        return REFUSED_NOT_APPLICABLE
    phase, at = rng.choice(shared)
    nodes, outs = draft.program(phase)
    suffix = [_mapped(n, lambda a: a + 1 if a > at else a) for n in nodes[at + 1 :]]
    new_nodes = [*nodes[: at + 1], nodes[at], *suffix]
    new_outs = [out + 1 if out > at else out for out in outs]
    uses = [(i, k) for i, n in enumerate(new_nodes) if i > at + 1
            for k, a in enumerate(n.args) if a == at]
    uses += [(-1, k) for k, out in enumerate(new_outs) if out == at]
    consumer, slot = rng.choice(uses)
    if consumer < 0:
        new_outs[slot] = at + 1
    else:
        args = list(new_nodes[consumer].args)
        args[slot] = at + 1
        new_nodes[consumer] = replace(new_nodes[consumer], args=tuple(args))
    return draft.with_program(phase, new_nodes, new_outs)


def _op_factorize(draft: _Draft, rng: random.Random, alphabet: PrimitiveAlphabet) -> _Edit:
    """Move a readout subexpression into a new register the update computes every event.

    Readout ``REG r lag 0`` is the value after the latest update, which in the update program
    is ``update.outputs[r]``; readout ``lag k`` is update ``lag k-1``. The new register holds
    exactly what the readout computed (up to FLOAT quantisation below 64 bits). A repeated
    subexpression is preferred when one exists.
    """
    counts = _uses(draft.readout, draft.readout_out)
    eligible = [i for i, n in enumerate(draft.readout)
                if n.kind is NodeKind.APPLY and _liftable(draft.readout, i, alphabet)]
    if not eligible:
        return REFUSED_NOT_APPLICABLE
    at = rng.choice([i for i in eligible if counts[i] >= 2] or eligible)
    graft, root = _lift(draft, at)
    kind = draft.readout[at].type
    spec = RegisterSpec(type=kind, init=False) if kind is IRType.BOOL else RegisterSpec(type=kind)
    staged = replace(draft, registers=(*draft.registers, spec)).with_program(
        ProgramPhase.UPDATE, (*draft.update, *graft), (*draft.update_out, root))
    reg = IRNode(kind=NodeKind.REG, type=kind, index=len(draft.registers))
    return staged.with_node(ProgramPhase.READOUT, at, reg)


def _liftable(nodes: Sequence[IRNode], at: int, alphabet: PrimitiveAlphabet) -> bool:
    node = nodes[at]
    if node.kind is NodeKind.APPLY:
        if alphabet.get(node.primitive).side_table:
            return False  # a per-session table read per event is a different computation
        return all(_liftable(nodes, arg, alphabet) for arg in node.args)
    return node.kind in (NodeKind.REG, NodeKind.CONST)


def _lift(draft: _Draft, at: int) -> tuple[list[IRNode], int]:
    graft: list[IRNode] = []
    placed: dict[int, int] = {}

    def place(index: int) -> int:
        if index not in placed:
            node = draft.readout[index]
            if node.kind is NodeKind.REG and node.lag == 0:
                placed[index] = draft.update_out[node.index]
                return placed[index]
            if node.kind is NodeKind.REG:
                graft.append(replace(node, lag=node.lag - 1))
            else:
                graft.append(replace(node, args=tuple(place(arg) for arg in node.args)))
            placed[index] = len(draft.update) + len(graft) - 1
        return placed[index]

    return graft, place(at)


def _op_sparsify(draft: _Draft, rng: random.Random, alphabet: PrimitiveAlphabet) -> _Edit:
    """Activate only required pathways: an INPUT becomes CONST zero."""
    spot = _pick(rng, draft, lambda n: n.kind is NodeKind.INPUT, (ProgramPhase.UPDATE,))
    if spot is None:
        return REFUSED_NOT_APPLICABLE
    return draft.with_node(*spot, _const(draft.update[spot[1]].type))


def _foldable(nodes: Sequence[IRNode], node: IRNode, alphabet: PrimitiveAlphabet) -> bool:
    if node.kind is not NodeKind.APPLY or node.primitive == "LOOKUP":
        return False  # LOOKUP depends on the genome's table, not only on its arguments
    prim = alphabet.get(node.primitive)
    if prim.side_table or prim.origin is not PrimitiveOrigin.SEED:
        return False
    return all(nodes[arg].kind is NodeKind.CONST for arg in node.args)


def _op_specialize(draft: _Draft, rng: random.Random, alphabet: PrimitiveAlphabet) -> _Edit:
    """Partial evaluation: fold one all-CONST APPLY into a CONST."""
    found = [(p, i) for p in _BOTH for i, n in enumerate(draft.program(p)[0])
             if _foldable(draft.program(p)[0], n, alphabet)]
    if not found:
        return REFUSED_NOT_APPLICABLE
    phase, index = rng.choice(found)
    nodes = draft.program(phase)[0]
    node = nodes[index]
    try:
        value = alphabet.get(node.primitive).fn(*(nodes[arg].value for arg in node.args))
    except (ArithmeticError, ValueError, TypeError) as exc:
        return f"FOLD_FAILED: {node.primitive}: {exc}"
    folded = _coerce(node.type, value)
    if folded is None:
        return f"FOLD_FAILED: {node.primitive} gave a non-finite {value!r}"
    return draft.with_node(phase, index, _const(node.type, folded))


def _op_compress(draft: _Draft, rng: random.Random, alphabet: PrimitiveAlphabet) -> _Edit:
    """Halve a FLOAT register's precision, or drop one slot of a ring."""
    moves = [(r, "precision") for r, s in enumerate(draft.registers)
             if s.type is IRType.FLOAT and s.precision_bits > 1]
    moves += [(r, "ring") for r, s in enumerate(draft.registers) if s.ring > 1]
    if not moves:
        return REFUSED_NOT_APPLICABLE
    register, what = rng.choice(moves)
    spec = draft.registers[register]
    if what == "precision":
        spec = replace(spec, precision_bits=max(1, spec.precision_bits // 2))
    else:  # a read at the dropped lag makes the child invalid: the IR refuses it (LAG_BOUND)
        spec = replace(spec, ring=spec.ring - 1)
    registers = (*draft.registers[:register], spec, *draft.registers[register + 1 :])
    return replace(draft, registers=registers)


def _op_developmental(draft: _Draft, rng: random.Random, alphabet: PrimitiveAlphabet) -> _Edit:
    """Change the phenotype-construction rule: the session aggregation."""
    others = [a for a in SessionAggregation if a is not draft.aggregation]
    return replace(draft, aggregation=rng.choice(others))


def _op_macro_insert(draft: _Draft, rng: random.Random, alphabet: PrimitiveAlphabet) -> _Edit:
    """INSERT restricted to PROMOTED macros, in the update program; stored expanded."""
    if not _primitives(alphabet, PrimitiveOrigin.PROMOTED):
        return REFUSED_NO_MACRO
    return _op_insert(draft, rng, alphabet, PrimitiveOrigin.PROMOTED, (ProgramPhase.UPDATE,))


def _subtree(nodes: Sequence[IRNode], root: int, start: int) -> list[IRNode]:
    """Copy ``root``'s subtree in index order, renumbered to begin at ``start``."""
    live: set[int] = set()
    stack = [root]
    while stack:
        index = stack.pop()
        if index not in live:
            live.add(index)
            stack.extend(nodes[index].args)
    remap = {old: start + position for position, old in enumerate(sorted(live))}
    return [_mapped(nodes[old], remap.__getitem__) for old in sorted(live)]


def _crossover_draft(a: _Draft, b: _Draft, rng: random.Random) -> _Edit:
    target = rng.randrange(len(a.update)) if a.update else -1
    donors = [i for i, n in enumerate(b.update) if target >= 0 and n.type is a.update[target].type]
    if not donors:
        return REFUSED_NOT_APPLICABLE
    graft = _subtree(b.update, rng.choice(donors), target)
    # A donor REG naming a register ``a`` lacks, or of another type, is left as is: the IR
    # refuses the child and the refusal is counted.
    return a.with_program(ProgramPhase.UPDATE, *_splice(a.update, a.update_out, target, graft,
                                                        wrap=False))


_OPERATORS: dict[VariationOperator, Callable[[_Draft, random.Random, PrimitiveAlphabet], _Edit]] = {
    VariationOperator.REPLACE: _op_replace,
    VariationOperator.MERGE: _op_merge,
    VariationOperator.SPLIT: _op_split,
    VariationOperator.FACTORIZE: _op_factorize,
    VariationOperator.SPARSIFY: _op_sparsify,
    VariationOperator.SPECIALIZE: _op_specialize,
    VariationOperator.REMOVE: _op_remove,
    VariationOperator.COMPRESS: _op_compress,
    VariationOperator.DEVELOPMENTAL: _op_developmental,
    VariationOperator.INSERT: _op_insert,
    VariationOperator.MACRO_INSERT: _op_macro_insert,
}


def _finish(operator: VariationOperator, edit: _Edit, parents: tuple[ComputationalGenomeV1, ...],
            alphabet: PrimitiveAlphabet) -> Mutation:
    if isinstance(edit, str):
        return Mutation(operator, None, edit)
    lineage = tuple(dict.fromkeys(parent.digest for parent in parents))
    try:
        child = _build(edit, alphabet, parents=lineage, label=operator.value)
    except ContractError as exc:
        return Mutation(operator, None, f"{getattr(exc, 'code', 'CONTRACT')}: {exc}")
    if child.digest == parents[0].digest:
        return Mutation(operator, None, REFUSED_NO_CHANGE)
    return Mutation(operator, child, "")


def mutate(
    genome: ComputationalGenomeV1,
    operator: VariationOperator,
    rng: random.Random,
    *,
    alphabet: PrimitiveAlphabet = SEED_ALPHABET,
) -> Mutation:
    """Apply one operator. The IR validator, never this function, decides validity."""
    if operator is VariationOperator.MOVE:
        return Mutation(operator, None, REFUSED_NO_BACKEND)
    if operator is VariationOperator.CROSSOVER:
        return crossover(genome, genome, rng, alphabet=alphabet)
    edit = _OPERATORS[operator](_draft_of(genome), rng, alphabet)
    return _finish(operator, edit, (genome,), alphabet)


def crossover(
    a: ComputationalGenomeV1,
    b: ComputationalGenomeV1,
    rng: random.Random,
    *,
    alphabet: PrimitiveAlphabet = SEED_ALPHABET,
) -> Mutation:
    """Graft a typed subtree of ``b``'s update into ``a``'s update; ``a`` keeps its registers."""
    edit = _crossover_draft(_draft_of(a), _draft_of(b), rng)
    return _finish(VariationOperator.CROSSOVER, edit, (a, b), alphabet)


# --------------------------------------------------------------------------- utility


def ablate_node(
    genome: ComputationalGenomeV1, node_index: int, *, alphabet: PrimitiveAlphabet = SEED_ALPHABET
) -> ComputationalGenomeV1 | None:
    """``A without c``: the deterministic REMOVE of node ``c`` (flat index).

    APPLY: uses rewired to the first same-typed argument, else CONST zero. INPUT: CONST zero.
    REG: CONST of the register's ``init``. CONST has nothing to remove (``None``). An ablation
    the IR refuses is ``None`` — never a repaired stand-in.
    """
    width = len(genome.update.nodes)
    if not 0 <= node_index < node_total(genome):
        raise ContractError(f"node_index {node_index} outside [0, {node_total(genome)})")
    phase = ProgramPhase.UPDATE if node_index < width else ProgramPhase.READOUT
    index = node_index if node_index < width else node_index - width
    draft = _draft_of(genome)
    node = draft.program(phase)[0][index]
    if node.kind is NodeKind.APPLY:
        edited = _delete_node(draft, phase, index, None)
    elif node.kind is NodeKind.INPUT:
        edited = draft.with_node(phase, index, _const(node.type))
    elif node.kind is NodeKind.REG:
        init = _coerce(node.type, draft.registers[node.index].init)
        edited = draft.with_node(phase, index, _const(node.type, init))
    else:
        return None
    try:
        return _build(edited, alphabet, parents=(genome.digest,), label="ABLATE")
    except ContractError:
        return None


def unique_utility(
    genome: ComputationalGenomeV1, node_index: int, suite: EvaluationSuite, *, meter: WorkMeter
) -> float | None:
    """Architecture §33: ``U(A) - U(A without c)`` on worst-case train AP.

    ``None`` when node ``c`` cannot be removed or either utility is unmeasured. Both
    evaluations are charged to ``meter``; the caller's budget bounds this like any search.
    """
    ablated = ablate_node(genome, node_index)
    if ablated is None:
        return None
    full = evaluate(genome, suite, meter=meter).worst_case_ap
    without = evaluate(ablated, suite, meter=meter).worst_case_ap
    return None if full is None or without is None else full - without
