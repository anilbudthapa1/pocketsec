"""D9.5 — the ONTOGENESIS typed IR: the language every Stage 9 genome is written in.

Stage 9 searches for the cheapest computation that does the security job. A search is only
as honest as the language it searches, so this module exists to make three properties hold
**by construction** rather than by observation:

* **Termination.** A program is a tuple of nodes whose argument indices are strictly smaller
  than their own index: a DAG executed once per event, in index order. There is no jump,
  loop or call node kind, so every well-formed program executes exactly ``len(nodes)``
  steps per event. A loop can only be written as a self reference (``SELF_REFERENCE``) or a
  forward reference (``FORWARD_REFERENCE``), and both are refused when the
  :class:`IRProgram` is constructed. Recursion can only be written as a macro that names
  itself; :mod:`pocketsec.stage9.foundry.primitives` refuses it (``MACRO_CYCLE``).
* **Bounded memory.** Registers, ring depth, constants, lookup entries, lineages and side
  tables all have a cap declared here. A ring above :data:`MAX_RING` cannot be constructed
  (``RING_BOUND``); more lineages than :data:`MAX_LINEAGES` are cut at run time by counted
  LRU eviction in :mod:`pocketsec.stage9.chemistry.phenotype`.
* **Exact static cost.** :func:`static_bounds` computes work units (WU) per event and bytes
  per session from the program text alone. The interpreter charges exactly that, so the
  cost axis of the search's Pareto front is a property of the genome, not a timing.

Values are typed (:class:`IRType`). ``FLOAT`` carries magnitudes, ``INT`` carries 64-bit
masks and enum ids, ``BOOL`` carries comparisons. Keeping them apart is what lets
:func:`validate_program` decide type correctness instead of guessing at it.

What this module refuses to do: it never evaluates text (no ``eval``/``exec``/``compile``),
it never repairs an ill-typed program, and it reads only :class:`EncodedTransition` fields
(``InputSource``); identity and display names are unreachable from the language (ADR-0007).
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage2.encoder.ssir_encoder import FEATURE_WIDTH

if TYPE_CHECKING:  # pragma: no cover - typing only; primitives.py imports this module
    from pocketsec.stage9.foundry.primitives import PrimitiveAlphabet

__all__ = [
    "CONST_WU",
    "FLOAT_CLAMP",
    "INPUT_TYPES",
    "INPUT_WU",
    "INT_MASK",
    "IR_ERROR_CODES",
    "IR_VERSION",
    "LINEAGE_OVERHEAD_BYTES",
    "MAX_CONSTANTS",
    "MAX_EVICTED_READOUTS",
    "MAX_LINEAGES",
    "MAX_LOOKUP_ENTRIES",
    "MAX_MACRO_DEPTH",
    "MAX_MACRO_NODES",
    "MAX_PRECISION_BITS",
    "MAX_PROGRAM_NODES",
    "MAX_REGISTERS",
    "MAX_RING",
    "MAX_SESSION_EVENTS",
    "REG_WU",
    "SIDE_ENTRY_BYTES",
    "SIDE_TABLE_ENTRIES",
    "VALUE_BYTES",
    "IRError",
    "IRNode",
    "IRProgram",
    "IRType",
    "InputSource",
    "NodeKind",
    "ProgramPhase",
    "ProgramReport",
    "RegisterSpec",
    "StaticBounds",
    "TypedIR",
    "check_references",
    "clamp_float",
    "coerce_value",
    "node_work_units",
    "quantise",
    "static_bounds",
    "validate_program",
]

IR_VERSION = "pocketsec-onto-ir.1.0.0"

#: Every bound below is a CHOSEN parameter (spec §4.21), not a measurement.
MAX_PROGRAM_NODES = 32
MAX_REGISTERS = 8
MAX_RING = 8
MAX_CONSTANTS = 32
MAX_LOOKUP_ENTRIES = 32
MAX_LINEAGES = 16
MAX_SESSION_EVENTS = 4096
SIDE_TABLE_ENTRIES = 256
#: Stage 3's ``SLOT_BYTES = 8`` precedent: one accounted slot per stored value.
VALUE_BYTES = 8
LINEAGE_OVERHEAD_BYTES = 64
SIDE_ENTRY_BYTES = 16
MAX_MACRO_DEPTH = 2
MAX_MACRO_NODES = 8
#: A double carries 53 significand bits; 64 is accepted and means "no quantisation".
MAX_PRECISION_BITS = 64

#: Every lineage readout needs at least one event to have activated the lineage, so a
#: session can read out at most MAX_SESSION_EVENTS lineages: MAX_LINEAGES live ones plus
#: this many evicted ones. Arithmetic from the bounds above, not a measurement.
MAX_EVICTED_READOUTS = MAX_SESSION_EVENTS - MAX_LINEAGES

INT_MASK = (1 << 64) - 1
#: Every FLOAT result is clamped here, so no primitive chain can overflow to inf.
FLOAT_CLAMP = 1e12

#: Work units per node kind; an APPLY node costs its primitive's ``work_units``.
INPUT_WU = 1
REG_WU = 1
CONST_WU = 0

IR_ERROR_CODES: frozenset[str] = frozenset(
    {
        "FORWARD_REFERENCE", "SELF_REFERENCE", "TYPE_MISMATCH", "UNKNOWN_PRIMITIVE",
        "ARITY", "NODE_BOUND", "REGISTER_BOUND", "RING_BOUND", "CONST_BOUND",
        "LOOKUP_BOUND", "FEATURE_INDEX", "INPUT_IN_READOUT", "PARAM_OUTSIDE_MACRO",
        "OUTPUT_TYPE", "OUTPUT_COUNT", "LAG_BOUND", "MACRO_CYCLE", "MACRO_DEPTH",
        "MACRO_SIZE", "DECLARED_BOUND_UNDERSTATED", "PRECISION_BOUND",
    }
)


class IRError(ContractError):
    """A genome program violates the typed IR; ``code`` names which rule (spec §4.3)."""

    def __init__(self, code: str, detail: str) -> None:
        if code not in IR_ERROR_CODES:
            raise ContractError(f"IRError raised with an unknown code {code!r}: {detail}")
        super().__init__(f"{code}: {detail}")
        self.code = code
        self.detail = detail


class IRType(StrEnum):
    FLOAT = "FLOAT"
    INT = "INT"  # a 64-bit mask: every INT result is ``& INT_MASK``
    BOOL = "BOOL"


class InputSource(StrEnum):
    """The only things a genome may read: :class:`EncodedTransition` fields (spec §3.2)."""

    FEATURE = "FEATURE"
    DELTA_PHI = "DELTA_PHI"
    STATE_DELTA_MASK = "STATE_DELTA_MASK"
    RELATION = "RELATION"
    RELATION_FAMILY = "RELATION_FAMILY"
    TIME_BUCKET = "TIME_BUCKET"
    OBJECT_PROPERTY_MASK = "OBJECT_PROPERTY_MASK"
    EPOCH_ID = "EPOCH_ID"
    LINEAGE_FIRST_EVENT = "LINEAGE_FIRST_EVENT"


INPUT_TYPES: Mapping[InputSource, IRType] = MappingProxyType(
    {
        InputSource.FEATURE: IRType.FLOAT,
        InputSource.DELTA_PHI: IRType.FLOAT,
        InputSource.STATE_DELTA_MASK: IRType.INT,
        InputSource.RELATION: IRType.INT,
        InputSource.RELATION_FAMILY: IRType.INT,
        InputSource.TIME_BUCKET: IRType.INT,
        InputSource.OBJECT_PROPERTY_MASK: IRType.INT,
        InputSource.EPOCH_ID: IRType.INT,
        InputSource.LINEAGE_FIRST_EVENT: IRType.BOOL,
    }
)


class NodeKind(StrEnum):
    """Node kinds. There is deliberately no JUMP, LOOP or CALL member: that absence is
    the termination argument. PARAM exists only inside a macro body."""

    INPUT = "INPUT"
    CONST = "CONST"
    REG = "REG"
    APPLY = "APPLY"
    PARAM = "PARAM"


class ProgramPhase(StrEnum):
    UPDATE = "UPDATE"  # once per event, per lineage; outputs are the new register values
    READOUT = "READOUT"  # once per lineage at session end (or at eviction); one FLOAT


def clamp_float(value: float) -> float:
    """Clamp to ±:data:`FLOAT_CLAMP`; NaN becomes 0.0 so equality stays deterministic."""
    if value != value:  # NaN is the only value unequal to itself
        return 0.0
    if value > FLOAT_CLAMP:
        return FLOAT_CLAMP
    if value < -FLOAT_CLAMP:
        return -FLOAT_CLAMP
    return float(value)


def quantise(value: float, bits: int) -> float:
    """Round ``value`` to ``bits`` significand bits, round-half-even (register writes).

    ``bits >= 53`` is the identity: a double has no more to give. Precision is how the
    genome's ``compression_law`` trades distinguishability for bytes, so it must be exact.
    """
    if bits >= 53 or value == 0.0:
        return value
    mantissa, exponent = math.frexp(value)  # mantissa in [0.5, 1)
    return math.ldexp(round(mantissa * (1 << bits)), exponent - bits)


def coerce_value(value: object, type_: IRType, what: str) -> float | int | bool:
    """Normalise a literal to its IR type, or refuse it (``TYPE_MISMATCH``).

    Normalising (``0`` -> ``0.0`` for FLOAT, and ``-0.0`` -> ``0.0``) keeps canonical JSON,
    and therefore every digest built on it, independent of how a caller spelled a number.
    The signed zero matters (S9-R6): ``0.0 == -0.0`` and they hash equal, so node and genome
    equality already treat them as one value, but JSON writes them differently, and the
    memoised genome digest then depended on which of two equal genomes was hashed first.
    No seed primitive distinguishes them (``DIV`` guards ``y == 0.0``), so this changes no
    score.
    """
    if type_ is IRType.BOOL:
        if not isinstance(value, bool):
            raise IRError("TYPE_MISMATCH", f"{what}: BOOL needs a bool, got {value!r}")
        return value
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise IRError("TYPE_MISMATCH", f"{what}: {type_} needs a number, got {value!r}")
    if type_ is IRType.INT:
        if not isinstance(value, int) or not 0 <= value <= INT_MASK:
            raise IRError("TYPE_MISMATCH", f"{what}: INT needs an int in [0, 2^64), got {value!r}")
        return value
    number = float(value)
    if not math.isfinite(number) or abs(number) > FLOAT_CLAMP:
        raise IRError("TYPE_MISMATCH", f"{what}: FLOAT literal must be finite, |x| <= 1e12")
    return number + 0.0  # -0.0 + 0.0 == +0.0: one spelling of zero


def _as_enum(enum_type: type[StrEnum], value: object, what: str) -> Any:
    wanted = enum_type.__name__
    if not isinstance(value, str):
        raise IRError("TYPE_MISMATCH", f"{what}: {value!r} is not a {wanted}")
    try:
        return enum_type(value)
    except ValueError as error:
        raise IRError("TYPE_MISMATCH", f"{what}: {value!r} is not a {wanted}") from error


def _plain_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


@dataclass(frozen=True, slots=True)
class IRNode:
    """One node. Only the fields its ``kind`` uses may be set; the rest stay default,
    so two spellings of the same node cannot have two digests."""

    kind: NodeKind
    type: IRType
    primitive: str = ""  # APPLY
    args: tuple[int, ...] = ()  # APPLY; each arg index < this node's index
    source: InputSource | None = None  # INPUT
    index: int = 0  # FEATURE index 0..95 | register | PARAM position
    lag: int = 0  # REG: 0 .. ring-1
    value: float | int | bool | None = None  # CONST

    def __post_init__(self) -> None:
        kind = _as_enum(NodeKind, self.kind, "IRNode.kind")
        type_ = _as_enum(IRType, self.type, "IRNode.type")
        object.__setattr__(self, "kind", kind)
        object.__setattr__(self, "type", type_)
        if not isinstance(self.args, tuple) or not all(_plain_int(a) for a in self.args):
            raise IRError("ARITY", f"IRNode.args must be a tuple of ints, got {self.args!r}")
        if not _plain_int(self.index) or not _plain_int(self.lag):
            raise IRError("TYPE_MISMATCH", "IRNode.index and IRNode.lag must be ints")
        if kind is not NodeKind.APPLY and (self.args or self.primitive):
            raise IRError("ARITY", f"a {kind} node carries no primitive and no args")
        if kind is not NodeKind.INPUT and self.source is not None:
            raise IRError("TYPE_MISMATCH", f"a {kind} node carries no input source")
        if kind is not NodeKind.CONST and self.value is not None:
            raise IRError("TYPE_MISMATCH", f"a {kind} node carries no constant value")
        if kind is not NodeKind.REG and self.lag != 0:
            raise IRError("LAG_BOUND", f"a {kind} node carries no lag")
        _check_kind_fields(self, kind, type_)

    def to_dict(self) -> dict[str, Any]:
        """Canonical JSON form; every field is written, so the form is exact-keyed."""
        return {
            "kind": self.kind.value,
            "type": self.type.value,
            "primitive": self.primitive,
            "args": list(self.args),
            "source": None if self.source is None else self.source.value,
            "index": self.index,
            "lag": self.lag,
            "value": self.value,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> IRNode:
        _exact_keys(payload, _NODE_KEYS, "IRNode")
        return cls(
            kind=payload["kind"],
            type=payload["type"],
            primitive=payload["primitive"],
            args=tuple(payload["args"]),
            source=payload["source"],
            index=payload["index"],
            lag=payload["lag"],
            value=payload["value"],
        )


_NODE_KEYS = frozenset({"kind", "type", "primitive", "args", "source", "index", "lag", "value"})


def _exact_keys(payload: Mapping[str, Any], keys: frozenset[str], what: str) -> None:
    if not isinstance(payload, Mapping) or set(payload) != keys:
        got = sorted(payload) if isinstance(payload, Mapping) else type(payload).__name__
        raise ContractError(f"{what} payload must have exactly {sorted(keys)}, got {got}")


def _check_kind_fields(node: IRNode, kind: NodeKind, type_: IRType) -> None:
    """Per-kind field rules; normalises ``source`` and ``value`` in place (construction)."""
    if kind is NodeKind.INPUT:
        source = _as_enum(InputSource, node.source, "IRNode.source")
        object.__setattr__(node, "source", source)
        if INPUT_TYPES[source] is not type_:
            raise IRError("TYPE_MISMATCH", f"{source} is {INPUT_TYPES[source]}, node says {type_}")
        if source is InputSource.FEATURE:
            if not 0 <= node.index < FEATURE_WIDTH:
                raise IRError(
                    "FEATURE_INDEX", f"feature {node.index} outside 0..{FEATURE_WIDTH - 1}"
                )
        elif node.index != 0:
            raise IRError("FEATURE_INDEX", f"{source} takes no index, got {node.index}")
    elif kind is NodeKind.CONST:
        object.__setattr__(node, "value", coerce_value(node.value, type_, "CONST"))
        if node.index != 0:
            raise IRError("TYPE_MISMATCH", "a CONST node carries no index")
    elif kind is NodeKind.REG:
        if not 0 <= node.index < MAX_REGISTERS:
            raise IRError("REGISTER_BOUND", f"register {node.index} outside 0..{MAX_REGISTERS - 1}")
        if not 0 <= node.lag < MAX_RING:
            raise IRError("LAG_BOUND", f"lag {node.lag} outside 0..{MAX_RING - 1}")
    elif kind is NodeKind.APPLY:
        if not isinstance(node.primitive, str) or not node.primitive:
            raise IRError("UNKNOWN_PRIMITIVE", "an APPLY node must name a primitive")
        if node.index != 0:
            raise IRError("TYPE_MISMATCH", "an APPLY node carries no index")
    elif not 0 <= node.index < MAX_MACRO_NODES:  # PARAM
        raise IRError("ARITY", f"PARAM position {node.index} outside 0..{MAX_MACRO_NODES - 1}")


@dataclass(frozen=True, slots=True)
class RegisterSpec:
    """One per-lineage register. ``ring > 1`` keeps the last ``ring`` values (lag 0 newest).

    Refused at construction, so an unbounded allocation is unconstructible: a ring above
    :data:`MAX_RING` (``RING_BOUND``) or a precision outside 1..64 (``PRECISION_BOUND``).
    """

    type: IRType
    ring: int = 1
    precision_bits: int = 64  # FLOAT writes are quantised to this many significand bits
    init: float | int | bool = 0

    def __post_init__(self) -> None:
        type_ = _as_enum(IRType, self.type, "RegisterSpec.type")
        object.__setattr__(self, "type", type_)
        if not _plain_int(self.ring) or not 1 <= self.ring <= MAX_RING:
            raise IRError("RING_BOUND", f"ring {self.ring!r} outside 1..{MAX_RING}")
        bits = self.precision_bits
        if not _plain_int(bits) or not 1 <= bits <= MAX_PRECISION_BITS:
            raise IRError("PRECISION_BOUND", f"precision_bits {bits!r} outside 1..64")
        init: object = self.init
        # The spec's default ``init = 0`` must mean "zero" for every type, so a BOOL
        # register accepts the ints 0 and 1 as False and True; CONST literals stay strict.
        if type_ is IRType.BOOL and _plain_int(init) and init in (0, 1):
            init = bool(init)
        init = coerce_value(init, type_, "RegisterSpec.init")
        if type_ is IRType.FLOAT:
            init = quantise(float(init), bits)
        object.__setattr__(self, "init", init)

    @property
    def state_bytes(self) -> int:
        return self.ring * VALUE_BYTES

    def to_dict(self) -> dict[str, Any]:
        return {
            "type": self.type.value,
            "ring": self.ring,
            "precision_bits": self.precision_bits,
            "init": self.init,
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> RegisterSpec:
        _exact_keys(payload, frozenset({"type", "ring", "precision_bits", "init"}), "RegisterSpec")
        return cls(
            type=payload["type"],
            ring=payload["ring"],
            precision_bits=payload["precision_bits"],
            init=payload["init"],
        )


def check_references(nodes: Sequence[IRNode]) -> None:
    """Refuse any APPLY argument that is not strictly earlier: the loop prohibition.

    Shared by :class:`IRProgram` and macro bodies, so there is one definition of "DAG".
    """
    for position, node in enumerate(nodes):
        for arg in node.args:
            if arg == position:
                raise IRError("SELF_REFERENCE", f"node {position} names itself as an argument")
            if arg > position or arg < 0:
                raise IRError(
                    "FORWARD_REFERENCE", f"node {position} names node {arg}, not strictly earlier"
                )


@dataclass(frozen=True, slots=True)
class IRProgram:
    """A typed DAG run once per event (UPDATE) or once per lineage (READOUT).

    Construction checks everything that needs no alphabet and no registers: size, the
    DAG rule, PARAM/INPUT placement, output count and readout type. :func:`validate_program`
    adds the checks that do.
    """

    phase: ProgramPhase
    nodes: tuple[IRNode, ...]
    outputs: tuple[int, ...]  # UPDATE: one per register; READOUT: exactly one FLOAT

    def __post_init__(self) -> None:
        phase = _as_enum(ProgramPhase, self.phase, "IRProgram.phase")
        object.__setattr__(self, "phase", phase)
        if not isinstance(self.nodes, tuple) or not all(isinstance(n, IRNode) for n in self.nodes):
            raise IRError("TYPE_MISMATCH", "IRProgram.nodes must be a tuple of IRNode")
        if not isinstance(self.outputs, tuple) or not all(_plain_int(o) for o in self.outputs):
            raise IRError("OUTPUT_COUNT", "IRProgram.outputs must be a tuple of ints")
        if not 1 <= len(self.nodes) <= MAX_PROGRAM_NODES:
            raise IRError("NODE_BOUND", f"{len(self.nodes)} nodes outside 1..{MAX_PROGRAM_NODES}")
        check_references(self.nodes)
        _check_placement(self)
        _check_outputs(self)

    def to_dict(self) -> dict[str, Any]:
        return {
            "phase": self.phase.value,
            "nodes": [node.to_dict() for node in self.nodes],
            "outputs": list(self.outputs),
        }

    @classmethod
    def from_dict(cls, payload: Mapping[str, Any]) -> IRProgram:
        _exact_keys(payload, frozenset({"phase", "nodes", "outputs"}), "IRProgram")
        return cls(
            phase=payload["phase"],
            nodes=tuple(IRNode.from_dict(node) for node in payload["nodes"]),
            outputs=tuple(payload["outputs"]),
        )


#: The integration plan's exposed name (spec §3.3).
TypedIR = IRProgram


def _check_placement(program: IRProgram) -> None:
    constants = 0
    for position, node in enumerate(program.nodes):
        if node.kind is NodeKind.PARAM:
            raise IRError("PARAM_OUTSIDE_MACRO", f"node {position} is a PARAM outside a macro")
        if node.kind is NodeKind.INPUT and program.phase is ProgramPhase.READOUT:
            raise IRError("INPUT_IN_READOUT", f"node {position} reads an input in a readout")
        constants += node.kind is NodeKind.CONST
    if constants > MAX_CONSTANTS:
        raise IRError("CONST_BOUND", f"{constants} constants above {MAX_CONSTANTS}")


def _check_outputs(program: IRProgram) -> None:
    for output in program.outputs:
        if not 0 <= output < len(program.nodes):
            raise IRError("FORWARD_REFERENCE", f"output {output} names no node")
    if program.phase is ProgramPhase.READOUT:
        if len(program.outputs) != 1:
            raise IRError("OUTPUT_COUNT", f"a readout has one output, got {program.outputs}")
        if program.nodes[program.outputs[0]].type is not IRType.FLOAT:
            raise IRError("OUTPUT_TYPE", "a readout's output must be FLOAT")
    elif not 1 <= len(program.outputs) <= MAX_REGISTERS:
        raise IRError("OUTPUT_COUNT", f"an update writes 1..{MAX_REGISTERS} registers")


@dataclass(frozen=True, slots=True)
class ProgramReport:
    """What :func:`validate_program` learned; ``work_units`` counts every node, dead or not,
    because every node executes (there is no branch to skip one)."""

    node_count: int
    apply_count: int
    work_units: int
    dead_nodes: int
    inputs_read: frozenset[tuple[InputSource, int]]
    primitives_used: frozenset[str]
    constants: int


@dataclass(frozen=True, slots=True)
class StaticBounds:
    """Exact cost ceilings computed from program text; the interpreter charges these."""

    update_wu_per_event: int  # sum of update-node WU (INPUT 1, REG 1, CONST 0, APPLY its WU)
    readout_wu_per_lineage: int
    max_steps_per_event: int  # == len(update.nodes)
    state_bytes_per_lineage: int  # sum(ring * VALUE_BYTES) + LINEAGE_OVERHEAD_BYTES
    session_state_bytes_max: int  # MAX_LINEAGES*per_lineage + side tables + scratch nodes*8
    session_wu_max: int  # MAX_SESSION_EVENTS*update + (MAX_LINEAGES+evicted cap)*readout


def node_work_units(node: IRNode, alphabet: PrimitiveAlphabet) -> int:
    if node.kind is NodeKind.APPLY:
        return alphabet.get(node.primitive).work_units
    if node.kind in (NodeKind.INPUT, NodeKind.REG):
        return INPUT_WU if node.kind is NodeKind.INPUT else REG_WU
    return CONST_WU


def _check_registers(registers: Sequence[RegisterSpec]) -> None:
    if not 1 <= len(registers) <= MAX_REGISTERS:
        raise IRError("REGISTER_BOUND", f"{len(registers)} registers outside 1..{MAX_REGISTERS}")
    if not all(isinstance(spec, RegisterSpec) for spec in registers):
        raise IRError("TYPE_MISMATCH", "registers must be RegisterSpec instances")


def _check_node_types(
    position: int, node: IRNode, nodes: Sequence[IRNode],
    registers: Sequence[RegisterSpec], alphabet: PrimitiveAlphabet,
) -> None:
    if node.kind is NodeKind.REG:
        if node.index >= len(registers):
            raise IRError("REGISTER_BOUND", f"node {position} reads missing register {node.index}")
        spec = registers[node.index]
        if node.lag >= spec.ring:
            raise IRError("LAG_BOUND", f"node {position} lag {node.lag} >= ring {spec.ring}")
        if node.type is not spec.type:
            raise IRError("TYPE_MISMATCH", f"node {position} is {node.type}, register {spec.type}")
    elif node.kind is NodeKind.APPLY:
        primitive = alphabet.get(node.primitive)
        if len(node.args) != len(primitive.arg_types):
            raise IRError(
                "ARITY", f"{node.primitive} takes {len(primitive.arg_types)}, got {len(node.args)}"
            )
        for arg, wanted in zip(node.args, primitive.arg_types, strict=True):
            if nodes[arg].type is not wanted:
                raise IRError(
                    "TYPE_MISMATCH",
                    f"{node.primitive} arg {arg} is {nodes[arg].type}, not {wanted}",
                )
        if node.type is not primitive.result_type:
            raise IRError("TYPE_MISMATCH", f"{node.primitive} returns {primitive.result_type}")


def _dead_nodes(program: IRProgram) -> int:
    live: set[int] = set()
    frontier = list(program.outputs)
    while frontier:
        position = frontier.pop()
        if position not in live:
            live.add(position)
            frontier.extend(program.nodes[position].args)
    return len(program.nodes) - len(live)


def validate_program(
    program: IRProgram, registers: Sequence[RegisterSpec], alphabet: PrimitiveAlphabet
) -> ProgramReport:
    """Type-check ``program`` against ``registers`` and ``alphabet``; raise :class:`IRError`.

    Never repairs anything: an ill-typed program is refused, and the caller counts it.
    """
    if not isinstance(program, IRProgram):
        raise IRError("TYPE_MISMATCH", "validate_program takes an IRProgram")
    _check_registers(registers)
    for position, node in enumerate(program.nodes):
        _check_node_types(position, node, program.nodes, registers, alphabet)
    if program.phase is ProgramPhase.UPDATE:
        if len(program.outputs) != len(registers):
            raise IRError("OUTPUT_COUNT", f"{len(program.outputs)} outputs, {len(registers)} regs")
        for register, (output, spec) in enumerate(zip(program.outputs, registers, strict=True)):
            if program.nodes[output].type is not spec.type:
                raise IRError("OUTPUT_TYPE", f"output for register {register} is not {spec.type}")
    return ProgramReport(
        node_count=len(program.nodes),
        apply_count=sum(node.kind is NodeKind.APPLY for node in program.nodes),
        work_units=sum(node_work_units(node, alphabet) for node in program.nodes),
        dead_nodes=_dead_nodes(program),
        inputs_read=frozenset(
            (node.source, node.index)
            for node in program.nodes
            if node.kind is NodeKind.INPUT and node.source is not None
        ),
        primitives_used=frozenset(n.primitive for n in program.nodes if n.kind is NodeKind.APPLY),
        constants=sum(node.kind is NodeKind.CONST for node in program.nodes),
    )


def _side_table_nodes(program: IRProgram, alphabet: PrimitiveAlphabet) -> int:
    return sum(
        1
        for node in program.nodes
        if node.kind is NodeKind.APPLY and alphabet.get(node.primitive).side_table
    )


def static_bounds(
    update: IRProgram,
    readout: IRProgram,
    registers: Sequence[RegisterSpec],
    alphabet: PrimitiveAlphabet,
) -> StaticBounds:
    """Validate both programs, then compute the exact per-event and per-session ceilings.

    Each side-table APPLY node owns one per-session table of :data:`SIDE_TABLE_ENTRIES`
    (two FIRST_SEEN nodes over different inputs must not see each other's keys), so the
    side-table term is ``nodes_with_side_table * SIDE_TABLE_ENTRIES * SIDE_ENTRY_BYTES``.
    """
    if update.phase is not ProgramPhase.UPDATE or readout.phase is not ProgramPhase.READOUT:
        raise IRError("TYPE_MISMATCH", "static_bounds takes (UPDATE, READOUT) programs")
    update_report = validate_program(update, registers, alphabet)
    readout_report = validate_program(readout, registers, alphabet)
    per_lineage = sum(spec.state_bytes for spec in registers) + LINEAGE_OVERHEAD_BYTES
    side_tables = _side_table_nodes(update, alphabet) + _side_table_nodes(readout, alphabet)
    scratch = (len(update.nodes) + len(readout.nodes)) * VALUE_BYTES
    return StaticBounds(
        update_wu_per_event=update_report.work_units,
        readout_wu_per_lineage=readout_report.work_units,
        max_steps_per_event=len(update.nodes),
        state_bytes_per_lineage=per_lineage,
        session_state_bytes_max=(
            MAX_LINEAGES * per_lineage
            + side_tables * SIDE_TABLE_ENTRIES * SIDE_ENTRY_BYTES
            + scratch
        ),
        session_wu_max=(
            MAX_SESSION_EVENTS * update_report.work_units
            + (MAX_LINEAGES + MAX_EVICTED_READOUTS) * readout_report.work_units
        ),
    )
