"""D9.4 (alphabet half) — the seed primitive alphabet Π0 and the immutable alphabet type.

The search can only find what its alphabet can say. This module exists so that the
alphabet is (a) small, (b) exactly specified — every primitive's signature, work units (WU)
and semantics are fixed here and pinned by ``tests/test_stage9_ir.py`` — and (c) immutable:
promoting a macro returns a **new** :class:`PrimitiveAlphabet`, so a search that grows its
language can never change what an already-evaluated genome meant.

Seed semantics (spec §4.4). ``F`` FLOAT, ``I`` INT (64-bit mask), ``B`` BOOL. Every FLOAT
result is clamped to ±1e12 and NaN becomes 0.0 (:func:`clamp_float`), so no chain of
primitives can overflow; every INT result is masked to 64 bits.

=================  ==========  ==  ===============================================
primitive          signature   WU  semantics (argument order is the signature order)
=================  ==========  ==  ===============================================
ADD SUB MUL        F,F->F      1   x+y, x-y, x*y
MIN MAX            F,F->F      1   min(x, y), max(x, y)
DIV                F,F->F      2   x/y, and 0.0 when y == 0 (safe; Stage 3 lacked it)
ABS CLIP01         F->F        1   |x|; clamp to [0, 1]
LT GT              F,F->B      1   x < y; x > y
EQ_I               I,I->B      1   a == b
SELECT             B,F,F->F    1   SELECT(b, a, c) = a if b else c
B2F                B->F        1   1.0 / 0.0
AND OR XOR         I,I->I      1   bitwise
NOT                I->I        1   ~x & INT_MASK
SHIFT              I,I->I      1   (a << (b % 64)) & INT_MASK
POPCOUNT           I->F        1   number of set bits
HASH               I->I        2   (x * 2654435761) & 0xFFFF
LOOKUP             I->F        2   lookup_table[x % len], 0.0 if the table is empty
COUNT              B,F->F      1   COUNT(b, prev) = prev + (1.0 if b else 0.0)
DECAY              F,F,F->F    2   DECAY(prev, x, lam) = clip01(lam) * prev + x
BIND               I,I->I      1   a ^ rotl64(b, 1)   (HDC bind)
GRAPH_EDGE         I,I->I      1   ((a & 0xFF) << 8) | (b & 0xFF)
STATE_DELTA        I,I->B      1   bit (b % 9) of mask a (the nine Stage 1 DIMENSIONS)
TEMPORAL_WITHIN    I,I,I->B    1   |a - b| <= c
FIRST_SEEN         I->B        4   True the first time x appears in this session's table
RARE               I->F        4   1 / (1 + prior count of x) in this session's table
=================  ==========  ==  ===============================================

That is **29** primitives. The spec's prose says "26"; its own table lists these 29 with
exact signatures, and consumers (the exhaustive enumeration's ABS/POPCOUNT, the raw
Φ-oracle's DIV, H2's POPCOUNT) need them, so the table wins and the count is reported as a
spec discrepancy. ``SUPERPOSE`` is deliberately absent: for two binary operands it is ``OR``,
and a duplicate primitive is a catalogue richer than its consumer (lesson 3).

FIRST_SEEN and RARE are **side-table** primitives: each such node owns a per-session LRU
table of ``SIDE_TABLE_ENTRIES`` keys whose evictions are counted, never silent.

What this module refuses: a macro that names itself (``MACRO_CYCLE``), a macro nested
beyond ``MAX_MACRO_DEPTH`` (``MACRO_DEPTH``), a macro body above ``MAX_MACRO_NODES``
(``MACRO_SIZE``), a macro that names a primitive the receiver does not already hold, and any
mutation of an existing alphabet.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections import OrderedDict
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import StrEnum
from functools import partial
from types import MappingProxyType
from typing import Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage9.chemistry.typed_ir import (
    CONST_WU,
    INPUT_WU,
    INT_MASK,
    IR_VERSION,
    MAX_MACRO_DEPTH,
    MAX_MACRO_NODES,
    REG_WU,
    SIDE_TABLE_ENTRIES,
    IRError,
    IRNode,
    IRProgram,
    IRType,
    NodeKind,
    check_references,
    clamp_float,
)

__all__ = [
    "HASH_MULTIPLIER",
    "SEED_ALPHABET",
    "SEED_PRIMITIVE_COUNT",
    "STATE_DELTA_BITS",
    "TABLE_READERS",
    "MacroBody",
    "Primitive",
    "PrimitiveAlphabet",
    "PrimitiveOrigin",
    "SideTable",
    "bind_context",
]

HASH_MULTIPLIER = 2654435761
#: Stage 1's ``DIMENSIONS`` has nine members; the test cross-checks this against it.
STATE_DELTA_BITS = 9
#: Primitives whose callable takes the genome's lookup table as its first argument.
TABLE_READERS: frozenset[str] = frozenset({"LOOKUP"})
_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,31}$")

FT, IT, BT = IRType.FLOAT, IRType.INT, IRType.BOOL


class PrimitiveOrigin(StrEnum):
    SEED = "SEED"
    PROMOTED = "PROMOTED"


@dataclass(frozen=True, slots=True)
class MacroBody:
    """A promoted compound: typed parameters, a small DAG over them, one output node."""

    params: tuple[IRType, ...]
    nodes: tuple[IRNode, ...]
    output: int

    def __post_init__(self) -> None:
        if not isinstance(self.params, tuple) or len(self.params) > MAX_MACRO_NODES:
            raise IRError("MACRO_SIZE", f"a macro takes 0..{MAX_MACRO_NODES} params")
        object.__setattr__(self, "params", tuple(IRType(p) for p in self.params))
        if not isinstance(self.nodes, tuple) or not all(isinstance(n, IRNode) for n in self.nodes):
            raise IRError("TYPE_MISMATCH", "MacroBody.nodes must be a tuple of IRNode")
        if not 1 <= len(self.nodes) <= MAX_MACRO_NODES:
            raise IRError("MACRO_SIZE", f"{len(self.nodes)} body nodes, cap {MAX_MACRO_NODES}")
        check_references(self.nodes)
        for position, node in enumerate(self.nodes):
            if node.kind is NodeKind.PARAM and (
                node.index >= len(self.params) or node.type is not self.params[node.index]
            ):
                raise IRError("TYPE_MISMATCH", f"body node {position} is not a declared param")
        if isinstance(self.output, bool) or not isinstance(self.output, int) or not (
            0 <= self.output < len(self.nodes)
        ):
            raise IRError("FORWARD_REFERENCE", f"macro output {self.output!r} names no body node")

    @property
    def result_type(self) -> IRType:
        return self.nodes[self.output].type

    def to_dict(self) -> dict[str, Any]:
        return {
            "params": [p.value for p in self.params],
            "nodes": [node.to_dict() for node in self.nodes],
            "output": self.output,
        }


@dataclass(frozen=True, slots=True)
class Primitive:
    """One alphabet entry. ``fn`` is excluded from equality: semantics are pinned by name
    and version (and by the semantics tests), not by function identity."""

    name: str
    arg_types: tuple[IRType, ...]
    result_type: IRType
    work_units: int
    side_table: bool
    fn: Callable[..., float | int | bool] = field(compare=False, repr=False)
    origin: PrimitiveOrigin = PrimitiveOrigin.SEED
    macro: MacroBody | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.name, str) or not _NAME_RE.match(self.name):
            raise ContractError(f"primitive name must match {_NAME_RE.pattern}, got {self.name!r}")
        object.__setattr__(self, "arg_types", tuple(IRType(t) for t in self.arg_types))
        object.__setattr__(self, "result_type", IRType(self.result_type))
        object.__setattr__(self, "origin", PrimitiveOrigin(self.origin))
        if isinstance(self.work_units, bool) or not isinstance(self.work_units, int) or (
            self.work_units < 0
        ):
            raise ContractError(f"{self.name}: work_units must be a non-negative int")
        if not callable(self.fn):
            raise ContractError(f"{self.name}: fn must be callable")
        if (self.origin is PrimitiveOrigin.PROMOTED) != (self.macro is not None):
            raise ContractError(f"{self.name}: exactly the PROMOTED primitives carry a macro")

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "arg_types": [t.value for t in self.arg_types],
            "result_type": self.result_type.value,
            "work_units": self.work_units,
            "side_table": self.side_table,
            "origin": self.origin.value,
            "macro": None if self.macro is None else self.macro.to_dict(),
        }


class SideTable:
    """A bounded per-session LRU of INT keys: the only growing state a primitive may own.

    At :data:`SIDE_TABLE_ENTRIES` keys the least recently touched key is evicted and
    counted, so a flood of distinct keys costs recall (an evicted key reads as new again)
    and never memory.
    """

    __slots__ = ("_capacity", "_entries", "evictions")

    def __init__(self, capacity: int = SIDE_TABLE_ENTRIES) -> None:
        if isinstance(capacity, bool) or not isinstance(capacity, int) or capacity < 1:
            raise ContractError(f"SideTable capacity must be a positive int, got {capacity!r}")
        self._capacity = capacity
        self._entries: OrderedDict[int, int] = OrderedDict()
        self.evictions = 0

    def __len__(self) -> int:
        return len(self._entries)

    def _insert(self, key: int, count: int) -> None:
        if len(self._entries) >= self._capacity:
            self._entries.popitem(last=False)
            self.evictions += 1
        self._entries[key] = count

    def first_seen(self, key: int) -> bool:
        if key in self._entries:
            self._entries[key] += 1
            self._entries.move_to_end(key)
            return False
        self._insert(key, 1)
        return True

    def bump(self, key: int) -> int:
        """Return the prior count of ``key`` (0 if absent or evicted), then increment it."""
        prior = self._entries.pop(key, 0)
        if prior:
            self._entries[key] = prior + 1
        else:
            self._insert(key, 1)
        return prior


# --- seed semantics -----------------------------------------------------------------


def _clip01(x: float) -> float:
    return 0.0 if x < 0.0 else 1.0 if x > 1.0 else float(x)


def _div(x: float, y: float) -> float:
    return 0.0 if y == 0.0 else clamp_float(x / y)


def _rotl64(value: int) -> int:
    return ((value << 1) | (value >> 63)) & INT_MASK


def _lookup(table: Sequence[float], x: int) -> float:
    return float(table[x % len(table)]) if table else 0.0


def _decay(prev: float, x: float, lam: float) -> float:
    return clamp_float(_clip01(lam) * prev + x)


def _first_seen(table: SideTable, x: int) -> bool:
    return table.first_seen(x)


def _rare(table: SideTable, x: int) -> float:
    return 1.0 / (1.0 + table.bump(x))


_SEED_ROWS: tuple[tuple[str, tuple[IRType, ...], IRType, int, bool, Callable[..., Any]], ...] = (
    ("ADD", (FT, FT), FT, 1, False, lambda x, y: clamp_float(x + y)),
    ("SUB", (FT, FT), FT, 1, False, lambda x, y: clamp_float(x - y)),
    ("MUL", (FT, FT), FT, 1, False, lambda x, y: clamp_float(x * y)),
    ("MIN", (FT, FT), FT, 1, False, lambda x, y: clamp_float(min(x, y))),
    ("MAX", (FT, FT), FT, 1, False, lambda x, y: clamp_float(max(x, y))),
    ("DIV", (FT, FT), FT, 2, False, _div),
    ("ABS", (FT,), FT, 1, False, lambda x: clamp_float(abs(x))),
    ("CLIP01", (FT,), FT, 1, False, _clip01),
    ("LT", (FT, FT), BT, 1, False, lambda x, y: x < y),
    ("GT", (FT, FT), BT, 1, False, lambda x, y: x > y),
    ("EQ_I", (IT, IT), BT, 1, False, lambda a, b: a == b),
    ("SELECT", (BT, FT, FT), FT, 1, False, lambda b, a, c: a if b else c),
    ("B2F", (BT,), FT, 1, False, lambda b: 1.0 if b else 0.0),
    ("AND", (IT, IT), IT, 1, False, lambda a, b: (a & b) & INT_MASK),
    ("OR", (IT, IT), IT, 1, False, lambda a, b: (a | b) & INT_MASK),
    ("XOR", (IT, IT), IT, 1, False, lambda a, b: (a ^ b) & INT_MASK),
    ("NOT", (IT,), IT, 1, False, lambda x: ~x & INT_MASK),
    ("SHIFT", (IT, IT), IT, 1, False, lambda a, b: (a << (b % 64)) & INT_MASK),
    ("POPCOUNT", (IT,), FT, 1, False, lambda x: float(x.bit_count())),
    ("HASH", (IT,), IT, 2, False, lambda x: (x * HASH_MULTIPLIER) & 0xFFFF),
    ("LOOKUP", (IT,), FT, 2, False, _lookup),
    ("COUNT", (BT, FT), FT, 1, False, lambda b, prev: clamp_float(prev + (1.0 if b else 0.0))),
    ("DECAY", (FT, FT, FT), FT, 2, False, _decay),
    ("BIND", (IT, IT), IT, 1, False, lambda a, b: (a ^ _rotl64(b)) & INT_MASK),
    ("GRAPH_EDGE", (IT, IT), IT, 1, False, lambda a, b: ((a & 0xFF) << 8) | (b & 0xFF)),
    ("STATE_DELTA", (IT, IT), BT, 1, False, lambda a, b: bool((a >> (b % STATE_DELTA_BITS)) & 1)),
    ("TEMPORAL_WITHIN", (IT, IT, IT), BT, 1, False, lambda a, b, c: abs(a - b) <= c),
    ("FIRST_SEEN", (IT,), BT, 4, True, _first_seen),
    ("RARE", (IT,), FT, 4, True, _rare),
)

SEED_PRIMITIVE_COUNT = len(_SEED_ROWS)


def bind_context(
    primitive: Primitive,
    *,
    lookup_table: Sequence[float] = (),
    side_table: SideTable | None = None,
) -> Callable[..., Any]:
    """The callable an interpreter step invokes with the node's argument values.

    Pure primitives are returned as-is. LOOKUP is bound to the genome's table and a
    side-table primitive to its per-session table. A macro is never bound: programs are
    expanded before they are run, so a macro's per-session state stays per-node.
    """
    if primitive.macro is not None:
        raise ContractError(f"{primitive.name} is a macro; expand the program before binding")
    if primitive.side_table:
        if side_table is None:
            raise ContractError(f"{primitive.name} needs its per-session SideTable")
        return partial(primitive.fn, side_table)
    if primitive.name in TABLE_READERS:
        return partial(primitive.fn, tuple(lookup_table))
    return primitive.fn


# --- the alphabet -------------------------------------------------------------------


class PrimitiveAlphabet:
    """An immutable, ordered set of primitives with a content digest.

    Macros may only name primitives that come **earlier** in the alphabet, so a cycle is
    unwritable except as a self reference, which is refused. That rule is re-checked on
    construction, so building an alphabet by hand cannot bypass :meth:`with_macro`.
    """

    __slots__ = ("_depths", "_digest", "_primitives")
    _depths: Mapping[str, int]
    _digest: str
    _primitives: Mapping[str, Primitive]

    def __init__(self, primitives: Iterable[Primitive]) -> None:
        table: dict[str, Primitive] = {}
        depths: dict[str, int] = {}
        for primitive in primitives:
            if not isinstance(primitive, Primitive):
                raise ContractError(f"an alphabet holds Primitive values, got {primitive!r}")
            if primitive.name in table:
                raise ContractError(f"duplicate primitive {primitive.name!r}")
            depths[primitive.name] = _macro_depth(primitive, table, depths)
            table[primitive.name] = primitive
        object.__setattr__(self, "_primitives", MappingProxyType(table))
        object.__setattr__(self, "_depths", MappingProxyType(depths))
        canonical = json.dumps(
            {"ir_version": IR_VERSION, "primitives": [p.to_dict() for p in table.values()]},
            sort_keys=True,
            separators=(",", ":"),
        )
        digest = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        object.__setattr__(self, "_digest", digest)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("PrimitiveAlphabet is immutable; with_macro returns a new one")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("PrimitiveAlphabet is immutable")

    def __len__(self) -> int:
        return len(self._primitives)

    def __contains__(self, name: object) -> bool:
        return name in self._primitives

    def __iter__(self) -> Iterator[Primitive]:
        return iter(self._primitives.values())

    @property
    def digest(self) -> str:
        return self._digest

    def get(self, name: str) -> Primitive:
        primitive = self._primitives.get(name)
        if primitive is None:
            raise IRError("UNKNOWN_PRIMITIVE", f"{name!r} is not in this alphabet")
        return primitive

    def names(self) -> tuple[str, ...]:
        return tuple(self._primitives)

    def depth(self, name: str) -> int:
        """0 for a seed primitive; 1 + the deepest macro a macro body names."""
        self.get(name)
        return self._depths[name]

    def with_macro(self, name: str, body: MacroBody) -> PrimitiveAlphabet:
        """Return a NEW alphabet with ``name`` promoted; the receiver is unchanged."""
        if not isinstance(body, MacroBody):
            raise ContractError("with_macro takes a MacroBody")
        if name in self._primitives:
            raise ContractError(f"{name!r} already names a primitive in this alphabet")
        work_units, side_table = _macro_cost(name, body, self)
        primitive = Primitive(
            name=name,
            arg_types=body.params,
            result_type=body.result_type,
            work_units=work_units,
            side_table=side_table,
            fn=partial(_evaluate_macro, body, self),
            origin=PrimitiveOrigin.PROMOTED,
            macro=body,
        )
        return PrimitiveAlphabet((*self._primitives.values(), primitive))

    def expand(self, program: IRProgram) -> IRProgram:
        """Inline every macro, returning a program over non-macro primitives only.

        The result is a fresh :class:`IRProgram`, so its size is re-checked
        (``NODE_BOUND``); a program with no macro is returned unchanged.
        """
        if not any(
            node.kind is NodeKind.APPLY and self.get(node.primitive).macro is not None
            for node in program.nodes
        ):
            return program
        out: list[IRNode] = []
        remap: list[int] = []
        for node in program.nodes:
            if node.kind is NodeKind.APPLY:
                remap.append(self._inline(node, tuple(remap[a] for a in node.args), out))
            else:
                out.append(node)
                remap.append(len(out) - 1)
        return IRProgram(
            phase=program.phase,
            nodes=tuple(out),
            outputs=tuple(remap[output] for output in program.outputs),
        )

    def _inline(self, node: IRNode, args: tuple[int, ...], out: list[IRNode]) -> int:
        primitive = self.get(node.primitive)
        if primitive.macro is None:
            out.append(replace(node, args=args))
            return len(out) - 1
        body = primitive.macro
        if len(args) != len(body.params):
            raise IRError("ARITY", f"{node.primitive} takes {len(body.params)}, got {len(args)}")
        local: list[int] = []
        for inner in body.nodes:
            if inner.kind is NodeKind.PARAM:
                local.append(args[inner.index])
            elif inner.kind is NodeKind.APPLY:
                local.append(self._inline(inner, tuple(local[a] for a in inner.args), out))
            else:
                out.append(inner)
                local.append(len(out) - 1)
        return local[body.output]


def _macro_depth(
    primitive: Primitive, earlier: dict[str, Primitive], depths: dict[str, int]
) -> int:
    """Depth of ``primitive`` given the primitives before it; refuses cycles and depth."""
    if primitive.macro is None:
        return 0
    deepest = 0
    for node in primitive.macro.nodes:
        if node.kind is not NodeKind.APPLY:
            continue
        if node.primitive == primitive.name:
            raise IRError("MACRO_CYCLE", f"macro {primitive.name} names itself")
        if node.primitive not in earlier:
            raise IRError(
                "UNKNOWN_PRIMITIVE",
                f"macro {primitive.name} names {node.primitive!r}, not defined before it",
            )
        deepest = max(deepest, depths[node.primitive])
    if deepest + 1 > MAX_MACRO_DEPTH:
        raise IRError(
            "MACRO_DEPTH", f"macro {primitive.name} nests {deepest + 1} deep, cap {MAX_MACRO_DEPTH}"
        )
    return deepest + 1


def _macro_cost(name: str, body: MacroBody, alphabet: PrimitiveAlphabet) -> tuple[int, bool]:
    """Type-check ``body`` against ``alphabet`` and return (WU of its expansion, side_table).

    A nested macro's WU is already its full expansion's WU, so the sum is exact. The
    self-reference check runs first so a recursive macro is refused as ``MACRO_CYCLE``
    rather than as an unknown name.
    """
    for node in body.nodes:
        if node.kind is NodeKind.APPLY and node.primitive == name:
            raise IRError("MACRO_CYCLE", f"macro {name} names itself")
    work_units, side_table = 0, False
    for position, node in enumerate(body.nodes):
        if node.kind is NodeKind.APPLY:
            inner = alphabet.get(node.primitive)
            if len(node.args) != len(inner.arg_types):
                raise IRError("ARITY", f"body node {position}: {node.primitive} arity")
            for arg, wanted in zip(node.args, inner.arg_types, strict=True):
                if body.nodes[arg].type is not wanted:
                    raise IRError("TYPE_MISMATCH", f"body node {position} arg {arg} not {wanted}")
            if node.type is not inner.result_type:
                raise IRError("TYPE_MISMATCH", f"body node {position} is not {inner.result_type}")
            work_units += inner.work_units
            side_table = side_table or inner.side_table
        elif node.kind in (NodeKind.INPUT, NodeKind.REG):
            work_units += INPUT_WU if node.kind is NodeKind.INPUT else REG_WU
        else:
            work_units += CONST_WU
    # Depth is checked once, by PrimitiveAlphabet.__init__ (_macro_depth), for every
    # alphabet however it was built.
    return work_units, side_table


def _evaluate_macro(body: MacroBody, alphabet: PrimitiveAlphabet, *args: Any) -> Any:
    """Evaluate a macro body on explicit arguments, for offline probing only.

    The phenotype never calls this: it runs expanded programs, where side tables are
    per-session. Here each side-table node gets a fresh table and LOOKUP an empty one,
    the honest semantics of a single stateless call. A body that reads an input or a
    register has no value without a lineage, so it is refused.
    """
    if len(args) != len(body.params):
        raise IRError("ARITY", f"macro takes {len(body.params)} arguments, got {len(args)}")
    values: list[Any] = []
    for node in body.nodes:
        if node.kind is NodeKind.PARAM:
            values.append(args[node.index])
        elif node.kind is NodeKind.CONST:
            values.append(node.value)
        elif node.kind is NodeKind.APPLY:
            inner = alphabet.get(node.primitive)
            fresh = inner.macro is None
            call = bind_context(inner, side_table=SideTable()) if fresh else inner.fn
            values.append(call(*(values[a] for a in node.args)))
        else:
            raise ContractError(f"a {node.kind} node has no value outside a running phenotype")
    return values[body.output]


SEED_ALPHABET = PrimitiveAlphabet(
    Primitive(name=name, arg_types=args, result_type=result, work_units=wu, side_table=side, fn=fn)
    for name, args, result, wu, side, fn in _SEED_ROWS
)
