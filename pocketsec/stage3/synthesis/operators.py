"""D3.7 (part) — one bounded synthesiser per :class:`OperatorForm`.

Architecture §34 is explicit: *do not bet on one synthesizer*. A single
representation would decide, in advance and without evidence, which shape
security knowledge has. So CRYSTAL tries several bounded operator families for
the same region and lets a measured selector choose (``selector.py``).

Every synthesiser here obeys the same two rules, and they are the reason this
module exists at all:

* **It refuses rather than growing past its bound.** A table that would need
  1025 entries returns ``None``; it does not quietly become 1025 entries. The
  bounds are what make a Knowledge Cell's cost auditable, so a synthesiser that
  relaxed its own bound would silently destroy the only property Stage 3 claims.
* **It refuses rather than approximating.** A lookup table whose key maps to two
  different targets is not a function of that key. Averaging the two would
  produce an operator that is cheap and wrong, and "cheap and wrong" is the
  failure mode this whole stage is built to avoid. Disagreement is a refusal.

Asking a synthesiser to exceed its *hard* cap is a programming error, not a
data-dependent refusal, and raises ``ContractError``.
That distinction is deliberate: ``None`` means "this region does not fit this
form", and an exception means "the caller tried to widen the bound".

No third-party import (ADR-0020): the decision DAG is a plain Gini search and
the linear fit is normal equations solved by Gaussian elimination in pure
Python. numpy is not available to Stage 3 and is not needed here.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.state.security_state import StateDelta
from pocketsec.stage3.bytecode.isa import (
    MAX_STACK,
    MAX_STATE_BYTES,
    MAX_TABLE_ENTRIES,
    OPERAND_ARITY,
    OPERAND_RANGE,
    STACK_EFFECT,
    TERMINATORS,
    Instruction,
    Op,
    ValueType,
    encode,
)
from pocketsec.stage3.bytecode.verifier import verify
from pocketsec.stage3.bytecode.vm import CellVM
from pocketsec.stage3.cells.frame import CellFrame
from pocketsec.stage3.cells.operator import (
    MAX_OPERATOR_STATE_BYTES,
    OperatorForm,
    OperatorProgram,
)

__all__ = [
    "EQUIVALENCE_EPSILON",
    "MAX_BITSET_TERMS",
    "MAX_DAG_DEPTH",
    "MAX_DAG_NODES",
    "MAX_FSM_STATES",
    "MAX_LINEAR_TERMS",
    "MAX_SYNTH_INSTRUCTIONS",
    "MAX_SYNTH_NODE_BUDGET",
    "OPERATOR_FEATURE_NAMES",
    "OperatorSample",
    "SYNTHESISERS",
    "feature_vector",
    "synthesize_bitset_predicate",
    "synthesize_bytecode",
    "synthesize_constant",
    "synthesize_decision_dag",
    "synthesize_fsm_fragment",
    "synthesize_linear_expression",
    "synthesize_lookup_table",
    "synthesize_weighted_transition",
]


#: Two risks closer than this are the same risk. Chosen to be far below the
#: smallest Φ step so an operator cannot "match" by rounding.
EQUIVALENCE_EPSILON = 1e-9

# --- hard caps. A caller may ask for less; asking for more is a contract error.
# The table cap is the ISA's ``MAX_TABLE_ENTRIES``, used rather than restated:
# the verifier refuses a wider table, so a synthesiser with its own looser
# number would produce programs that can never run.
MAX_BITSET_TERMS = 2
MAX_DAG_DEPTH = 4
MAX_DAG_NODES = 31
MAX_FSM_STATES = 8
MAX_LINEAR_TERMS = 6
MAX_SYNTH_INSTRUCTIONS = 24
MAX_SYNTH_NODE_BUDGET = 20_000

#: Operand candidates come from the ISA's own ``OPERAND_RANGE``, capped here so
#: the search space stays finite. The verifier range-checks operands anyway; this
#: only bounds how many the enumerator is willing to try.
_MAX_ENUM_OPERAND = 8


@dataclass(frozen=True, slots=True)
class OperatorSample:
    """One frame paired with the behaviour an operator must reproduce.

    The frame is a :class:`CellFrame` and not a Stage 2 ``EncodedTransition``
    on purpose. §30 makes ``CellFrame`` the only thing a cell may read, so
    fitting an operator on features the VM cannot reach would produce a program
    that is unexecutable by construction.
    """

    frame: CellFrame
    risk: float
    delta: StateDelta
    abstain: bool = False


#: Fixed feature layout derived from ``CellFrame``. The index order is a wire
#: commitment: a DECISION_DAG or LINEAR_EXPRESSION program stores feature
#: *indices*, so reordering this tuple silently repoints every fitted operator.
OPERATOR_FEATURE_NAMES: tuple[str, ...] = (
    "relation_family",
    "phi",
    "delta_phi",
    "uncertainty",
    "epoch_id",
    "delta_mask",
    "delta_bits",
    "actor_mask",
    "actor_bits",
    "object_mask",
    "object_bits",
    "window_total",
)


def feature_vector(frame: CellFrame) -> tuple[float, ...]:
    """Project a frame onto :data:`OPERATOR_FEATURE_NAMES`, in that order."""
    delta_mask = frame.delta.bitmask()
    return (
        float(int(frame.relation_family)),
        float(frame.phi),
        float(frame.delta_phi),
        float(frame.uncertainty),
        float(frame.epoch_id),
        float(delta_mask),
        float(delta_mask.bit_count()),
        float(frame.actor_properties),
        float(frame.actor_properties.bit_count()),
        float(frame.object_properties),
        float(frame.object_properties.bit_count()),
        float(sum(frame.window_counts.values())),
    )


# --- program construction ----------------------------------------------------


def _state_bytes(words: Sequence[int], table: Mapping[str, float]) -> int:
    """Declared resident cost. Counted, never estimated with a fudge factor."""
    return 4 * len(words) + sum(len(key.encode("utf-8")) + 8 for key in table)


def _program(
    form: OperatorForm,
    *,
    words: Sequence[int] = (),
    table: Mapping[str, float] | None = None,
    max_steps: int,
) -> OperatorProgram | None:
    """Build a program, or refuse when its declared state would exceed the cap.

    The digest is deliberately *not* passed: ``OperatorProgram`` binds it from
    its own canonical bytes, so computing one here would create a second source
    of truth for operator identity.

    A BYTECODE program declares the ISA's stack ceiling rather than its own peak
    depth. The verifier requires ``declared >= computed``, so over-declaring is
    safe; it is recorded here as an over-declaration rather than presented as a
    measured footprint.
    """
    resolved = dict(table or {})
    if len(resolved) > MAX_TABLE_ENTRIES:
        return None
    declared_bytes = (
        MAX_STATE_BYTES if form is OperatorForm.BYTECODE else _state_bytes(words, resolved)
    )
    if declared_bytes > min(MAX_OPERATOR_STATE_BYTES, MAX_STATE_BYTES):
        return None
    return OperatorProgram(
        form=form,
        words=tuple(int(w) for w in words),
        table=resolved,
        max_steps=max(1, max_steps),
        max_state_bytes=declared_bytes,
    )


def _require_cap(value: int, cap: int, name: str) -> None:
    if value > cap:
        raise ContractError(f"{name}={value} exceeds the hard cap {cap}")


def _same(values: Sequence[float]) -> bool:
    return all(abs(v - values[0]) <= EQUIVALENCE_EPSILON for v in values)


def _delta_key(delta: StateDelta) -> tuple[tuple[str, int, int], ...]:
    return tuple(sorted((name, lo, hi) for name, (lo, hi) in delta.raised.items()))


# --- the eight synthesisers --------------------------------------------------


def synthesize_constant(samples: Sequence[OperatorSample]) -> OperatorProgram | None:
    """Fit a single risk/delta pair. Refuses the moment the region disagrees."""
    if not samples:
        return None
    if not _same([s.risk for s in samples]):
        return None
    if len({_delta_key(s.delta) for s in samples}) != 1:
        return None
    if len({s.abstain for s in samples}) != 1:
        return None
    head = samples[0]
    table = {
        "risk": float(head.risk),
        "abstain": 1.0 if head.abstain else 0.0,
        "delta_mask": float(head.delta.bitmask()),
    }
    return _program(OperatorForm.CONSTANT, table=table, max_steps=1)


def _lookup_key(frame: CellFrame) -> str:
    return f"{int(frame.relation_family)}:{frame.actor_properties}:{frame.delta.bitmask()}"


def synthesize_lookup_table(
    samples: Sequence[OperatorSample], *, max_entries: int = 1024
) -> OperatorProgram | None:
    """Quantised key -> risk. Refuses on overflow and on a non-functional key."""
    _require_cap(max_entries, MAX_TABLE_ENTRIES, "max_entries")
    if not samples:
        return None
    table: dict[str, float] = {}
    for sample in samples:
        key = _lookup_key(sample.frame)
        previous = table.get(key)
        # A key that maps to two targets is not a key. Averaging here would
        # manufacture an operator that is cheap and wrong.
        if previous is not None and abs(previous - sample.risk) > EQUIVALENCE_EPSILON:
            return None
        table[key] = float(sample.risk)
        if len(table) > max_entries:
            return None
    return _program(OperatorForm.LOOKUP_TABLE, table=table, max_steps=1)


def _two_valued(samples: Sequence[OperatorSample]) -> tuple[float, float] | None:
    risks = sorted({round(s.risk, 12) for s in samples})
    if len(risks) != 2:
        return None
    return risks[1], risks[0]


def synthesize_bitset_predicate(
    samples: Sequence[OperatorSample],
) -> OperatorProgram | None:
    """Find a property mask whose membership test separates two risk levels."""
    if not samples:
        return None
    split = _two_valued(samples)
    if split is None:
        return None
    hit, miss = split
    present = 0
    for sample in samples:
        present |= sample.frame.actor_properties
    bits = [1 << i for i in range(present.bit_length()) if present >> i & 1]
    # Bounded: single bits, then pairs. Three-term masks are not searched, so
    # the cost of this synthesiser is quadratic in the observed property width.
    for width in range(1, MAX_BITSET_TERMS + 1):
        mask = _search_mask(samples, bits, width, hit)
        if mask is not None:
            table = {"mask": float(mask), "hit": float(hit), "miss": float(miss)}
            return _program(OperatorForm.BITSET_PREDICATE, table=table, max_steps=3)
    return None


def _search_mask(
    samples: Sequence[OperatorSample], bits: Sequence[int], width: int, hit: float
) -> int | None:
    candidates: list[int] = list(bits) if width == 1 else []
    if width == 2:
        candidates = [a | b for i, a in enumerate(bits) for b in bits[i + 1 :]]
    for mask in candidates:
        if all(
            ((s.frame.actor_properties & mask) == mask)
            == (abs(s.risk - hit) <= EQUIVALENCE_EPSILON)
            for s in samples
        ):
            return mask
    return None


def _gini(labels: Sequence[float]) -> float:
    total = len(labels)
    if total == 0:
        return 0.0
    counts: dict[float, int] = {}
    for label in labels:
        counts[label] = counts.get(label, 0) + 1
    return 1.0 - sum((count / total) ** 2 for count in counts.values())


def _best_split(rows: Sequence[tuple[tuple[float, ...], float]]) -> tuple[int, float] | None:
    labels = [label for _, label in rows]
    base = _gini(labels)
    best: tuple[float, int, float] | None = None
    for index in range(len(OPERATOR_FEATURE_NAMES)):
        values = sorted({row[0][index] for row in rows})
        for left_value, right_value in zip(values, values[1:], strict=False):
            threshold = (left_value + right_value) / 2.0
            left = [label for features, label in rows if features[index] <= threshold]
            right = [label for features, label in rows if features[index] > threshold]
            if not left or not right:
                continue
            impurity = (
                len(left) * _gini(left) + len(right) * _gini(right)
            ) / len(rows)
            if impurity < base - EQUIVALENCE_EPSILON and (best is None or impurity < best[0]):
                best = (impurity, index, threshold)
    return None if best is None else (best[1], best[2])


def synthesize_decision_dag(
    samples: Sequence[OperatorSample], *, max_depth: int = 4, max_nodes: int = 31
) -> OperatorProgram | None:
    """Gini-split tree over :data:`OPERATOR_FEATURE_NAMES`.

    Refuses whenever a leaf would still be impure inside the bounds. A
    depth-limited tree normally emits a majority-vote leaf; here that would be
    an operator that knowingly disagrees with its own training region, so the
    honest answer is ``None`` and the selector picks another form.
    """
    _require_cap(max_depth, MAX_DAG_DEPTH, "max_depth")
    _require_cap(max_nodes, MAX_DAG_NODES, "max_nodes")
    if not samples:
        return None
    rows = [(feature_vector(s.frame), round(s.risk, 12)) for s in samples]
    table: dict[str, float] = {}
    counter = [0]
    if _build_node(rows, table, counter, depth=0, max_depth=max_depth, max_nodes=max_nodes) < 0:
        return None
    table["nodes"] = float(counter[0])
    return _program(OperatorForm.DECISION_DAG, table=table, max_steps=max_depth + 1)


def _build_node(
    rows: Sequence[tuple[tuple[float, ...], float]],
    table: dict[str, float],
    counter: list[int],
    *,
    depth: int,
    max_depth: int,
    max_nodes: int,
) -> int:
    if counter[0] >= max_nodes:
        return -1
    node = counter[0]
    counter[0] += 1
    labels = [label for _, label in rows]
    if _gini(labels) <= EQUIVALENCE_EPSILON:
        table[f"n{node}.kind"] = 0.0
        table[f"n{node}.risk"] = float(labels[0])
        return node
    if depth >= max_depth:
        return -1
    split = _best_split(rows)
    if split is None:
        return -1
    index, threshold = split
    left_rows = [row for row in rows if row[0][index] <= threshold]
    right_rows = [row for row in rows if row[0][index] > threshold]
    table[f"n{node}.kind"] = 1.0
    table[f"n{node}.feature"] = float(index)
    table[f"n{node}.threshold"] = float(threshold)
    kwargs = {"max_depth": max_depth, "max_nodes": max_nodes}
    left = _build_node(left_rows, table, counter, depth=depth + 1, **kwargs)
    right = _build_node(right_rows, table, counter, depth=depth + 1, **kwargs)
    if left < 0 or right < 0:
        return -1
    table[f"n{node}.left"] = float(left)
    table[f"n{node}.right"] = float(right)
    return node


def _fsm_states(samples: Sequence[OperatorSample], max_states: int) -> list[int] | None:
    states: list[int] = []
    for sample in samples:
        mask = sample.frame.delta.bitmask()
        if mask not in states:
            states.append(mask)
            if len(states) > max_states:
                return None
    return states


def synthesize_fsm_fragment(
    samples: Sequence[OperatorSample], *, max_states: int = 8
) -> OperatorProgram | None:
    """Deterministic fragment over observed ΔS masks. Refuses non-determinism."""
    _require_cap(max_states, MAX_FSM_STATES, "max_states")
    states = _fsm_states(samples, max_states)
    if not states:
        return None
    table: dict[str, float] = {"states": float(len(states))}
    for current, following in zip(samples, samples[1:], strict=False):
        source = states.index(current.frame.delta.bitmask())
        key = f"t{source}|{int(following.frame.relation_family)}"
        target = float(states.index(following.frame.delta.bitmask()))
        if key in table and abs(table[key] - target) > EQUIVALENCE_EPSILON:
            return None  # a non-deterministic edge is not an FSM
        table[key] = target
    for sample in samples:
        key = f"r{states.index(sample.frame.delta.bitmask())}"
        if key in table and abs(table[key] - sample.risk) > EQUIVALENCE_EPSILON:
            return None
        table[key] = float(sample.risk)
    return _program(OperatorForm.FSM_FRAGMENT, table=table, max_steps=len(states))


def synthesize_weighted_transition(
    samples: Sequence[OperatorSample], *, max_states: int = 8
) -> OperatorProgram | None:
    """Same bounded state set, but edges carry observed frequency.

    Unlike the FSM fragment this tolerates non-determinism — that is the point
    of a weighted fragment — but it still refuses to exceed ``max_states``, and
    it refuses when one state carries two different risks, because the risk is
    the security output and cannot be probabilistic here.
    """
    _require_cap(max_states, MAX_FSM_STATES, "max_states")
    states = _fsm_states(samples, max_states)
    if not states:
        return None
    counts: dict[str, int] = {}
    totals: dict[int, int] = {}
    for current, following in zip(samples, samples[1:], strict=False):
        source = states.index(current.frame.delta.bitmask())
        key = (
            f"p{source}|{int(following.frame.relation_family)}"
            f"|{states.index(following.frame.delta.bitmask())}"
        )
        counts[key] = counts.get(key, 0) + 1
        totals[source] = totals.get(source, 0) + 1
    table: dict[str, float] = {"states": float(len(states))}
    for key, count in counts.items():
        source = int(key[1:].split("|", 1)[0])
        table[key] = count / totals[source]
    for sample in samples:
        key = f"r{states.index(sample.frame.delta.bitmask())}"
        if key in table and abs(table[key] - sample.risk) > EQUIVALENCE_EPSILON:
            return None
        table[key] = float(sample.risk)
    return _program(OperatorForm.WEIGHTED_TRANSITION, table=table, max_steps=len(states))


def _solve(matrix: list[list[float]], rhs: list[float]) -> list[float] | None:
    """Gaussian elimination with partial pivoting. ``None`` when singular."""
    size = len(rhs)
    for column in range(size):
        pivot = max(range(column, size), key=lambda r: abs(matrix[r][column]))
        if abs(matrix[pivot][column]) < 1e-12:
            return None
        matrix[column], matrix[pivot] = matrix[pivot], matrix[column]
        rhs[column], rhs[pivot] = rhs[pivot], rhs[column]
        for row in range(column + 1, size):
            factor = matrix[row][column] / matrix[column][column]
            for inner in range(column, size):
                matrix[row][inner] -= factor * matrix[column][inner]
            rhs[row] -= factor * rhs[column]
    solution = [0.0] * size
    for row in reversed(range(size)):
        acc = rhs[row] - sum(matrix[row][c] * solution[c] for c in range(row + 1, size))
        solution[row] = acc / matrix[row][row]
    return solution


def _rank_features(
    rows: Sequence[tuple[float, ...]], targets: Sequence[float], k: int
) -> list[int]:
    """Pick up to ``k`` informative features, best correlated with risk first.

    A zero-variance feature is dropped rather than ranked last: it is collinear
    with the intercept, so including it makes the normal matrix singular and the
    fit would be refused for a reason that has nothing to do with the region.
    """
    count = len(targets)
    mean_target = sum(targets) / count
    scored: list[tuple[float, int]] = []
    for index in range(len(OPERATOR_FEATURE_NAMES)):
        column = [row[index] for row in rows]
        mean_column = sum(column) / count
        covariance = sum(
            (column[i] - mean_column) * (targets[i] - mean_target) for i in range(count)
        )
        spread = sum((value - mean_column) ** 2 for value in column)
        if spread < 1e-12:
            continue
        scored.append((abs(covariance) / spread**0.5, index))
    scored.sort(key=lambda item: (-item[0], item[1]))
    return sorted(index for _, index in scored[:k])


def synthesize_linear_expression(
    samples: Sequence[OperatorSample], *, max_terms: int = 6
) -> OperatorProgram | None:
    """Least squares by normal equations, at most ``max_terms`` features.

    Refuses a singular system and refuses a fit whose worst residual exceeds
    :data:`EQUIVALENCE_EPSILON` scaled to ``_LINEAR_MAX_RESIDUAL`` — an operator
    that does not reproduce its own region is not an equivalent operator.
    """
    _require_cap(max_terms, MAX_LINEAR_TERMS, "max_terms")
    if len(samples) < max_terms + 1:
        return None
    rows = [feature_vector(s.frame) for s in samples]
    targets = [float(s.risk) for s in samples]
    chosen = _rank_features(rows, targets, max_terms)
    if not chosen:
        return None  # nothing in the frame varies: there is no expression to fit
    design = [[1.0, *(row[i] for i in chosen)] for row in rows]
    size = len(chosen) + 1
    normal = [[sum(r[a] * r[b] for r in design) for b in range(size)] for a in range(size)]
    rhs = [sum(design[i][a] * targets[i] for i in range(len(targets))) for a in range(size)]
    solution = _solve(normal, rhs)
    if solution is None:
        return None
    residual = max(
        abs(sum(design[i][a] * solution[a] for a in range(size)) - targets[i])
        for i in range(len(targets))
    )
    if residual > _LINEAR_MAX_RESIDUAL:
        return None
    table = {"b": solution[0]}
    table.update({f"w{index}": solution[pos + 1] for pos, index in enumerate(chosen)})
    return _program(OperatorForm.LINEAR_EXPRESSION, table=table, max_steps=len(chosen) + 1)


#: A linear operator must reproduce its region, not merely trend with it.
_LINEAR_MAX_RESIDUAL = 1e-6


def _operands(op: Op) -> tuple[int, ...]:
    if OPERAND_ARITY[op] == 0:
        return (0,)
    return tuple(range(min(OPERAND_RANGE[op], _MAX_ENUM_OPERAND)))


def _stack_after(stack: tuple[ValueType, ...], op: Op) -> tuple[ValueType, ...] | None:
    """Abstract stack typing. ``None`` prunes the branch as ill-typed."""
    pops, pushes = STACK_EFFECT[op]
    if len(pops) > len(stack):
        return None
    if pops and tuple(stack[len(stack) - len(pops) :]) != tuple(pops):
        return None
    result = stack[: len(stack) - len(pops)] + tuple(pushes)
    return None if len(result) > MAX_STACK else result


def synthesize_bytecode(
    samples: Sequence[OperatorSample],
    *,
    max_instructions: int = 24,
    node_budget: int = 20_000,
) -> OperatorProgram | None:
    """Bounded enumerative search over the PCB ISA, verifier as acceptance test.

    The enumerator reads the ISA's own ``OPERAND_ARITY``, ``OPERAND_RANGE`` and
    ``STACK_EFFECT`` tables rather than hardcoding a program shape, prunes
    ill-typed prefixes by abstract stack typing, and only ever *proposes* a
    program — :func:`verify` decides, and the candidate is then executed on
    every sample and must reproduce it exactly. So this function cannot return
    an unverified program: that is a property of the control flow here, not of
    the tests.

    ``node_budget`` bounds expanded prefixes. Exhausting it returns ``None``.
    The budget is small next to the ISA's branching factor, so in practice the
    search reaches only short programs — a refusal to search further, never a
    claim that no longer program exists.

    **A constant cannot be reached this wave.** ``LOAD_CONST`` indexes a pool
    that ``isa.load_constants`` reads out of ``OperatorProgram.table``, but
    ``OperatorProgram`` refuses a table on a BYTECODE program. The pool is
    therefore always empty and every ``LOAD_CONST`` fails its range check, so
    the enumerator cannot emit a literal. This is recorded as a cross-package
    conflict rather than worked around: emitting a table here would mean
    shipping an operator the shared constructor refuses to build.
    """
    _require_cap(max_instructions, MAX_SYNTH_INSTRUCTIONS, "max_instructions")
    _require_cap(node_budget, MAX_SYNTH_NODE_BUDGET, "node_budget")
    if not samples:
        return None
    vm = CellVM()
    budget = [node_budget]
    for length in range(1, max_instructions + 1):
        found = _enumerate(samples, vm, budget, prefix=(), stack=(), remaining=length)
        if found is not None:
            return found
        if budget[0] <= 0:
            return None
    return None


def _enumerate(
    samples: Sequence[OperatorSample],
    vm: CellVM,
    budget: list[int],
    *,
    prefix: tuple[Instruction, ...],
    stack: tuple[ValueType, ...],
    remaining: int,
) -> OperatorProgram | None:
    if budget[0] <= 0:
        return None
    if remaining == 0:
        if not prefix or prefix[-1].op not in TERMINATORS:
            return None
        return _accept(samples, vm, prefix)
    for op in Op:
        if op in TERMINATORS and remaining != 1:
            continue
        for operand in _operands(op):
            budget[0] -= 1
            if budget[0] <= 0:
                return None
            after = _stack_after(stack, op)
            if after is None:
                continue
            found = _enumerate(
                samples,
                vm,
                budget,
                prefix=(*prefix, Instruction(op=op, operand=operand)),
                stack=after,
                remaining=remaining - 1,
            )
            if found is not None:
                return found
    return None


def _accept(
    samples: Sequence[OperatorSample],
    vm: CellVM,
    prefix: tuple[Instruction, ...],
) -> OperatorProgram | None:
    """Verify, then require exact reproduction of every sample. Else refuse."""
    program = _program(OperatorForm.BYTECODE, words=encode(prefix), max_steps=len(prefix))
    if program is None or not verify(program).ok:
        return None
    for sample in samples:
        result = vm.run(program, sample.frame)
        if result.abstained != sample.abstain:
            return None
        if abs(result.risk - sample.risk) > EQUIVALENCE_EPSILON:
            return None
        if sample.delta.raised and _delta_key(result.delta) != _delta_key(sample.delta):
            return None
    return program


#: The selector iterates this list. A tuple rather than a chain of ``if``s so
#: that adding a form is one line and cannot forget a call site.
SYNTHESISERS: tuple[tuple[OperatorForm, Callable[..., OperatorProgram | None]], ...] = (
    (OperatorForm.CONSTANT, synthesize_constant),
    (OperatorForm.LOOKUP_TABLE, synthesize_lookup_table),
    (OperatorForm.BITSET_PREDICATE, synthesize_bitset_predicate),
    (OperatorForm.DECISION_DAG, synthesize_decision_dag),
    (OperatorForm.FSM_FRAGMENT, synthesize_fsm_fragment),
    (OperatorForm.WEIGHTED_TRANSITION, synthesize_weighted_transition),
    (OperatorForm.LINEAR_EXPRESSION, synthesize_linear_expression),
    (OperatorForm.BYTECODE, synthesize_bytecode),
)

assert len(SYNTHESISERS) == len(OperatorForm), "every operator form needs a synthesiser"
assert {form for form, _ in SYNTHESISERS} == set(OperatorForm)
