"""D9.5 (interpreter) — the phenotype: a genome's typed programs, run over one session.

A genome is text; a phenotype is what that text does to a session of
:class:`EncodedTransition` events. This module exists so that every Stage 9 score — search
fitness, ARGUS attacks, held-out winners — is produced by ONE interpreter whose cost is
exactly the static bound the IR computed, whose state is bounded, and whose output is
deterministic byte for byte.

How a session runs:

* Events are grouped into **lineages** keyed by ``EncodedTransition.actor_slot`` (a
  session-local index, never an identity). Each lineage owns its registers. The UPDATE
  program runs once per event against that event's lineage; the READOUT program runs once
  per lineage, and the lineage readouts are aggregated (MAX, SUM or MEAN) into the score.
* At most :data:`MAX_LINEAGES` lineages are live. A new lineage evicts the least recently
  updated one; the victim's readout is charged, computed and **folded into the aggregate**,
  its state is dropped, the eviction is counted, and if it reappears it restarts from
  ``init``. This is deliberate and it is the attack surface ARGUS's ``lineage_table_flood``
  measures — a bound whose cost is reported, not hidden.
* A session longer than :data:`MAX_SESSION_EVENTS` **abstains** (``score=None``, no work
  done) and its overflow is counted in ``truncated_events``. It used to score the first
  4096 events and return an ordinary number, so 4096 cheap events pushed an attack out of
  the scored window with nothing flagged (S9-FC-02): a bound that is hit must fail CLOSED
  to UNKNOWN, as the successor contract's ``ABSTAIN_UNKNOWN`` says, never to a confident
  prefix score. A session with fewer than ``min_events_for_score`` events abstains too:
  too little evidence, like too much to cover, is a valid answer, not a zero.
* FLOAT register writes are quantised to the register's ``precision_bits`` (round half to
  even), which is the genome's compression law made executable.

Cost: a meter is charged ``events * update_wu`` **before** any event runs, and each lineage
readout **before** it is computed. :class:`WorkBudgetExceeded` propagates, so a starved run
produces no score at all — never a partial one computed from the events it could afford.

What this module refuses to do: it never evaluates text (the program is lowered to a flat
tuple of ``(callable, argument slots)`` steps built from the alphabet's functions — no
``eval``, ``exec`` or ``compile``), it holds no randomness, it never iterates a set to
decide an outcome, and it writes nothing outside the session it is running.
"""

from __future__ import annotations

import hashlib
import json
from collections import OrderedDict, deque
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage2.dataset import Stage2Dataset
from pocketsec.stage2.encoder.ssir_encoder import FEATURE_WIDTH, EncodedTransition
from pocketsec.stage6.resources import WorkMeter
from pocketsec.stage9.chemistry.typed_ir import (
    INT_MASK,
    IR_VERSION,
    MAX_LINEAGES,
    MAX_LOOKUP_ENTRIES,
    MAX_SESSION_EVENTS,
    SIDE_ENTRY_BYTES,
    VALUE_BYTES,
    InputSource,
    IRError,
    IRNode,
    IRProgram,
    IRType,
    NodeKind,
    ProgramPhase,
    RegisterSpec,
    StaticBounds,
    clamp_float,
    coerce_value,
    quantise,
    static_bounds,
    validate_program,
)
from pocketsec.stage9.foundry.primitives import (
    SEED_ALPHABET,
    PrimitiveAlphabet,
    SideTable,
    bind_context,
)

__all__ = [
    "MAX_EVIDENCE_EVENTS",
    "Phenotype",
    "SessionAggregation",
    "SessionInterventions",
    "SessionRun",
]

#: Evidence events kept per lineage (spec §4.5): the most recent register-changing events.
MAX_EVIDENCE_EVENTS = 8

#: Slots 0..2 of every step's value vector hold (event, lineage registers, first-event flag);
#: node ``i`` of the program writes slot ``i + _BASE``.
_BASE = 3

Runner = Callable[[list[Any]], Any]
#: One lowered node: the runner that computes it and the value slots it reads (kept for
#: audit; the runner already closes over them).
Step = tuple[Runner, tuple[int, ...]]


class SessionAggregation(StrEnum):
    MAX = "MAX"
    SUM = "SUM"
    MEAN = "MEAN"


@dataclass(frozen=True, slots=True)
class SessionInterventions:
    """Counterfactual edits to a run, applied **before** the event at the given index.

    An index equal to the session's event count applies after the last event, before the
    final readout. ``reset_at`` models a detector restart (ARGUS): every piece of session
    state is dropped — live lineages, side tables and the aggregate folded so far — so
    the score reflects only events from the reset on. ``forget`` deletes one lineage's
    state (CHRONOS World B = M minus m): no readout is folded for it.
    """

    reset_at: int | None = None
    forget: tuple[tuple[int, int], ...] = ()

    def __post_init__(self) -> None:
        reset_at = self.reset_at
        if reset_at is not None and (
            isinstance(reset_at, bool) or not isinstance(reset_at, int) or reset_at < 0
        ):
            raise ContractError(f"reset_at must be a non-negative int or None, got {reset_at!r}")
        if not isinstance(self.forget, tuple) or len(self.forget) > MAX_SESSION_EVENTS:
            raise ContractError(f"forget must be a tuple of at most {MAX_SESSION_EVENTS} pairs")
        for pair in self.forget:
            if not (
                isinstance(pair, tuple)
                and len(pair) == 2
                and all(isinstance(v, int) and not isinstance(v, bool) and v >= 0 for v in pair)
            ):
                raise ContractError(f"forget entries are (event index, actor_slot), got {pair!r}")


@dataclass(frozen=True, slots=True)
class SessionRun:
    #: None = abstained (events < min_events_for_score, more than MAX_SESSION_EVENTS events,
    #: or no lineage left)
    score: float | None
    work_units: int  # exactly events*update_wu + readouts*readout_wu
    events: int  # events processed: 0 when the session abstained
    #: Events beyond MAX_SESSION_EVENTS. > 0 means the session abstained unprocessed.
    truncated_events: int
    lineages: int  # live lineages at session end (<= MAX_LINEAGES)
    lineage_evictions: int  # LRU; an evicted lineage's readout is folded into the aggregate
    side_table_evictions: int
    state_bytes_peak: int  # accounted from live registers + side tables, <= static bound
    evidence: tuple[str, ...]  # locators of the <= 8 latest events that changed the winner


class _Lineage:
    __slots__ = ("evidence", "fresh", "regs", "slot")

    def __init__(self, slot: int, registers: Sequence[RegisterSpec]) -> None:
        self.slot = slot
        self.regs = [deque([spec.init] * spec.ring, maxlen=spec.ring) for spec in registers]
        self.evidence: deque[tuple[str, ...]] = deque(maxlen=MAX_EVIDENCE_EVENTS)
        self.fresh = True


class _Aggregate:
    """Running MAX/SUM/MEAN over folded lineage readouts, in fold order (deterministic)."""

    __slots__ = ("best", "count", "mode", "total")

    def __init__(self, mode: SessionAggregation) -> None:
        self.mode = mode
        self.total = 0.0
        self.count = 0
        self.best: tuple[float, int, tuple[tuple[str, ...], ...]] | None = None

    def fold(self, value: float, lineage: _Lineage) -> None:
        self.total += value
        self.count += 1
        # Ties go to the lowest actor_slot; an equal (value, slot) keeps the earlier fold.
        if self.best is None or value > self.best[0] or (
            value == self.best[0] and lineage.slot < self.best[1]
        ):
            self.best = (value, lineage.slot, tuple(lineage.evidence))

    def score(self) -> float | None:
        if self.count == 0 or self.best is None:
            return None
        if self.mode is SessionAggregation.MAX:
            return self.best[0]
        return self.total if self.mode is SessionAggregation.SUM else self.total / self.count

    def evidence(self) -> tuple[str, ...]:
        if self.best is None:
            return ()
        seen: dict[str, None] = {}
        for locators in self.best[2]:
            for locator in locators:
                seen.setdefault(locator, None)
        return tuple(seen)


# --- lowering a program to steps (no eval: closures over validated node fields) --------


def _applier(fn: Callable[..., Any], slots: tuple[int, ...]) -> Runner:
    """A closure that calls ``fn`` on the value slots it names, specialised by arity so
    the per-event loop pays one call per node rather than a generic unpack."""
    if len(slots) == 1:
        (a,) = slots
        return lambda v: fn(v[a])
    if len(slots) == 2:
        a, b = slots
        return lambda v: fn(v[a], v[b])
    if len(slots) == 3:
        a, b, c = slots
        return lambda v: fn(v[a], v[b], v[c])
    return lambda v: fn(*[v[slot] for slot in slots])


def _constant(value: Any) -> Runner:
    return lambda v: value


def _register(index: int, lag: int) -> Runner:
    return lambda v: v[1][index][lag]


def _feature(index: int) -> Runner:
    return lambda v: clamp_float(v[0].features[index])


def _int_field(name: str) -> Runner:
    return lambda v: int(getattr(v[0], name)) & INT_MASK


_INT_FIELDS: Mapping[InputSource, str] = {
    InputSource.STATE_DELTA_MASK: "state_delta_mask",
    InputSource.RELATION: "relation",
    InputSource.RELATION_FAMILY: "relation_family",
    InputSource.TIME_BUCKET: "time_bucket",
    InputSource.OBJECT_PROPERTY_MASK: "object_property_mask",
    InputSource.EPOCH_ID: "epoch_id",
}


def _input_step(node: IRNode) -> Step:
    source = node.source
    if source is InputSource.FEATURE:
        return (_feature(node.index), (0,))
    if source is InputSource.DELTA_PHI:
        return (lambda v: clamp_float(v[0].delta_phi), (0,))
    if source is InputSource.LINEAGE_FIRST_EVENT:
        return (lambda v: v[2], (2,))
    if source is None or source not in _INT_FIELDS:  # pragma: no cover - IRNode refuses this
        raise IRError("TYPE_MISMATCH", f"no reader for input {source!r}")
    return (_int_field(_INT_FIELDS[source]), (0,))


def _template(program: IRProgram, alphabet: PrimitiveAlphabet) -> tuple[tuple[Any, ...], ...]:
    """Lower once: (runner | None, slots, primitive | None) per node, in index order.

    Slots 0..2 are (event, lineage registers, first-event flag); node ``i`` writes slot
    ``i + _BASE``. An APPLY row keeps its primitive so each session can bind its own
    side tables.
    """
    rows: list[tuple[Any, ...]] = []
    for node in program.nodes:
        if node.kind is NodeKind.INPUT:
            rows.append((*_input_step(node), None))
        elif node.kind is NodeKind.REG:
            rows.append((_register(node.index, node.lag), (1,), None))
        elif node.kind is NodeKind.CONST:
            rows.append((_constant(node.value), (), None))
        else:
            primitive = alphabet.get(node.primitive)
            rows.append((None, tuple(arg + _BASE for arg in node.args), primitive))
    return tuple(rows)


def _bind(
    template: tuple[tuple[Any, ...], ...], lookup: tuple[float, ...], tables: list[SideTable]
) -> tuple[Step, ...]:
    """Bind a template for one session: each side-table node gets its own fresh table."""
    steps: list[Step] = []
    for runner, slots, primitive in template:
        if primitive is None:
            steps.append((runner, slots))
            continue
        table = None
        if primitive.side_table:
            table = SideTable()
            tables.append(table)
        fn = bind_context(primitive, lookup_table=lookup, side_table=table)
        steps.append((_applier(fn, slots), slots))
    return tuple(steps)


def _run(steps: tuple[Step, ...], values: list[Any]) -> list[Any]:
    append = values.append
    for runner, _slots in steps:
        append(runner(values))
    return values


# --- one session ----------------------------------------------------------------------


class _Session:
    """Mutable state of one run; lives only inside :meth:`Phenotype.run_session`."""

    def __init__(self, phenotype: Phenotype, meter: WorkMeter | None) -> None:
        self.p = phenotype
        self.meter = meter
        self.readouts = 0
        self.evictions = 0
        self.peak = 0
        self.retired_side_evictions = 0
        self.tables: list[SideTable] = []
        self.update_steps: tuple[Step, ...] = ()
        self.readout_steps: tuple[Step, ...] = ()
        self.lineages: OrderedDict[int, _Lineage] = OrderedDict()
        self.aggregate = _Aggregate(phenotype._aggregation)
        self.reset()

    def reset(self) -> None:
        """Drop every piece of session state; work already paid for stays counted."""
        self.retired_side_evictions += sum(table.evictions for table in self.tables)
        self.tables = []
        self.update_steps = _bind(self.p._update_template, self.p._lookup, self.tables)
        self.readout_steps = _bind(self.p._readout_template, self.p._lookup, self.tables)
        self.lineages = OrderedDict()
        self.aggregate = _Aggregate(self.p._aggregation)

    def readout(self, lineage: _Lineage) -> None:
        if self.meter is not None:
            self.meter.charge(self.p._bounds.readout_wu_per_lineage)
        self.readouts += 1
        values = _run(self.readout_steps, [None, lineage.regs, None])
        self.aggregate.fold(values[self.p._readout_output], lineage)

    def lineage_for(self, slot: int) -> _Lineage:
        lineage = self.lineages.get(slot)
        if lineage is not None:
            self.lineages.move_to_end(slot)
            return lineage
        if len(self.lineages) >= MAX_LINEAGES:
            _, victim = self.lineages.popitem(last=False)
            self.readout(victim)
            self.evictions += 1
        lineage = _Lineage(slot, self.p._registers)
        self.lineages[slot] = lineage
        return lineage

    def step(self, event: EncodedTransition) -> None:
        if self.p._reads_features and len(event.features) != FEATURE_WIDTH:
            raise ContractError(f"event has {len(event.features)} features, not {FEATURE_WIDTH}")
        lineage = self.lineage_for(event.actor_slot)
        values = _run(self.update_steps, [event, lineage.regs, lineage.fresh])
        changed = False
        for register, output, bits in self.p._writes:
            value = values[output]
            if bits is not None:
                value = quantise(value, bits)
            ring = lineage.regs[register]
            if ring[0] != value:
                changed = True
            ring.appendleft(value)
        if changed:
            lineage.evidence.append(event.evidence)
        lineage.fresh = False

    def account(self) -> None:
        """Sample accounted bytes. Live lineages and side-table sizes never shrink between
        interventions (eviction replaces, it does not free), so sampling just before each
        reset/forget and at session end yields the exact peak without a per-event cost."""
        side = sum(len(table) for table in self.tables) * SIDE_ENTRY_BYTES
        live = len(self.lineages) * self.p._bounds.state_bytes_per_lineage
        self.peak = max(self.peak, live + side + self.p._scratch_bytes)

    def side_evictions(self) -> int:
        return self.retired_side_evictions + sum(table.evictions for table in self.tables)


class Phenotype:
    """A validated, lowered genome program pair, ready to score sessions.

    Construction expands macros, validates both programs against ``alphabet``, computes the
    static bounds, and lowers each program to a flat step tuple. Nothing is mutable after
    construction; each :meth:`run_session` builds and discards its own state.
    """

    __slots__ = (
        "_aggregation", "_alphabet", "_bounds", "_digest", "_lookup", "_min_events",
        "_readout", "_readout_output", "_readout_template", "_reads_features", "_registers",
        "_scratch_bytes", "_update", "_update_template", "_writes",
    )

    def __init__(
        self,
        *,
        update: IRProgram,
        readout: IRProgram,
        registers: Sequence[RegisterSpec],
        aggregation: SessionAggregation,
        lookup_table: Sequence[float] = (),
        min_events_for_score: int = 1,
        alphabet: PrimitiveAlphabet = SEED_ALPHABET,
    ) -> None:
        registers = tuple(registers)
        if not isinstance(update, IRProgram) or update.phase is not ProgramPhase.UPDATE:
            raise IRError("TYPE_MISMATCH", "update must be an UPDATE IRProgram")
        if not isinstance(readout, IRProgram) or readout.phase is not ProgramPhase.READOUT:
            raise IRError("TYPE_MISMATCH", "readout must be a READOUT IRProgram")
        # Validate the call sites first (macro signatures), then the inlined programs.
        validate_program(update, registers, alphabet)
        validate_program(readout, registers, alphabet)
        self._update = alphabet.expand(update)
        self._readout = alphabet.expand(readout)
        self._registers = registers
        self._alphabet = alphabet
        self._bounds = static_bounds(self._update, self._readout, registers, alphabet)
        self._aggregation = _aggregation(aggregation)
        self._lookup = _lookup_table(lookup_table)
        self._min_events = _min_events(min_events_for_score)
        self._update_template = _template(self._update, alphabet)
        self._readout_template = _template(self._readout, alphabet)
        self._readout_output = self._readout.outputs[0] + _BASE
        pairs = zip(self._update.outputs, registers, strict=True)
        self._writes = tuple(
            (index, output + _BASE, spec.precision_bits if spec.type is IRType.FLOAT else None)
            for index, (output, spec) in enumerate(pairs)
        )
        self._reads_features = any(
            node.source is InputSource.FEATURE for node in self._update.nodes
        )
        self._scratch_bytes = (len(self._update.nodes) + len(self._readout.nodes)) * VALUE_BYTES
        self._digest = self._compute_digest()

    def _compute_digest(self) -> str:
        # The computation is the expanded programs over non-macro primitives, so the digest
        # binds those and not the macro vocabulary a search happened to propose them in.
        executed = PrimitiveAlphabet(p for p in self._alphabet if p.macro is None)
        canonical = json.dumps(
            {
                "ir_version": IR_VERSION,
                "alphabet": executed.digest,
                "update": self._update.to_dict(),
                "readout": self._readout.to_dict(),
                "registers": [spec.to_dict() for spec in self._registers],
                "aggregation": self._aggregation.value,
                "lookup_table": list(self._lookup),
                "min_events_for_score": self._min_events,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @property
    def bounds(self) -> StaticBounds:
        return self._bounds

    @property
    def digest(self) -> str:
        return self._digest

    @property
    def update(self) -> IRProgram:
        return self._update

    @property
    def readout(self) -> IRProgram:
        return self._readout

    @property
    def registers(self) -> tuple[RegisterSpec, ...]:
        return self._registers

    @property
    def aggregation(self) -> SessionAggregation:
        return self._aggregation

    @property
    def lookup_table(self) -> tuple[float, ...]:
        return self._lookup

    @property
    def min_events_for_score(self) -> int:
        return self._min_events

    def run_session(
        self,
        steps: Sequence[EncodedTransition],
        *,
        meter: WorkMeter | None = None,
        interventions: SessionInterventions = SessionInterventions(),  # noqa: B008 - frozen
    ) -> SessionRun:
        """Score one session; charges the meter before working (see the module docstring)."""
        if len(steps) > MAX_SESSION_EVENTS:  # fail closed, never a prefix score (S9-FC-02)
            return SessionRun(None, 0, 0, len(steps) - MAX_SESSION_EVENTS, 0, 0, 0, 0, ())
        events, truncated = len(steps), 0
        if events < self._min_events:
            return SessionRun(None, 0, events, truncated, 0, 0, 0, 0, ())
        if meter is not None:
            meter.charge(events * self._bounds.update_wu_per_event)
        session = _Session(self, meter)
        forget = _forget_schedule(interventions.forget)
        marks = set(forget) | ({interventions.reset_at} - {None})
        for index in range(events):
            if index in marks:
                _intervene(session, index, interventions.reset_at, forget)
            session.step(steps[index])
        _intervene(session, events, interventions.reset_at, forget)
        session.account()
        for lineage in session.lineages.values():
            session.readout(lineage)
        return SessionRun(
            score=session.aggregate.score(),
            work_units=(
                events * self._bounds.update_wu_per_event
                + session.readouts * self._bounds.readout_wu_per_lineage
            ),
            events=events,
            truncated_events=truncated,
            lineages=len(session.lineages),
            lineage_evictions=session.evictions,
            side_table_evictions=session.side_evictions(),
            state_bytes_peak=session.peak,
            evidence=session.aggregate.evidence(),
        )

    def run_dataset(
        self, dataset: Stage2Dataset, *, meter: WorkMeter | None = None
    ) -> tuple[SessionRun, ...]:
        """Score every session of ``dataset`` in order, sharing one meter."""
        return tuple(self.run_session(sample.steps, meter=meter) for sample in dataset.samples)


def _forget_schedule(forget: tuple[tuple[int, int], ...]) -> dict[int, tuple[int, ...]]:
    schedule: dict[int, list[int]] = {}
    for index, slot in forget:
        schedule.setdefault(index, []).append(slot)
    return {index: tuple(slots) for index, slots in schedule.items()}


def _intervene(
    session: _Session, index: int, reset_at: int | None, forget: dict[int, tuple[int, ...]]
) -> None:
    session.account()  # the last moment the state about to be dropped is still live
    if reset_at == index:
        session.reset()
    for slot in forget.get(index, ()):
        session.lineages.pop(slot, None)


def _aggregation(value: object) -> SessionAggregation:
    try:
        if not isinstance(value, str):
            raise ValueError(value)
        return SessionAggregation(value)
    except ValueError as error:
        raise ContractError(f"unknown session aggregation {value!r}") from error


def _lookup_table(values: Sequence[float]) -> tuple[float, ...]:
    table = tuple(values)
    if len(table) > MAX_LOOKUP_ENTRIES:
        raise IRError("LOOKUP_BOUND", f"{len(table)} lookup entries above {MAX_LOOKUP_ENTRIES}")
    return tuple(float(coerce_value(v, IRType.FLOAT, "lookup entry")) for v in table)


def _min_events(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ContractError(f"min_events_for_score must be an int >= 1, got {value!r}")
    return value
