"""D9.10 — CHRONOS: which memory law buys the most security per retained byte?

The architecture (§25-§28) says the memory architecture "is selected by security utility per
retained byte, not by convention", and that forgetting should be an optimisation target
rather than an accident. This module makes both claims measurable on one genome at a time:

* :func:`memory_family_genome` rebuilds a base genome's FIRST register with one of six
  memory laws (:class:`MemoryFamily`). The base register must have the shape
  ``r0' = op(r0, u)`` — a previous value combined with an input term ``u`` — which is the
  shape of the Φ-oracle (``MAX``) and of H1 (``ADD``). Everything else in the genome is kept.
* :func:`evaluate_families` picks each family's one parameter on the TRAIN suite's worst-case
  AP from a small fixed grid, then reports held-out worst-case AP and
  ``utility per byte = (held-out worst-case AP - base rate) / bytes per lineage``.
* :func:`counterfactual_deletion` is architecture §27 made literal: World A runs with the full
  memory, World B forgets one (event, lineage) item through
  :class:`~pocketsec.stage9.chemistry.phenotype.SessionInterventions`, and the report counts
  exactly how many deletions changed a decision and how many pushed a malicious session below
  the threshold (S9X-058, S9X-059).
* :func:`compare_forgetting` holds every family against the control ``EXACT_RING`` (§7).

The families, in the language's own primitives (``u`` = the base register's input term):

=================  ===========================================================================
EXACT_RING         ring of the last ``L`` values of ``u``; readout folds the ring with ``op``
EXPONENTIAL_DECAY  ``r' = DECAY(r, u, lam)`` = ``lam * r + u``
ACCUMULATE         ``r' = ADD(r, u)``: never forgets
SKETCH             ``r' = u`` (memoryless); the session memory is a per-session
                   ``stage1.novelty.sketches.CountMinSketch`` over RELATION, whose mean
                   rarity is ADDED to the session score as a side score. It is not a genome
                   memory law: the language has no sketch primitive, and adding one for this
                   comparison would be a catalogue richer than its consumer (lesson 3).
PROTOTYPE          ``r' = r + alpha * (u - r)``: a running scalar prototype (EWMA)
MULTISCALE         a fast ``DECAY(0.5)`` register and a slow ``DECAY(lam)`` one, read as MAX
=================  ===========================================================================

What this module refuses to do: it never rebuilds a register that is not ``op(prev, u)``
(a ContractError, not a guess), it never counts a deletion as negligible when nothing was
deleted, it never re-fits the decision threshold in World B, and it never declares a family
better than the control on utility per byte if that was bought with more than 0.01 AP.
"""

from __future__ import annotations

import math
import random
from collections.abc import Callable, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.novelty.sketches import CountMinSketch
from pocketsec.stage2.dataset import Stage2Dataset, Stage2Sample
from pocketsec.stage6.resources import WorkMeter
from pocketsec.stage9.chemistry.phenotype import SessionInterventions
from pocketsec.stage9.chemistry.typed_ir import (
    MAX_LINEAGES,
    IRNode,
    IRProgram,
    IRType,
    NodeKind,
    RegisterSpec,
)
from pocketsec.stage9.genome.computational import ComputationalGenomeV1
from pocketsec.stage9.labs.splits import PHI_ORACLE_CEILING
from pocketsec.stage9.laplace.state_discovery import (
    decisions,
    fit_threshold,
    prune_program,
    rebuild,
)
from pocketsec.stage9.ontogenesis.fitness import (
    EvaluationSuite,
    evaluate,
    score_ap,
    session_scores,
)
from pocketsec.stage9.spec.mssc import DetectorComparison, MechanismVerdict

__all__ = [
    "AP_TOLERANCE",
    "FAMILY_GRID",
    "LEARNED_FORGETTING_DEFAULT_ENABLED",
    "MULTISCALE_FAST_LAMBDA",
    "NEGLIGIBLE_SHARE",
    "SKETCH_DEPTH",
    "UTILITY_GAIN",
    "DeletionReport",
    "ForgettingLaw",
    "MemoryFamily",
    "compare_forgetting",
    "counterfactual_deletion",
    "evaluate_families",
    "memory_family_genome",
]

#: Ships False. Only the integrator may set it True, after a measured JUSTIFIED verdict.
LEARNED_FORGETTING_DEFAULT_ENABLED: bool = False

#: A deletion set is negligible when at most this share of deletions changed a decision.
NEGLIGIBLE_SHARE = 0.01
#: JUSTIFIED needs >= 20% better utility per byte than the control ...
UTILITY_GAIN = 0.20
#: ... at held-out worst-case AP no more than this below the control's.
AP_TOLERANCE = 0.01
MULTISCALE_FAST_LAMBDA = 0.5
SKETCH_DEPTH = 2

_MECHANISM = "pocketsec.stage9.chronos.forgetting_law:LEARNED_FORGETTING_DEFAULT_ENABLED"
_FOLDABLE = frozenset({"MAX", "MIN", "ADD"})


class MemoryFamily(StrEnum):
    EXACT_RING = "EXACT_RING"
    EXPONENTIAL_DECAY = "EXPONENTIAL_DECAY"
    ACCUMULATE = "ACCUMULATE"
    SKETCH = "SKETCH"
    PROTOTYPE = "PROTOTYPE"
    MULTISCALE = "MULTISCALE"


#: The parameter grid each family is fitted over on TRAIN (chosen, not measured):
#: ring length, decay lambda, none, sketch width, prototype alpha, slow lambda.
FAMILY_GRID: dict[MemoryFamily, tuple[float | None, ...]] = {
    MemoryFamily.EXACT_RING: (2.0, 4.0, 8.0),
    MemoryFamily.EXPONENTIAL_DECAY: (0.25, 0.5, 0.9),
    MemoryFamily.ACCUMULATE: (None,),
    MemoryFamily.SKETCH: (16.0, 64.0),
    MemoryFamily.PROTOTYPE: (0.1, 0.25, 0.5),
    MemoryFamily.MULTISCALE: (0.9, 0.99),
}
_PARAMETER_NAMES = {
    MemoryFamily.EXACT_RING: "ring_length",
    MemoryFamily.EXPONENTIAL_DECAY: "lambda",
    MemoryFamily.SKETCH: "sketch_width",
    MemoryFamily.PROTOTYPE: "alpha",
    MemoryFamily.MULTISCALE: "slow_lambda",
}


@dataclass(frozen=True, slots=True)
class ForgettingLaw:
    """One memory family, fitted on train, measured held-out."""

    family: str
    parameters: tuple[tuple[str, float], ...]
    bytes_per_lineage: int  # 0 when the family could not be built on this base
    heldout_worst_case_ap: float | None
    utility_per_byte: float | None  # (AP - base_rate) / bytes_per_lineage


@dataclass(frozen=True, slots=True)
class DeletionReport:
    """World A (full memory) against World B (one item forgotten), per deletion."""

    deletions: int
    decisions_changed: int
    negligible: bool  # decisions_changed <= 1% of deletions, and deletions > 0
    catastrophic: int  # malicious sessions a deletion pushed below the threshold (S9X-059)


# --- rebuilding the first register ------------------------------------------------------------


def _is_reg0(node: IRNode) -> bool:
    return node.kind is NodeKind.REG and node.index == 0


def _depends_on_reg0(program: IRProgram, index: int) -> bool:
    stack, seen = [index], set()
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        node = program.nodes[current]
        if _is_reg0(node):
            return True
        stack.extend(node.args)
    return False


def _first_register_shape(base: ComputationalGenomeV1) -> tuple[int, int, str]:
    """(index of the REG r0 read, index of the input term u, combining primitive)."""
    if not base.registers:
        raise ContractError("the base genome has no register to rebuild")
    spec = base.registers[0]
    if spec.type is not IRType.FLOAT or spec.ring != 1:
        raise ContractError("CHRONOS rebuilds a FLOAT ring-1 first register only")
    update = base.update
    out = update.nodes[update.outputs[0]]
    if out.kind is not NodeKind.APPLY or len(out.args) != 2:
        raise ContractError("the first register's update is not op(prev, u)")
    reads = [arg for arg in out.args if _is_reg0(update.nodes[arg])]
    if len(reads) != 1:
        raise ContractError("the first register's update does not read its own previous value once")
    prev = reads[0]
    term = out.args[1] if out.args[0] == prev else out.args[0]
    if update.nodes[term].type is not IRType.FLOAT or _depends_on_reg0(update, term):
        raise ContractError("the first register's input term is not a FLOAT free of r0")
    for program in (base.update, base.readout):
        if any(_is_reg0(n) and n.lag != 0 for n in program.nodes):
            raise ContractError("the base reads r0 at a lag; it is not a ring-1 register")
    return prev, term, out.primitive


def _append(nodes: list[IRNode], node: IRNode) -> int:
    nodes.append(node)
    return len(nodes) - 1


def _apply(nodes: list[IRNode], primitive: str, *args: int) -> int:
    return _append(
        nodes, IRNode(kind=NodeKind.APPLY, type=IRType.FLOAT, primitive=primitive, args=args)
    )


def _const(nodes: list[IRNode], value: float) -> int:
    return _append(nodes, IRNode(kind=NodeKind.CONST, type=IRType.FLOAT, value=float(value)))


def _reg(nodes: list[IRNode], index: int, lag: int = 0) -> int:
    return _append(nodes, IRNode(kind=NodeKind.REG, type=IRType.FLOAT, index=index, lag=lag))


def _substitute_reg0(program: IRProgram, emit: Callable[[list[IRNode]], int]) -> IRProgram:
    """Rebuild ``program`` with every REG r0 read replaced by the nodes ``emit`` appends."""
    nodes: list[IRNode] = []
    remap: list[int] = []
    for node in program.nodes:
        if _is_reg0(node):
            remap.append(emit(nodes))
        else:
            remap.append(_append(nodes, replace(node, args=tuple(remap[a] for a in node.args))))
    return IRProgram(
        phase=program.phase, nodes=tuple(nodes), outputs=tuple(remap[o] for o in program.outputs)
    )


def _new_value(
    family: MemoryFamily, nodes: list[IRNode], prev: int, term: int, parameter: float, extra: int
) -> tuple[int, int | None]:
    """Append r0's new-value expression; returns (r0 output, extra register's output)."""
    if family in (MemoryFamily.EXACT_RING, MemoryFamily.SKETCH):
        return term, None
    if family is MemoryFamily.ACCUMULATE:
        return _apply(nodes, "ADD", prev, term), None
    if family is MemoryFamily.EXPONENTIAL_DECAY:
        return _apply(nodes, "DECAY", prev, term, _const(nodes, parameter)), None
    if family is MemoryFamily.PROTOTYPE:
        step = _apply(nodes, "MUL", _const(nodes, parameter), _apply(nodes, "SUB", term, prev))
        return _apply(nodes, "ADD", prev, step), None
    fast = _apply(nodes, "DECAY", prev, term, _const(nodes, MULTISCALE_FAST_LAMBDA))
    slow = _apply(nodes, "DECAY", _reg(nodes, extra), term, _const(nodes, parameter))
    return fast, slow


def _readout_emitter(
    family: MemoryFamily, parameter: float, combine: str, extra: int
) -> Callable[[list[IRNode]], int]:
    if family is MemoryFamily.EXACT_RING:
        op = combine if combine in _FOLDABLE else "MAX"

        def fold(nodes: list[IRNode]) -> int:
            acc = _reg(nodes, 0, 0)
            for lag in range(1, int(parameter)):
                acc = _apply(nodes, op, acc, _reg(nodes, 0, lag))
            return acc

        return fold
    if family is MemoryFamily.MULTISCALE:
        return lambda nodes: _apply(nodes, "MAX", _reg(nodes, 0), _reg(nodes, extra))
    return lambda nodes: _reg(nodes, 0)


def _default_parameter(family: MemoryFamily) -> float:
    value = FAMILY_GRID[family][len(FAMILY_GRID[family]) // 2]
    return 0.0 if value is None else value


def memory_family_genome(
    family: MemoryFamily, base: ComputationalGenomeV1, *, parameter: float | None = None
) -> ComputationalGenomeV1:
    """``base`` with its first register rebuilt under ``family``'s memory law.

    ``parameter`` is the family's one knob (see :data:`FAMILY_GRID`); ``None`` takes the
    grid's middle value. Other registers that read r0 in the UPDATE program keep seeing its
    raw stored value; only the READOUT sees the family's memory view.
    """
    family = MemoryFamily(family)
    value = _default_parameter(family) if parameter is None else float(parameter)
    if family is MemoryFamily.EXACT_RING and not (value >= 1 and value == int(value)):
        raise ContractError(f"a ring length must be a positive integer, got {value!r}")
    prev, term, combine = _first_register_shape(base)
    extra = len(base.registers)
    nodes = list(base.update.nodes)
    r0_out, extra_out = _new_value(family, nodes, prev, term, value, extra)
    outputs = (r0_out, *base.update.outputs[1:])
    registers = list(base.registers)
    if family is MemoryFamily.EXACT_RING:
        registers[0] = replace(registers[0], ring=int(value))
    if extra_out is not None:
        outputs = (*outputs, extra_out)
        registers.append(RegisterSpec(type=IRType.FLOAT, init=0.0))
    update = prune_program(IRProgram(phase=base.update.phase, nodes=tuple(nodes), outputs=outputs))
    readout = prune_program(
        _substitute_reg0(base.readout, _readout_emitter(family, value, combine, extra))
    )
    return rebuild(
        base,
        mutation=f"chronos-{family.value}",
        registers=registers,
        update=update,
        readout=readout,
    )


# --- measuring a family ---------------------------------------------------------------------------


def _sketch_side_score(sample: Stage2Sample, width: int) -> float:
    """Mean rarity of RELATION within the session, from a fresh per-session CountMinSketch."""
    sketch = CountMinSketch(width=width, depth=SKETCH_DEPTH)
    total = 0.0
    for step in sample.steps:
        key = str(step.relation)
        total += 1.0 / (1.0 + sketch.estimate(key))
        sketch.add(key)
    return total / len(sample.steps) if sample.steps else 0.0


def _sketch_worst_case(
    genome: ComputationalGenomeV1, suite: EvaluationSuite, width: int
) -> float | None:
    """Worst-case AP of (memoryless genome score + sketch side score), fitness's convention."""
    worst = math.inf
    for variant in suite.variants:
        scores = [
            None if score is None else score + _sketch_side_score(sample, width)
            for score, sample in zip(
                session_scores(genome, variant.dataset), variant.dataset.samples, strict=True
            )
        ]
        ap, _abstained = score_ap(suite.labels_for(variant), scores)
        if ap is None:
            return None
        worst = min(worst, ap)
    return None if worst == math.inf else worst


def _sketch_bytes(width: int) -> int:
    """A per-session sketch amortised over the lineage-table bound, so it is per lineage."""
    return math.ceil(CountMinSketch(width=width, depth=SKETCH_DEPTH).memory_bytes / MAX_LINEAGES)


def _measure(
    family: MemoryFamily, genome: ComputationalGenomeV1, suite: EvaluationSuite, parameter: float
) -> float | None:
    if family is MemoryFamily.SKETCH:
        return _sketch_worst_case(genome, suite, int(parameter))
    return evaluate(genome, suite, meter=WorkMeter()).worst_case_ap


def _bytes_per_lineage(
    family: MemoryFamily, genome: ComputationalGenomeV1, parameter: float
) -> int:
    per_lineage = genome.bounds.state_bytes_per_lineage
    return per_lineage + (_sketch_bytes(int(parameter)) if family is MemoryFamily.SKETCH else 0)


def _fit_family(
    family: MemoryFamily, base: ComputationalGenomeV1, train: EvaluationSuite
) -> tuple[float, ComputationalGenomeV1]:
    """The grid value with the best TRAIN worst-case AP (ties: the first, i.e. the smaller)."""
    best: tuple[float, ComputationalGenomeV1] | None = None
    best_ap = -math.inf
    for raw in FAMILY_GRID[family]:
        parameter = 0.0 if raw is None else raw
        genome = memory_family_genome(family, base, parameter=parameter)
        ap = _measure(family, genome, train, parameter)
        if best is None or (ap is not None and ap > best_ap):
            best, best_ap = (parameter, genome), (-math.inf if ap is None else ap)
    assert best is not None  # every grid is non-empty
    return best


def evaluate_families(
    base: ComputationalGenomeV1, train: EvaluationSuite, heldout: EvaluationSuite
) -> tuple[ForgettingLaw, ...]:
    """Every :class:`MemoryFamily` on ``base``: parameter fitted on train, measured held-out.

    A family that cannot be built on ``base`` is still reported, with 0 bytes and ``None``
    metrics, so its absence from the comparison is visible rather than silent.
    """
    laws = []
    for family in MemoryFamily:
        try:
            parameter, genome = _fit_family(family, base, train)
        except ContractError:
            laws.append(ForgettingLaw(family.value, (), 0, None, None))
            continue
        ap = _measure(family, genome, heldout, parameter)
        size = _bytes_per_lineage(family, genome, parameter)
        utility = None if ap is None or size <= 0 else (ap - heldout.base_rate) / size
        name = _PARAMETER_NAMES.get(family)
        parameters = () if name is None else ((name, parameter),)
        laws.append(ForgettingLaw(family.value, parameters, size, ap, utility))
    return tuple(laws)


# --- counterfactual deletion (§27) ----------------------------------------------------------------


def counterfactual_deletion(
    genome: ComputationalGenomeV1,
    dataset: Stage2Dataset,
    *,
    seed: int,
    per_session: int = 1,
    threshold: float | None = None,
) -> DeletionReport:
    """Forget one random (event, lineage) item at a time and count decisions that change.

    Each deletion is its own World B (``M \\ {m}``), compared with World A at ONE threshold:
    ``threshold`` if given, else fitted on World A's scores of ``dataset`` at FPR 0.05. The
    deleted lineage is the one that acted just before the chosen point, so every deletion
    removes state that exists. ``catastrophic`` counts distinct malicious sessions some deletion
    pushed from alert to no alert.
    """
    if isinstance(per_session, bool) or not isinstance(per_session, int) or per_session < 1:
        raise ContractError(f"per_session must be a positive int, got {per_session!r}")
    phenotype = genome.phenotype()
    world_a = tuple(phenotype.run_session(sample.steps).score for sample in dataset.samples)
    cut = fit_threshold(dataset.labels, world_a) if threshold is None else float(threshold)
    decided_a = decisions(world_a, cut)
    rng = random.Random(seed)
    deletions = changed = 0
    catastrophic: set[int] = set()
    for index, sample in enumerate(dataset.samples):
        for _ in range(per_session):
            # Forgetting applies BEFORE the event at ``event``; the lineage that acted at
            # ``event - 1`` has just written its registers, so the deletion removes state
            # that exists (index == len(steps) means before the final readout).
            event = rng.randrange(1, len(sample.steps) + 1)
            forget = SessionInterventions(forget=((event, sample.steps[event - 1].actor_slot),))
            score_b = phenotype.run_session(sample.steps, interventions=forget).score
            decided_b = decisions((score_b,), cut)[0]
            deletions += 1
            if decided_b != decided_a[index]:
                changed += 1
                if sample.label == 1 and decided_a[index]:
                    catastrophic.add(index)
    negligible = deletions > 0 and changed <= NEGLIGIBLE_SHARE * deletions
    return DeletionReport(deletions, changed, negligible, len(catastrophic))


# --- the comparison -------------------------------------------------------------------------------


def _beats_control(law: ForgettingLaw, control: ForgettingLaw) -> bool:
    assert control.utility_per_byte is not None and control.heldout_worst_case_ap is not None
    if law.utility_per_byte is None or law.heldout_worst_case_ap is None:
        return False
    target = control.utility_per_byte + UTILITY_GAIN * abs(control.utility_per_byte)
    return (
        law.utility_per_byte > 0.0
        and law.utility_per_byte >= target
        and law.heldout_worst_case_ap >= control.heldout_worst_case_ap - AP_TOLERANCE
    )


def _forgetting_verdict(
    control: ForgettingLaw, others: Sequence[ForgettingLaw]
) -> tuple[MechanismVerdict, int, bool]:
    """(verdict, families that beat the control, saturated?) for a measured control."""
    assert control.utility_per_byte is not None and control.heldout_worst_case_ap is not None
    winners = sum(1 for law in others if _beats_control(law, control))
    measured = [law.utility_per_byte for law in others if law.utility_per_byte is not None]
    # At the AP ceiling every family "keeps quality", so utility per byte ranks bytes
    # alone: a ceiling artefact, not a memory-law result (ADR-0010's saturation trap).
    saturated = control.heldout_worst_case_ap >= PHI_ORACLE_CEILING
    if saturated:
        return MechanismVerdict.NOT_YET_JUSTIFIED, winners, True
    if winners:
        return MechanismVerdict.JUSTIFIED, winners, False
    if measured and all(value < control.utility_per_byte for value in measured):
        return MechanismVerdict.REJECTED, 0, False
    return MechanismVerdict.NOT_YET_JUSTIFIED, 0, False


def compare_forgetting(laws: Sequence[ForgettingLaw]) -> DetectorComparison:
    """Every family against ``EXACT_RING`` on utility per byte (spec §4.15, §7).

    JUSTIFIED iff some family's utility per byte is >= 20% better than the control's (and
    positive) at held-out worst-case AP within 0.01; REJECTED iff every measured family is
    strictly worse per byte; UNMEASURED when the control has no figure. A control at the AP
    ceiling (>= ``PHI_ORACLE_CEILING``) means a saturated split: NOT_YET_JUSTIFIED whatever
    the byte counts say. ``fired`` counts the families that would replace the control.
    """
    control = next((law for law in laws if law.family == MemoryFamily.EXACT_RING.value), None)
    others = [law for law in laws if law is not control]
    metric = "(held-out worst-case AP - base rate) / bytes per lineage"
    detail = "; ".join(
        f"{law.family}{dict(law.parameters)}: ap={law.heldout_worst_case_ap} "
        f"bytes={law.bytes_per_lineage} upb={law.utility_per_byte}"
        for law in laws
    )
    if control is None or control.utility_per_byte is None or control.heldout_worst_case_ap is None:
        return DetectorComparison(
            _MECHANISM, metric, None, (("EXACT_RING", None),), MechanismVerdict.UNMEASURED, 0,
            f"control EXACT_RING unmeasured; {detail}",
        )  # fmt: skip
    verdict, fired, saturated = _forgetting_verdict(control, others)
    measured = [law for law in others if law.utility_per_byte is not None]
    best = max(measured, key=lambda law: law.utility_per_byte or -math.inf, default=None)
    prefix = f"SATURATED (control AP {control.heldout_worst_case_ap}); " if saturated else ""
    return DetectorComparison(
        mechanism=_MECHANISM,
        metric=metric,
        value=None if best is None else best.utility_per_byte,
        controls=(("EXACT_RING", control.utility_per_byte),),
        verdict=verdict,
        fired=fired,
        detail=f"{prefix}best family {None if best is None else best.family}; {detail}",
    )
