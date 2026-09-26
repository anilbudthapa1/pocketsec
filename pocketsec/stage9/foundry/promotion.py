"""D9.4 (gate half) — the primitive promotion gate: when may a recurring subgraph join the language?

The architecture (§7-§8) grows the search language by promoting subgraphs that "occur
independently in many successful systems", after canonicalisation, a unique-contribution
measurement, ARGUS counterexamples and cross-host/epoch reproduction. Every one of those
steps is a place where a search can fool itself — a subgraph recurs because the alphabet
makes it cheap to write, not because it computes anything new — so this module applies them
as REFUSALS, in the spec's order (§4.16), and stops at the first one that fires:

1. ``REFUSED_CONVERGENCE`` — the subgraph is in fewer than :data:`PROMOTION_MIN_RUNS`
   independent run winners.
2. ``REFUSED_REPRODUCES_DSL`` — it is semantically one seed primitive, or a projection of one
   of its operands, on :func:`reproduces_seed`'s random typed inputs.
3. ``REFUSED_ABLATION`` — replacing it by its best single-primitive substitute (or a
   projection) in each containing winner costs less than :data:`UNIQUE_CONTRIBUTION_MIN`
   held-out worst-case AP, in at least one winner — or the substitute set is larger than
   :data:`MAX_SUBSTITUTES`, so the best substitute cannot be established.
4. ``REFUSED_ARGUS`` — some winner containing it loses more than :data:`ARGUS_DROP_MAX` AP
   under an ARGUS scenario attack on held-out.
5. ``REFUSED_NO_RESOURCE_BENEFIT`` — writing it as a macro saves no description length.
6. ``REFUSED_CROSS_EPOCH`` — its contribution does not hold in every measurable epoch of
   Stage 2's drift corpus, or that could not be measured (``None`` refuses).

A promoted primitive is returned as a :class:`MacroBody` for
``SEED_ALPHABET.with_macro``. Macros are EXPANDED before any genome is validated or run, so a
promotion changes what the search proposes and what description length it pays, never what
a phenotype runs (S9X-012). Production never receives an alphabet.

What this module refuses to do: it never promotes by omission (an unmeasured criterion
refuses), never examines more than :data:`MAX_CANDIDATES` subgraphs (the rest are counted as
dropped), and never edits a genome in place.
"""

from __future__ import annotations

import hashlib
import itertools
import random
import re
from collections import Counter
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, replace
from enum import StrEnum
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage2.dataset import Stage2Dataset
from pocketsec.stage6.resources import WorkMeter
from pocketsec.stage9.chemistry.typed_ir import INT_MASK, IRNode, IRProgram, IRType, NodeKind
from pocketsec.stage9.foundry.primitives import (
    SEED_ALPHABET,
    TABLE_READERS,
    MacroBody,
    Primitive,
    PrimitiveAlphabet,
    SideTable,
    bind_context,
)
from pocketsec.stage9.genome.computational import ComputationalGenomeV1, build_genome
from pocketsec.stage9.laplace.state_discovery import prune_program
from pocketsec.stage9.ontogenesis.fitness import (
    EvaluationCache,
    EvaluationSuite,
    FitnessRecord,
    evaluate,
    score_ap,
    session_scores,
)
from pocketsec.stage9.spec.mssc import DetectorComparison, MechanismVerdict

if TYPE_CHECKING:  # pragma: no cover - typing only; search imports the search stack
    from pocketsec.stage9.ontogenesis.search import SearchRun

__all__ = [
    "ARGUS_DROP_MAX",
    "COMMUTATIVE",
    "MAX_CANDIDATES",
    "MAX_SUBSTITUTES",
    "PRIMITIVE_FOUNDRY_DEFAULT_ENABLED",
    "PROMOTION_MIN_RUNS",
    "UNIQUE_CONTRIBUTION_MIN",
    "CandidatePool",
    "PrimitiveCandidate",
    "PromotionDecision",
    "PromotionVerdict",
    "canonical_subgraphs",
    "collect_candidates",
    "compare_foundry",
    "construct_reachable",
    "macro_name",
    "promoted_macros",
    "promotion_gate",
    "reproduces_seed",
    "run_winner",
]

#: Ships False. Only the integrator may set it True, after a measured JUSTIFIED verdict.
PRIMITIVE_FOUNDRY_DEFAULT_ENABLED: bool = False
PROMOTION_MIN_RUNS = 2
UNIQUE_CONTRIBUTION_MIN = 0.01
MAX_CANDIDATES = 64
#: Substitutes tried per winner in the ablation (chosen). If a subgraph has more, the
#: contribution would only be an upper bound, so the ablation refuses instead of guessing.
MAX_SUBSTITUTES = 64
#: A containing winner losing more than this under an attack refuses the subgraph (§4.16).
ARGUS_DROP_MAX = 0.05
#: Arguments of these primitives are sorted in the canonical form.
COMMUTATIVE: frozenset[str] = frozenset({"ADD", "MUL", "MIN", "MAX", "AND", "OR", "XOR", "EQ_I"})

_MECHANISM = "pocketsec.stage9.foundry.promotion:PRIMITIVE_FOUNDRY_DEFAULT_ENABLED"
_PRIMITIVE_RE = re.compile(r"([A-Z][A-Z0-9_]*)\(")
_TYPE_CODE = {IRType.FLOAT: "F", IRType.INT: "I", IRType.BOOL: "B"}


class PromotionVerdict(StrEnum):
    PROMOTED = "PROMOTED"
    REFUSED_CONVERGENCE = "REFUSED_CONVERGENCE"
    REFUSED_ABLATION = "REFUSED_ABLATION"
    REFUSED_ARGUS = "REFUSED_ARGUS"
    REFUSED_NO_RESOURCE_BENEFIT = "REFUSED_NO_RESOURCE_BENEFIT"
    REFUSED_REPRODUCES_DSL = "REFUSED_REPRODUCES_DSL"
    REFUSED_CROSS_EPOCH = "REFUSED_CROSS_EPOCH"


@dataclass(frozen=True, slots=True)
class PrimitiveCandidate:
    """One canonical subgraph and what the gate measured before it stopped (None = not
    reached or not measurable)."""

    canonical: str
    body: MacroBody
    runs_containing: int  # run winners containing it
    runs_reachable: int  # runs whose search could have produced it
    unique_contribution: float | None
    argus_survived: bool | None
    description_bits_saved: float
    reproduces_seed: bool
    #: Added beyond spec §4.16's field list so the law observatory can tell "not
    #: reproduced across epochs" (False) from "not measured" (None).
    cross_epoch: bool | None = None


@dataclass(frozen=True, slots=True)
class PromotionDecision:
    candidate: PrimitiveCandidate
    verdict: PromotionVerdict
    reasons: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _Occurrence:
    genome_digest: str
    phase_update: bool
    root: int
    holes: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class CandidatePool:
    """The subgraphs the gate examines, with the bound's truncation made explicit."""

    candidates: tuple[tuple[str, MacroBody], ...]
    examined: int  # distinct canonical subgraphs across all winners
    dropped: int  # beyond MAX_CANDIDATES, never examined
    unrepresentable: int  # canonical subgraphs too large to be a MacroBody


# --- canonical form -------------------------------------------------------------------------------


def _rooted_sets(program: IRProgram, root: int, max_nodes: int) -> Iterator[frozenset[int]]:
    """Connected APPLY sets containing ``root`` in which every member feeds ``root``."""
    seen: set[frozenset[int]] = set()
    frontier = [frozenset({root})]
    while frontier:
        current = frontier.pop()
        if len(current) >= 2:
            yield current
        if len(current) >= max_nodes:
            continue
        for member in sorted(current):
            for arg in program.nodes[member].args:
                grown = current | {arg}
                if (
                    arg not in current
                    and program.nodes[arg].kind is NodeKind.APPLY
                    and grown not in seen
                ):
                    seen.add(grown)
                    frontier.append(grown)


def _render(
    program: IRProgram, members: frozenset[int], index: int
) -> tuple[str, tuple[Any, ...], tuple[int, ...]]:
    """(canonical text, canonical tree, hole node indices in canonical order)."""
    node = program.nodes[index]
    if index not in members:
        return f"?{_TYPE_CODE[node.type]}", ("?", node.type), (index,)
    children = [_render(program, members, arg) for arg in node.args]
    if node.primitive in COMMUTATIVE:
        children.sort(key=lambda child: child[0])
    text = f"{node.primitive}({','.join(child[0] for child in children)})"
    tree = ("A", node.primitive, node.type, tuple(child[1] for child in children))
    holes = tuple(hole for child in children for hole in child[2])
    return text, tree, holes


def _occurrences(
    genome: ComputationalGenomeV1, max_nodes: int
) -> Iterator[tuple[str, tuple[Any, ...], _Occurrence]]:
    for is_update, program in ((True, genome.update), (False, genome.readout)):
        for root, node in enumerate(program.nodes):
            if node.kind is not NodeKind.APPLY:
                continue
            for members in _rooted_sets(program, root, max_nodes):
                text, tree, holes = _render(program, members, root)
                yield text, tree, _Occurrence(genome.digest, is_update, root, holes)


def canonical_subgraphs(genome: ComputationalGenomeV1, *, max_nodes: int = 3) -> frozenset[str]:
    """Connected APPLY subgraphs of 2..``max_nodes`` nodes, operands abstracted to typed
    holes (``?F`` ``?I`` ``?B``) and commutative arguments sorted.

    Subgraphs are ROOTED (every member feeds one root), because a macro has one output.
    Holes are independent: ``MUL(x, x)`` renders as ``MUL(?F,?F)``, a generalisation a
    macro can still express.
    """
    if isinstance(max_nodes, bool) or not isinstance(max_nodes, int) or max_nodes < 2:
        raise ContractError(f"max_nodes must be an int >= 2, got {max_nodes!r}")
    return frozenset(text for text, _tree, _occ in _occurrences(genome, max_nodes))


def _body_from_tree(tree: tuple[Any, ...]) -> MacroBody:
    """PARAM nodes first (one per hole, canonical order), then APPLY nodes post-order."""
    params: list[IRType] = []

    def collect(t: tuple[Any, ...]) -> None:
        if t[0] == "?":
            params.append(t[1])
        else:
            for child in t[3]:
                collect(child)

    collect(tree)
    nodes = [IRNode(kind=NodeKind.PARAM, type=type_, index=i) for i, type_ in enumerate(params)]
    counter = itertools.count()

    def build(t: tuple[Any, ...]) -> int:
        if t[0] == "?":
            return next(counter)
        args = tuple(build(child) for child in t[3])
        nodes.append(IRNode(kind=NodeKind.APPLY, type=t[2], primitive=t[1], args=args))
        return len(nodes) - 1

    output = build(tree)
    return MacroBody(params=tuple(params), nodes=tuple(nodes), output=output)


def macro_name(canonical: str) -> str:
    """A deterministic alphabet name for a canonical subgraph."""
    return "M_" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:12].upper()


# --- reproduces the DSL? --------------------------------------------------------------------------


def _random_value(rng: random.Random, type_: IRType) -> Any:
    if type_ is IRType.BOOL:
        return rng.random() < 0.5
    if type_ is IRType.INT:
        return rng.randrange(0, 32) if rng.random() < 0.5 else rng.getrandbits(64) & INT_MASK
    if rng.random() < 0.25:
        return rng.choice((0.0, 1.0, -1.0, 0.5, 8.0))
    return rng.uniform(-100.0, 100.0)


def _seed_call(primitive: Primitive, args: Sequence[Any]) -> Any:
    """One stateless call: a side-table primitive gets a fresh table, as a macro probe does."""
    return bind_context(primitive, side_table=SideTable() if primitive.side_table else None)(*args)


def _matches(outputs: Sequence[Any], trials: Sequence[Sequence[Any]], fn: Any) -> bool:
    return all(fn(args) == out for args, out in zip(trials, outputs, strict=True))


def reproduces_seed(body: MacroBody, *, trials: int = 256, seed: int = 0) -> bool:
    """True if ``body`` equals one seed primitive (on some injective choice of its params) or
    a projection of one param, on every one of ``trials`` random typed inputs.

    The body is evaluated through ``SEED_ALPHABET.with_macro`` (the alphabet's own macro
    semantics: fresh side tables, an empty lookup table). LOOKUP is never a match target,
    because with no table it is the constant 0.0 and would "match" any constant body.
    """
    probe = SEED_ALPHABET.with_macro("S9_PROBE", body).get("S9_PROBE").fn
    rng = random.Random(seed)
    inputs = [tuple(_random_value(rng, t) for t in body.params) for _ in range(trials)]
    outputs = [probe(*args) for args in inputs]
    result = body.result_type
    for position, type_ in enumerate(body.params):
        if type_ is result and _matches(outputs, inputs, lambda a, p=position: a[p]):
            return True
    for primitive in SEED_ALPHABET:
        if primitive.result_type is not result or primitive.name in TABLE_READERS:
            continue
        for chosen in itertools.permutations(range(len(body.params)), len(primitive.arg_types)):
            if any(
                body.params[c] is not t for c, t in zip(chosen, primitive.arg_types, strict=True)
            ):
                continue
            call = lambda a, c=chosen, p=primitive: _seed_call(p, [a[i] for i in c])  # noqa: E731
            if _matches(outputs, inputs, call):
                return True
    return False


# --- runs -----------------------------------------------------------------------------------------


def run_winner(run: SearchRun) -> ComputationalGenomeV1 | None:
    """The run's winning genome, or None when no genome satisfied the constraints."""
    return None if run.winner is None else run.genomes[run.winner]


def construct_reachable(run: SearchRun, construct: str) -> bool:
    """Could this run have produced ``construct``?

    An EXHAUSTIVE run searches a fixed 126-genome space, so it could only if some genome it
    evaluated contains the construct. Every other strategy searches the whole seed language,
    so it could whenever every primitive the construct names is a seed primitive.
    """
    if str(run.config.strategy) == "EXHAUSTIVE":
        return any(construct in canonical_subgraphs(genome) for genome in run.genomes)
    return all(name in SEED_ALPHABET for name in _PRIMITIVE_RE.findall(construct))


def collect_candidates(runs: Sequence[SearchRun], *, max_nodes: int = 3) -> CandidatePool:
    """Every canonical subgraph of every run winner, bounded to :data:`MAX_CANDIDATES`
    (most-converged first, then canonical text); the rest are counted as dropped."""
    trees: dict[str, tuple[Any, ...]] = {}
    containing: Counter[str] = Counter()
    for run in runs:
        winner = run_winner(run)
        if winner is None:
            continue
        found = {text: tree for text, tree, _occ in _occurrences(winner, max_nodes)}
        trees.update({t: tr for t, tr in found.items() if t not in trees})
        containing.update(found.keys())
    ordered = sorted(trees, key=lambda text: (-containing[text], text))
    kept: list[tuple[str, MacroBody]] = []
    unrepresentable = 0
    for text in ordered:
        if len(kept) >= MAX_CANDIDATES:
            break
        try:
            kept.append((text, _body_from_tree(trees[text])))
        except ContractError:  # IRError MACRO_SIZE: too many holes for one macro
            unrepresentable += 1
    dropped = len(ordered) - len(kept) - unrepresentable
    return CandidatePool(tuple(kept), len(ordered), dropped, unrepresentable)


# --- ablation and the macro rewrite ---------------------------------------------------------------


def _redirect(program: IRProgram, alias: dict[int, int]) -> IRProgram:
    nodes = tuple(replace(n, args=tuple(alias.get(a, a) for a in n.args)) for n in program.nodes)
    outputs = tuple(alias.get(o, o) for o in program.outputs)
    return prune_program(IRProgram(phase=program.phase, nodes=nodes, outputs=outputs))


def _rewrite(
    genome: ComputationalGenomeV1,
    occurrences: Sequence[_Occurrence],
    make: Any,
    *,
    alphabet: PrimitiveAlphabet = SEED_ALPHABET,
    mutation: str,
) -> ComputationalGenomeV1:
    """Replace each occurrence's root by ``make(occ, program)`` (an IRNode) or, if ``make``
    returns an int, alias the root to that node; prune, then rebuild through the IR."""
    programs = {True: genome.update, False: genome.readout}
    for is_update in (True, False):
        program = programs[is_update]
        nodes = list(program.nodes)
        alias: dict[int, int] = {}
        for occ in occurrences:
            if occ.phase_update is not is_update:
                continue
            made = make(occ, program)
            if isinstance(made, int):
                alias[occ.root] = made
            else:
                nodes[occ.root] = made
        programs[is_update] = _redirect(
            IRProgram(phase=program.phase, nodes=tuple(nodes), outputs=program.outputs), alias
        )
    return build_genome(
        registers=genome.registers,
        update=programs[True],
        readout=programs[False],
        aggregation=genome.aggregation,
        lookup_table=genome.lookup_table,
        alphabet=alphabet,
        min_events_for_score=genome.min_events_for_score,
        parent_digests=(genome.digest,),
        mutation=mutation,
    )


def _substitute_plans(body: MacroBody) -> list[tuple[str, tuple[int, ...]]]:
    """(primitive or "", hole positions): single-primitive substitutes, then projections."""
    plans: list[tuple[str, tuple[int, ...]]] = []
    result = body.result_type
    for primitive in SEED_ALPHABET:
        if primitive.result_type is not result:
            continue
        for chosen in itertools.permutations(range(len(body.params)), len(primitive.arg_types)):
            if primitive.name in COMMUTATIVE and list(chosen) != sorted(chosen):
                continue  # ADD(a, b) and ADD(b, a) are one substitute
            if all(body.params[c] is t for c, t in zip(chosen, primitive.arg_types, strict=True)):
                plans.append((primitive.name, chosen))
    plans.extend(("", (p,)) for p, t in enumerate(body.params) if t is result)
    return plans


def _substituted(
    genome: ComputationalGenomeV1,
    occurrences: Sequence[_Occurrence],
    plan: tuple[str, tuple[int, ...]],
) -> ComputationalGenomeV1:
    name, positions = plan

    def make(occ: _Occurrence, program: IRProgram) -> IRNode | int:
        if not name:
            return occ.holes[positions[0]]
        root = program.nodes[occ.root]
        return IRNode(
            kind=NodeKind.APPLY,
            type=root.type,
            primitive=name,
            args=tuple(occ.holes[p] for p in positions),
        )

    return _rewrite(
        genome, occurrences, make, mutation=f"foundry-substitute-{name or 'projection'}"
    )


def _winner_occurrences(
    runs: Sequence[SearchRun], text: str
) -> list[tuple[ComputationalGenomeV1, list[_Occurrence]]]:
    seen: dict[str, tuple[ComputationalGenomeV1, list[_Occurrence]]] = {}
    for run in runs:
        winner = run_winner(run)
        if winner is None or winner.digest in seen:
            continue
        occs = [occ for t, _tree, occ in _occurrences(winner, 3) if t == text]
        if occs:
            seen[winner.digest] = (winner, occs)
    return list(seen.values())


def _heldout(
    genome: ComputationalGenomeV1, suite: EvaluationSuite, cache: EvaluationCache
) -> FitnessRecord:
    return evaluate(genome, suite, meter=WorkMeter(), cache=cache)


def _best_substitute(
    genome: ComputationalGenomeV1,
    occs: Sequence[_Occurrence],
    body: MacroBody,
    heldout: EvaluationSuite,
    cache: EvaluationCache,
    notes: list[str],
) -> tuple[ComputationalGenomeV1 | None, float | None]:
    plans = _substitute_plans(body)
    if len(plans) > MAX_SUBSTITUTES:
        # Trying a subset would overstate the contribution; refuse to measure instead.
        notes.append(f"{len(plans)} substitutes exceed the cap {MAX_SUBSTITUTES}; not measured")
        return (None, None)
    best: tuple[ComputationalGenomeV1 | None, float | None] = (None, None)
    for plan in plans:
        try:
            candidate = _substituted(genome, occs, plan)
        except ContractError:
            continue
        ap = _heldout(candidate, heldout, cache).worst_case_ap
        if ap is not None and (best[1] is None or ap > best[1]):
            best = (candidate, ap)
    return best


def _macro_saving(
    genome: ComputationalGenomeV1, occs: Sequence[_Occurrence], text: str, body: MacroBody
) -> float:
    name = macro_name(text)
    alphabet = SEED_ALPHABET.with_macro(name, body)

    def make(occ: _Occurrence, program: IRProgram) -> IRNode:
        root = program.nodes[occ.root]
        return IRNode(kind=NodeKind.APPLY, type=root.type, primitive=name, args=occ.holes)

    try:
        rewritten = _rewrite(
            genome, occs, make, alphabet=alphabet, mutation=f"foundry-macro-{name}"
        )
    except ContractError:
        return 0.0
    return genome.description_length_bits() - rewritten.description_length_bits(alphabet)


# --- cross-epoch ----------------------------------------------------------------------------------


def _session_epoch(steps: Sequence[Any]) -> int:
    counts: Counter[int] = Counter(int(step.epoch_id) for step in steps)
    return min(counts, key=lambda epoch: (-counts[epoch], epoch))


def _epoch_aps(genome: ComputationalGenomeV1, drift: Stage2Dataset) -> dict[int, float | None]:
    scores = session_scores(genome, drift)
    groups: dict[int, tuple[list[int], list[float | None]]] = {}
    for sample, score in zip(drift.samples, scores, strict=True):
        labels, values = groups.setdefault(_session_epoch(sample.steps), ([], []))
        labels.append(sample.label)
        values.append(score)
    return {
        epoch: score_ap(labels, values)[0] for epoch, (labels, values) in sorted(groups.items())
    }


def _cross_epoch(
    pairs: Sequence[tuple[ComputationalGenomeV1, ComputationalGenomeV1]],
    drift: Stage2Dataset | None,
) -> bool | None:
    """True iff, for every containing winner, the contribution over its best substitute is
    >= UNIQUE_CONTRIBUTION_MIN in every epoch where both APs exist, with >= 2 such epochs."""
    if drift is None or not pairs:
        return None
    for winner, substitute in pairs:
        full, sub = _epoch_aps(winner, drift), _epoch_aps(substitute, drift)
        deltas = [
            mine - theirs
            for epoch, mine in full.items()
            if mine is not None and (theirs := sub.get(epoch)) is not None
        ]
        if len(deltas) < 2:
            return None
        if any(delta < UNIQUE_CONTRIBUTION_MIN for delta in deltas):
            return False
    return True


# --- the gate -------------------------------------------------------------------------------------


def _argus_survived(records: Sequence[FitnessRecord]) -> bool | None:
    for record in records:
        attacked = [ap for _name, ap in record.variant_aps[1:] if ap is not None]
        if record.clean_ap is None or len(attacked) != len(record.variant_aps) - 1:
            return None
        if attacked and record.clean_ap - min(attacked) > ARGUS_DROP_MAX:
            return False
    return True


@dataclass(frozen=True, slots=True)
class _Measured:
    unique: float | None
    pairs: tuple[tuple[ComputationalGenomeV1, ComputationalGenomeV1], ...]
    records: tuple[FitnessRecord, ...]


def _ablate(
    winners: Sequence[tuple[ComputationalGenomeV1, list[_Occurrence]]],
    body: MacroBody,
    heldout: EvaluationSuite,
    cache: EvaluationCache,
    notes: list[str],
) -> _Measured:
    contributions: list[float] = []
    pairs = []
    records = []
    for genome, occs in winners:
        record = _heldout(genome, heldout, cache)
        records.append(record)
        substitute, sub_ap = _best_substitute(genome, occs, body, heldout, cache, notes)
        if substitute is None or sub_ap is None or record.worst_case_ap is None:
            return _Measured(None, (), tuple(records))
        contributions.append(record.worst_case_ap - sub_ap)
        pairs.append((genome, substitute))
    unique = min(contributions) if contributions else None
    return _Measured(unique, tuple(pairs), tuple(records))


@dataclass(frozen=True, slots=True)
class _Outcome:
    verdict: PromotionVerdict
    reason: str
    unique: float | None = None
    argus: bool | None = None
    epoch: bool | None = None


def _measured_refusals(
    winners: Sequence[tuple[ComputationalGenomeV1, list[_Occurrence]]],
    body: MacroBody,
    saved: float,
    context: tuple[EvaluationSuite, Stage2Dataset | None, EvaluationCache],
    notes: list[str],
) -> _Outcome:
    """Refusals 3-6 (ablation, ARGUS, description length, cross-epoch), in order."""
    heldout, drift, cache = context
    measured = _ablate(winners, body, heldout, cache, notes)
    unique = measured.unique
    if unique is None or unique < UNIQUE_CONTRIBUTION_MIN:
        return _Outcome(
            PromotionVerdict.REFUSED_ABLATION,
            f"unique held-out contribution {unique} < {UNIQUE_CONTRIBUTION_MIN}",
            unique,
        )
    survived = _argus_survived(measured.records)
    if survived is not True:
        return _Outcome(
            PromotionVerdict.REFUSED_ARGUS, f"ARGUS survival {survived}", unique, survived
        )
    if saved <= 0.0:
        reason = f"description bits saved {saved:.3f} <= 0"
        return _Outcome(PromotionVerdict.REFUSED_NO_RESOURCE_BENEFIT, reason, unique, survived)
    epoch = _cross_epoch(measured.pairs, drift)
    if epoch is not True:
        reason = f"cross-epoch reproduction {epoch}"
        return _Outcome(PromotionVerdict.REFUSED_CROSS_EPOCH, reason, unique, survived, epoch)
    return _Outcome(
        PromotionVerdict.PROMOTED, "every refusal examined; none fired", unique, True, True
    )


def _decide(
    text: str,
    body: MacroBody,
    runs: Sequence[SearchRun],
    context: tuple[EvaluationSuite, Stage2Dataset | None, EvaluationCache],
) -> PromotionDecision:
    winners = _winner_occurrences(runs, text)  # distinct winner genomes, for measurement
    containing = sum(  # RUNS, not genomes: two runs converging on one winner count twice
        1 for run in runs if (w := run_winner(run)) is not None and text in canonical_subgraphs(w)
    )
    saved = min((_macro_saving(g, occs, text, body) for g, occs in winners), default=0.0)
    dsl = reproduces_seed(body)
    notes: list[str] = []
    if containing < PROMOTION_MIN_RUNS:
        reason = f"in {containing} of {len(runs)} run winners < {PROMOTION_MIN_RUNS}"
        outcome = _Outcome(PromotionVerdict.REFUSED_CONVERGENCE, reason)
    elif dsl:
        reason = "semantically a seed primitive or a projection"
        outcome = _Outcome(PromotionVerdict.REFUSED_REPRODUCES_DSL, reason)
    else:
        outcome = _measured_refusals(winners, body, saved, context, notes)
    candidate = PrimitiveCandidate(
        canonical=text,
        body=body,
        runs_containing=containing,
        runs_reachable=sum(1 for run in runs if construct_reachable(run, text)),
        unique_contribution=outcome.unique,
        argus_survived=outcome.argus,
        description_bits_saved=saved,
        reproduces_seed=dsl,
        cross_epoch=outcome.epoch,
    )
    return PromotionDecision(candidate, outcome.verdict, (outcome.reason, *notes))


def promotion_gate(
    runs: Sequence[SearchRun], heldout: EvaluationSuite, *, drift: Stage2Dataset | None = None
) -> tuple[PromotionDecision, ...]:
    """Decide every candidate subgraph of the run winners (spec §4.16 refusal order).

    ``drift`` is Stage 2's drift corpus compiled by the caller; without it cross-epoch
    reproduction is unmeasured and every candidate that reaches that step is refused.
    """
    pool = collect_candidates(runs)
    cache = EvaluationCache()
    context = (heldout, drift, cache)
    return tuple(_decide(text, body, runs, context) for text, body in pool.candidates)


def promoted_macros(decisions: Sequence[PromotionDecision]) -> tuple[tuple[str, MacroBody], ...]:
    """(alphabet name, body) for each PROMOTED decision — input to ``with_macro`` in research."""
    return tuple(
        (macro_name(d.candidate.canonical), d.candidate.body)
        for d in decisions
        if d.verdict is PromotionVerdict.PROMOTED
    )


def _median(values: Sequence[float]) -> float:
    ordered = sorted(values)
    middle = len(ordered) // 2
    return ordered[middle] if len(ordered) % 2 else (ordered[middle - 1] + ordered[middle]) / 2


def _enlarged_arm(
    decisions: Sequence[PromotionDecision],
    main: Sequence[SearchRun],
    train: EvaluationSuite,
    heldout: EvaluationSuite,
) -> tuple[list[float], int]:
    """Re-run each main-arm config over SEED + promoted macros; (held-out deltas, changed)."""
    from pocketsec.stage9.ontogenesis.search import heldout_report, run_search  # search stack

    alphabet = SEED_ALPHABET
    for name, body in promoted_macros(decisions):
        alphabet = alphabet.with_macro(name, body)
    enlarged = [run_search(run.config, train, alphabet=alphabet) for run in main]
    before, after = heldout_report(main, heldout), heldout_report(enlarged, heldout)
    deltas = [
        b.heldout_worst_case_ap - a.heldout_worst_case_ap
        for a, b in zip(before, after, strict=True)
        if a.heldout_worst_case_ap is not None and b.heldout_worst_case_ap is not None
    ]
    changed = sum(
        1 for a, b in zip(before, after, strict=True) if a.genome_digest != b.genome_digest
    )
    return deltas, changed


def _foundry_verdict(deltas: Sequence[float], changed: int) -> MechanismVerdict:
    if not deltas:
        return MechanismVerdict.UNMEASURED
    median = _median(deltas)
    if median >= 0.02 and all(d > 0 for d in deltas) and changed > 0:
        return MechanismVerdict.JUSTIFIED
    return MechanismVerdict.REJECTED if median <= -0.02 else MechanismVerdict.NOT_YET_JUSTIFIED


def compare_foundry(
    decisions: Sequence[PromotionDecision],
    *,
    main: Sequence[SearchRun] = (),
    train: EvaluationSuite | None = None,
    heldout: EvaluationSuite | None = None,
) -> DetectorComparison:
    """The primitive foundry against the seed alphabet (spec §7) for gate G9.9.

    * Nothing promoted: the enlarged alphabet IS the seed alphabet, so the mechanism cannot
      change any outcome — NOT_YET_JUSTIFIED with ``fired = 0`` (INERT), decided without a run.
    * Something promoted and ``main``/``train``/``heldout`` given: every main-arm config is
      re-run over the enlarged alphabet (same seed, same budget) and the winners' held-out
      worst-case AP compared seed by seed. JUSTIFIED iff the median delta is >= +0.02 and
      every delta is > 0; REJECTED iff the median is <= -0.02.
    * Something promoted but the arm not given: UNMEASURED. It is never assumed.
    """
    promoted = sum(1 for d in decisions if d.verdict is PromotionVerdict.PROMOTED)
    tally = dict(sorted(Counter(d.verdict.value for d in decisions).items()))
    metric = "median held-out worst-case AP delta, enlarged alphabet vs seed alphabet"
    controls: tuple[tuple[str, float | None], ...] = (("seed alphabet", 0.0),)
    head = f"{len(decisions)} candidates examined; verdicts {tally}; {promoted} promoted"
    if promoted == 0:
        note = "the enlarged alphabet equals the seed alphabet, so it changes nothing"
        verdict = MechanismVerdict.NOT_YET_JUSTIFIED
        return DetectorComparison(_MECHANISM, metric, 0.0, controls, verdict, 0, f"{head}; {note}")
    if not main or train is None or heldout is None:
        note = "the enlarged-alphabet search arm was not run"
        verdict = MechanismVerdict.UNMEASURED
        return DetectorComparison(_MECHANISM, metric, None, controls, verdict, 0, f"{head}; {note}")
    deltas, changed = _enlarged_arm(decisions, main, train, heldout)
    note = f"per-seed deltas {deltas}; winners changed on {changed} of {len(main)} seeds"
    median = _median(deltas) if deltas else None
    verdict = _foundry_verdict(deltas, changed)
    return DetectorComparison(
        _MECHANISM, metric, median, controls, verdict, changed, f"{head}; {note}"
    )
