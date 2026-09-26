"""The first half of the Stage 9 gate context: splits, references, searches, comparisons.

Each public function is one build step of ``gate._STEPS``. A step reads what earlier steps
stored on the :class:`~pocketsec.stage9.gate_state.Stage9GateContext` and stores its own
results there; it raises when an input is missing, and the gate records the error against
the step so the checks that need it FAIL with the reason (spec §6: never a silent pass).

The order is the spec's §6 order: compile (step 1), audit and contamination (step 2, which
can refuse the whole context), expressibility and saturation (step 3), then the searches
(step 4). No step here selects anything on held-out data: held-out is only ever evaluated.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TypeVar

from pocketsec.stage1.labs.ambiguous_corpus import build_ambiguous_corpus
from pocketsec.stage2.dataset import Stage2Dataset
from pocketsec.stage6.resources import WorkMeter
from pocketsec.stage9.argus.adversary import SCENARIO_ATTACKS
from pocketsec.stage9.gaia.qd_ecology import compare_qd
from pocketsec.stage9.gate_state import Stage9GateContext
from pocketsec.stage9.genome.computational import ComputationalGenomeV1
from pocketsec.stage9.genome.expressibility import (
    check_expressibility,
    hand_designed_genomes,
    order_free_control_genome,
    phi_oracle_genome,
)
from pocketsec.stage9.harness.hardware_in_loop import tcn_pareto_point
from pocketsec.stage9.labs.splits import (
    CLEAN,
    compile_scenarios,
    compile_variant,
    compile_variants,
    split_key,
    stage9_saturation,
)
from pocketsec.stage9.laplace.law_discovery import compile_drift_corpus
from pocketsec.stage9.ontogenesis.fitness import (
    EvaluationCache,
    EvaluationSuite,
    FitnessRecord,
    contamination_check,
    evaluate,
    score_ap,
    session_scores,
)
from pocketsec.stage9.ontogenesis.search import (
    SearchConfig,
    SearchRun,
    SearchStrategy,
    compare_arm,
    compare_strategies,
    heldout_report,
    run_search,
    run_shuffled_label_control,
)
from pocketsec.stage9.renormalization.laboratory import attribution_counterfactuals
from pocketsec.stage9.symmetry.suite import ARGUS_VARIANT_OF, Transformation, permute_actor_slots

__all__ = [
    "PHI",
    "audit_splits",
    "compare_searches",
    "compile_splits",
    "measure_expressibility",
    "measure_references",
    "need",
    "run_searches",
    "transformed",
]

#: The name every gate table uses for the zero-parameter incumbent.
PHI = "phi-oracle"
_ORDER_FREE = "order-free"
_T = TypeVar("_T")


def need(value: _T | None, what: str) -> _T:
    """The input a step needs, or a ``LookupError`` naming the step that did not store it."""
    if value is None:
        raise LookupError(f"{what} is missing: an earlier gate step failed (see its error)")
    return value


# --- step 1: compile ----------------------------------------------------------------------------


def compile_splits(ctx: Stage9GateContext) -> None:
    """Train and held-out (clean + 6 attacks), the saturated split, the pairs, the drift corpus.

    Held-out clean is compiled serially with ``keep_results`` because the Stage 6 exit needs
    ``ScenarioResult`` evidence; its content digest equals the pooled path's (splits.py).
    """
    cfg = ctx.config
    attacks = tuple(attack.attack_id for attack in SCENARIO_ATTACKS)
    train = compile_variants(
        count=cfg.count, seed=cfg.train_seed, attack_ids=(CLEAN, *attacks), workers=cfg.workers
    )
    held_attacked = compile_variants(
        count=cfg.count, seed=cfg.heldout_seed, attack_ids=attacks, workers=cfg.workers
    )
    held_clean = compile_variant(count=cfg.count, seed=cfg.heldout_seed, keep_results=True)
    ctx.saturated = compile_variant(
        count=cfg.saturated_count, seed=cfg.heldout_seed, keep_results=True
    )
    ctx.saturated_sessions = tuple(r.transitions for r in ctx.saturated.results if r.transitions)
    ctx.heldout_results = held_clean.results
    ctx.pairs = _pair_dataset(cfg.count, cfg.heldout_seed)
    ctx.drift = compile_drift_corpus(count=cfg.drift_count, seed=cfg.drift_seed).dataset
    ctx.raw_variants = (tuple(train), (held_clean, *held_attacked))


def _pair_dataset(count: int, seed: int) -> Stage2Dataset:
    """Spec §4.10: each held-out malicious scenario and its attribution twin, interleaved."""
    scenarios = build_ambiguous_corpus(count=count, seed=seed, split="eval")
    pairs = attribution_counterfactuals(scenarios, seed=seed)
    flat = [scenario for pair in pairs for scenario in pair]
    return compile_scenarios(flat, key=split_key(count=count, seed=seed)).dataset


# --- step 2: audit and contamination -----------------------------------------------------------


def audit_splits(ctx: Stage9GateContext) -> None:
    """Corpus audit on every variant, then contamination; either failure refuses the context."""
    if len(ctx.raw_variants) != 2:
        raise LookupError("the compiled splits are missing: the compile step failed")
    train, heldout = ctx.raw_variants
    ctx.raw_variants = ()  # the audited suites are the only readers from here on
    saturated = need(ctx.saturated, "the saturated split")
    failures = tuple(
        f"{v.key.corpus}/{v.key.count}/{v.key.seed}/{v.key.attack_id}: {reason}"
        for v in (*train, *heldout, saturated)
        for reason in v.audit_failures
    )
    ctx.audit_failures = failures
    if failures:
        ctx.refused = f"corpus audit failed: {'; '.join(failures)}"
        return
    ctx.train = EvaluationSuite(name="train", clean=train[0], attacked=tuple(train[1:]))
    ctx.heldout = EvaluationSuite(name="heldout", clean=heldout[0], attacked=tuple(heldout[1:]))
    ctx.contamination = contamination_check(ctx.train, ctx.heldout)
    if ctx.contamination.refused:
        ctx.refused = f"contamination check refused: {ctx.contamination.to_dict()}"


# --- step 3: references, saturation, expressibility --------------------------------------------


def _ap(genome: ComputationalGenomeV1, dataset: Stage2Dataset) -> float | None:
    return score_ap(dataset.labels, session_scores(genome, dataset))[0]


def measure_references(ctx: Stage9GateContext) -> None:
    """Φ-oracle, H1, H2 fitness on train and held-out; saturation on both reference splits."""
    train, heldout = need(ctx.train, "train suite"), need(ctx.heldout, "held-out suite")
    ctx.hand = {PHI: phi_oracle_genome(), **hand_designed_genomes()}
    meter, cache = WorkMeter(), EvaluationCache()
    for name, genome in ctx.hand.items():
        ctx.hand_train[name] = evaluate(genome, train, meter=meter, cache=cache)
        ctx.hand_heldout[name] = evaluate(genome, heldout, meter=meter, cache=cache)
    scorers = {**ctx.hand, _ORDER_FREE: order_free_control_genome()}
    splits = {
        "headroom": heldout.clean.dataset,
        "saturated": need(ctx.saturated, "saturated split").dataset,
    }
    for split, dataset in splits.items():
        aps = {name: _ap(genome, dataset) for name, genome in scorers.items()}
        ctx.reference_aps[split] = aps
        ctx.saturation[split] = stage9_saturation(
            aps, phi_oracle=aps[PHI], order_free=aps[_ORDER_FREE]
        )
    ctx.saturated_phi_ap = ctx.reference_aps["saturated"][PHI]
    ctx.tcn_point = tcn_pareto_point()


def measure_expressibility(ctx: Stage9GateContext) -> None:
    """Spec §6 step 3 / G9.1(a): run on the saturated split WITH its SSIR sessions."""
    saturated = need(ctx.saturated, "saturated split")
    ctx.expressibility = check_expressibility(saturated.dataset, sessions=ctx.saturated_sessions)


# --- step 4: the searches ----------------------------------------------------------------------


def _arm(
    ctx: Stage9GateContext,
    strategy: SearchStrategy,
    *,
    subtractive: bool = False,
    fossil_avoidance: bool = False,
    niches: bool = False,
) -> tuple[SearchRun, ...]:
    train, cfg = need(ctx.train, "train suite"), ctx.config
    configs = [
        SearchConfig(strategy=strategy, seed=seed, budget_wu=cfg.budget_wu) for seed in cfg.seeds
    ]
    flags = {"subtractive": subtractive, "fossil_avoidance": fossil_avoidance, "niches": niches}
    if any(flags.values()):  # an ablation arm switches exactly one flag on, seed-matched
        configs = [
            SearchConfig(strategy=strategy, seed=c.seed, budget_wu=c.budget_wu, **flags)
            for c in configs
        ]
    return tuple(run_search(config, train) for config in configs)


def run_searches(ctx: Stage9GateContext) -> None:
    """Main arm (defaults: every flag at its shipped False), random, exhaustive, three arms.

    ``compare_strategies`` later reads the main arm only, so no arm is chosen after the fact.
    """
    cfg = ctx.config
    ctx.runs["evolutionary"] = _arm(ctx, SearchStrategy.EVOLUTIONARY)
    ctx.runs["random"] = _arm(ctx, SearchStrategy.RANDOM)
    exhaustive = SearchConfig(
        strategy=SearchStrategy.EXHAUSTIVE, seed=cfg.seeds[0], budget_wu=cfg.budget_wu
    )
    ctx.runs["exhaustive"] = (run_search(exhaustive, need(ctx.train, "train suite")),)
    ctx.runs["subtractive"] = _arm(ctx, SearchStrategy.EVOLUTIONARY, subtractive=True)
    ctx.runs["fossil_avoidance"] = _arm(ctx, SearchStrategy.EVOLUTIONARY, fossil_avoidance=True)
    ctx.runs["niches"] = _arm(ctx, SearchStrategy.EVOLUTIONARY, niches=True)
    ctx.shuffled = run_shuffled_label_control(
        need(ctx.train, "train suite"),
        need(ctx.heldout, "held-out suite"),
        seed=cfg.seeds[0],
        budget_wu=cfg.budget_wu,
    )


def _winner_records(ctx: Stage9GateContext) -> None:
    """Every distinct run winner, with its train record and a held-out evaluation."""
    heldout, meter, cache = need(ctx.heldout, "held-out suite"), WorkMeter(), EvaluationCache()
    for runs in ctx.runs.values():
        for run in runs:
            if run.winner is None:
                continue
            genome, train = run.genomes[run.winner], run.records[run.winner]
            if genome.digest not in ctx.winners:
                held = evaluate(genome, heldout, meter=meter, cache=cache)
                ctx.winners[genome.digest] = (genome, train, held)


def _subject(ctx: Stage9GateContext) -> None:
    """Spec §6 step 5: the evolutionary winners, else the best winner of any arm, chosen on
    TRAIN worst-case AP. With no winner anywhere the labs run on the Φ-oracle, and say so."""

    def best(runs: Sequence[SearchRun]) -> tuple[ComputationalGenomeV1, FitnessRecord] | None:
        pool = [(r.genomes[r.winner], r.records[r.winner]) for r in runs if r.winner is not None]
        return max(
            pool, key=lambda gr: (gr[1].worst_case_ap or -1.0, -gr[1].wu_per_event), default=None
        )

    picked = best(ctx.runs.get("evolutionary", ()))
    reason = "best evolutionary-arm winner by train worst-case AP"
    if picked is None:
        picked = best([run for runs in ctx.runs.values() for run in runs])
        reason = (
            "the evolutionary arm produced no MSSC-satisfying winner; best winner of any "
            "arm by train worst-case AP"
        )
    if picked is None:
        ctx.subject, ctx.subject_reason = (
            phi_oracle_genome(),
            ("NO run produced an MSSC-satisfying winner; the labs run on the Φ-oracle genome"),
        )
        return
    ctx.subject, ctx.subject_reason = picked[0], reason


def compare_searches(ctx: Stage9GateContext) -> None:
    """Held-out winner reports, the strategy verdict and the three arm verdicts (G9.9)."""
    heldout = need(ctx.heldout, "held-out suite")
    everything = [run for runs in ctx.runs.values() for run in runs]
    ctx.reports = heldout_report(everything, heldout)
    _winner_records(ctx)
    main = ctx.runs["evolutionary"]
    ctx.strategy = compare_strategies(main, ctx.runs["random"], ctx.runs["exhaustive"][0], heldout)
    for comparison in (
        ctx.strategy.as_detector(),
        compare_arm(main, ctx.runs["subtractive"], heldout, flag="subtractive"),
        compare_arm(main, ctx.runs["fossil_avoidance"], heldout, flag="fossil_avoidance"),
        compare_qd(main, ctx.runs["niches"], heldout),
    ):
        ctx.comparisons[comparison.mechanism] = comparison
    _subject(ctx)


# --- shared by the physics lab and the successor step ------------------------------------------


def transformed(ctx: Stage9GateContext, *, train: bool) -> dict[Transformation, Stage2Dataset]:
    """The measurable symmetry transformations of one split: an actor-slot permutation, and
    the three ARGUS variants that ARE transformations (path class, time, benign reorder)."""
    suite = need(ctx.train if train else ctx.heldout, "train suite" if train else "held-out")
    by_attack = {variant.key.attack_id: variant.dataset for variant in suite.attacked}
    out = {
        Transformation.ACTOR_SLOT_PERMUTATION: permute_actor_slots(
            suite.clean.dataset, seed=ctx.config.heldout_seed
        )
    }
    out.update({t: by_attack[attack] for t, attack in ARGUS_VARIANT_OF.items()})
    return out
