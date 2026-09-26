"""The second half of the Stage 9 gate context: every lab that runs on the search's output.

Spec §6 step 5: ARGUS on every winner and the three references, then the physics, laws,
runtime and successor labs on the *subject* genome (the evolutionary winner, else the best
winner of any arm, chosen on train), and hardware-in-loop on the catalog and Pareto set.
Each public function is one build step; each stores its results on the context, and every
``compare_*`` verdict lands in ``ctx.comparisons`` keyed by the flag it decides, which is
exactly what G9.9 reads.

Nothing here decides a criterion. The checks in ``gate_criteria`` do that, from what is
stored. Nothing here selects on held-out data either: held-out is scored, never chosen on.
"""

from __future__ import annotations

from pocketsec.stage9.argus.adversary import (
    ArgusFinding,
    ArgusSurface,
    attack_findings,
    constant_corruption,
    fittest_die_under_attack,
    session_cap_padding,
    state_reset_midsession,
    tampered_genome,
    train_label_noise,
    work_budget_starvation,
)
from pocketsec.stage9.chronos.forgetting_law import (
    compare_forgetting,
    counterfactual_deletion,
    evaluate_families,
)
from pocketsec.stage9.compression.msdl import compare_msdl_selection, compare_surprise
from pocketsec.stage9.foundry.promotion import collect_candidates, compare_foundry, promotion_gate
from pocketsec.stage9.gaia.qd_ecology import (
    QualityDiversityArchive,
    hypothesis_explosion,
    single_architecture_dominance,
)
from pocketsec.stage9.gate_abstractions import measure_abstractions
from pocketsec.stage9.gate_build import PHI, need, transformed
from pocketsec.stage9.gate_exit import hand_over_successors
from pocketsec.stage9.gate_isolation import measure_isolation
from pocketsec.stage9.gate_state import Stage9GateContext
from pocketsec.stage9.genesis.speciation import compare_morphogenesis, speciate
from pocketsec.stage9.genome.computational import ComputationalGenomeV1
from pocketsec.stage9.geometry.causal import compare_causal_geometry
from pocketsec.stage9.geometry.phase import compare_phase
from pocketsec.stage9.harness.hardware_in_loop import measure_phenotype, proxy_vs_real
from pocketsec.stage9.laplace.law_discovery import compare_learning_laws
from pocketsec.stage9.observatory.convergence import convergence, law_gate
from pocketsec.stage9.ontogenesis.fitness import FitnessRecord, contamination_attack
from pocketsec.stage9.renormalization.laboratory import run_renormalization
from pocketsec.stage9.runtime.homeostatic import (
    REGIME_ORDER,
    HomeostaticController,
    ResourceObservation,
    build_catalog,
    compare_hysteresis,
    degradation_trace,
    drive,
)
from pocketsec.stage9.spec.mssc import DetectorComparison, pareto_front
from pocketsec.stage9.symmetry.conservation import compare_conservation, conservation_search
from pocketsec.stage9.symmetry.suite import (
    Transformation,
    compare_symmetry_breaking,
    invariance,
)

__all__ = [
    "run_abstractions",
    "run_argus",
    "run_hardware",
    "run_isolation",
    "run_laws",
    "run_physics",
    "run_runtime",
    "run_successors",
    "shuffled_label_finding",
]

_RENORMALIZATION_FLAG = (
    "pocketsec.stage9.renormalization.laboratory:RENORMALIZATION_DEFAULT_ENABLED"
)
_SEARCH_RUNNER = "pocketsec.stage9.ontogenesis.search:run_shuffled_label_control"
#: train_label_noise re-ranks this many of the best train records (spec §4.6).
_NOISE_TOP = 16


def _subject(ctx: Stage9GateContext) -> ComputationalGenomeV1:
    return need(ctx.subject, "the subject genome")


def _scored(ctx: Stage9GateContext) -> dict[str, ComputationalGenomeV1]:
    """Every genome ARGUS attacks: each distinct winner, the Φ-oracle, H1 and H2."""
    genomes = {genome.digest: genome for genome, _, _ in ctx.winners.values()}
    genomes.update({g.digest: g for g in ctx.hand.values()})
    return genomes


# --- ARGUS (G9.8) -------------------------------------------------------------------------------


def shuffled_label_finding(ctx: Stage9GateContext) -> ArgusFinding:
    """The shuffled-label search as a DEFENCE: it holds iff the null is not LEAK_SUSPECTED."""
    control = need(ctx.shuffled, "the shuffled-label control")
    held = 0 if control.verdict.value == "LEAK_SUSPECTED" else 1
    return ArgusFinding(
        attack_id="shuffled_label_search",
        surface=ArgusSurface.SEARCH,
        kind="DEFENCE",
        fired=held,
        total=1,
        inert=held == 0,
        metric_before=control.train_ap_on_shuffled,
        metric_after=control.heldout_ap,
        detail=(
            f"verdict {control.verdict.value}; permutation p {control.permutation_p_value}; "
            f"prior percentile {control.prior_percentile}; {control.detail}"
        ),
        measured_by=_SEARCH_RUNNER,
    )


def _top_records(ctx: Stage9GateContext) -> list[tuple[ComputationalGenomeV1, FitnessRecord]]:
    pool: dict[str, tuple[ComputationalGenomeV1, FitnessRecord]] = {}
    for runs in ctx.runs.values():
        for run in runs:
            for genome, record in zip(run.genomes, run.records, strict=True):
                if record.worst_case_ap is not None:
                    pool.setdefault(genome.digest, (genome, record))
    ranked = sorted(pool.values(), key=lambda gr: (-(gr[1].worst_case_ap or 0.0), gr[0].digest))
    return ranked[:_NOISE_TOP]


def run_argus(ctx: Stage9GateContext) -> None:
    """Every scenario attack on every scored genome; every lifecycle runner once (spec §6)."""
    train, heldout = need(ctx.train, "train suite"), need(ctx.heldout, "held-out suite")
    for genome in _scored(ctx).values():
        ctx.findings.extend(attack_findings(genome, heldout.clean, heldout.attacked))
    subject, clean = _subject(ctx), heldout.clean.dataset
    ctx.findings.extend(
        (
            constant_corruption(subject, clean, seed=ctx.config.heldout_seed),
            state_reset_midsession(subject, clean),
            work_budget_starvation(subject, clean),
            session_cap_padding(subject, clean),
            tampered_genome(subject),
            contamination_attack(train, heldout),
            train_label_noise(_top_records(ctx), train, seed=ctx.config.train_seed),
            shuffled_label_finding(ctx),
            hypothesis_explosion(lambda: QualityDiversityArchive(niches=True)),
        )
    )  # tampered_successor is appended by run_successors, on the real packages
    reference = need(ctx.hand_train.get(PHI), "the Φ-oracle's train record").worst_case_ap
    for run in ctx.runs.get("evolutionary", ()):
        ctx.attrition.append(
            (
                run.config.label,
                fittest_die_under_attack(
                    run.records, reference_worst_case=reference if reference is not None else 0.0
                ),
            )
        )


# --- physics (G9.9) -----------------------------------------------------------------------------


def _store(ctx: Stage9GateContext, comparison: DetectorComparison) -> None:
    ctx.comparisons[comparison.mechanism] = comparison


def run_physics(ctx: Stage9GateContext) -> None:
    """Renormalization, symmetry, conservation, geometry, phase, MSDL and surprise verdicts."""
    train, heldout, genome = need(ctx.train, "train"), need(ctx.heldout, "heldout"), _subject(ctx)
    t_clean, h_clean = train.clean.dataset, heldout.clean.dataset
    renorm = run_renormalization(
        genome, t_clean, h_clean, need(ctx.pairs, "pairs"), seed=ctx.config.heldout_seed
    )
    _store(
        ctx,
        DetectorComparison(
            mechanism=_RENORMALIZATION_FLAG,
            metric="held-out AP at the chosen coarse-graining",
            value=None,
            controls=(("random_drop_control_ap", renorm.random_drop_control_ap),),
            verdict=renorm.verdict,
            fired=renorm.fired,
            detail=renorm.detail,
        ),
    )
    held_t, train_t = transformed(ctx, train=False), transformed(ctx, train=True)
    invariants = [invariance(genome, h_clean, held_t.get(t), t) for t in Transformation]
    ctx.lab_notes["symmetry"] = "; ".join(
        f"{s.transformation}: invariant={s.invariant} changed {s.score_changed}/{s.sessions}"
        for s in invariants
    )
    _store(
        ctx,
        compare_symmetry_breaking(
            genome,
            h_clean,
            list(held_t.values()),
            train_clean=t_clean,
            train_variants=list(train_t.values()),
        ),
    )
    tests = conservation_search(t_clean, h_clean, invariants, transformed_heldout=held_t)
    _store(ctx, compare_conservation(tests, h_clean, train=t_clean))
    _store(ctx, compare_causal_geometry(t_clean, h_clean))
    _store(ctx, compare_phase(t_clean, h_clean)[1])
    _store(ctx, compare_msdl_selection(ctx.runs.get("evolutionary", ()), heldout, train=t_clean))
    _store(ctx, compare_surprise(t_clean, h_clean))


# --- laws (G9.2, G9.9) --------------------------------------------------------------------------


def run_laws(ctx: Stage9GateContext) -> None:
    """Learning laws, CHRONOS, the promotion gate and the law gate."""
    train, heldout, genome = need(ctx.train, "train"), need(ctx.heldout, "heldout"), _subject(ctx)
    cfg, drift = ctx.config, need(ctx.drift, "drift corpus")
    _store(
        ctx, compare_learning_laws(genome, count=cfg.drift_count, seed=cfg.drift_seed, drift=drift)
    )
    _store(ctx, compare_forgetting(evaluate_families(genome, train, heldout)))
    deletion = counterfactual_deletion(genome, heldout.clean.dataset, seed=cfg.heldout_seed)
    ctx.lab_notes["deletion"] = (
        f"{deletion.deletions} deletions changed "
        f"{deletion.decisions_changed} decisions; catastrophic "
        f"{deletion.catastrophic}; negligible {deletion.negligible}"
    )
    main = ctx.runs.get("evolutionary", ())
    ctx.candidates_examined = collect_candidates(main).examined
    ctx.promotions = promotion_gate(main, heldout, drift=drift)
    _store(ctx, compare_foundry(ctx.promotions, main=main, train=train, heldout=heldout))
    main_labels = {run.config.label for run in main}
    ctx.laws = law_gate(
        ctx.promotions,
        main,
        winners=[r for r in ctx.reports if r.run in main_labels],
        hand=ctx.hand_heldout,
    )
    ctx.lab_notes["convergence"] = (
        "; ".join(
            f"{d.candidate.canonical}: {convergence(main, d.candidate.canonical).value}"
            for d in ctx.promotions
        )
        or "no candidate subgraph"
    )


def run_abstractions(ctx: Stage9GateContext) -> None:
    """G9.3: every abstraction's semantic-conservation and counterfactual records."""
    ctx.coarsenings.extend(measure_abstractions(ctx))


# --- runtime (G9.5, G9.9, G9.10c) ----------------------------------------------------------------


def _pool(
    ctx: Stage9GateContext, *, heldout: bool
) -> list[tuple[ComputationalGenomeV1, FitnessRecord]]:
    hand = ctx.hand_heldout if heldout else ctx.hand_train
    pool = [(ctx.hand[name], record) for name, record in hand.items()]
    pool += [
        (g, held if heldout else train)
        for g, train, held in ctx.winners.values()
        if g.digest not in {genome.digest for genome in ctx.hand.values()}
    ]
    return pool


def run_runtime(ctx: Stage9GateContext) -> None:
    """Catalog, the degradation trace, hysteresis, speciation and the no-catalog fallback."""
    ctx.catalog = build_catalog(_pool(ctx, heldout=True))
    ctx.regime_decisions = drive(ctx.catalog, degradation_trace())
    ctx.transitions_into = {
        regime.value: sum(1 for d in ctx.regime_decisions if d.transitioned and d.regime is regime)
        for regime in REGIME_ORDER
    }
    _store(ctx, compare_hysteresis(ctx.catalog))
    _store(
        ctx,
        compare_morphogenesis(speciate(_pool(ctx, heldout=False), need(ctx.heldout, "heldout"))),
    )
    fallback = HomeostaticController(None).step(
        ResourceObservation(
            available_bytes=10 * 1024**3, cpu_share=0.1, queue_depth=0, basis="SIMULATED"
        )
    )
    ctx.survival_digest = f"{fallback.regime.value}:{fallback.genome_digest}"
    niched = [run for run in ctx.runs.get("niches", ())]
    shares = []
    for run in niched:  # rebuild each niched run's archive from its elites (S9X-080)
        archive = QualityDiversityArchive(niches=True)
        for elite in run.archive_elites:
            archive.insert(elite.genome, elite.fitness, lineage=elite.lineage)
        shares.append(single_architecture_dominance(archive).share)
    ctx.lab_notes["dominance"] = f"single-architecture dominance share per niched run {shares}"


# --- hardware in the loop (G9.4) ------------------------------------------------------------------


def _pareto_genomes(ctx: Stage9GateContext) -> list[ComputationalGenomeV1]:
    pool = _pool(ctx, heldout=True)
    front = set(pareto_front([(g.digest, r.objective()) for g, r in pool]))
    return [g for g, _ in pool if g.digest in front]


def run_hardware(ctx: Stage9GateContext) -> None:
    """HIL on every catalog phenotype, the Pareto set, the Φ-oracle, H1 and H2."""
    dataset = need(ctx.heldout, "heldout").clean.dataset
    catalog = need(ctx.catalog, "phenotype catalog")
    genomes = {e.genome.digest: e.genome for e in catalog.entries}
    genomes.update({g.digest: g for g in (*_pareto_genomes(ctx), *ctx.hand.values())})
    ctx.measurements = [measure_phenotype(g, dataset) for g in genomes.values()]
    ctx.proxy = proxy_vs_real(ctx.measurements)


# --- successor and the Stage 6 exit (G9.6) -----------------------------------------------------


def run_successors(ctx: Stage9GateContext) -> None:
    """Each distinct winner: DAEDALUS, the package, lab install/rollback, tampering, exit."""
    evidence = hand_over_successors(ctx)
    ctx.successors.extend(evidence)
    ctx.findings.extend(e.tampering for e in evidence)


def run_isolation(ctx: Stage9GateContext) -> None:
    """G9.10(b): the Φ-oracle's held-out AP in a process where Stages 7-9 cannot import."""
    ctx.isolation = measure_isolation(ctx)
