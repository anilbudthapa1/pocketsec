"""D8.20 — the baselines Stage 8 must beat, the null FDR, the ablation and the threshold sweep.

A discovery engine is only worth its complexity if it beats the dumbest thing that could work
on the same data and budget (spec §7). This module runs those comparisons with the real loop
(``labs.discovery_run``) and turns each into a verdict that can go against Stage 8:

* baseline (1) the Φ-oracle (no discovery) — does a REPRODUCED package catch a REPLICATION
  positive the existing theory misses? (:func:`phi_oracle_baseline`, :func:`residual_gain`);
* baseline (2) random search and (3) exhaustive single-step search at the SAME
  ``ResearchBudget`` and discipline (:func:`compare_search`);
* the NAIVE discipline on a null corpus whose ground truth is "nothing to find"
  (:func:`run_null_fdr`) — if naive and disciplined both find nothing the null was too easy
  and the verdict is DEGENERATE, never a pass;
* a small model trained directly on labels (:func:`direct_model_baseline`), ORACLE selection
  policies (:func:`oracle_comparison`), one ablation row per flag (:func:`run_ablation`) and a
  threshold sweep (:func:`threshold_sensitivity`, lesson 5).

What it refuses to do: it never writes the project's experiment registry (registration is an
explicit CLI act, lesson 7); it never reads a figure it did not compute in the call; every
lab-oracle figure is labelled ``lab_oracle_authored`` and every detection gain
``counterfactual_at_boundary`` (Stage 6 adopts nothing, B8-1). Every corpus here shares an
author with the engine (lesson 6): a JUSTIFIED verdict is a mechanism result on a world built
to contain what it looks for, not evidence about real telemetry.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field, replace
from enum import StrEnum
from typing import Any

from pocketsec.stage0.benchmark.security_metrics import average_precision
from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.guillotine.features import LogisticProbe
from pocketsec.stage8.core_ids import ABLATION_FLAGS, STAGE8_FUNCTIONS
from pocketsec.stage8.ecology.population import MDL_GAIN_PER_BIT, ScoreMode
from pocketsec.stage8.episode import Episode, FitCounts, Split, fit_counts
from pocketsec.stage8.forge.package import (
    ReproducibilityStatus, RepresentationKind, TournamentResult,
)
from pocketsec.stage8.forge.representations import pooled_features
from pocketsec.stage8.forge.tournament import (
    ENDPOINT_ARTIFACT_MAX_BYTES,
    FORGE_AGREEMENT_MIN,
    FORGE_FPR_TOLERANCE,
    FORGE_RECALL_TOLERANCE,
    FORGE_WALL_RATIO_MAX,
)
from pocketsec.stage8.genome.grammar import Modifier, parse_mechanism
from pocketsec.stage8.genome.hypothesis import Direction, GeneratorKind
from pocketsec.stage8.governor.budget import ResearchBudget
from pocketsec.stage8.labs.discovery_corpus import (
    DEFAULT_COUNTS,
    PLANTED_MECHANISMS,
    CorpusArm,
    DiscoveryCorpus,
    build_discovery_corpus,
    relabel_null,
)
from pocketsec.stage8.labs.discovery_run import (
    PLANTED_AGREEMENT_MIN,
    DiscoveryRunReport,
    RunConfig,
    _execute,
    _Knobs,
    agreement,
    run_discovery,
)
from pocketsec.stage8.oracle.planner import SelectionPolicy
from pocketsec.stage8.residual.observatory import FPR_BUDGET, PhiOracleExplainer
from pocketsec.stage8.residual.priority_field import PriorityMode
from pocketsec.stage8.sandbox.integrity import ALPHA

__all__ = [
    "ALPHA_SWEEP",
    "BOUNDARY_LABEL",
    "FORGE_TOLERANCE_SWEEP",
    "LAB_ORACLE_LABEL",
    "MDL_SWEEP",
    "NULL_ANY_REPRODUCED_SHARE_MAX",
    "NULL_MEAN_REPRODUCED_MAX",
    "NULL_SEEDS",
    "SEARCH_SEEDS",
    "AblationRow",
    "ComponentVerdict",
    "DirectModelReport",
    "NullReport",
    "NullRow",
    "OracleCell",
    "OracleComparison",
    "PhiBaselineReport",
    "ResidualGain",
    "SearchArm",
    "SearchComparison",
    "SensitivityRow",
    "ablation_base",
    "ablation_control",
    "compare_search",
    "deployable_at",
    "direct_model_baseline",
    "oracle_comparison",
    "phi_oracle_baseline",
    "residual_gain",
    "run_ablation",
    "run_null_fdr",
    "search_verdict",
    "threshold_sensitivity",
]

# Every value below is chosen, not measured (spec §4.21).
NULL_SEEDS = 20
NULL_MEAN_REPRODUCED_MAX = 0.10
NULL_ANY_REPRODUCED_SHARE_MAX = 0.10
SEARCH_SEEDS = 3
RESIDUAL_GAIN_MIN = 0.05          # recall(Φ OR packages) must beat recall(Φ) by this much …
RESIDUAL_FPR_SLACK = 0.01         # … at an FPR no worse than Φ's plus this.
DIRECT_MODEL_RECALL_SLACK = 0.02
ALPHA_SWEEP = (0.01, 0.05, 0.10)
MDL_SWEEP = (0.0, 0.01, 0.05)
FORGE_TOLERANCE_SWEEP = (0.0, 0.02, 0.05)
MAX_REPORTED_IDS = 32
LAB_ORACLE_LABEL = "lab_oracle_authored"
REPLAY_LABEL = "replay_only"
BOUNDARY_LABEL = "counterfactual_at_boundary"
THRESHOLD_DECIDES = "THRESHOLD_DECIDES"


class ComponentVerdict(StrEnum):
    JUSTIFIED = "JUSTIFIED"
    NOT_YET_JUSTIFIED = "NOT_YET_JUSTIFIED"
    INERT = "INERT"
    HARMFUL = "HARMFUL"
    DEGENERATE = "DEGENERATE"


# -- baseline (1): the Φ-oracle ------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class PhiBaselineReport:
    threshold: float | None            # TRAIN threshold at FPR_BUDGET; None = never fires
    replication_recall: float | None
    replication_false_positive_rate: float | None
    replication_ap: float | None
    positives: int
    negatives: int
    missed_positive_ids: tuple[str, ...]   # ≤ MAX_REPORTED_IDS, truncation counted
    missed_positives: int
    replication_episodes: tuple[Episode, ...] = field(default=(), repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class ResidualGain:
    phi_missed_positives: int
    caught_by_packages: int            # Φ-missed REPLICATION positives a package catches
    caught_ids: tuple[str, ...]
    phi_recall: float | None
    combined_recall: float | None
    phi_false_positive_rate: float | None
    combined_false_positive_rate: float | None
    packages_used: int
    beats_phi: bool
    label: str = BOUNDARY_LABEL


def phi_oracle_baseline(corpus: DiscoveryCorpus) -> PhiBaselineReport:
    """Stage 2's surviving scorer at its TRAIN FPR-budget threshold, measured on REPLICATION."""
    phi = PhiOracleExplainer.fit(corpus.episodes(Split.TRAIN), fpr_budget=FPR_BUDGET)
    replication = corpus.episodes(Split.REPLICATION)
    labelled = [e for e in replication if e.label is not None]
    counts = fit_counts(phi.fires, labelled)
    missed = [e.episode_id for e in labelled if e.label == 1 and not phi.fires(e)]
    labels = [int(e.label) for e in labelled]  # type: ignore[arg-type]
    ap = average_precision(labels, [e.phi_oracle_score() for e in labelled]) if labelled else None
    return PhiBaselineReport(
        threshold=phi.threshold, replication_recall=counts.recall,
        replication_false_positive_rate=counts.false_positive_rate, replication_ap=ap,
        positives=counts.positives, negatives=counts.negatives,
        missed_positive_ids=tuple(missed[:MAX_REPORTED_IDS]), missed_positives=len(missed),
        replication_episodes=tuple(labelled))


def residual_gain(report: DiscoveryRunReport, phi: PhiBaselineReport) -> ResidualGain:
    """What REPRODUCED MALICIOUS packages add to the Φ-oracle on the same REPLICATION episodes."""
    episodes = phi.replication_episodes
    threshold = phi.threshold
    mechanisms = [p.mechanism for p in report.packages if p.direction is Direction.MALICIOUS
                  and p.reproducibility.status is ReproducibilityStatus.REPRODUCED]

    def phi_fires(e: Episode) -> bool:
        return threshold is not None and e.phi_oracle_score() >= threshold

    def package_fires(e: Episode) -> bool:
        return any(m.matches(e.steps) for m in mechanisms)

    phi_counts = fit_counts(phi_fires, episodes)
    both = fit_counts(lambda e: phi_fires(e) or package_fires(e), episodes)
    missed = [e for e in episodes if e.label == 1 and not phi_fires(e)]
    caught = [e.episode_id for e in missed if package_fires(e)]
    beats = bool(caught) and _gain(phi_counts, both)
    return ResidualGain(
        phi_missed_positives=len(missed),
        caught_by_packages=len(caught), caught_ids=tuple(caught[:MAX_REPORTED_IDS]),
        phi_recall=phi_counts.recall, combined_recall=both.recall,
        phi_false_positive_rate=phi_counts.false_positive_rate,
        combined_false_positive_rate=both.false_positive_rate,
        packages_used=len(mechanisms), beats_phi=beats)


def _gain(phi: FitCounts, both: FitCounts) -> bool:
    if None in (phi.recall, both.recall, phi.false_positive_rate, both.false_positive_rate):
        return False
    recall_gain = both.recall - phi.recall  # type: ignore[operator]
    fpr_cost = both.false_positive_rate - phi.false_positive_rate  # type: ignore[operator]
    return recall_gain > RESIDUAL_GAIN_MIN and fpr_cost <= RESIDUAL_FPR_SLACK


# -- baselines (2) and (3): random and exhaustive single-step search at equal budget -------------


@dataclass(frozen=True, slots=True)
class SearchArm:
    arm: str                                   # "PROMETHEUS" | GeneratorKind value
    seeds: tuple[int, ...]
    planted_recovered: tuple[int, ...]         # families recovered, per seed
    families: tuple[str, ...]                  # union over seeds
    false_reproduced: tuple[int, ...]
    work_units: tuple[int, ...]
    budget_exhausted: tuple[bool, ...]


@dataclass(frozen=True, slots=True)
class SearchComparison:
    arms: tuple[SearchArm, ...]
    # strictly more families, false reproduced <= random's, AND random spent at least as much
    # (F7: an equal CAP is not equal spend; random under-spending cannot be "beaten").
    beats_random: bool
    # Families PROMETHEUS recovers that exhaustive does not, among those EXHAUSTIVE_SINGLE can
    # EXPRESS (F7, lesson 2: a 2-step or REPEATED family is beyond it by construction).
    beyond_exhaustive: tuple[str, ...]
    verdict: ComponentVerdict
    precondition_problems: tuple[str, ...]


_SEARCH_ARMS: tuple[tuple[str, tuple[GeneratorKind, ...] | None], ...] = (
    ("PROMETHEUS", None),
    (GeneratorKind.RANDOM_BASELINE.value, (GeneratorKind.RANDOM_BASELINE,)),
    (GeneratorKind.EXHAUSTIVE_SINGLE_BASELINE.value, (GeneratorKind.EXHAUSTIVE_SINGLE_BASELINE,)),
)


def _recovered(report: DiscoveryRunReport) -> tuple[str, ...]:
    return tuple(family for family, ok in report.planted_recovered if ok)


def compare_search(corpus: DiscoveryCorpus, *, seed: int,
                   budget: ResearchBudget = ResearchBudget(),
                   seeds: int = SEARCH_SEEDS) -> SearchComparison:
    """PROMETHEUS vs RANDOM vs EXHAUSTIVE_SINGLE: same corpus, same budget, same discipline."""
    arms: list[SearchArm] = []
    problems: tuple[str, ...] = ()
    for name, generators in _SEARCH_ARMS:
        reports = []
        for offset in range(seeds):
            config = RunConfig(arm=corpus.arm, seed=seed + offset, budget=budget)
            if generators is not None:
                config = replace(config, generators=generators)
            reports.append(run_discovery(corpus, config))
        problems = problems or reports[0].precondition_problems
        arms.append(SearchArm(
            arm=name, seeds=tuple(seed + i for i in range(seeds)),
            planted_recovered=tuple(len(_recovered(r)) for r in reports),
            families=tuple(sorted({f for r in reports for f in _recovered(r)})),
            false_reproduced=tuple(r.false_reproduced for r in reports),
            work_units=tuple(r.governor.spent for r in reports),
            budget_exhausted=tuple(r.budget_exhausted for r in reports)))
    return search_verdict(tuple(arms), problems)


def search_verdict(arms: tuple[SearchArm, ...],
                   problems: tuple[str, ...] = ()) -> SearchComparison:
    """The comparison's verdict from its three arms (PROMETHEUS, RANDOM, EXHAUSTIVE_SINGLE).

    F7: it used to return JUSTIFIED by construction whenever PROMETHEUS recovered any 2-step
    family, because the single-step arm cannot express one (so it was always "beyond"
    exhaustive), and random lost at an equal cap while spending less. Now a family counts as
    beyond exhaustive only if the exhaustive arm could express it, and random is beaten only
    when it spent at least as much.
    """
    prom, rand, exhaustive = arms
    beats_random = (sum(prom.planted_recovered) > sum(rand.planted_recovered)
                    and sum(prom.false_reproduced) <= sum(rand.false_reproduced)
                    and sum(rand.work_units) >= sum(prom.work_units))
    expressible = {family.value for family, mechanism in PLANTED_MECHANISMS.items()
                   if len(mechanism.steps) == 1 and mechanism.modifier is Modifier.NONE}
    beyond = tuple(f for f in prom.families
                   if f in expressible and f not in exhaustive.families)
    if problems:
        verdict = ComponentVerdict.DEGENERATE
    elif beats_random and beyond:
        verdict = ComponentVerdict.JUSTIFIED
    else:
        verdict = ComponentVerdict.NOT_YET_JUSTIFIED
    return SearchComparison(arms=arms, beats_random=beats_random, beyond_exhaustive=beyond,
                            verdict=verdict, precondition_problems=problems)


# -- the null corpus: false-discovery rate, disciplined vs naive --------------------------------


@dataclass(frozen=True, slots=True)
class NullRow:
    label_seed: int
    registered: int
    survived: int
    reproduced: int
    naive_tested: int
    naive_selected: int
    budget_exhausted: bool


@dataclass(frozen=True, slots=True)
class NullReport:
    content_seed: int
    rows: tuple[NullRow, ...]
    disciplined_mean_reproduced: float
    disciplined_any_share: float
    naive_mean_selected: float
    naive_any_share: float
    within_limits: bool                # disciplined mean <= 0.10 and share with any <= 0.10
    halts_packaging: bool              # F3: the engine manufactures discoveries on noise
    verdict: ComponentVerdict          # JUSTIFIED iff within limits AND naive > disciplined


def run_null_fdr(*, seeds: Sequence[int] = tuple(range(NULL_SEEDS)), content_seed: int,
                 counts: Mapping[Split, int] = DEFAULT_COUNTS,
                 budget: ResearchBudget = ResearchBudget()) -> NullReport:
    """One NULL render, ``len(seeds)`` label draws; each run disciplined AND naive."""
    if not seeds:
        raise ContractError("run_null_fdr needs at least one label seed")
    base = build_discovery_corpus(arm=CorpusArm.NULL, seed=content_seed, counts=counts)
    rows = []
    for label_seed in seeds:
        corpus = relabel_null(base, label_seed=label_seed)
        config = RunConfig(arm=CorpusArm.NULL, seed=label_seed, budget=budget)
        disciplined = run_discovery(corpus, config)
        naive = run_discovery(corpus, replace(config, holdout_discipline=False, bonferroni=False))
        rows.append(NullRow(
            label_seed=label_seed, registered=disciplined.registered,
            survived=len(disciplined.survived), reproduced=len(disciplined.reproduced),
            naive_tested=naive.births, naive_selected=len(naive.survived),
            budget_exhausted=disciplined.budget_exhausted or naive.budget_exhausted))
    return _null_report(content_seed, rows)


def _null_report(content_seed: int, rows: Sequence[NullRow]) -> NullReport:
    n = len(rows)
    d_mean = sum(r.reproduced for r in rows) / n
    d_any = sum(r.reproduced > 0 for r in rows) / n
    n_mean = sum(r.naive_selected for r in rows) / n
    n_any = sum(r.naive_selected > 0 for r in rows) / n
    within = d_mean <= NULL_MEAN_REPRODUCED_MAX and d_any <= NULL_ANY_REPRODUCED_SHARE_MAX
    if not within:
        verdict = ComponentVerdict.NOT_YET_JUSTIFIED
    elif n_mean <= d_mean:
        verdict = ComponentVerdict.DEGENERATE   # too easy a null: the discipline stopped nothing
    else:
        verdict = ComponentVerdict.JUSTIFIED
    return NullReport(content_seed=content_seed, rows=tuple(rows),
                      disciplined_mean_reproduced=d_mean, disciplined_any_share=d_any,
                      naive_mean_selected=n_mean, naive_any_share=n_any, within_limits=within,
                      halts_packaging=not within, verdict=verdict)


# -- the direct model: LOGISTIC on TRAIN + HOLDOUT labels over pooled features (F8) -------------


@dataclass(frozen=True, slots=True)
class DirectModelReport:
    train_episodes: int
    replication_precision: float | None
    replication_recall: float | None
    replication_false_positive_rate: float | None
    replication_ap: float | None
    work_units_per_event: float | None     # pooled feature reads per episode
    refusal: str | None                    # "NO_BOTH_CLASSES" when the fitted labels are one-class


def direct_model_baseline(corpus: DiscoveryCorpus) -> DirectModelReport:
    """No discovery at all: a stdlib logistic model fitted on the labels the loop reads (§51).

    F8: it used to be fitted on TRAIN alone, where the trap is a perfect positive feature, so
    G8.12 compared FORGE against a trap-poisoned model while the discovery loop itself also
    reads HOLDOUT labels through the vault. It is now fitted on TRAIN + HOLDOUT (equal
    information); ``train_episodes`` counts every labelled episode it was fitted on.
    """
    train = [e for split in (Split.TRAIN, Split.HOLDOUT) for e in corpus.episodes(split)
             if e.label is not None]
    labels = [int(e.label) for e in train]  # type: ignore[arg-type]
    if len(set(labels)) < 2:
        return DirectModelReport(len(train), None, None, None, None, None, "NO_BOTH_CLASSES")
    probe = LogisticProbe().fit([list(pooled_features(e)) for e in train], labels)
    replication = [e for e in corpus.episodes(Split.REPLICATION) if e.label is not None]
    scores = probe.predict([list(pooled_features(e)) for e in replication])
    decided = {e.episode_id: s >= 0.5 for e, s in zip(replication, scores, strict=True)}
    counts = fit_counts(lambda e: decided[e.episode_id], replication)
    width = len(pooled_features(replication[0])) if replication else 0
    reads = sum(len(e.steps) * width for e in replication)
    truth = [int(e.label) for e in replication]  # type: ignore[arg-type]
    return DirectModelReport(
        train_episodes=len(train), replication_precision=counts.precision,
        replication_recall=counts.recall,
        replication_false_positive_rate=counts.false_positive_rate,
        replication_ap=average_precision(truth, scores) if replication else None,
        work_units_per_event=reads / len(replication) if replication else None, refusal=None)


# -- ORACLE selection policies, lab oracle off and on ---------------------------------------------


@dataclass(frozen=True, slots=True)
class OracleCell:
    policy: str
    lab_oracle: bool
    seed: int
    reports: int
    experiments: int
    work_units: int                    # ORACLE work units to its stops
    stops: tuple[str, ...]
    correct_leading: int               # leaders agreeing >= 0.98 with a planted mechanism
    label: str                         # lab_oracle_authored | replay_only


@dataclass(frozen=True, slots=True)
class OracleComparison:
    cells: tuple[OracleCell, ...]
    eig_beats_cheap: tuple[tuple[str, bool], ...]   # per lab setting (replay / lab-authored)
    verdict: ComponentVerdict


def oracle_comparison(corpus: DiscoveryCorpus, *, seeds: Sequence[int],
                      budget: ResearchBudget = ResearchBudget()) -> OracleComparison:
    """EIG_PER_COST vs EIG_ONLY vs RANDOM vs CHEAPEST; every lab-on figure is lab-authored."""
    cells = []
    replication = corpus.episodes(Split.REPLICATION)
    for lab in (False, True):
        for policy in SelectionPolicy:
            for seed in seeds:
                config = RunConfig(arm=corpus.arm, seed=seed, budget=budget,
                                   oracle_policy=policy, use_lab_oracle=lab)
                report = run_discovery(corpus, config)
                cells.append(_oracle_cell(report, policy, lab, seed, replication))
    verdicts = []
    for lab in (False, True):
        mine = [c for c in cells if c.lab_oracle is lab]
        verdicts.append((LAB_ORACLE_LABEL if lab else REPLAY_LABEL, _eig_beats_cheap(mine)))
    # The production default is replay only: only the lab-off comparison can justify ORACLE.
    justified = verdicts[0][1]
    verdict = ComponentVerdict.JUSTIFIED if justified else ComponentVerdict.NOT_YET_JUSTIFIED
    return OracleComparison(cells=tuple(cells), eig_beats_cheap=tuple(verdicts), verdict=verdict)


def _oracle_cell(report: DiscoveryRunReport, policy: SelectionPolicy, lab: bool, seed: int,
                 replication: Sequence[Episode]) -> OracleCell:
    correct = sum(_leader_is_planted(dsl, replication) for _, dsl in report.oracle_leaders)
    return OracleCell(
        policy=policy.value, lab_oracle=lab, seed=seed, reports=len(report.oracle),
        experiments=sum(len(r.experiments) for r in report.oracle),
        work_units=sum(r.work_units for r in report.oracle),
        stops=tuple(r.stop.value for r in report.oracle), correct_leading=correct,
        label=LAB_ORACLE_LABEL if lab else REPLAY_LABEL)


def _leader_is_planted(dsl: str, replication: Sequence[Episode]) -> bool:
    direction, _, text = dsl.partition(":")
    if direction != Direction.MALICIOUS.value:
        return False
    mechanism = parse_mechanism(text)
    for planted in PLANTED_MECHANISMS.values():
        same = agreement(lambda e: mechanism.matches(e.steps),
                         lambda e, m=planted: m.matches(e.steps), replication)
        if (same or 0.0) >= PLANTED_AGREEMENT_MIN:
            return True
    return False


def _eig_beats_cheap(cells: Sequence[OracleCell]) -> bool:
    """F8: EIG_PER_COST uses fewer work units than RANDOM and CHEAPEST at no worse accuracy."""
    def total(policy: SelectionPolicy, attr: str) -> int:
        return sum(getattr(c, attr) for c in cells if c.policy == policy.value)

    eig = SelectionPolicy.EIG_PER_COST
    if total(eig, "reports") == 0:
        return False
    return all(total(eig, "work_units") < total(other, "work_units")
               and total(eig, "correct_leading") >= total(other, "correct_leading")
               for other in (SelectionPolicy.RANDOM, SelectionPolicy.CHEAPEST))


# -- ablation: one row per flag ------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AblationRow:
    flag: str
    control: str
    core_id: str
    delta_planted_recovered: int        # base − control (positive: the component helps)
    delta_false_reproduced: int         # base − control (negative: the component helps)
    delta_residual_recall: float | None
    delta_work_units: int
    firings: int
    outcome_changes: int                # |tested/terminal outcomes that differ from the control|
    verdict: ComponentVerdict
    experiment_slug: str


_GENERATOR_FLAGS: Mapping[str, GeneratorKind] = {
    "residual_motif": GeneratorKind.RESIDUAL_MOTIF, "analogy": GeneratorKind.ANALOGY,
    "null_benign": GeneratorKind.NULL_BENIGN, "stage7_seed": GeneratorKind.STAGE7_SEED,
    "external_proposal": GeneratorKind.EXTERNAL_PROPOSAL,
}
_FLAG_COMPONENTS: Mapping[str, tuple[str, ...]] = {
    "priority_field": ("priority_field",), "diversity": ("diversity",),
    "mutation": ("mutation", "merge_split"), "mdl": ("mdl",), "score_full": ("score_full",),
    "oracle": ("oracle",), "cost_aware": ("oracle",), "eig": ("oracle",),
    "doppelganger_screen": ("doppelganger_screen",), "negative_memory": ("negative_memory",),
    "holdout_discipline": ("vault",), "bonferroni": ("bonferroni",),
    **{flag: (f"generator:{kind.value}",) for flag, kind in _GENERATOR_FLAGS.items()},
}
_CONTROLS: Mapping[str, tuple[Mapping[str, object], str]] = {
    "priority_field": ({"priority_mode": PriorityMode.SIZE_ONLY}, "SIZE_ONLY"),
    "diversity": ({"diversity": False}, "top-k by TRAIN f1"),
    "mdl": ({"mdl": False}, "any f1 gain accepted"),
    "score_full": ({"score_mode": ScoreMode.FIT_ONLY}, "FIT_ONLY"),
    "oracle": ({"oracle_policy": None}, "off (register top-k by score)"),
    "cost_aware": ({"oracle_policy": SelectionPolicy.EIG_ONLY}, "EIG_ONLY"),
    "eig": ({"oracle_policy": SelectionPolicy.RANDOM}, "RANDOM"),
    "doppelganger_screen": ({"doppelganger_screen": False}, "off"),
    "negative_memory": ({"negative_memory": False}, "off"),
    "holdout_discipline": ({"holdout_discipline": False, "bonferroni": False},
                           "NAIVE (control only)"),
    "bonferroni": ({"bonferroni": False}, "uncorrected alpha (control only)"),
}


def ablation_base(base: RunConfig) -> RunConfig:
    """``base`` with every OPTIONAL component on: what an ablation row switches one thing off from.

    ORACLE is default-off in production (ADR-0078 amendment 2), but a default-off component
    still needs its row: measuring it against a base where it is already off would compare a
    run with itself (DEGENERATE). So the ablation base turns ORACLE on at EIG_PER_COST.
    """
    if base.oracle_policy is None:
        return replace(base, oracle_policy=SelectionPolicy.EIG_PER_COST)
    return base


def ablation_control(flag: str, base: RunConfig) -> tuple[RunConfig, _Knobs, str]:
    """The isolating control for one flag: the all-on base with exactly that mechanism off."""
    base = ablation_base(base)
    knobs = _Knobs()
    if flag in _GENERATOR_FLAGS:
        kind = _GENERATOR_FLAGS[flag]
        kept = tuple(g for g in base.generators if g is not kind)
        return replace(base, generators=kept), knobs, f"{kind.value} off"
    if flag == "mutation":
        return base, replace(knobs, evolve=False), "no evolution (mutation, merge, split off)"
    if flag not in _CONTROLS:
        raise ContractError(f"no control defined for ablation flag {flag!r}")
    changes, name = _CONTROLS[flag]
    return replace(base, **changes), knobs, name  # type: ignore[arg-type]


def _core_id(flag: str) -> str:
    return next((f.core_id for f in STAGE8_FUNCTIONS if flag in f.ablation_flags), "")


def _outcome_changes(base: DiscoveryRunReport, control: DiscoveryRunReport) -> int:
    return len(set(base.outcomes) ^ set(control.outcomes))


def _verdict(*, degenerate: bool, firings: int, changes: int, d_planted: int, d_false: int,
             d_recall: float | None) -> ComponentVerdict:
    if degenerate:
        return ComponentVerdict.DEGENERATE
    if changes == 0:
        return ComponentVerdict.INERT
    if d_false > 0 or (d_recall is not None and d_recall < 0):
        return ComponentVerdict.HARMFUL
    improves = d_planted > 0 or d_false < 0 or (d_recall is not None and d_recall > 0)
    if improves and firings > 0:
        return ComponentVerdict.JUSTIFIED
    return ComponentVerdict.NOT_YET_JUSTIFIED


def _combined_recall(report: DiscoveryRunReport, phi: PhiBaselineReport) -> float | None:
    return residual_gain(report, phi).combined_recall


def run_ablation(corpus: DiscoveryCorpus, base: RunConfig,
                 flags: Iterable[str] = ABLATION_FLAGS) -> tuple[AblationRow, ...]:
    """One row per ablation flag of ``core_ids``: the base run against its isolating control."""
    phi = phi_oracle_baseline(corpus)
    base = ablation_base(base)
    base_report = run_discovery(corpus, base)
    degenerate = bool(base_report.precondition_problems)
    return tuple(_ablation_row(flag, corpus, base, base_report, phi, degenerate) for flag in flags)


def _firings(flag: str, base: RunConfig, report: DiscoveryRunReport) -> int:
    if flag == "diversity":   # the engine selects every birth with it; no per-run counterfactual
        return sum(len(g.births) for g in report.generation) if base.diversity else 0
    names = _FLAG_COMPONENTS.get(flag, ())
    return sum(f.firings for f in report.firings if f.component in names)


def _ablation_row(flag: str, corpus: DiscoveryCorpus, base: RunConfig,
                  base_report: DiscoveryRunReport, phi: PhiBaselineReport,
                  degenerate: bool) -> AblationRow:
    config, knobs, control_name = ablation_control(flag, base)
    control = _execute(corpus, config, gateway=None, knobs=knobs, stores=None)
    base_recall, control_recall = _combined_recall(base_report, phi), _combined_recall(control, phi)
    d_recall = (None if base_recall is None or control_recall is None
                else base_recall - control_recall)
    d_planted = len(_recovered(base_report)) - len(_recovered(control))
    d_false = base_report.false_reproduced - control.false_reproduced
    changes = _outcome_changes(base_report, control)
    firings = _firings(flag, base, base_report)
    # A control identical to the base (the component is already off) cannot be measured.
    unmeasurable = config == base and knobs == _Knobs()
    verdict = _verdict(degenerate=degenerate or unmeasurable, firings=firings, changes=changes,
                       d_planted=d_planted, d_false=d_false, d_recall=d_recall)
    return AblationRow(
        flag=flag, control=control_name, core_id=_core_id(flag),
        delta_planted_recovered=d_planted, delta_false_reproduced=d_false,
        delta_residual_recall=d_recall,
        delta_work_units=base_report.governor.spent - control.governor.spent, firings=firings,
        outcome_changes=changes, verdict=verdict,
        experiment_slug=f"ablation-{flag.replace('_', '-')}")


# -- threshold sensitivity (lesson 5) ------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SensitivityRow:
    parameter: str
    value: float
    is_default: bool
    reproduced: int
    planted_recovered: int
    false_reproduced: int
    deployable: int
    outcomes_changed: int              # outcomes differing from the default value's
    outcomes: int                      # size of the default value's outcome vector
    flag: str                          # THRESHOLD_DECIDES when this value flips every outcome


def deployable_at(result: TournamentResult, tolerance: float) -> bool:
    """D8.15's selection rule restated with the recall/precision tolerance as a parameter.

    Used only by the sweep; a test pins that at the default tolerance it reproduces the
    tournament's own ``deployable`` bit, so this restatement cannot drift silently.
    """
    ref = next((m for m in result.entrants if m.kind is RepresentationKind.TYPED_RULE), None)
    if ref is None or None in (ref.recall, ref.precision, ref.false_positive_rate,
                               ref.work_units_per_event, ref.artifact_bytes):
        return False
    for m in result.entrants:
        if m.kind is RepresentationKind.TYPED_RULE or not m.expressible:
            continue
        values = (m.precision, m.recall, m.false_positive_rate, m.pr_auc, m.decision_agreement,
                  m.work_units_per_event, m.artifact_bytes)
        if None in values:
            continue
        if _eligible(m, ref, tolerance) and _cheaper(m, ref):
            return True
    return False


def _eligible(m: Any, ref: Any, tolerance: float) -> bool:
    return (m.recall >= ref.recall - tolerance and m.precision >= ref.precision - tolerance
            and m.false_positive_rate <= ref.false_positive_rate + FORGE_FPR_TOLERANCE
            and m.decision_agreement >= FORGE_AGREEMENT_MIN
            and m.artifact_bytes <= ENDPOINT_ARTIFACT_MAX_BYTES)


def _cheaper(m: Any, ref: Any) -> bool:
    """No worse on both cost axes, strictly better on one, and no slower in the same run."""
    units, size, wall = m.work_units_per_event, m.artifact_bytes, m.wall_ratio_to_reference
    return (wall is not None and wall <= FORGE_WALL_RATIO_MAX
            and units <= ref.work_units_per_event and size <= ref.artifact_bytes
            and (units < ref.work_units_per_event or size < ref.artifact_bytes))


def _changed(default: Mapping[str, str], other: Mapping[str, str]) -> int:
    return sum(1 for key, value in default.items() if other.get(key) != value)


def _rows_for(parameter: str, values: Sequence[float], default: float,
              reports: Mapping[float, DiscoveryRunReport]) -> list[SensitivityRow]:
    base = dict(reports[default].outcomes)
    rows = []
    for value in values:
        report = reports[value]
        changed = _changed(base, dict(report.outcomes))
        decides = value != default and bool(base) and changed == len(base)
        rows.append(SensitivityRow(
            parameter=parameter, value=value, is_default=value == default,
            reproduced=len(report.reproduced), planted_recovered=len(_recovered(report)),
            false_reproduced=report.false_reproduced,
            deployable=sum(p.detector_candidates.deployable for p in report.packages),
            outcomes_changed=changed, outcomes=len(base),
            flag=THRESHOLD_DECIDES if decides else ""))
    return rows


def threshold_sensitivity(corpus: DiscoveryCorpus, base: RunConfig) -> tuple[SensitivityRow, ...]:
    """Sweep α, MDL gain per bit and FORGE tolerance; flag a value that flips every outcome."""
    def run(knobs: _Knobs) -> DiscoveryRunReport:
        return _execute(corpus, base, gateway=None, knobs=knobs, stores=None)

    # alpha above the genome's registered alpha cannot loosen it (the vault uses the minimum):
    # the 0.10 row therefore reproduces 0.05, which is the discipline, not an insensitivity.
    alpha_runs = {a: run(_Knobs(alpha=a)) for a in ALPHA_SWEEP}
    mdl_runs = {g: run(_Knobs(mdl_gain_per_bit=g)) for g in MDL_SWEEP}
    rows = _rows_for("alpha", ALPHA_SWEEP, ALPHA, alpha_runs)
    rows += _rows_for("mdl_gain_per_bit", MDL_SWEEP, MDL_GAIN_PER_BIT, mdl_runs)
    rows += _forge_rows(alpha_runs[ALPHA])
    return tuple(rows)


def _forge_rows(report: DiscoveryRunReport) -> list[SensitivityRow]:
    tournaments = {p.package_id: p.detector_candidates for p in report.packages}
    base = {pid: str(deployable_at(t, FORGE_RECALL_TOLERANCE)) for pid, t in tournaments.items()}
    rows = []
    for tolerance in FORGE_TOLERANCE_SWEEP:
        outcome = {pid: str(deployable_at(t, tolerance)) for pid, t in tournaments.items()}
        changed = _changed(base, outcome)
        decides = tolerance != FORGE_RECALL_TOLERANCE and bool(base) and changed == len(base)
        rows.append(SensitivityRow(
            parameter="forge_tolerance", value=tolerance,
            is_default=tolerance == FORGE_RECALL_TOLERANCE,
            reproduced=len(report.reproduced), planted_recovered=len(_recovered(report)),
            false_reproduced=report.false_reproduced,
            deployable=sum(v == "True" for v in outcome.values()), outcomes_changed=changed,
            outcomes=len(base), flag=THRESHOLD_DECIDES if decides else ""))
    return rows
