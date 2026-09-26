"""Stage 8 package ``experiments``: the discovery loop, its baselines and the S8X catalogue.

Behaviour and failure paths on small real corpora (Stage 1 renders, <= 100 sessions per split)
and small budgets: the trap is generated and refuted with the discipline and "discovered"
without it; the vault alone falsifies the trap; a null corpus reproduces nothing; the budget is
a kill switch that returns a report; every ablation flag has a row with a firing count; the
catalogue has 128 honest rows; the run never touches the project's experiment registry; the
endurance stores stay bounded. Every corpus shares an author with the engine (lesson 6): these
are mechanism tests, not detection claims.
"""

from __future__ import annotations

import ast
import hashlib
from dataclasses import replace

import pytest

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.gate import REPO_ROOT
from pocketsec.stage8.core_ids import ABLATION_FLAGS
from pocketsec.stage8.episode import Split
from pocketsec.stage8.forge.package import ReproducibilityStatus, verify_package
from pocketsec.stage8.forge.tournament import FORGE_RECALL_TOLERANCE
from pocketsec.stage8.genome.hypothesis import Direction, GeneratorKind
from pocketsec.stage8.governor.budget import ResearchBudget
from pocketsec.stage8.labs import baselines as B
from pocketsec.stage8.labs import eighty_experiments as X
from pocketsec.stage8.labs.discovery_corpus import CorpusArm, build_discovery_corpus
from pocketsec.stage8.labs.discovery_run import (
    PROMETHEUS_GENERATORS,
    ComponentFiring,
    DiscoveryRunReport,
    RunConfig,
    lab_gateway,
    probe_trap_at_holdout,
    run_discovery,
    run_endurance,
)
from pocketsec.stage8.oracle.planner import SelectionPolicy

COUNTS = {Split.TRAIN: 48, Split.HOLDOUT: 48, Split.REPLICATION: 100, Split.LAB_POOL: 30,
          Split.INDEPENDENT: 30}
SMALL = ResearchBudget(max_active_residual_clusters=4, max_hypotheses_per_residual=16,
                       max_population=64, max_registrations_per_batch=6)
TINY = replace(SMALL, max_registrations_per_batch=2)
LABS = REPO_ROOT / "pocketsec" / "stage8" / "labs"
MINE = ("discovery_run.py", "baselines.py", "eighty_experiments.py")
REGISTRY = REPO_ROOT / "experiments" / "registry.jsonl"
V = B.ComponentVerdict


def _registry_digest() -> str | None:
    return hashlib.sha256(REGISTRY.read_bytes()).hexdigest() if REGISTRY.exists() else None


@pytest.fixture(scope="module")
def registry_before() -> str | None:
    return _registry_digest()


@pytest.fixture(scope="module")
def planted(registry_before: str | None):  # noqa: ANN201 - DiscoveryCorpus
    return build_discovery_corpus(arm=CorpusArm.PLANTED, seed=3, counts=COUNTS)


@pytest.fixture(scope="module")
def gateway():  # noqa: ANN201 - QuarantineGateway
    return lab_gateway()


@pytest.fixture(scope="module")
def run(planted, gateway) -> DiscoveryRunReport:  # noqa: ANN001
    config = RunConfig(arm=CorpusArm.PLANTED, seed=3, budget=SMALL)
    return run_discovery(planted, config, gateway=gateway)


@pytest.fixture(scope="module")
def naive(planted, gateway) -> DiscoveryRunReport:  # noqa: ANN001
    config = RunConfig(arm=CorpusArm.PLANTED, seed=3, budget=SMALL, holdout_discipline=False,
                       bonferroni=False)
    return run_discovery(planted, config, gateway=gateway)


# -- the trap: true on TRAIN by construction, worthless held out ---------------------------------


def test_trap_is_generated_and_refuted_with_the_discipline(run: DiscoveryRunReport) -> None:
    trap = run.trap
    assert trap.generated and trap.refuted and trap.hypothesis_id is not None
    assert trap.refuted_at is not None
    # Never survives anything: not a HOLDOUT survivor, not reproduced, never packaged.
    assert trap.hypothesis_id not in run.survived
    assert trap.hypothesis_id not in run.reproduced
    assert all(p.hypothesis_id != trap.hypothesis_id for p in run.packages)
    reproduced = {key for key, status in run.outcomes if status == "REPRODUCED"}
    assert "MALICIOUS:SINGLE(SPAWN)" not in reproduced


def test_the_vault_alone_falsifies_the_trap_after_preregistration(planted) -> None:  # noqa: ANN001
    probe = probe_trap_at_holdout(planted, seed=3)
    assert probe.generated and probe.registered and probe.refuted
    assert probe.refuted_at == "HOLDOUT"


def test_naive_control_discovers_the_trap_and_is_never_packaged(
        naive: DiscoveryRunReport) -> None:
    assert naive.trap.generated and not naive.trap.refuted
    assert naive.trap.hypothesis_id in naive.survived        # selected on TRAIN: the shortcut wins
    assert naive.false_reproduced >= 1
    # A control's output never travels, even with a gateway in hand.
    assert naive.packages == () and naive.receipts == () and naive.registered == 0
    assert all(status == "SELECTED_ON_TRAIN" for _, status in naive.outcomes)


# -- the disciplined loop end to end ---------------------------------------------------------------


def test_every_package_is_verified_reproduced_and_has_lineage(run: DiscoveryRunReport) -> None:
    assert run.packages, "the small PLANTED run must package at least one theory (else VACUOUS)"
    assert run.package_problems == () and run.ledger_problems == ()
    for package in run.packages:
        assert verify_package(package) == ()
        assert package.reproducibility.status is ReproducibilityStatus.REPRODUCED
        assert package.hypothesis_id in run.reproduced
        assert package.evidence_lineage[0].startswith("rc-")      # a RESIDUAL root
        assert package.evidence_lineage[-1].startswith("tn-")     # the FORGE candidate
        assert package.failure_conditions and not package.novelty_claim_permitted
        assert package.synthetic_data
        registrations = {r.registration_id for r in package.falsification_results
                         if r.registration_id}
        assert len(registrations) == 2                             # one HOLDOUT, one REPLICATION


def test_one_package_per_observational_equivalence_class(run: DiscoveryRunReport) -> None:
    dedup = run.firing("package_dedup")
    assert dedup is not None and dedup.firings == len(run.reproduced)   # every REPRODUCED seen
    assert len(run.packages) == dedup.firings - dedup.outcome_changes   # duplicates counted
    assert {p.hypothesis_id for p in run.packages} <= set(run.reproduced)


def test_packages_reach_stage6_only_through_the_adapter(run: DiscoveryRunReport) -> None:
    assert len(run.receipts) == len(run.packages)
    for receipt in run.receipts:
        assert receipt.capsule_ids and len(receipt.stage6_buckets) == len(receipt.capsule_ids)
        # Recorded verbatim; whatever Stage 6 says is counted, never reinterpreted (B8-1).
        trusted = sum(b == "TRUSTED_CANDIDATE" for b in receipt.stage6_buckets)
        assert receipt.trusted_candidates == trusted


def test_planted_recovery_is_measured_against_the_planted_mechanism(
        run: DiscoveryRunReport) -> None:
    recovered = dict(run.planted_recovered)
    assert set(recovered) == {"DROP_EXEC_EGRESS", "REPEATED_EGRESS", "CREDENTIAL_EGRESS"}
    assert recovered["DROP_EXEC_EGRESS"], "PM1 is the mechanism the Φ-oracle cannot see (M0.6)"
    assert run.synthetic_data and run.config.use_lab_oracle is False


def test_every_component_reports_firings(run: DiscoveryRunReport) -> None:
    names = {f.component for f in run.firings}
    for required in ("observatory", "priority_field", "counterfactual_screen",
                     "necessary_step_screen", "doppelganger_screen", "vault", "identifiability",
                     "reproducibility", "forge", "stage6_adapter",
                     "generator:SYMBOLIC_ENUMERATOR"):
        assert required in names, required
    for firing in run.firings:
        assert isinstance(firing, ComponentFiring)
        assert firing.firings >= 0 and firing.outcome_changes >= 0
    vault, screen = run.firing("vault"), run.firing("counterfactual_screen")
    assert vault is not None and vault.firings == run.registered
    # F1: this line used to assert the counterfactual screen refutes something; every such
    # refutation here was a decoy the hypothesis itself names. Judged relative to the
    # hypothesis, the screen runs on every candidate and refutes none on this run (INERT, reported
    # in the findings §F). A pre-holdout screen that really refutes is still required:
    assert screen is not None and screen.firings > 0
    refuting = [run.firing(n) for n in ("doppelganger_screen", "necessary_step_screen")]
    assert any(f is not None and f.outcome_changes >= 1 for f in refuting)


def test_identifiability_is_carried_into_every_package(run: DiscoveryRunReport) -> None:
    assert run.identifiability
    for verdict in run.identifiability:
        if verdict.klass.value != "IDENTIFIED":
            assert verdict.verdict is not None      # UNIDENTIFIABLE / INSUFFICIENT_EVIDENCE
    by_id = {v.hypothesis_id: v.klass for v in run.identifiability}
    for package in run.packages:
        assert package.identifiability is by_id[package.hypothesis_id]


def test_lab_interventions_fire_only_with_the_lab_oracle(planted,  # noqa: ANN001
                                                          run: DiscoveryRunReport) -> None:
    """Both arms register up to 16: after F1 (decoys judged relative to the hypothesis) the
    non-escalating singles the decoy used to refute pass the screen and take SMALL's 6
    registration slots, so the order/co-occurrence twins only interventions separate are
    registered at 16, not at 6 (measured this wave: 0 vs 0 at 6, 0 vs 15 at 16)."""
    budget = replace(SMALL, max_registrations_per_batch=16)
    run = run_discovery(planted, RunConfig(arm=CorpusArm.PLANTED, seed=3, budget=budget))
    lab = run_discovery(planted, RunConfig(arm=CorpusArm.PLANTED, seed=3, budget=budget,
                                           use_lab_oracle=True))
    replay = sum(v.distinguishing_episodes for v in run.identifiability)
    authored = sum(v.distinguishing_episodes for v in lab.identifiability)
    assert authored > replay          # interventions separate twins replay alone cannot
    assert any(o.lab_oracle_used for o in lab.oracle) or not lab.oracle
    assert not any(o.lab_oracle_used for o in run.oracle)


def test_wall_clock_is_recorded_beside_loadavg(run: DiscoveryRunReport) -> None:
    assert run.wall_seconds > 0 and len(run.loadavg) == 3


# -- refusals and the kill switch ----------------------------------------------------------------


def test_config_refusals(planted) -> None:  # noqa: ANN001
    with pytest.raises(ContractError):
        run_discovery(planted, RunConfig(arm=CorpusArm.NULL, seed=0, budget=SMALL))
    with pytest.raises(ContractError):
        run_discovery(planted, RunConfig(arm=CorpusArm.PLANTED, seed=0,
                                         generators=(GeneratorKind.MUTATION,)))
    with pytest.raises(ContractError):
        run_discovery(planted, RunConfig(arm=CorpusArm.PLANTED, seed=0, generators=()))
    dup = (GeneratorKind.SYMBOLIC_ENUMERATOR, GeneratorKind.SYMBOLIC_ENUMERATOR)
    with pytest.raises(ContractError):
        run_discovery(planted, RunConfig(arm=CorpusArm.PLANTED, seed=0, generators=dup))
    with pytest.raises(ContractError):
        run_endurance(cycles=0)


def test_runaway_search_hits_the_budget_not_the_host(planted) -> None:  # noqa: ANN001
    flood = tuple(f"REPEATED(CONNECT+EXTERNAL_ENDPOINT,{2 + i % 7})" for i in range(10_000))
    budget = replace(SMALL, work_units=200_000)
    config = RunConfig(arm=CorpusArm.PLANTED, seed=3, budget=budget, external_texts=flood)
    report = run_discovery(planted, config)
    assert report.budget_exhausted                     # the run ended on the budget, cleanly
    assert sum(g.external_refused for g in report.generation) > 0   # the flood met a store cap
    assert report.governor.spent <= budget.work_units
    assert report.packages == () and report.ledger_problems == ()


# -- the null corpus -----------------------------------------------------------------------------


def test_null_corpus_reproduces_nothing_with_the_discipline() -> None:
    report = B.run_null_fdr(seeds=(0, 1, 2), content_seed=5, counts=COUNTS, budget=SMALL)
    assert len(report.rows) == 3
    assert all(row.reproduced == 0 for row in report.rows)
    assert report.within_limits and not report.halts_packaging
    # Honesty: when the naive control ALSO finds nothing, the null was too easy (never a pass).
    if report.naive_mean_selected <= report.disciplined_mean_reproduced:
        assert report.verdict is V.DEGENERATE
    else:
        assert report.verdict is V.JUSTIFIED


def test_null_verdict_rules() -> None:
    def row(seed: int, reproduced: int, naive: int) -> B.NullRow:
        return B.NullRow(seed, 1, reproduced, reproduced, 10, naive, False)

    good = B._null_report(0, [row(s, 0, 2) for s in range(10)])
    assert good.verdict is V.JUSTIFIED and good.within_limits
    easy = B._null_report(0, [row(s, 0, 0) for s in range(10)])
    assert easy.verdict is V.DEGENERATE
    leaky = B._null_report(0, [row(s, 1 if s < 2 else 0, 3) for s in range(10)])   # 20 % of seeds
    assert leaky.halts_packaging and leaky.verdict is V.NOT_YET_JUSTIFIED
    with pytest.raises(ContractError):
        B.run_null_fdr(seeds=(), content_seed=0, counts=COUNTS, budget=SMALL)


# -- baselines -----------------------------------------------------------------------------------


def test_phi_baseline_and_residual_gain_are_consistent(planted,  # noqa: ANN001
                                                       run: DiscoveryRunReport) -> None:
    phi = B.phi_oracle_baseline(planted)
    assert phi.positives > 0 and phi.negatives > 0
    assert phi.missed_positives >= len(phi.missed_positive_ids)
    gain = B.residual_gain(run, phi)
    assert gain.label == B.BOUNDARY_LABEL
    assert gain.caught_by_packages <= gain.phi_missed_positives
    assert gain.combined_recall >= gain.phi_recall                   # type: ignore[operator]
    if gain.beats_phi:   # baseline (1) is beaten only by a caught positive AND a recall margin
        assert gain.caught_by_packages > 0
        margin = gain.combined_recall - gain.phi_recall  # type: ignore[operator]
        assert margin > B.RESIDUAL_GAIN_MIN
    if gain.caught_by_packages == 0:
        assert not gain.beats_phi


def test_direct_model_reads_the_loops_labels_and_refuses_one_class(planted) -> None:  # noqa: ANN001
    """F8: the direct model is fitted on TRAIN + HOLDOUT, the labels the loop reads (it was
    fitted on TRAIN alone, where the trap is a perfect feature); one-class labels are refused."""
    report = B.direct_model_baseline(planted)
    assert report.refusal is None and report.replication_recall is not None
    assert report.train_episodes == len(planted.episodes(Split.TRAIN)) + len(
        planted.episodes(Split.HOLDOUT))
    one = {split: tuple(e.with_split(split, label=0) for e in planted.episodes(split))
           for split in (Split.TRAIN, Split.HOLDOUT)}
    refused = B.direct_model_baseline(replace(planted, splits={**planted.splits, **one}))
    assert refused.refusal == "NO_BOTH_CLASSES" and refused.replication_recall is None


def test_search_comparison_runs_all_three_arms_at_equal_budget(planted) -> None:  # noqa: ANN001
    result = B.compare_search(planted, seed=3, budget=TINY, seeds=1)
    arms = [a.arm for a in result.arms]
    assert arms == ["PROMETHEUS", "RANDOM_BASELINE", "EXHAUSTIVE_SINGLE_BASELINE"]
    for arm in result.arms:
        assert arm.seeds == (3,) and all(w <= TINY.work_units for w in arm.work_units)
    prom, rand, exhaustive = result.arms
    # F7: random is beaten only at an equal SPEND (here it spent 918 885 of PROMETHEUS's
    # 2 588 191 under the same cap), and a family is beyond exhaustive only if the exhaustive
    # arm could express it (no planted family is single-step without REPEATED).
    assert result.beats_random == (sum(prom.planted_recovered) > sum(rand.planted_recovered)
                                   and sum(prom.false_reproduced) <= sum(rand.false_reproduced)
                                   and sum(rand.work_units) >= sum(prom.work_units))
    assert result.beyond_exhaustive == ()
    assert result.verdict is not V.JUSTIFIED


def test_forge_tolerance_restatement_matches_the_tournament(run: DiscoveryRunReport) -> None:
    assert run.packages
    for package in run.packages:
        tournament = package.detector_candidates
        assert B.deployable_at(tournament, FORGE_RECALL_TOLERANCE) == tournament.deployable


def test_threshold_decides_is_flagged_only_when_every_outcome_flips(
        run: DiscoveryRunReport) -> None:
    base = dict(run.outcomes)
    assert base
    flipped = replace(run, outcomes=tuple((k, "FALSIFIED" if v != "FALSIFIED" else "SURVIVED")
                                          for k, v in base.items()))
    partial = replace(run, outcomes=tuple(list(run.outcomes)[1:]))
    rows = B._rows_for("alpha", (0.01, 0.05, 0.10), 0.05,
                       {0.01: flipped, 0.05: run, 0.10: partial})
    by_value = {r.value: r for r in rows}
    assert by_value[0.01].flag == "THRESHOLD_DECIDES"
    assert by_value[0.05].flag == "" and by_value[0.05].outcomes_changed == 0
    if len(base) > 1:
        assert by_value[0.10].flag == "" and by_value[0.10].outcomes_changed == 1


def test_oracle_policy_verdict_needs_fewer_units_at_no_worse_accuracy() -> None:
    def cell(policy: SelectionPolicy, units: int, correct: int) -> B.OracleCell:
        return B.OracleCell(policy.value, False, 0, 1, 2, units, ("identified",), correct,
                            B.REPLAY_LABEL)

    cheap = [cell(SelectionPolicy.EIG_PER_COST, 10, 1), cell(SelectionPolicy.RANDOM, 50, 1),
             cell(SelectionPolicy.CHEAPEST, 20, 1)]
    assert B._eig_beats_cheap(cheap)
    worse = [cell(SelectionPolicy.EIG_PER_COST, 10, 0), cell(SelectionPolicy.RANDOM, 50, 1),
             cell(SelectionPolicy.CHEAPEST, 20, 1)]
    assert not B._eig_beats_cheap(worse)
    assert not B._eig_beats_cheap([])                    # nothing ran: never a pass


# -- ablation ------------------------------------------------------------------------------------


def test_ablation_has_one_row_per_flag_with_firings(planted) -> None:  # noqa: ANN001
    rows = B.run_ablation(planted, RunConfig(arm=CorpusArm.PLANTED, seed=3, budget=TINY))
    assert tuple(r.flag for r in rows) == ABLATION_FLAGS
    for row in rows:
        assert row.core_id.startswith("PROM-F") and row.experiment_slug.startswith("ablation-")
        assert row.firings >= 0 and row.outcome_changes >= 0
        assert isinstance(row.verdict, V)
        if row.verdict is not V.DEGENERATE and row.outcome_changes == 0:
            assert row.verdict is V.INERT
    discipline = next(r for r in rows if r.flag == "holdout_discipline")
    assert discipline.outcome_changes > 0              # the discipline changes what is "found"


def test_ablation_verdict_rules() -> None:
    def v(**kw: object) -> V:
        args = {"degenerate": False, "firings": 5, "changes": 2, "d_planted": 0, "d_false": 0,
                "d_recall": None}
        return B._verdict(**{**args, **kw})  # type: ignore[arg-type]

    assert v(degenerate=True, d_planted=1) is V.DEGENERATE
    assert v(changes=0, d_planted=1) is V.INERT
    assert v(d_planted=1, d_false=1) is V.HARMFUL
    assert v(d_recall=-0.1) is V.HARMFUL
    assert v(d_planted=1) is V.JUSTIFIED
    assert v(d_false=-1) is V.JUSTIFIED
    assert v(firings=0, d_planted=1) is V.NOT_YET_JUSTIFIED
    assert v(d_recall=0.0) is V.NOT_YET_JUSTIFIED
    with pytest.raises(ContractError):
        B.ablation_control("no_such_flag", RunConfig(arm=CorpusArm.PLANTED, seed=0))


def test_every_ablation_flag_has_an_isolating_control() -> None:
    base = RunConfig(arm=CorpusArm.PLANTED, seed=0)
    on = B.ablation_base(base)   # ORACLE is default-off; its rows are measured from all-on
    for flag in ABLATION_FLAGS:
        config, knobs, name = B.ablation_control(flag, base)
        assert name and (config != on or knobs != type(knobs)()), flag
    no_analogy = B.ablation_control("analogy", base)[0].generators
    assert no_analogy == tuple(g for g in PROMETHEUS_GENERATORS if g is not GeneratorKind.ANALOGY)


# -- the catalogue -------------------------------------------------------------------------------


def test_catalogue_has_128_honest_rows() -> None:
    assert len(X.CATALOGUE) == X.CATALOGUE_SIZE == 128
    assert X.catalogue_problems() == ()
    rows = {r.experiment_id: r for r in X.CATALOGUE}
    for n in (74, 75, 76):
        row = rows[f"S8X-{n:03d}"]
        assert row.status is X.CatalogueStatus.BLOCKED and "B8-1" in row.reason
    for n in range(81, 129):
        row = rows[f"S8X-{n:03d}"]
        measured = row.status is X.CatalogueStatus.MEASURED_IN_GATE
        assert measured == (n in (114, 119, 125)) and row.deliverable == "AION"
    for n in (8, 44, 45, 46, 47, 49, 55, 57, 58, 63, 66, 68, 77, 78):
        assert rows[f"S8X-{n:03d}"].status is X.CatalogueStatus.NOT_BUILT


def test_catalogue_problems_catch_tampering() -> None:
    first, rest = X.CATALOGUE[0], X.CATALOGUE[1:]
    bad_runner = (replace(first, runner="pocketsec.stage8.nowhere:missing"),) + rest
    assert any("does not resolve" in p for p in X.catalogue_problems(bad_runner))
    no_reason = X.CATALOGUE[:7] + (replace(X.CATALOGUE[7], reason=" "),) + X.CATALOGUE[8:]
    assert any("no reason" in p for p in X.catalogue_problems(no_reason))
    retitled = (replace(first, title="residual field construction, improved"),) + rest
    assert any("not the architecture's" in p for p in X.catalogue_problems(retitled))
    assert any("missing S8X-128" in p for p in X.catalogue_problems(X.CATALOGUE[:-1]))
    duplicated = X.CATALOGUE + (X.CATALOGUE[0],)
    assert any("duplicate S8X-001" in p for p in X.catalogue_problems(duplicated))


# -- the registry and the boundary ---------------------------------------------------------------


def test_runs_never_touch_the_experiment_registry(run: DiscoveryRunReport,
                                                  naive: DiscoveryRunReport,
                                                  registry_before: str | None) -> None:
    assert run.packages and naive.survived                   # the runs really happened
    assert _registry_digest() == registry_before
    for name in MINE:
        tree = ast.parse((LABS / name).read_text(encoding="utf-8"))
        constants = [n.value for n in ast.walk(tree)
                     if isinstance(n, ast.Constant) and isinstance(n.value, str)]
        assert not any("registry.jsonl" in c for c in constants), name


def test_my_modules_never_call_stage6_admit_or_import_stage5() -> None:
    for name in MINE:
        tree = ast.parse((LABS / name).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                assert node.func.attr != "admit", name
            if isinstance(node, ast.ImportFrom):
                assert not (node.module or "").startswith("pocketsec.stage5"), name
                assert "research" not in (node.module or ""), name


# -- endurance -----------------------------------------------------------------------------------


def test_endurance_stores_stay_bounded() -> None:
    counts = {Split.TRAIN: 40, Split.HOLDOUT: 40, Split.REPLICATION: 90, Split.LAB_POOL: 24,
              Split.INDEPENDENT: 24}
    report = run_endurance(cycles=2, seed=7, counts=counts, budget=TINY)
    assert report.cycles == report.cycles_completed == 2 and report.plateau_ok, report.problems
    caps = dict(report.store_caps)
    for name, sizes in report.store_sizes:
        assert len(sizes) == 2 and max(sizes) <= caps[name], name
    assert report.capsules_created == report.capsules_admitted
    if report.rss_start is not None and report.rss_peak is not None:
        assert report.rss_peak > 0
    assert len(report.loadavg) == 3


def test_endurance_reports_a_failed_cycle_instead_of_crashing(monkeypatch) -> None:  # noqa: ANN001
    from pocketsec.stage8.labs import discovery_run as D
    from pocketsec.stage8.ledger.theory import LedgerError

    real, calls = D._execute, []

    def failing(*args, **kwargs):  # noqa: ANN002, ANN003, ANN202
        calls.append(1)
        if len(calls) == 2:
            raise LedgerError("hyp-x has no retained record in this ledger")
        return real(*args, **kwargs)

    monkeypatch.setattr(D, "_execute", failing)
    counts = {Split.TRAIN: 30, Split.HOLDOUT: 30, Split.REPLICATION: 40, Split.LAB_POOL: 16,
              Split.INDEPENDENT: 16}
    report = run_endurance(cycles=3, seed=1, counts=counts, budget=TINY)
    assert not report.plateau_ok and report.cycles == 3 and report.cycles_completed == 1
    assert any("cycle 1: LedgerError" in p for p in report.problems)


def test_directions_are_typed(run: DiscoveryRunReport) -> None:
    assert all(p.direction in (Direction.MALICIOUS, Direction.BENIGN) for p in run.packages)
