"""Does PROMETHEUS beat the SIMPLEST search that can EXPRESS the planted function? (lesson 2, 4)

The gate's baseline (3) is exhaustive SINGLE-step search, which cannot express PM1 by
construction (precondition P2), so "PROMETHEUS beats exhaustive" is a construction result. The
isolating controls here hold the discipline fixed and vary only the search:

  PROMETHEUS      ``run_discovery`` defaults (the gate's arm).
  RANDOM_512      ``RandomGenerator`` at its default 512 draws per cluster (the gate's arm).
  RANDOM_3840     the same at 3840 draws per cluster (the largest count the generator accepts).
  ENUM_MIN        SYMBOLIC_ENUMERATOR only; diversity, MDL, evolution, ORACLE, negative
                  memory off; priority SIZE_ONLY; score FIT_ONLY. Screens + vault + Bonferroni
                  kept: the discipline without the PROMETHEUS machinery.
  EXH2_ENGINE     brute force: EVERY mechanism of the <=2-step class over TRAIN's observed
                  step vocabulary (<=1 property bit and <=1 raised bit per predicate), MALICIOUS,
                  fitted on TRAIN; the population cap (256) keeps the top TRAIN F1; then the
                  identical ``_Run`` path: screens -> rank -> one HOLDOUT batch (<= 64) ->
                  identifiability -> one REPLICATION batch -> package. No residuals, generators,
                  ecology or ORACLE.
  EXH2_ENGINE_NODOPP  as EXH2_ENGINE without the doppelganger screen.
  EXH2_BONF_OFFLINE   no machinery: every mechanism of the class tested ONCE on HOLDOUT as ONE
                  Bonferroni family (alpha/N), the three registered HOLDOUT rules, then one
                  REPLICATION batch over the survivors. Outside the vault's 64-registration
                  batch bound, so it is a statistical control, not a Stage 8 configuration.

Scored exactly as the gate scores: ``planted_recovered`` (agreement >= 0.98 with a planted
mechanism on REPLICATION) and ``false_reproduced``; plus the Φ-oracle OR the reproduced
mechanisms on REPLICATION (baseline 1). Work units are the run governor's meter.

Usage: ``PYTHONHASHSEED=0 python benchmarks/stage8/search_controls.py [corpus_seed ...]``
"""

from __future__ import annotations

import functools
import hashlib
import sys
import time
from dataclasses import replace

from _common import loadavg, rates, save, stamp

import pocketsec.stage8.labs.discovery_run as dr
from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage8.ecology.population import ScoreMode
from pocketsec.stage8.episode import Split, fit_counts
from pocketsec.stage8.genome.grammar import (
    GrammarError,
    Mechanism,
    MechanismRelation,
    Modifier,
    StepPredicate,
)
from pocketsec.stage8.genome.hypothesis import (
    Direction,
    GeneratorKind,
    GenomeProvenance,
    ObservationScope,
    genome_for,
)
from pocketsec.stage8.labs.baselines import phi_oracle_baseline, residual_gain
from pocketsec.stage8.labs.discovery_corpus import (
    PLANTED_MECHANISMS,
    CorpusArm,
    build_discovery_corpus,
)
from pocketsec.stage8.oracle.planner import SelectionPolicy  # noqa: F401  (documented default)
from pocketsec.stage8.prometheus.engine import _top_k, oriented_fit
from pocketsec.stage8.prometheus.generators import RandomGenerator
from pocketsec.stage8.residual.priority_field import PriorityMode
from pocketsec.stage8.sandbox.integrity import ALPHA, binomial_upper_tail

POPULATION_CAP = 256


# -- the <=2-step class over TRAIN's observed vocabulary -------------------------------------


def predicate_pool(train) -> list[StepPredicate]:
    sig = {(s.relation, s.object_property_mask, s.state_delta_mask)
           for e in train for s in e.steps}
    pool = set()
    for rel, props, raised in sig:
        pbits = [0] + [1 << i for i in range(props.bit_length()) if props >> i & 1]
        rbits = [0] + [1 << i for i in range(raised.bit_length()) if raised >> i & 1]
        for p in pbits:
            for r in rbits:
                pool.add((rel, p, r))
    return [StepPredicate(rel, p, 0, r) for rel, p, r in sorted(pool)]


def mechanism_class(train, *, max_repeat: int = 8) -> list[Mechanism]:
    preds = predicate_pool(train)
    found: dict[str, Mechanism] = {}

    def add(make):
        try:
            m = make()
        except GrammarError:
            return
        found.setdefault(m.digest(), m)

    for a in preds:
        add(lambda a=a: Mechanism(MechanismRelation.SINGLE, (a,)))
        for k in range(2, max_repeat + 1):
            add(lambda a=a, k=k: Mechanism(MechanismRelation.SINGLE, (a,), Modifier.REPEATED, k))
        for b in preds:
            if a == b:
                continue
            for rel in (MechanismRelation.PRECEDES, MechanismRelation.CO_OCCURS,
                        MechanismRelation.WITHOUT):
                add(lambda a=a, b=b, rel=rel: Mechanism(rel, (a, b)))
    return sorted(found.values(), key=lambda m: m.to_dsl())


# -- helpers ----------------------------------------------------------------------------------


def _digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


def _reproduced_mechanisms(report) -> list[Mechanism]:
    ledger = report.ledger
    return [ledger.genome(h).proposed_mechanism for h in report.reproduced
            if ledger.genome(h).direction is Direction.MALICIOUS]


def summarise(name: str, report, corpus, phi, wall: float, cpu: float, l0, l1) -> dict:
    rep_eps = phi.replication_episodes
    mechs = _reproduced_mechanisms(report)
    labels = [int(e.label) for e in rep_eps]
    phi_fires = [phi.threshold is not None and e.phi_oracle_score() >= phi.threshold
                 for e in rep_eps]
    any_fires = [f or any(m.matches(e.steps) for m in mechs)
                 for f, e in zip(phi_fires, rep_eps, strict=True)]
    gain = residual_gain(report, phi)
    return {
        "arm": name, "seed": report.config.seed,
        "planted_recovered": [f for f, ok in report.planted_recovered if ok],
        "false_reproduced": report.false_reproduced,
        "births": report.births, "challenged_out": report.challenged_out,
        "registered": report.registered, "survived": len(report.survived),
        "reproduced": len(report.reproduced), "packages": len(report.packages),
        "work_units": report.governor.spent, "budget_exhausted": report.budget_exhausted,
        "trap": {"generated": report.trap.generated, "registered": report.trap.registered,
                 "refuted": report.trap.refuted, "refuted_at": report.trap.refuted_at},
        "reproduced_dsl": sorted(m.to_dsl() for m in mechs),
        "package_dsl": [p.mechanism.to_dsl() for p in report.packages],
        "phi_or_packages": {"recall": gain.combined_recall,
                            "fpr": gain.combined_false_positive_rate,
                            "caught_of_phi_missed": [gain.caught_by_packages,
                                                     gain.phi_missed_positives]},
        "phi_or_all_reproduced": rates(any_fires, labels),
        "precondition_problems": report.precondition_problems,
        "wall_s": wall, "cpu_s": cpu, "loadavg": [l0, l1],
    }


def run_arm(name: str, corpus, config, phi, knobs=None) -> dict:
    """A run that raises (the ORACLE posterior defect) is recorded as CRASHED and re-run with
    ORACLE off, labelled ``oracle_off_after_crash``: the crash is a finding, not a skip."""
    l0, w0, c0 = loadavg(), time.perf_counter(), time.process_time()
    try:
        report = dr._execute(corpus, config, gateway=None, knobs=knobs or dr._Knobs(),
                             stores=None)
    except ContractError as exc:
        print(f"  {name:<20} seed {config.seed} CRASHED {type(exc).__name__}: {exc}; "
              f"re-running with oracle_policy=None", flush=True)
        row = run_arm(name + "_ORACLE_OFF_AFTER_CRASH", corpus,
                      replace(config, oracle_policy=None), phi, knobs)
        row["crashed"] = f"{type(exc).__name__}: {exc}"
        return row
    row = summarise(name, report, corpus, phi, time.perf_counter() - w0,
                    time.process_time() - c0, l0, loadavg())
    _print(row)
    return row


def _print(row: dict) -> None:
    print(f"  {row['arm']:<20} seed {row['seed']} recovered {row['planted_recovered']} "
          f"false {row['false_reproduced']} births {row['births']} reg {row['registered']} "
          f"surv {row['survived']} repro {row['reproduced']} pkgs {row['packages']} "
          f"wu {row['work_units']} Φ∪pkg recall {row['phi_or_packages']['recall']} "
          f"fpr {row['phi_or_packages']['fpr']} Φ∪all {row['phi_or_all_reproduced']} "
          f"wall {row['wall_s']:.1f}s cpu {row['cpu_s']:.1f}s load {row['loadavg']}",
          flush=True)


# -- EXH2 through the identical discipline ----------------------------------------------------


def run_exhaustive_engine(name: str, corpus, config, phi, mechanisms) -> dict:
    """``_drive`` with the generation step replaced by brute-force enumeration."""
    l0, w0, c0 = loadavg(), time.perf_counter(), time.process_time()
    run = dr._Run(corpus, config, dr._Knobs(evolve=False), None, None)
    try:
        ranked = run.observe()
        cluster = run.clusters[ranked[0].cluster_id]
        scope = ObservationScope(residual_cluster_ids=(cluster.cluster_id,),
                                 residual_types=cluster.types, episode_ids=())
        genomes = [genome_for(m, direction=Direction.MALICIOUS, scope=scope,
                              provenance=GenomeProvenance(
                                  generator=GeneratorKind.SYMBOLIC_ENUMERATOR,
                                  source_digest=_digest("exhaustive<=2:" + m.to_dsl()),
                                  foreign=False, seed=config.seed))
                   for m in mechanisms]
        meter, fits = run.governor.meter, {}
        before = meter.spent
        for g in genomes:
            counts = fit_counts(lambda e, g=g: g.decides(e, meter=meter), run.train, meter=meter)
            fits[g.hypothesis_id] = oriented_fit(counts, g.direction)
        run.governor.account("exhaustive.fit", meter.spent - before)
        chosen = _top_k(genomes, fits, POPULATION_CAP)
        born_before = set(run.ledger.hypothesis_ids())
        for g in chosen:
            run.ledger.record_birth(g)
            run.stores.population.add(g)
        run.adopt_births(born_before, cluster.cluster_id)
        candidates = run.candidates()
        registered = run.rank(run.run_oracle(run.screen(candidates)))
        survivors = run.run_holdout(registered)
        run.identify(survivors)
        run.package_all(run.reproduce(survivors))
    except dr.WorkBudgetExceeded:
        run.budget_exhausted = True
    report = dr._report(run, time.perf_counter() - w0)
    row = summarise(name, report, corpus, phi, time.perf_counter() - w0,
                    time.process_time() - c0, l0, loadavg())
    row["class_size"] = len(mechanisms)
    row["population_kept"] = len(chosen)
    _print(row)
    return row


# -- EXH2 with full-family Bonferroni, no machinery -------------------------------------------


def _counts(m: Mechanism, episodes):
    matched = tp = pos = 0
    for e in episodes:
        y = int(e.label)
        pos += y
        if m.matches(e.steps):
            matched += 1
            tp += y
    return matched, tp, pos, len(episodes) - pos


def _passes(m: Mechanism, episodes, alpha: float) -> tuple[bool, float]:
    matched, tp, pos, neg = _counts(m, episodes)
    if matched == 0:
        return False, 1.0
    p = binomial_upper_tail(tp, matched, pos / (pos + neg))
    fpr = (matched - tp) / neg if neg else 1.0
    recall = tp / pos if pos else 0.0
    return (p <= alpha and fpr <= 0.01 and recall >= 0.10), p


def _doppelganger_share(m: Mechanism, doppels) -> float:
    return max((sum(m.matches(e.steps) for e in eps) / len(eps) for eps in doppels if eps),
               default=0.0)


def exhaustive_bonferroni(corpus, phi, mechanisms) -> dict:
    """Raw, then with the reproducibility gate's INDEPENDENT FP rule (<= 0.01 per mechanism,
    ``INDEPENDENT_FP_MAX``) and the doppelganger rule (matched share <= 0.05 over 16 benign
    alternatives of each of the 7 families, ``DOPPELGANGER_PER_FAMILY``) applied per mechanism
    after REPLICATION: the two rules the engine applies that raw Bonferroni does not."""
    rows = {}
    raw = _exhaustive_bonferroni(corpus, phi, mechanisms, screened=False)
    rows["raw"] = raw
    rows["screened"] = _exhaustive_bonferroni(corpus, phi, mechanisms, screened=True)
    return rows


def _exhaustive_bonferroni(corpus, phi, mechanisms, *, screened: bool) -> dict:
    from pocketsec.stage8.doppelganger.engine import DoppelgangerFamily
    from pocketsec.stage8.labs.discovery_corpus import CorpusDoppelgangers

    l0, w0, c0 = loadavg(), time.perf_counter(), time.process_time()
    holdout = corpus.episodes(Split.HOLDOUT)
    replication = corpus.episodes(Split.REPLICATION)
    independent = corpus.episodes(Split.INDEPENDENT)
    n = len(mechanisms)
    hold = [m for m in mechanisms if _passes(m, holdout, ALPHA / n)[0]]
    repro = [m for m in hold if _passes(m, replication, ALPHA / max(1, len(hold)))[0]]
    screened_out = {"independent_fp": 0, "doppelganger": 0}
    if screened:
        source = CorpusDoppelgangers()
        doppels = [source.benign_alternatives(f, count=16, seed=0) for f in DoppelgangerFamily]
        kept = []
        for m in repro:
            ind = sum(m.matches(e.steps) for e in independent) / len(independent)
            if ind > 0.01:
                screened_out["independent_fp"] += 1
                continue
            if _doppelganger_share(m, doppels) > 0.05:
                screened_out["doppelganger"] += 1
                continue
            kept.append(m)
        repro = kept
    recovered, false = set(), 0
    for m in repro:
        hits = [f.value for f, pm in PLANTED_MECHANISMS.items()
                if dr.agreement(lambda e, m=m: m.matches(e.steps),
                                lambda e, pm=pm: pm.matches(e.steps), replication)
                >= dr.PLANTED_AGREEMENT_MIN]
        if hits:
            recovered.update(hits)
        else:
            false += 1
    rep_eps = phi.replication_episodes
    labels = [int(e.label) for e in rep_eps]
    phi_fires = [phi.threshold is not None and e.phi_oracle_score() >= phi.threshold
                 for e in rep_eps]
    any_fires = [f or any(m.matches(e.steps) for m in repro)
                 for f, e in zip(phi_fires, rep_eps, strict=True)]
    ind_fp = sum(1 for e in independent if any(m.matches(e.steps) for m in repro))
    trap_digest = corpus.trap_mechanism.digest()
    row = {
        "arm": "EXH2_BONF_OFFLINE" + ("_SCREENED" if screened else ""),
        "screened_out": screened_out, "class_size": n, "holdout_alpha": ALPHA / n,
        "holdout_survivors": len(hold), "replication_reproduced": len(repro),
        "planted_recovered": sorted(recovered), "false_reproduced": false,
        "trap_in_class": any(m.digest() == trap_digest for m in mechanisms),
        "trap_survived_holdout": any(m.digest() == trap_digest for m in hold),
        "phi_or_reproduced": rates(any_fires, labels),
        "independent_false_positives": [ind_fp, len(independent)],
        "reproduced_dsl": sorted(m.to_dsl() for m in repro)[:80],
        "wall_s": time.perf_counter() - w0, "cpu_s": time.process_time() - c0,
        "loadavg": [l0, loadavg()],
    }
    print(f"  {row['arm']:<27} N {n} alpha/N {ALPHA / n:.2e} holdout surv {len(hold)} "
          f"screened out {screened_out} "
          f"repro {len(repro)} recovered {sorted(recovered)} false {false} "
          f"Φ∪repro {row['phi_or_reproduced']} indep FP {ind_fp}/{len(independent)} "
          f"trap survived {row['trap_survived_holdout']} wall {row['wall_s']:.1f}s", flush=True)
    return row


# -- driver -----------------------------------------------------------------------------------


def minimal_config(corpus, seed):
    return dr.RunConfig(arm=corpus.arm, seed=seed,
                        generators=(GeneratorKind.SYMBOLIC_ENUMERATOR,), diversity=False,
                        mdl=False, score_mode=ScoreMode.FIT_ONLY,
                        priority_mode=PriorityMode.SIZE_ONLY, oracle_policy=None,
                        negative_memory=False)


def main(corpus_seeds: list[int], run_seeds: list[int]) -> None:
    out = {"runs": [], "offline": []}
    name = ("search_controls" if corpus_seeds == [0, 1, 2]
            else "search_controls_" + "_".join(map(str, corpus_seeds)))
    for cseed in corpus_seeds:
        stamp(f"corpus seed {cseed}")
        corpus = build_discovery_corpus(arm=CorpusArm.PLANTED, seed=cseed)
        phi = phi_oracle_baseline(corpus)
        mechanisms = mechanism_class(corpus.episodes(Split.TRAIN))
        print(f"  <=2-step class over TRAIN vocabulary: {len(mechanisms)} mechanisms; "
              f"Φ REPLICATION recall {phi.replication_recall} FPR "
              f"{phi.replication_false_positive_rate}", flush=True)
        out["offline"].append({"corpus_seed": cseed,
                               **exhaustive_bonferroni(corpus, phi, mechanisms)})
        seeds = run_seeds if cseed == corpus_seeds[0] else run_seeds[:1]
        for seed in seeds:
            base = dr.RunConfig(arm=CorpusArm.PLANTED, seed=seed)
            rows = [run_arm("PROMETHEUS", corpus, base, phi)]
            rows.append(run_arm("RANDOM_512", corpus,
                                replace(base, generators=(GeneratorKind.RANDOM_BASELINE,)), phi))
            original = dr.RandomGenerator
            dr.RandomGenerator = functools.partial(RandomGenerator, count=3840)
            try:
                rows.append(run_arm("RANDOM_3840", corpus,
                                    replace(base, generators=(GeneratorKind.RANDOM_BASELINE,)),
                                    phi))
            finally:
                dr.RandomGenerator = original
            rows.append(run_arm("ENUM_MIN", corpus, minimal_config(corpus, seed), phi,
                                knobs=dr._Knobs(evolve=False)))
            ex_config = replace(minimal_config(corpus, seed), generators=PROM_GENERATORS)
            rows.append(run_exhaustive_engine("EXH2_ENGINE", corpus, ex_config, phi, mechanisms))
            rows.append(run_exhaustive_engine(
                "EXH2_ENGINE_NODOPP", corpus, replace(ex_config, doppelganger_screen=False),
                phi, mechanisms))
            for row in rows:
                row["corpus_seed"] = cseed
            out["runs"].extend(rows)
            save(name, out)
    stamp("done")
    save(name, out)


PROM_GENERATORS = dr.PROMETHEUS_GENERATORS

if __name__ == "__main__":
    cseeds = [int(a) for a in sys.argv[1:]] or [0, 1, 2]
    main(cseeds, [0, 1, 2])
