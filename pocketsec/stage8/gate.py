"""The Stage 8 acceptance gate (``docs/stage-8-spec.md`` §6), as an executable check.

Twelve criteria, one per bullet of architecture §54 in its order, each evaluated by running
the real subsystems rather than inspecting a document. Like every earlier stage's gate this
is code: ``pocketsec-stage8 gate`` exits non-zero if any criterion fails.

Four things about this gate are worth stating before anyone reads a result off it.

**It is expected to fail, and its failures are Stage 8's findings.** Spec §6.1 said so in
advance: G8.12 fails *by construction* on synthetic data (its PASS additionally requires
``synthetic_data is False``), and realised Stage 6 adoption of a discovery is 0 (B8-1,
ADR-0076). Beyond that, every check that would otherwise pass on an empty result is written
to fail instead: a check over zero objects is VACUOUS, and a vacuous check is reported FAILED
with the reason. A build step that raises is recorded and its checks FAIL with the error.

**The boundary checks run the same checker the tests attack.** G8.9 and G8.10 call
:mod:`pocketsec.stage8.gate_boundary`, whose predicates ``tests/test_stage8_boundary.py``
proves against committed negative fixtures.

**Nothing measured here is a detection result, and no timing is a device figure.** Every
corpus is synthetic, its planted truth shares an author with the engine (lesson 6), every
detection gain is a ``counterfactual_at_boundary`` (Stage 6 adopts no Stage 8 discovery), and
the lab oracle is ground truth by fiat. ``/proc/loadavg`` is recorded beside every timing;
only within-run ratios transfer.

This gate **never** appends to ``experiments/registry.jsonl`` (spec §2.5): nothing here opens
the registry for writing, and G8.12 asserts the ledger is byte-identical before and after the
run. Registration is ``pocketsec-stage8 experiments --register``.
"""

from __future__ import annotations

import hashlib
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from pathlib import Path
from types import MappingProxyType
from typing import Any, TypeVar

from pocketsec.stage0.benchmark.profiles import ProfileReport, check_profile
from pocketsec.stage0.benchmark.resource_metrics import ResourceSampler
from pocketsec.stage0.gate import REPO_ROOT, GateCheck, GateReport
from pocketsec.stage6.capsule.quarantine import QuarantineGateway
from pocketsec.stage6.provenance.ledger import ProvenanceLedger
from pocketsec.stage6.resources import loadavg
from pocketsec.stage8 import gate_construction as construction
from pocketsec.stage8 import gate_evidence as evidence
from pocketsec.stage8 import gate_measured as measured
from pocketsec.stage8.core_ids import ABLATION_FLAGS
from pocketsec.stage8.episode import Split
from pocketsec.stage8.forge.tournament import EndpointFootprint, measure_endpoint_footprint
from pocketsec.stage8.governor.budget import ResearchBudget
from pocketsec.stage8.labs.baselines import (
    NULL_SEEDS,
    SEARCH_SEEDS,
    AblationRow,
    DirectModelReport,
    NullReport,
    OracleComparison,
    PhiBaselineReport,
    ResidualGain,
    SearchComparison,
    SensitivityRow,
    compare_search,
    direct_model_baseline,
    oracle_comparison,
    phi_oracle_baseline,
    residual_gain,
    run_ablation,
    run_null_fdr,
    threshold_sensitivity,
)
from pocketsec.stage8.labs.discovery_corpus import (
    DEFAULT_COUNTS,
    CorpusArm,
    DiscoveryCorpus,
    PreconditionReport,
    build_discovery_corpus,
    corpus_preconditions,
)
from pocketsec.stage8.labs.discovery_run import (
    ENDURANCE_COUNTS,
    DiscoveryRunReport,
    EnduranceReport,
    RunConfig,
    TrapOutcome,
    lab_gateway,
    probe_trap_at_holdout,
    run_discovery,
    run_endurance,
)
from pocketsec.stage8.novelty.prior_art_audit import ABLATION_HYPOTHESIS
from pocketsec.stage8.oracle.planner import SelectionPolicy
from pocketsec.stage8.prometheus.generators import INJECTION_SUITE

__all__ = [
    "ABLATION_HYPOTHESIS",
    "CORPUS_SEED",
    "EXPERIMENT_ID",
    "FLOOD_TEXTS",
    "FLOOD_WORK_UNITS",
    "FORGE_HYPOTHESIS",
    "GATE_SEED",
    "REGISTRY_PATH",
    "STAGE8_HYPOTHESIS",
    "GateConfig",
    "Stage8GateContext",
    "flood_texts",
    "registry_digest",
    "run_gate",
    "summary",
]

#: Spec §2.6 / ADR-0070: no H14 is minted. The gate binds to BASE, FORGE rows to H4 and the
#: ablation rows to H8.
#: ``ABLATION_HYPOTHESIS`` is the novelty audit's own constant, imported rather than restated,
#: so the prior-art entry the audit binds to and the ablation rows' hypothesis cannot drift.
STAGE8_HYPOTHESIS = "BASE"
EXPERIMENT_ID = "PS-S8-20260926-BASE-prometheus-gate-0001"
FORGE_HYPOTHESIS = "H4"
REGISTRY_PATH = REPO_ROOT / "experiments" / "registry.jsonl"
GATE_SEED = 0
CORPUS_SEED = 0
#: G8.11(a), spec §6: a 10 000-text external-proposal flood under a 200 000-unit budget.
FLOOD_TEXTS = 10_000
FLOOD_WORK_UNITS = 200_000

Counts = tuple[tuple[Split, int], ...]


def _counts(mapping: Mapping[Split, int]) -> Counts:
    return tuple(sorted(mapping.items(), key=lambda item: item[0].value))


_DEFAULT_COUNTS = _counts(DEFAULT_COUNTS)
_ENDURANCE_COUNTS = _counts(ENDURANCE_COUNTS)


@dataclass(frozen=True, slots=True)
class GateConfig:
    """Run sizes. The defaults ARE the spec's gate (§4.19, §4.21, §6); ``pocketsec-stage8 gate``
    always uses them. :meth:`small` exists only so tests can exercise every check's code path
    in minutes — its report is never the gate's verdict (every check is forced to FAIL)."""

    counts: Counts = _DEFAULT_COUNTS
    null_seeds: int = NULL_SEEDS
    search_seeds: int = SEARCH_SEEDS
    oracle_seeds: tuple[int, ...] = (GATE_SEED,)
    endurance_cycles: int = 12
    endurance_counts: Counts = _ENDURANCE_COUNTS
    ablation_flags: tuple[str, ...] = ABLATION_FLAGS
    sensitivity: bool = True

    @classmethod
    def small(cls) -> GateConfig:
        small = {Split.TRAIN: 60, Split.HOLDOUT: 60, Split.REPLICATION: 100,
                 Split.LAB_POOL: 40, Split.INDEPENDENT: 30}
        return cls(counts=_counts(small), null_seeds=2, search_seeds=1, oracle_seeds=(0,),
                   endurance_cycles=2, endurance_counts=_counts({**small, Split.REPLICATION: 60}),
                   ablation_flags=("oracle", "doppelganger_screen"), sensitivity=False)

    @property
    def full(self) -> bool:
        return self == GateConfig()

    def count_map(self) -> Mapping[Split, int]:
        return MappingProxyType(dict(self.counts))


Timing = tuple[str, float, tuple[float, float, float]]
_T = TypeVar("_T")


def registry_digest(path: Path = REGISTRY_PATH) -> str | None:
    """sha256 of the real experiment ledger's bytes, or ``None`` when it does not exist."""
    if not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


def flood_texts(count: int = FLOOD_TEXTS) -> tuple[str, ...]:
    """G8.11(a)'s runaway input: the injection suite repeated, plus one valid text per three.

    Deterministic and defensive: every string is a DSL candidate or one of §6.2's injection
    strings; none is anything that could run.
    """
    dims = ("reachability", "trust", "modification")
    return tuple(INJECTION_SUITE[i % len(INJECTION_SUITE)] if i % 3
                 else f"SINGLE(CONNECT+EXTERNAL_ENDPOINT^{dims[(i // 3) % 3]})"
                 for i in range(count))


@dataclass
class Stage8GateContext:
    """One build and one run of everything, so twelve checks do not replay them."""

    config: GateConfig
    registry_before: str | None
    planted: DiscoveryCorpus | None = None
    dropout: DiscoveryCorpus | None = None
    preconditions: dict[str, PreconditionReport] = field(default_factory=dict)
    provenance: ProvenanceLedger | None = None
    offered: tuple[int, int] = (0, 0)          # the lab gateway's "offered" before, after
    main: DiscoveryRunReport | None = None     # PLANTED, lab oracle off, handed to Stage 6
    lab_on: DiscoveryRunReport | None = None   # PLANTED, lab oracle on (lab_oracle_authored)
    injected: DiscoveryRunReport | None = None  # PLANTED + the §6.2 injection suite
    dropout_run: DiscoveryRunReport | None = None
    naive: DiscoveryRunReport | None = None    # PLANTED, NAIVE control (never packaged)
    flood: DiscoveryRunReport | None = None
    trap_probe: TrapOutcome | None = None
    endurance: EnduranceReport | None = None
    phi: PhiBaselineReport | None = None
    gain: ResidualGain | None = None
    search: SearchComparison | None = None
    null: NullReport | None = None
    oracle_cmp: OracleComparison | None = None
    direct: DirectModelReport | None = None
    ablation: tuple[AblationRow, ...] = ()
    sensitivity: tuple[SensitivityRow, ...] = ()
    footprint: EndpointFootprint | None = None
    footprint_profile: ProfileReport | None = None
    errors: dict[str, str] = field(default_factory=dict)
    timings: list[Timing] = field(default_factory=list)

    def registry_now(self) -> str | None:
        return registry_digest()

    def base_config(self) -> RunConfig:
        return RunConfig(arm=CorpusArm.PLANTED, seed=GATE_SEED)

    def reports(self) -> tuple[DiscoveryRunReport, ...]:
        """Every discovery run whose ledger this gate holds (the audited runs)."""
        return tuple(r for r in (self.main, self.lab_on, self.injected, self.dropout_run)
                     if r is not None)

    def step(self, label: str, work: Callable[[], _T]) -> _T | None:
        """Run one build step, recording wall clock beside loadavg (observed, never asserted).

        A step that raises is recorded under ``errors`` and its checks FAIL with the reason;
        the gate still reports every other criterion.
        """
        started = time.perf_counter()
        try:
            return work()
        except Exception as error:
            self.errors[label] = f"{type(error).__name__}: {error}"
            return None
        finally:
            self.timings.append((label, round(time.perf_counter() - started, 3), loadavg()))

    @classmethod
    def build(cls, *, config: GateConfig | None = None) -> Stage8GateContext:
        config = config if config is not None else GateConfig()
        ctx = cls(config=config, registry_before=registry_digest())
        counts = config.count_map()
        ctx.planted = ctx.step("corpus planted", lambda: build_discovery_corpus(
            arm=CorpusArm.PLANTED, seed=CORPUS_SEED, counts=counts))
        ctx.dropout = ctx.step("corpus dropout", lambda: build_discovery_corpus(
            arm=CorpusArm.DROPOUT, seed=CORPUS_SEED, counts=counts))
        _build_preconditions(ctx)
        _build_runs(ctx)
        _build_resources(ctx)
        _build_baselines(ctx)
        return ctx


def _build_preconditions(ctx: Stage8GateContext) -> None:
    """P1-P5 per arm, read before any figure (spec §4.19). NULL is built by the null run."""
    for name, corpus in (("PLANTED", ctx.planted), ("DROPOUT", ctx.dropout)):
        if corpus is None:
            continue
        report = ctx.step(f"preconditions {name}", lambda c=corpus: corpus_preconditions(c))
        if report is not None:
            ctx.preconditions[name] = report
    null = ctx.step("corpus null", lambda: build_discovery_corpus(
        arm=CorpusArm.NULL, seed=CORPUS_SEED, counts=ctx.config.count_map()))
    if null is not None:
        report = ctx.step("preconditions NULL", lambda: corpus_preconditions(null))
        if report is not None:
            ctx.preconditions["NULL"] = report


def _offered(gateway: QuarantineGateway) -> int:
    return int(dict(gateway.stats().counts).get("offered", 0))


def _build_runs(ctx: Stage8GateContext) -> None:
    planted, base = ctx.planted, ctx.base_config()
    if planted is None:
        return
    provenance = ProvenanceLedger()
    gateway = lab_gateway(provenance=provenance)
    before = _offered(gateway)
    ctx.provenance = provenance
    ctx.main = ctx.step("run planted", lambda: run_discovery(planted, base, gateway=gateway))
    ctx.offered = (before, _offered(gateway))
    # ORACLE is default-off (ADR-0078 amendment 2); the runs that test ORACLE's own properties
    # (G8.3(c) sandboxed experiments, the DROPOUT telemetry stop) turn it on explicitly.
    ctx.lab_on = ctx.step("run planted lab-on", lambda: run_discovery(
        planted, replace(base, use_lab_oracle=True, oracle_policy=SelectionPolicy.EIG_PER_COST)))
    ctx.injected = ctx.step("run planted injected", lambda: run_discovery(
        planted, replace(base, external_texts=INJECTION_SUITE)))
    ctx.naive = ctx.step("run planted naive", lambda: run_discovery(
        planted, replace(base, holdout_discipline=False, bonferroni=False)))
    ctx.trap_probe = ctx.step("trap probe", lambda: probe_trap_at_holdout(planted, seed=GATE_SEED))
    dropout = ctx.dropout
    if dropout is not None:
        ctx.dropout_run = ctx.step("run dropout", lambda: run_discovery(
            dropout, RunConfig(arm=CorpusArm.DROPOUT, seed=GATE_SEED,
                               oracle_policy=SelectionPolicy.EIG_PER_COST)))
    ctx.flood = ctx.step("run flood", lambda: run_discovery(planted, replace(
        base, budget=ResearchBudget(work_units=FLOOD_WORK_UNITS), external_texts=flood_texts())))


def _build_resources(ctx: Stage8GateContext) -> None:
    config = ctx.config
    ctx.endurance = ctx.step("endurance", lambda: run_endurance(
        cycles=config.endurance_cycles, seed=GATE_SEED,
        counts=MappingProxyType(dict(config.endurance_counts))))
    main, planted = ctx.main, ctx.planted
    if main is None or planted is None:
        return

    def footprint() -> tuple[EndpointFootprint, ProfileReport]:
        # The outer sampler is the WHOLE gate process (research state included): recorded
        # beside the edge profile, never asserted. The endpoint figure is the inner one.
        with ResourceSampler() as sampler:
            inner = measure_endpoint_footprint(main.packages, planted.episodes(Split.REPLICATION))
        metrics = sampler.result(events_processed=inner.events, startup_seconds=None)
        return inner, check_profile(metrics, "edge")

    measured_pair = ctx.step("endpoint footprint", footprint)
    if measured_pair is not None:
        ctx.footprint, ctx.footprint_profile = measured_pair


def _build_baselines(ctx: Stage8GateContext) -> None:
    planted, config, base = ctx.planted, ctx.config, ctx.base_config()
    if planted is None:
        return
    ctx.phi = ctx.step("phi-oracle baseline", lambda: phi_oracle_baseline(planted))
    phi, main = ctx.phi, ctx.main
    if phi is not None and main is not None:
        ctx.gain = ctx.step("residual gain", lambda: residual_gain(main, phi))
    ctx.direct = ctx.step("direct model", lambda: direct_model_baseline(planted))
    ctx.search = ctx.step("compare search", lambda: compare_search(
        planted, seed=GATE_SEED, seeds=config.search_seeds))
    ctx.null = ctx.step("null fdr", lambda: run_null_fdr(
        seeds=tuple(range(config.null_seeds)), content_seed=CORPUS_SEED,
        counts=config.count_map()))
    ctx.oracle_cmp = ctx.step("oracle comparison", lambda: oracle_comparison(
        planted, seeds=config.oracle_seeds))
    ctx.ablation = ctx.step("ablation", lambda: run_ablation(
        planted, base, flags=config.ablation_flags)) or ()
    if config.sensitivity:
        ctx.sensitivity = ctx.step("threshold sensitivity",
                                   lambda: threshold_sensitivity(planted, base)) or ()


def run_gate(ctx: Stage8GateContext | None = None) -> GateReport:
    """Evaluate all twelve Stage 8 acceptance criteria."""
    ctx = ctx if ctx is not None else Stage8GateContext.build()
    checks = (
        construction.check_g8_1, construction.check_g8_2, construction.check_g8_3,
        evidence.check_g8_4, evidence.check_g8_5, evidence.check_g8_6, evidence.check_g8_7,
        evidence.check_g8_8, evidence.check_g8_9, construction.check_g8_10,
        measured.check_g8_11, measured.check_g8_12,
    )
    results = tuple(_guarded(check, ctx) for check in checks)
    if not ctx.config.full:  # a reduced run exercises code paths; it is never a verdict
        results = tuple(GateCheck(c.id, c.title, False,
                                  f"NOT THE GATE: reduced GateConfig, never a verdict. {c.detail}")
                        for c in results)
    return GateReport(checks=results)


def _guarded(check: Callable[[Stage8GateContext], GateCheck],
             ctx: Stage8GateContext) -> GateCheck:
    """A check that raises FAILS with the error; it never takes the gate down with it."""
    try:
        return check(ctx)
    except Exception as error:
        name = check.__name__.replace("check_g8_", "G8.")
        return GateCheck(name, "check raised", False, f"{type(error).__name__}: {error}")


def summary(ctx: Stage8GateContext) -> dict[str, Any]:
    """Figures the CLI prints beside the checks (errors and timings; never a verdict)."""
    return {"errors": dict(ctx.errors), "timings": [list(t) for t in ctx.timings],
            "loadavg_end": loadavg()}
