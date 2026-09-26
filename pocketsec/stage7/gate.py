"""The Stage 7 acceptance gate (``docs/stage-7-spec.md`` §6), as an executable check.

Eleven criteria, one per bullet of architecture §50 in its order, each evaluated by running
the real subsystems rather than inspecting a document. Like every earlier stage's gate this
is code: ``pocketsec-stage7 gate`` exits non-zero if any criterion fails.

Four things about this gate are worth stating before anyone reads a result off it.

**It is expected to fail, and its failures are Stage 7's findings.** Spec §6.1 said so in
advance: G7.8 is blocked on Stage 6 (B7-1: every foreign capsule scores 0.08 < 0.5, so no
foreign knowledge is ever promoted), G7.4's adaptive-Sybil arm needs an identity authority
that does not exist, and G7.11 fails *by construction* on synthetic data. Beyond that, every
check that would otherwise pass on an empty result is written to fail instead: a check over
zero objects is VACUOUS, and a vacuous check is reported FAILED with the reason.

**The boundary checks run the same checker the tests attack.** G7.1(a), G7.2 and G7.3's
T7 clause call :mod:`pocketsec.stage7.gate_boundary`, whose predicates
``tests/test_stage7_boundary.py`` proves against committed negative fixtures.

**Nothing measured here is a detection result, and no timing is a device figure.** The fleet
is simulated in-process, every corpus is synthetic, every detection gain is a
``counterfactual_at_boundary`` (Stage 6 admits nothing foreign), and the adversary, the
defences and the ground truth share an author. ``/proc/loadavg`` is recorded beside every
timing; only within-run ratios transfer.

This gate **never** appends to ``experiments/registry.jsonl`` (spec §2.5): nothing here opens
the registry for writing, and G7.11 asserts the ledger is byte-identical before and after
the run. Registration is ``pocketsec-stage7 experiments --register``.
"""

from __future__ import annotations

import hashlib
import time
from collections import Counter
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypeVar

from pocketsec.stage0.gate import REPO_ROOT, GateCheck, GateReport
from pocketsec.stage6.resources import loadavg
from pocketsec.stage7 import gate_construction as construction
from pocketsec.stage7 import gate_measured as measured
from pocketsec.stage7.capsule.knowledge_capsule import KnowledgeCapsuleV1, KnowledgeType
from pocketsec.stage7.gate_evidence import (
    FLOOD_IDENTITIES,
    UNANIMOUS_ROUNDS,
    FloodEvidence,
    NonIidEvidence,
    RevocationEvidence,
    RunObservation,
    UnanimousEvidence,
    capsule_samples,
    false_revocation_evidence,
    flood_evidence,
    non_iid_evidence,
    observe_run,
    revocation_evidence,
    unanimous_evidence,
)
from pocketsec.stage7.labs import privacy_attacks
from pocketsec.stage7.labs.byzantine_suite import (
    SHARES,
    SYBIL_COUNTS,
    ByzantineReport,
    run_byzantine_suite,
    siem_oracle,
)
from pocketsec.stage7.labs.campaign_sim import (
    CampaignCaseOutcome,
    CampaignSimReport,
    build_campaign_cases,
    run_campaign_case,
    run_campaign_sim,
)
from pocketsec.stage7.labs.fleet_corpus import (
    FleetCorpus,
    Precondition,
    build_fleet_corpus,
    fleet_preconditions,
    raw_scan_set,
)
from pocketsec.stage7.labs.partition import (
    CHURN_ROUNDS,
    ChurnReport,
    OfflineEquivalence,
    SuiteRun,
    run_churn_endurance,
    run_offline_equivalence,
    run_scale,
    simulate,
)
from pocketsec.stage7.labs.simulated_fleet import (
    SUITE_ROUNDS,
    UNANIMOUS_PEERS,
    AdversaryArm,
    FleetSpec,
    default_receivers,
)

__all__ = [
    "ABLATION_HYPOTHESIS",
    "CORPUS_SEED",
    "EXPERIMENT_ID",
    "GATE_SEED",
    "GateConfig",
    "REGISTRY_PATH",
    "STAGE7_HYPOTHESIS",
    "Stage7GateContext",
    "registry_digest",
    "run_gate",
    "summary",
]

#: Spec §2.6 / ADR-0060: no H13 is minted; the gate binds to BASE, ablation rows to H8.
STAGE7_HYPOTHESIS = "BASE"
EXPERIMENT_ID = "PS-S7-20260926-BASE-orpheus-gate-0001"
ABLATION_HYPOTHESIS = "H8"
REGISTRY_PATH = REPO_ROOT / "experiments" / "registry.jsonl"
GATE_SEED = 0
CORPUS_SEED = 7


@dataclass(frozen=True, slots=True)
class GateConfig:
    """Run sizes. The defaults ARE the spec's gate (§4.23, §6); ``pocketsec-stage7 gate``
    always uses them. :meth:`small` exists only so tests can exercise every check's code
    path in seconds — its report is never the gate's verdict."""

    hosts: int = 24
    episodes_per_host: int = 40
    shares: tuple[float, ...] = SHARES
    sybil_counts: tuple[int, ...] = SYBIL_COUNTS
    rounds: int = SUITE_ROUNDS
    scale_peers: tuple[int, ...] = (10, 100, 1000, 10000)
    flood_identities: int = FLOOD_IDENTITIES
    churn_rounds: int = CHURN_ROUNDS
    campaign_cases_per_arm: int = 8
    privacy_trials: int = 200
    ablations: bool = True
    sensitivity: bool = True

    @classmethod
    def small(cls) -> GateConfig:
        return cls(hosts=8, episodes_per_host=16, shares=(0.0, 0.2), sybil_counts=(1, 8),
                   rounds=4, scale_peers=(10, 1200), flood_identities=64, churn_rounds=30, campaign_cases_per_arm=2,
                   privacy_trials=40, ablations=False, sensitivity=False)

    @property
    def full(self) -> bool:
        return self == GateConfig()

Timing = tuple[str, float, tuple[float, float, float]]
_T = TypeVar("_T")


def registry_digest(path: Path = REGISTRY_PATH) -> str | None:
    """sha256 of the real experiment ledger's bytes, or ``None`` when it does not exist."""
    if not path.is_file():
        return None
    return hashlib.sha256(path.read_bytes()).hexdigest()


@dataclass
class Stage7GateContext:
    """One build and one run of everything, so eleven checks do not replay them."""

    corpus: FleetCorpus
    receivers: tuple[str, ...]
    preconditions: tuple[Precondition, ...]
    registry_before: str | None
    config: GateConfig = field(default_factory=GateConfig)
    unanimous_peers: int = UNANIMOUS_PEERS
    suite: ByzantineReport | None = None
    observations: list[RunObservation] = field(default_factory=list)
    base_fp: dict[tuple[str, float], float | None] = field(default_factory=dict)
    non_iid: NonIidEvidence | None = None
    unanimous: UnanimousEvidence | None = None
    authority_offered: Counter[str] = field(default_factory=Counter)
    capsule_samples: dict[KnowledgeType, KnowledgeCapsuleV1] = field(default_factory=dict)
    offline: list[tuple[str, OfflineEquivalence]] = field(default_factory=list)
    revocation: RevocationEvidence | None = None
    false_revocation: tuple[int, int, int] = (0, 0, 0)
    campaign: CampaignSimReport | None = None
    campaign_outcomes: list[CampaignCaseOutcome] = field(default_factory=list)
    membership: dict[str, privacy_attacks.LeakageMeasurement] = field(default_factory=dict)
    property_attack: dict[str, privacy_attacks.LeakageMeasurement] = field(default_factory=dict)
    dp_curve: tuple[tuple[float | None, float | None, float | None], ...] = ()
    siem: tuple[float | None, int] = (None, 0)
    exported: dict[str, bytes] = field(default_factory=dict)
    canary_hits: tuple[int, tuple[str, ...]] = (0, ())
    flood: FloodEvidence | None = None
    churn: ChurnReport | None = None
    errors: dict[str, str] = field(default_factory=dict)
    timings: list[Timing] = field(default_factory=list)

    @property
    def exported_count(self) -> int:
        return len(self.exported)

    @property
    def scan_size(self) -> int:
        return len(raw_scan_set(self.corpus))

    def registry_now(self) -> str | None:
        return registry_digest()

    def step(self, label: str, work: Callable[[], _T]) -> _T | None:
        """Run one build step, recording wall clock beside loadavg (observed, never asserted).

        A step that raises is recorded under ``errors`` and its checks FAIL with the reason;
        the gate still reports every other criterion.
        """
        started = time.perf_counter()
        try:
            return work()
        except Exception as error:  # noqa: BLE001 - reported verbatim by the failing check
            self.errors[label] = f"{type(error).__name__}: {error}"
            return None
        finally:
            self.timings.append((label, round(time.perf_counter() - started, 3), loadavg()))

    @classmethod
    def build(cls, *, seed: int = GATE_SEED, config: GateConfig | None = None
              ) -> Stage7GateContext:
        config = config if config is not None else GateConfig()
        before = registry_digest()
        corpus = build_fleet_corpus(hosts=config.hosts, episodes_per_host=config.episodes_per_host,
                                    seed=CORPUS_SEED)
        receivers = default_receivers(corpus)
        ctx = cls(corpus=corpus, receivers=receivers, config=config,
                  preconditions=fleet_preconditions(corpus), registry_before=before)
        # Resources first, so the RSS block is not measured on top of the suite's leftovers.
        ctx.flood = ctx.step("resources", lambda: flood_evidence(
            corpus, receivers[0], seed=seed,
            scale=lambda: run_scale(peer_counts=config.scale_peers, seed=seed, corpus=corpus),
            identities=config.flood_identities))
        ctx.churn = ctx.step("churn", lambda: run_churn_endurance(
            corpus, rounds=config.churn_rounds, seed=seed))
        ctx.suite = ctx.step("suite", lambda: _run_suite(ctx, seed))
        _build_boundary(ctx, seed)
        _build_campaign(ctx, seed)
        _build_privacy(ctx, seed)
        return ctx


def _run_suite(ctx: Stage7GateContext, seed: int) -> ByzantineReport:
    """The full D7.9 suite, observing each run once at the Stage 6 boundary."""

    def observe(run: SuiteRun) -> None:
        ctx.observations.append(observe_run(run))
        ctx.base_fp[(run.spec.arm.value, float(run.spec.adversary_share))] = \
            ctx.observations[-1].base_fp
        _collect_exports(ctx, run)
        if run.spec.arm is AdversaryArm.NONE:
            ctx.non_iid = non_iid_evidence(run)

    c = ctx.config
    return run_byzantine_suite(ctx.corpus, shares=c.shares, sybil_counts=c.sybil_counts,
                               rounds=c.rounds, seed=seed, receivers=ctx.receivers,
                               with_stage6=True, ablations=c.ablations,
                               sensitivity=c.sensitivity, observe=observe)


def _collect_exports(ctx: Stage7GateContext, run: SuiteRun) -> None:
    """Every distinct byte string an HONEST host exported in this run, plus local capsules."""
    blobs = [d.data for deliveries in run.traffic for d in deliveries if not d.adversarial]
    blobs += [c.canonical_bytes() for h in run.receivers for c in run.fleet.local_capsules(h)]
    for blob in blobs:
        ctx.exported.setdefault(hashlib.sha256(blob).hexdigest(), blob)


def _build_boundary(ctx: Stage7GateContext, seed: int) -> None:
    corpus, receivers = ctx.corpus, ctx.receivers
    ctx.unanimous = ctx.step("unanimous", lambda: unanimous_evidence(corpus, receivers,
                                                                     seed=seed))
    authority = ctx.step("authority", lambda: simulate(corpus, FleetSpec(
        arm=AdversaryArm.AUTHORITY_INJECTION, rounds=UNANIMOUS_ROUNDS, seed=seed,
        receivers=receivers)))
    ctx.authority_offered = Counter(authority.offered) if authority is not None else Counter()
    ctx.capsule_samples = ctx.step("samples", lambda: capsule_samples(corpus)) or {}
    for host in receivers:
        row = ctx.step(f"offline {host}", lambda h=host: run_offline_equivalence(corpus,
                                                                                 receiver=h))
        if row is not None:
            ctx.offline.append((host, row))
    none_run = ctx.step("revocation run", lambda: simulate(corpus, FleetSpec(
        arm=AdversaryArm.NONE, rounds=ctx.config.rounds, seed=seed, receivers=receivers),
        with_stage6=True))
    if none_run is not None:
        ctx.revocation = ctx.step("revocation", lambda: revocation_evidence(none_run))
    ctx.false_revocation = ctx.step("false revocation", lambda: false_revocation_evidence(
        corpus, receivers, seed=seed)) or (0, 0, 0)


def _build_campaign(ctx: Stage7GateContext, seed: int) -> None:
    cases = ctx.step("campaign cases", lambda: build_campaign_cases(
        seed=seed, per_arm=ctx.config.campaign_cases_per_arm))
    if cases is None:
        ctx.errors.setdefault("campaign", ctx.errors.get("campaign cases", "no cases"))
        return
    ctx.campaign = ctx.step("campaign", lambda: run_campaign_sim(cases))
    ctx.campaign_outcomes = ctx.step("campaign outcomes",
                                     lambda: [run_campaign_case(c) for c in cases]) or []


def _build_privacy(ctx: Stage7GateContext, seed: int) -> None:
    corpus = ctx.corpus

    def attacks() -> None:
        for representation in privacy_attacks.REPRESENTATIONS:
            ctx.membership[representation] = privacy_attacks.membership_inference(
                corpus, representation=representation, trials=ctx.config.privacy_trials, seed=seed)
            ctx.property_attack[representation] = privacy_attacks.property_inference(
                corpus, representation=representation, trials=ctx.config.privacy_trials, seed=seed)
        ctx.dp_curve = privacy_attacks.dp_curve(corpus, seed=seed)
        ctx.siem = siem_oracle(corpus, receiver=ctx.receivers[0])

    ctx.step("privacy", attacks)
    for capsule in ctx.capsule_samples.values():
        blob = capsule.canonical_bytes()
        ctx.exported.setdefault(hashlib.sha256(blob).hexdigest(), blob)
    scan = ctx.step("canary scan", lambda: privacy_attacks.canary_scan(
        corpus, list(ctx.exported.values())))
    ctx.canary_hits = scan if scan is not None else (0, ())
    if scan is None:
        ctx.errors.setdefault("privacy", ctx.errors.get("canary scan", "scan failed"))


def run_gate(ctx: Stage7GateContext | None = None) -> GateReport:
    """Evaluate all eleven Stage 7 acceptance criteria."""
    ctx = ctx if ctx is not None else Stage7GateContext.build()
    checks = (
        construction.check_g7_1, construction.check_g7_2, construction.check_g7_3,
        measured.check_g7_4, measured.check_g7_5, measured.check_g7_6, measured.check_g7_7,
        measured.check_g7_8, construction.check_g7_9, measured.check_g7_10, measured.check_g7_11,
    )
    results = tuple(check(ctx) for check in checks)
    if not ctx.config.full:  # a reduced run exercises code paths; it is never a verdict
        results = tuple(GateCheck(c.id, c.title, False,
                                  f"NOT THE GATE: reduced GateConfig, never a verdict. {c.detail}")
                        for c in results)
    return GateReport(checks=results)


def summary(ctx: Stage7GateContext) -> dict[str, Any]:
    """Figures the CLI prints beside the checks (errors and timings; never a verdict)."""
    return {"errors": dict(ctx.errors), "timings": [list(t) for t in ctx.timings],
            "receivers": list(ctx.receivers), "loadavg_end": loadavg()}
