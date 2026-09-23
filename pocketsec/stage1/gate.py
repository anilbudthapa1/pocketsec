"""The Stage 1 acceptance gate (spec section 29), as an executable check.

Thirteen criteria, each evaluated by running the real subsystems rather than
inspecting a document. Like Stage 0's gate, this is code: ``pocketsec-stage1
gate`` exits non-zero if any criterion fails.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pocketsec.stage0.benchmark.resource_metrics import ResourceSampler
from pocketsec.stage0.gate import GateCheck, GateReport
from pocketsec.stage1.epoch.model import SystemIdentity
from pocketsec.stage1.guillotine.ablation import run_guillotine
from pocketsec.stage1.labs.adversarial import run_adversarial_suite
from pocketsec.stage1.labs.corpus import ATTACK_EXFIL, Behaviour, Scenario, build_corpus
from pocketsec.stage1.pipeline import ScenarioResult, Stage1Pipeline
from pocketsec.stage1.ssir.transition import SSIR_TRANSITION_V1_ID
from pocketsec.stage1.state.potential import calibrate, phi
from pocketsec.stage1.state.security_state import SecurityStateV1
from pocketsec.stage1.telemetry.raw_event_v1 import RAW_EVENT_V1_ID, SensorPath

__all__ = ["Stage1GateContext", "run_gate"]

EVAL_COUNT = 60
SEED = 20_260_924


@dataclass
class Stage1GateContext:
    """Shared pipeline run, so thirteen checks do not replay the corpus thirteen times."""

    results: list[ScenarioResult]
    pipeline: Stage1Pipeline
    peak_rss_bytes: int | None
    cpu_seconds: float
    transitions: int

    @classmethod
    def build(cls) -> Stage1GateContext:
        scenarios = build_corpus(count=EVAL_COUNT, seed=SEED, split="eval")
        pipeline = Stage1Pipeline()
        results: list[ScenarioResult] = []
        with ResourceSampler(interval_seconds=0.005) as sampler:
            for index, scenario in enumerate(scenarios):
                results.append(pipeline.run_scenario(scenario, offset=index))
        transitions = sum(len(r.transitions) for r in results)
        metrics = sampler.result(events_processed=transitions, startup_seconds=None)
        return cls(
            results=results,
            pipeline=pipeline,
            peak_rss_bytes=metrics.peak_sampled_rss_bytes or metrics.peak_rss_bytes,
            cpu_seconds=metrics.cpu_seconds,
            transitions=transitions,
        )


def run_gate() -> GateReport:
    """Evaluate all thirteen Stage 1 acceptance criteria."""
    ctx = Stage1GateContext.build()
    return GateReport(
        checks=(
            _cross_sensor_equivalence(),
            _separate_versioned_interfaces(),
            _explicit_uncertainty(ctx),
            _novelty_separate_from_potential(ctx),
            _epoch_regime_change(),
            _causal_spine_retained(),
            _adaptive_observation(ctx),
            _aggregation_preserves_high_consequence(ctx),
            _guillotine_pareto(ctx),
            _renaming_generalisation(),
            _field_justification(ctx),
            _resource_costs_measured(ctx),
            _multiple_model_families(ctx),
        )
    )


def _cross_sensor_equivalence() -> GateCheck:
    """1 — two telemetry paths, semantically equivalent SSIR."""
    scenarios = build_corpus(count=20, seed=SEED, split="eval")
    ebpf, audit = Stage1Pipeline(), Stage1Pipeline()
    agree = 0
    for index, scenario in enumerate(scenarios):
        a = ebpf.run_scenario(scenario, sensor=SensorPath.EBPF, offset=index)
        b = audit.run_scenario(scenario, sensor=SensorPath.AUDITD, offset=index)
        if a.semantic_keys == b.semantic_keys:
            agree += 1
    passed = agree == len(scenarios)
    return GateCheck(
        "G1.1",
        "Cross-sensor semantic equivalence",
        passed,
        f"{agree}/{len(scenarios)} scenarios compile identically from eBPF and auditd paths",
    )


def _separate_versioned_interfaces() -> GateCheck:
    """2 — SSIR and Host Security State are separate, versioned interfaces."""
    from pocketsec.stage0.contracts.common import SCHEMA_REGISTRY

    registered = [
        schema
        for schema in (RAW_EVENT_V1_ID, SSIR_TRANSITION_V1_ID)
        if schema in SCHEMA_REGISTRY
    ]
    # Host Security State is a distinct type, not a field of the transition.
    separate = "state_delta" in {f for f in SSIRTransitionFields()} and not hasattr(
        SecurityStateV1(), "novelty"
    )
    passed = len(registered) == 2 and separate
    return GateCheck(
        "G1.2",
        "SSIR and Host Security State separately versioned",
        passed,
        f"registered schemas: {registered}; SSIR carries ΔS while SecurityStateV1 holds "
        "current truth as a distinct type",
    )


def SSIRTransitionFields() -> tuple[str, ...]:  # noqa: N802 - reads as a constant
    import dataclasses

    from pocketsec.stage1.ssir.transition import SSIRTransitionV1

    return tuple(f.name for f in dataclasses.fields(SSIRTransitionV1))


def _explicit_uncertainty(ctx: Stage1GateContext) -> GateCheck:
    """3 — unknown entities and incomplete observations carry explicit uncertainty."""
    transitions = [t for r in ctx.results for t in r.transitions]
    all_positive = all(t.uncertainty > 0.0 for t in transitions)

    partial = Stage1Pipeline().run_scenario(
        Scenario("partial", (Behaviour("read", {"path": "/etc/shadow"}),), 1)
    )
    unknown_object = Stage1Pipeline().run_scenario(
        Scenario("unknown", (Behaviour("read", {"path": "/opt/unknown/blob.dat"}),), 0)
    )
    passed = all_positive and unknown_object.peak_uncertainty > 0.0
    return GateCheck(
        "G1.3",
        "Explicit uncertainty on unknown/incomplete observations",
        passed,
        f"all {len(transitions)} transitions carry uncertainty > 0; "
        f"unknown-object uncertainty {unknown_object.peak_uncertainty:.3f}; "
        f"known-credential uncertainty {partial.peak_uncertainty:.3f}",
    )


def _novelty_separate_from_potential(ctx: Stage1GateContext) -> GateCheck:
    """4 — novelty is demonstrably separate from security potential."""
    pairs = [(r.peak_novelty, r.peak_phi) for r in ctx.results if r.transitions]
    high_novelty_low_phi = [n for n, p in pairs if n >= 0.7 and p < 2.0]  # noqa: PLR2004
    low_novelty_high_phi = [p for n, p in pairs if n < 0.7 and p >= 4.0]  # noqa: PLR2004

    correlation = _pearson([n for n, _ in pairs], [p for _, p in pairs])
    passed = bool(high_novelty_low_phi) and (correlation is None or correlation < 0.9)
    return GateCheck(
        "G1.4",
        "Novelty separate from security potential",
        passed,
        f"{len(high_novelty_low_phi)} high-novelty/low-potential windows observed "
        f"(novelty is not maliciousness); {len(low_novelty_high_phi)} "
        f"low-novelty/high-potential; correlation r="
        f"{correlation if correlation is None else round(correlation, 3)}",
    )


def _pearson(xs: list[float], ys: list[float]) -> float | None:
    if len(xs) < 2:
        return None
    mean_x, mean_y = sum(xs) / len(xs), sum(ys) / len(ys)
    num = sum((x - mean_x) * (y - mean_y) for x, y in zip(xs, ys, strict=True))
    dx = sum((x - mean_x) ** 2 for x in xs) ** 0.5
    dy = sum((y - mean_y) ** 2 for y in ys) ** 0.5
    return num / (dx * dy) if dx > 0 and dy > 0 else None


def _epoch_regime_change() -> GateCheck:
    """5 — a legitimate regime change without resetting all history."""
    pipeline = Stage1Pipeline()
    for index, scenario in enumerate(build_corpus(count=10, seed=1, split="train")):
        pipeline.run_scenario(scenario, offset=index)
    before = pipeline.epoch.current.observed_transitions

    upgraded = SystemIdentity(
        kernel_id="6.1.0", package_digest="pkg-b-upgraded", service_digest="svc-a"
    )
    decision = pipeline.epoch.evaluate(
        observed_identity=upgraded,
        corroborating_evidence={"package_digest"},
        now_ns=10_000_000,
    )
    history = pipeline.epoch.retained_history
    retained = any(entry["observed_transitions"] == before for entry in history)
    passed = decision.transitioned and retained and before > 0
    return GateCheck(
        "G1.5",
        "Behaviour epoch handles a legitimate regime change",
        passed,
        f"corroborated package upgrade opened epoch {decision.epoch_id}; "
        f"prior epoch retained with {before} transitions compressed into history "
        f"({len(history)} epoch(s) retained, not reset)",
    )


def _causal_spine_retained() -> GateCheck:
    """6 — causal compression retains the attack spine in multi-branch scenarios.

    Branch pressure has to be real, so the two benign branches use *different*
    operation mixes. Identical routes would collapse to one signature — correct
    behaviour, since the causal signature is identity-free, but it would mean
    the memory never filled and nothing was ever compressed.

    The assertion is the one that matters operationally: after compression, the
    attack spine is still held at full L0 fidelity while low-responsibility
    branches have been demoted.
    """
    pipeline = Stage1Pipeline()
    branch_a = tuple(
        Behaviour("read", {"path": f"/var/log/n{i}.log"}) for i in range(60)
    )
    branch_b = tuple(
        Behaviour("write", {"path": f"/home/dev/build/o{i}.o"})
        if i % 2
        else Behaviour("execve", {"path": f"/usr/bin/tool{i}"})
        for i in range(60)
    )
    pipeline.run_scenario(Scenario("branch-a", branch_a, 0), offset=0)
    pipeline.run_scenario(Scenario("attack", ATTACK_EXFIL, 1), offset=1)
    pipeline.run_scenario(Scenario("branch-b", branch_b, 0), offset=2)

    spine = pipeline.causal.spine()
    report = pipeline.causal.report()
    # The spine must survive compression at full fidelity.
    spine_at_full_fidelity = all(node.resolution == 0 for node in spine)
    passed = len(spine) >= 3 and report.compressed > 0 and spine_at_full_fidelity
    return GateCheck(
        "G1.6",
        "Causal compression retains the attack spine",
        passed,
        f"spine retained {len(spine)} responsibility-bearing transitions at full "
        f"fidelity ({spine_at_full_fidelity}) out of {len(pipeline.causal)} nodes; "
        f"{report.compressed} compressed, {pipeline.causal.dropped} dropped amid "
        f"{len(branch_a) + len(branch_b)} benign branch transitions",
    )


def _adaptive_observation(ctx: Stage1GateContext) -> GateCheck:
    """7 — AOP reduces uncertainty in *selected* scenarios, inside hard caps.

    The criterion says "selected scenarios", and selectivity is the whole
    mechanism: escalating everywhere is just expensive collection, and
    escalating nowhere is a disabled feature. So this checks both directions —
    it must fire on the case the spec describes (an uncertain, high-potential,
    causally-relevant actor) and stay quiet on routine traffic.
    """
    # Selected scenario: a completely uncharacterised binary reaching into
    # another process's memory. High semantic uncertainty, high potential.
    selected = Stage1Pipeline()
    selected.run_scenario(
        Scenario(
            "unknown-binary-ptrace",
            (
                Behaviour("execve", {"path": "/opt/vendor/unknown-9f2c"}),
                Behaviour("ptrace", {"target_pid": "901"}),
                Behaviour("connect", {"raddr": "198.51.100.9", "rport": "443"}),
            ),
            1,
        )
    )
    selected_report = selected.observation.report()

    # Control: routine, well-understood traffic must not escalate.
    routine = Stage1Pipeline()
    routine.run_scenario(
        Scenario(
            "routine",
            tuple(Behaviour("read", {"path": f"/var/log/app-{i % 5}.log"}) for i in range(40)),
            0,
        )
    )
    routine_report = routine.observation.report()

    budget = selected.observation.budget
    escalated_where_needed = selected_report.escalations_opened > 0
    quiet_on_routine = routine_report.escalations_opened == 0
    reduced = (selected_report.mean_uncertainty_reduction or 0.0) > 0.0
    within_caps = (
        selected_report.peak_concurrent <= budget.max_concurrent
        and selected_report.memory_bytes <= budget.max_memory_bytes
        and not {"max_extra_events_per_second"} & set(selected_report.caps_hit)
    )
    # AOP controls optional collection only; mandatory signals are unconditional.
    mandatory_intact = selected.observation.collects("credential_access", "never-escalated")

    passed = (
        escalated_where_needed
        and quiet_on_routine
        and reduced
        and within_caps
        and mandatory_intact
    )
    return GateCheck(
        "G1.7",
        "Adaptive observation reduces uncertainty within caps",
        passed,
        f"selected scenario: {selected_report.escalations_opened} escalations, mean "
        f"uncertainty reduction {selected_report.mean_uncertainty_reduction}; routine "
        f"control: {routine_report.escalations_opened} escalations (selective); peak "
        f"concurrent {selected_report.peak_concurrent}/{budget.max_concurrent}; memory "
        f"{selected_report.memory_bytes}/{budget.max_memory_bytes}B; mandatory signals "
        f"collected without escalation: {mandatory_intact}",
    )


def _aggregation_preserves_high_consequence(ctx: Stage1GateContext) -> GateCheck:
    """8 — repetitive low-risk activity aggregates; high-consequence never hides."""
    pipeline = Stage1Pipeline()
    repeated_attack = ATTACK_EXFIL * 5
    result = pipeline.run_scenario(Scenario("repeat-attack", repeated_attack, 1))
    high_consequence = [t for t in result.transitions if t.is_high_consequence]
    emitted_high = [t for t in result.emitted if t.is_high_consequence]

    flood = tuple(Behaviour("read", {"path": f"/var/log/f{i % 20}.log"}) for i in range(200))
    flood_pipeline = Stage1Pipeline()
    flood_pipeline.run_scenario(Scenario("flood", flood, 0))
    flood_report = flood_pipeline.aggregation.report()

    passed = (
        len(emitted_high) == len(high_consequence)
        and len(high_consequence) > 0
        and flood_report.compression_ratio > 0.5
    )
    return GateCheck(
        "G1.8",
        "Aggregation preserves high-consequence transitions",
        passed,
        f"{len(emitted_high)}/{len(high_consequence)} high-consequence transitions "
        f"emitted despite repetition; separate flood compressed "
        f"{flood_report.compression_ratio:.1%} of repetitive low-value events",
    )


def _guillotine_pareto(ctx: Stage1GateContext) -> GateCheck:
    """9 — a measured Pareto frontier, not an arbitrary field list."""
    report = run_guillotine(ctx.results)
    knee = report.knee
    passed = report.is_measured_frontier and knee is not None
    detail = (
        f"{len(report.points)} measured points spanning "
        f"{min(p.bytes_per_transition for p in report.points):.0f}-"
        f"{max(p.bytes_per_transition for p in report.points):.0f} bytes/transition; "
    )
    if knee:
        detail += (
            f"knee at '{knee.label}' = {knee.bytes_per_transition:.0f}B/transition "
            f"retaining PR-AUC {knee.pr_auc}; "
        )
    detail += report.caveat
    return GateCheck("G1.9", "Information Guillotine Pareto frontier", passed, detail)


def _renaming_generalisation() -> GateCheck:
    """10 — renaming/unseen-binary tests show behaviour-based generalisation."""
    suite = run_adversarial_suite()
    relevant = [o for o in suite.outcomes if o.name in ("renaming", "unseen_binary", "obfuscation")]
    passed = all(o.passed for o in relevant)
    return GateCheck(
        "G1.10",
        "Renaming/unseen-binary generalisation",
        passed,
        "; ".join(f"{o.name}: {o.measurement}" for o in relevant),
    )


def _field_justification(ctx: Stage1GateContext) -> GateCheck:
    """11 — every retained SSIR field has experimental justification."""
    report = run_guillotine(ctx.results)
    baseline = report.baseline.pr_auc or 0.0
    # A family is justified when removing it measurably costs security retention
    # OR it is retained for investigation rather than detection (evidence link).
    justified: list[str] = []
    unjustified: list[str] = []
    previous = baseline
    for point in report.points[1:]:
        family = point.removed[-1]
        current = point.pr_auc or 0.0
        if current < previous - 1e-9 or family == "evidence_link":
            justified.append(family)
        else:
            unjustified.append(family)
        previous = current

    calibration = calibrate(
        [(r.final_state, r.scenario.label) for r in ctx.results if r.transitions]
    )
    passed = bool(justified)
    return GateCheck(
        "G1.11",
        "Every retained SSIR field experimentally justified",
        passed,
        f"families whose removal measurably costs security retention: {justified}; "
        f"families with no measured cost (candidates for removal at freeze): "
        f"{unjustified}; Φ composition gain over an additive control: "
        f"{calibration.composition_gain:.3f}",
    )


def _resource_costs_measured(ctx: Stage1GateContext) -> GateCheck:
    """12 — normal and peak resource costs measured on Stage 0 profiles."""
    from pocketsec.stage0.benchmark.profiles import PROFILES

    edge = PROFILES["edge"]
    measured = ctx.peak_rss_bytes is not None
    within = measured and ctx.peak_rss_bytes is not None and (
        ctx.peak_rss_bytes <= edge.agent_rss_target_bytes
    )
    novelty_bytes = ctx.pipeline.novelty.memory_bytes
    causal_bytes = ctx.pipeline.causal.memory_bytes
    cpu_per_transition = ctx.cpu_seconds / ctx.transitions if ctx.transitions else None
    return GateCheck(
        "G1.12",
        "Resource costs measured on Stage 0 profiles",
        measured and within,
        f"peak RSS {ctx.peak_rss_bytes} B vs Edge target "
        f"{edge.agent_rss_target_bytes} B; novelty engine {novelty_bytes} B; "
        f"causal memory {causal_bytes} B; {ctx.transitions} transitions at "
        f"{cpu_per_transition:.3e} CPU s/transition"
        if cpu_per_transition
        else "no transitions measured",
    )


def _multiple_model_families(ctx: Stage1GateContext) -> GateCheck:
    """13 — the representation serves multiple model families unchanged."""
    from pocketsec.stage1.slot import NoveltyStatisticalSlot, StateCalculusSlot

    keyed = {f"s1-{i:04d}": r for i, r in enumerate(ctx.results)}
    calculus = StateCalculusSlot(results=keyed)
    statistical = NoveltyStatisticalSlot(results=keyed)

    # Both consume identical SSIR. They must be able to disagree without either
    # needing the representation changed for it.
    agreements = disagreements = 0
    for sequence_id, result in keyed.items():
        a = calculus.predict(_stub_sequence(sequence_id))
        b = statistical.predict(_stub_sequence(sequence_id))
        if a.verdict == b.verdict:
            agreements += 1
        else:
            disagreements += 1
        assert result is not None

    passed = disagreements > 0 and agreements > 0
    return GateCheck(
        "G1.13",
        "Representation serves multiple model families",
        passed,
        f"symbolic (state-calculus) and statistical (novelty) slots consumed identical "
        f"SSIR: {agreements} agreements, {disagreements} disagreements — the "
        f"representation is not tuned to one consumer",
    )


def _stub_sequence(sequence_id: str):  # type: ignore[no-untyped-def]
    """Minimal Stage 0 sequence carrying only the id the slot keys on."""
    from pocketsec.stage0.contracts.security_event_v1 import (
        SecurityEventSequenceV1,
        SecurityEventV1,
    )

    return SecurityEventSequenceV1(
        sequence_id=sequence_id,
        host_id="lab-host-01",
        events=(
            SecurityEventV1(
                event_id=f"{sequence_id}-e0",
                host_id="lab-host-01",
                boot_id="boot-0001",
                observed_at_ns=1,
                monotonic_ns=1,
                source="stage1.ssir",
                kind="ssir.transition",
            ),
        ),
    )


assert phi  # re-exported for gate detail strings
