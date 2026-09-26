"""Stage 9 runtime package: homeostatic regimes, speciation, hardware-in-loop, the §67
programme and the reproducibility manifest (spec §4.19-§4.20).

Every test is named after the invariant it protects. The splits are tiny (6 sessions) so the
file runs in seconds; no figure here is a detection result.
"""

from __future__ import annotations

import ast
import dataclasses
import math
import random
import re
from pathlib import Path

import pytest

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.repro.seeds import SeedSet
from pocketsec.stage2.encoder.ssir_encoder import NEED_SIGNAL_INDICES
from pocketsec.stage6.resources import WorkMeter
from pocketsec.stage9.chemistry.phenotype import SessionAggregation
from pocketsec.stage9.chemistry.typed_ir import (
    InputSource,
    IRNode,
    IRProgram,
    IRType,
    NodeKind,
    ProgramPhase,
    RegisterSpec,
)
from pocketsec.stage9.genesis import speciation as sp
from pocketsec.stage9.genome.computational import ComputationalGenomeV1, build_genome
from pocketsec.stage9.genome.expressibility import hand_designed_genomes, phi_oracle_genome
from pocketsec.stage9.harness import hardware_in_loop as hil
from pocketsec.stage9.harness import reproducibility as rep
from pocketsec.stage9.labs import one_twenty_experiments as prog
from pocketsec.stage9.labs.splits import CompiledVariant, compile_variant
from pocketsec.stage9.ontogenesis.fitness import EvaluationSuite, FitnessRecord, evaluate
from pocketsec.stage9.runtime import homeostatic as hs
from pocketsec.stage9.spec.mssc import DetectorComparison, MechanismVerdict

REPO = Path(__file__).resolve().parents[1]
MIB = 1024 * 1024
F, INT = IRType.FLOAT, IRType.INT


# --- fixtures ----------------------------------------------------------------------------------


def _node(kind: NodeKind, type_: IRType, **kw: object) -> IRNode:
    return IRNode(kind=kind, type=type_, **kw)  # type: ignore[arg-type]


def _max_register_genome(source: InputSource, index: int = 0) -> ComputationalGenomeV1:
    """r' = MAX(r, x) over one FLOAT input, readout r, aggregation MAX."""
    update = IRProgram(
        phase=ProgramPhase.UPDATE,
        nodes=(
            _node(NodeKind.REG, F, index=0),
            _node(NodeKind.INPUT, F, source=source, index=index),
            _node(NodeKind.APPLY, F, primitive="MAX", args=(0, 1)),
        ),
        outputs=(2,),
    )
    readout = IRProgram(
        phase=ProgramPhase.READOUT, nodes=(_node(NodeKind.REG, F, index=0),), outputs=(0,)
    )
    return build_genome(
        registers=(RegisterSpec(type=F),), update=update, readout=readout,
        aggregation=SessionAggregation.MAX,
    )  # fmt: skip


def _wide_genome() -> ComputationalGenomeV1:
    """18 WU/event: reads relation family, time bucket, object properties and features[73]."""
    nodes = (
        _node(NodeKind.REG, F, index=0),
        _node(NodeKind.INPUT, INT, source=InputSource.RELATION_FAMILY),
        _node(NodeKind.APPLY, F, primitive="RARE", args=(1,)),
        _node(NodeKind.INPUT, INT, source=InputSource.TIME_BUCKET),
        _node(NodeKind.APPLY, F, primitive="RARE", args=(3,)),
        _node(NodeKind.INPUT, F, source=InputSource.FEATURE, index=73),
        _node(NodeKind.INPUT, INT, source=InputSource.OBJECT_PROPERTY_MASK),
        _node(NodeKind.APPLY, F, primitive="POPCOUNT", args=(6,)),
        _node(NodeKind.APPLY, F, primitive="ADD", args=(2, 4)),
        _node(NodeKind.APPLY, F, primitive="ADD", args=(8, 5)),
        _node(NodeKind.APPLY, F, primitive="ADD", args=(9, 7)),
        _node(NodeKind.APPLY, F, primitive="MAX", args=(0, 10)),
    )
    update = IRProgram(phase=ProgramPhase.UPDATE, nodes=nodes, outputs=(11,))
    readout = IRProgram(
        phase=ProgramPhase.READOUT, nodes=(_node(NodeKind.REG, F, index=0),), outputs=(0,)
    )
    return build_genome(
        registers=(RegisterSpec(type=F),), update=update, readout=readout,
        aggregation=SessionAggregation.MAX,
    )  # fmt: skip


def _suite(name: str, seed: int) -> EvaluationSuite:
    clean = compile_variant(count=6, seed=seed)
    attacked = tuple(
        compile_variant(count=6, seed=seed, attack_id=a)
        for a in ("rename_binaries", "sensor_drop_10")
    )
    return EvaluationSuite(name=name, clean=clean, attacked=attacked)


@pytest.fixture(scope="module")
def train() -> EvaluationSuite:
    return _suite("tiny-train", 3)


@pytest.fixture(scope="module")
def heldout() -> EvaluationSuite:
    return _suite("tiny-heldout", 11)


@pytest.fixture(scope="module")
def genomes() -> dict[str, ComputationalGenomeV1]:
    hand = hand_designed_genomes()
    return {"phi": phi_oracle_genome(), "H1": hand["H1"], "H2": hand["H2"], "wide": _wide_genome()}


def _records(
    gs: dict[str, ComputationalGenomeV1], suite: EvaluationSuite
) -> dict[str, FitnessRecord]:
    return {k: evaluate(g, suite, meter=WorkMeter()) for k, g in gs.items()}


@pytest.fixture(scope="module")
def heldout_records(
    genomes: dict[str, ComputationalGenomeV1], heldout: EvaluationSuite
) -> dict[str, FitnessRecord]:
    return _records(genomes, heldout)


@pytest.fixture(scope="module")
def full_catalog(
    genomes: dict[str, ComputationalGenomeV1], heldout_records: dict[str, FitnessRecord]
) -> hs.PhenotypeCatalog:
    """One entry per regime, APs measured on the tiny held-out suite."""

    def entry(regime: hs.Regime, key: str) -> hs.PhenotypeEntry:
        g = genomes[key]
        return hs.PhenotypeEntry(
            regime=regime, genome=g, heldout_worst_case_ap=heldout_records[key].worst_case_ap,
            wu_per_event=g.bounds.update_wu_per_event,
            state_bytes=g.bounds.session_state_bytes_max, coverage=hs.coverage_of(g),
        )  # fmt: skip

    return hs.PhenotypeCatalog(
        entries=(
            entry(hs.Regime.ADAPTIVE, "wide"),
            entry(hs.Regime.REDUCED, "H1"),
            entry(hs.Regime.REFLEX, "H2"),
            entry(hs.Regime.SURVIVAL, "phi"),
        )
    )


def _obs(mib: float, cpu: float = 0.2, queue: int = 0) -> hs.ResourceObservation:
    return hs.ResourceObservation(
        available_bytes=int(mib * MIB), cpu_share=cpu, queue_depth=queue, basis="SIMULATED"
    )


# --- homeostatic runtime -----------------------------------------------------------------------


def test_regime_enum_has_no_research_member_so_research_is_unrepresentable() -> None:
    assert {r.value for r in hs.Regime} == {"ADAPTIVE", "REDUCED", "REFLEX", "SURVIVAL"}
    with pytest.raises(ValueError):
        hs.Regime("RESEARCH")
    assert tuple(hs.Regime) == hs.REGIME_ORDER
    assert dict(hs.REGIME_BUDGET_BYTES) == {
        hs.Regime.ADAPTIVE: 600 * MIB, hs.Regime.REDUCED: 250 * MIB,
        hs.Regime.REFLEX: 100 * MIB, hs.Regime.SURVIVAL: 40 * MIB,
    }  # fmt: skip
    assert [hs.REGIME_WU_CAP[r] for r in hs.REGIME_ORDER] == [64, 16, 8, 4]


def test_controller_never_selects_a_regime_outside_the_four(
    full_catalog: hs.PhenotypeCatalog,
) -> None:
    rng = random.Random(5)
    trace = [
        _obs(rng.uniform(0, 900), rng.uniform(0, 1), rng.randrange(0, 5000)) for _ in range(300)
    ]
    controller = hs.HomeostaticController(full_catalog, hysteresis=True)
    for observation in trace:
        assert controller.step(observation).regime in hs.REGIME_ORDER
    controller.report_failure(hs.Regime.ADAPTIVE)
    assert controller.step(_obs(900)).regime in hs.REGIME_ORDER


def test_degradation_trace_visits_every_regime_and_reports_lost_coverage_and_penalty(
    full_catalog: hs.PhenotypeCatalog,
) -> None:
    trace = hs.degradation_trace()
    assert len(trace) == 140 and {o.basis for o in trace} == {"SIMULATED"}
    assert [trace[i].available_bytes // MIB for i in range(0, 140, 20)] == [
        700, 300, 120, 45, 120, 300, 700,
    ]  # fmt: skip
    controller = hs.HomeostaticController(full_catalog)
    decisions = [controller.step(o) for o in trace]
    assert {d.regime for d in decisions} == set(hs.Regime)
    assert all(controller.transitions_into[r] >= 1 for r in hs.Regime)
    for d in decisions:
        assert d.basis == "SIMULATED"
        if d.regime is not hs.Regime.ADAPTIVE:
            assert isinstance(d.coverage, hs.CoverageVector)
            assert isinstance(d.lost, tuple)
            assert d.uncertainty_penalty is not None
    reflex = next(d for d in decisions if d.regime is hs.Regime.REFLEX)
    # H2 reads only the state-delta mask; the ADAPTIVE genome also reads time and semantics.
    assert set(reflex.lost) == {"temporal", "semantic"}
    adaptive_ap = full_catalog.for_regime(hs.Regime.ADAPTIVE).heldout_worst_case_ap
    reflex_ap = full_catalog.for_regime(hs.Regime.REFLEX).heldout_worst_case_ap
    assert reflex.uncertainty_penalty == pytest.approx(adaptive_ap - reflex_ap)


def test_catalog_none_runs_the_phi_oracle_in_survival_and_it_cannot_be_isolated() -> None:
    controller = hs.HomeostaticController(None)
    decision = controller.step(_obs(900))
    phi = phi_oracle_genome()
    assert decision.regime is hs.Regime.SURVIVAL
    assert decision.genome_digest == phi.digest
    assert decision.phenotype_digest == phi.phenotype().digest
    active = controller.active_entry
    assert active is not None and active.genome.digest == phi.digest
    assert decision.uncertainty_penalty is None  # no ADAPTIVE entry to compare against
    after = controller.report_failure(hs.Regime.SURVIVAL)
    assert after.regime is hs.Regime.SURVIVAL and not after.substituted
    assert controller.counters["unrepairable_failures"] == 1


def test_missing_catalog_entry_falls_to_the_next_lower_regime(
    genomes: dict[str, ComputationalGenomeV1],
) -> None:
    g = genomes["wide"]
    adaptive = hs.PhenotypeEntry(
        regime=hs.Regime.ADAPTIVE, genome=g, heldout_worst_case_ap=0.9,
        wu_per_event=g.bounds.update_wu_per_event, state_bytes=g.bounds.session_state_bytes_max,
        coverage=hs.coverage_of(g),
    )  # fmt: skip
    catalog = hs.PhenotypeCatalog(entries=(adaptive, hs.survival_entry(0.5)))
    controller = hs.HomeostaticController(catalog)
    assert controller.step(_obs(700)).regime is hs.Regime.ADAPTIVE
    fallen = controller.step(_obs(300))  # REDUCED supported, but no REDUCED entry exists
    assert fallen.regime is hs.Regime.SURVIVAL
    assert fallen.uncertainty_penalty == pytest.approx(0.4)


def test_up_moves_wait_for_hysteresis_steps_with_margin_and_down_moves_are_immediate(
    full_catalog: hs.PhenotypeCatalog,
) -> None:
    assert hs.HYSTERESIS_DEFAULT_ENABLED is False
    controller = hs.HomeostaticController(full_catalog, hysteresis=True)
    assert controller.step(_obs(120)).regime is hs.Regime.REFLEX
    # 260 MiB supports REDUCED but not with the 10% margin (275 MiB): it never moves up.
    assert all(controller.step(_obs(260)).regime is hs.Regime.REFLEX for _ in range(10))
    regimes = [controller.step(_obs(300)).regime for _ in range(hs.HYSTERESIS_STEPS)]
    assert regimes[:-1] == [hs.Regime.REFLEX] * (hs.HYSTERESIS_STEPS - 1)
    assert regimes[-1] is hs.Regime.REDUCED
    assert controller.step(_obs(45)).regime is hs.Regime.SURVIVAL  # down on the first step
    plain = hs.HomeostaticController(full_catalog, hysteresis=False)
    plain.step(_obs(120))
    assert plain.step(_obs(260)).regime is hs.Regime.REDUCED


def test_hysteresis_reduces_transitions_on_the_oscillation_trace(
    full_catalog: hs.PhenotypeCatalog,
) -> None:
    trace = hs.synthetic_resource_trace()
    assert len(trace) == 400 and {o.basis for o in trace} == {"SIMULATED"}
    plain = hs.drive(full_catalog, trace, hysteresis=False)
    damped = hs.drive(full_catalog, trace, hysteresis=True)
    t_plain = sum(d.transitioned for d in plain)
    t_damped = sum(d.transitioned for d in damped)
    assert t_plain > 0 and t_damped < t_plain
    verdict = hs.compare_hysteresis(full_catalog)
    assert isinstance(verdict, DetectorComparison)
    assert verdict.mechanism == "pocketsec.stage9.runtime.homeostatic:HYSTERESIS_DEFAULT_ENABLED"
    assert verdict.value == pytest.approx(1.0 - t_damped / t_plain)
    assert verdict.fired > 0
    assert verdict.verdict is not MechanismVerdict.UNMEASURED
    extra = dict(verdict.controls)["extra lower-regime fraction"]
    justified = verdict.value >= 0.5 and extra <= 0.10
    assert (verdict.verdict is MechanismVerdict.JUSTIFIED) == justified


def test_report_failure_substitutes_the_next_lower_validated_phenotype_and_isolates_it(
    full_catalog: hs.PhenotypeCatalog,
) -> None:
    controller = hs.HomeostaticController(full_catalog)
    assert controller.step(_obs(700)).regime is hs.Regime.ADAPTIVE
    repaired = controller.report_failure(hs.Regime.ADAPTIVE)
    assert repaired.substituted and repaired.regime is hs.Regime.REDUCED
    assert repaired.basis == "FAILURE_REPORT"
    reduced = full_catalog.for_regime(hs.Regime.REDUCED)
    assert repaired.genome_digest == reduced.genome.digest
    # Isolated: plenty of memory no longer brings the failed ADAPTIVE phenotype back.
    assert controller.step(_obs(700)).regime is hs.Regime.REDUCED
    controller.report_failure(hs.Regime.REDUCED)
    assert controller.step(_obs(700)).regime is hs.Regime.REFLEX
    assert controller.counters["substitutions"] == 2
    repairs = hs.self_repair_substitutions(full_catalog)
    assert [d.regime for d in repairs] == [
        hs.Regime.REDUCED, hs.Regime.REFLEX, hs.Regime.SURVIVAL, hs.Regime.SURVIVAL,
    ]  # fmt: skip
    # The last row is the Φ-oracle floor itself: nothing validated lies below it.
    assert [d.substituted for d in repairs] == [True, True, True, False]


def test_decision_history_is_bounded_and_evictions_are_counted(
    full_catalog: hs.PhenotypeCatalog,
) -> None:
    controller = hs.HomeostaticController(full_catalog)
    for _ in range(300):
        controller.step(_obs(700))
    history = controller.history()
    assert len(history) == hs.MAX_DECISION_HISTORY == 256
    assert history[0].step == 44 and history[-1].step == 299
    assert controller.counters["history_evictions"] == 44


def test_cpu_and_queue_pressure_demote_the_regime_and_are_counted(
    full_catalog: hs.PhenotypeCatalog,
) -> None:
    trace = hs.pressure_trace()
    controller = hs.HomeostaticController(full_catalog)
    regimes = [controller.step(o).regime for o in trace]
    assert regimes[:10] == [hs.Regime.ADAPTIVE] * 10
    assert set(regimes[10:20]) == {hs.Regime.REDUCED}  # CPU 0.95
    assert set(regimes[20:30]) == {hs.Regime.REDUCED}  # queue 4096
    assert set(regimes[30:40]) == {hs.Regime.REFLEX}  # both
    assert controller.counters["pressure_demotions"] == 30


def test_resource_observation_refuses_invalid_or_unlabelled_input() -> None:
    for bad in (
        {"available_bytes": -1, "cpu_share": 0.1, "queue_depth": 0},
        {"available_bytes": 1, "cpu_share": 1.5, "queue_depth": 0},
        {"available_bytes": 1, "cpu_share": math.nan, "queue_depth": 0},
        {"available_bytes": 1, "cpu_share": 0.1, "queue_depth": -3},
        {"available_bytes": 1, "cpu_share": 0.1, "queue_depth": 0, "basis": "GUESSED"},
    ):
        with pytest.raises(ContractError):
            hs.ResourceObservation(**bad)  # type: ignore[arg-type]
    with pytest.raises(ContractError):
        hs.HomeostaticController(None).step("700 MiB")  # type: ignore[arg-type]


def test_catalog_refuses_entries_over_the_regime_cap_or_with_understated_cost(
    genomes: dict[str, ComputationalGenomeV1],
) -> None:
    wide = genomes["wide"]
    bounds = wide.bounds
    kwargs = {"genome": wide, "heldout_worst_case_ap": 0.5, "coverage": hs.coverage_of(wide),
              "wu_per_event": bounds.update_wu_per_event,
              "state_bytes": bounds.session_state_bytes_max}  # fmt: skip
    with pytest.raises(ContractError, match="caps update WU"):
        hs.PhenotypeEntry(regime=hs.Regime.REFLEX, **kwargs)  # type: ignore[arg-type]
    with pytest.raises(ContractError, match="static update WU"):
        hs.PhenotypeEntry(regime=hs.Regime.ADAPTIVE, **{**kwargs, "wu_per_event": 1})  # type: ignore[arg-type]
    with pytest.raises(ContractError, match="coverage"):
        hs.PhenotypeEntry(
            regime=hs.Regime.ADAPTIVE,
            **{**kwargs, "coverage": hs.coverage_of(genomes["phi"])},  # type: ignore[arg-type]
        )
    with pytest.raises(ContractError, match="one entry per regime"):
        hs.PhenotypeCatalog(entries=(hs.survival_entry(), hs.survival_entry()))


def test_build_catalog_respects_caps_and_takes_the_survival_ap_from_the_phi_oracle(
    genomes: dict[str, ComputationalGenomeV1], heldout_records: dict[str, FitnessRecord]
) -> None:
    pairs = [(genomes[k], heldout_records[k]) for k in genomes]
    catalog = hs.build_catalog(pairs)
    for entry in catalog.entries:
        assert entry.wu_per_event <= hs.REGIME_WU_CAP[entry.regime]
    survival = catalog.for_regime(hs.Regime.SURVIVAL)
    assert survival is not None and survival.genome.digest == genomes["phi"].digest
    assert survival.heldout_worst_case_ap == heldout_records["phi"].worst_case_ap
    with pytest.raises(ContractError, match="not the record"):
        hs.build_catalog([(genomes["H1"], heldout_records["H2"])])
    assert hs.build_catalog([]).for_regime(hs.Regime.SURVIVAL).heldout_worst_case_ap is None


def test_coverage_is_a_static_input_read_statement(
    genomes: dict[str, ComputationalGenomeV1],
) -> None:
    phi = hs.coverage_of(genomes["phi"])
    assert phi.basis == "STATIC_INPUT_READ"
    assert phi.temporal == 0.0 and phi.semantic == 0.0 and phi.process > 0.0
    assert hs.coverage_of(genomes["H2"]) == phi  # the mask and ΔΦ carry the same 9 dimensions
    wide = hs.coverage_of(genomes["wide"])
    assert wide.temporal > 0.0 and wide.semantic > 0.0 and wide.network == 1.0
    assert hs.COVERAGE_DIMENSIONS[1] == "auth"
    with pytest.raises(ContractError):
        dataclasses.replace(phi, basis="MEASURED_RECALL")


def test_homeostatic_module_imports_no_search_law_or_physics_module() -> None:
    source = (REPO / "pocketsec/stage9/runtime/homeostatic.py").read_text(encoding="utf-8")
    banned = ("ontogenesis.search", "genesis", "gaia", "laplace", "chronos", "foundry.promotion",
              "observatory", "renormalization", "symmetry", "geometry", "compression")  # fmt: skip
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.ImportFrom) and node.module:
            assert not any(f"pocketsec.stage9.{b}" in node.module for b in banned), node.module
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert not any(f"pocketsec.stage9.{b}" in alias.name for b in banned)


# --- speciation and morphogenesis --------------------------------------------------------------


def test_niche_table_matches_the_spec_and_unmeasurable_niches_carry_the_reason() -> None:
    measurable = {n.name for n in sp.NICHES if n.measurable}
    assert measurable == {"very_low_memory", "reflex", "sensor_limited", "full"}
    for n in sp.NICHES:
        if not n.measurable:
            assert n.unmeasurable_reason == "single synthetic corpus with no host roles"
    assert sp.niche_by_name("very_low_memory").ram_bytes_max == 4096
    assert sp.niche_by_name("reflex").wu_per_event_max == 4
    assert sp.MORPHOGENESIS_DEFAULT_ENABLED is False
    with pytest.raises(ContractError):
        sp.NicheSpec("x", 1, 1, frozenset(), None, False, "")  # unmeasurable needs a reason


def test_sensor_limited_niche_admits_state_inputs_and_refuses_novelty_and_time(
    genomes: dict[str, ComputationalGenomeV1],
) -> None:
    limited = sp.niche_by_name("sensor_limited")
    assert sp.admissible(genomes["phi"], limited)  # features[73] is the delta_phi group
    assert sp.admissible(genomes["H2"], limited)
    assert not sp.admissible(genomes["wide"], limited)  # TIME_BUCKET, OBJECT_PROPERTY_MASK
    novelty = _max_register_genome(InputSource.FEATURE, NEED_SIGNAL_INDICES["novelty_peak"])
    assert sp.feature_group(NEED_SIGNAL_INDICES["novelty_peak"]) == "novelty_scalars"
    assert not sp.admissible(novelty, limited)
    assert sp.admissible(novelty, sp.niche_by_name("full"))
    assert not sp.admissible(genomes["wide"], sp.niche_by_name("very_low_memory"))  # 9448 B


def test_unmeasurable_niche_yields_an_unmeasured_speciation(
    genomes: dict[str, ComputationalGenomeV1],
    train: EvaluationSuite,
    heldout: EvaluationSuite,
) -> None:
    elites = list(zip(genomes.values(), _records(genomes, train).values(), strict=True))
    results = sp.speciate(elites, heldout)
    assert [s.niche for s in results] == [n.name for n in sp.NICHES]
    for s in results:
        if not sp.niche_by_name(s.niche).measurable:
            assert s.verdict == "UNMEASURED"
            assert s.species_digest is None and s.species_heldout_worst_ap is None
        else:
            assert s.verdict != "UNMEASURED"
            assert s.species_digest in {g.digest for g in genomes.values()}
    comparison = sp.compare_morphogenesis(results)
    assert comparison.mechanism.endswith(":MORPHOGENESIS_DEFAULT_ENABLED")
    assert "desktop" in comparison.detail


def test_universal_inadmissible_species_is_compared_with_the_phi_floor(
    genomes: dict[str, ComputationalGenomeV1],
    train: EvaluationSuite,
    heldout: EvaluationSuite,
) -> None:
    real = _records({"wide": genomes["wide"], "H1": genomes["H1"]}, train)
    # Selection inputs are train records; pin the ranking so the 18-WU genome is universal.
    elites = [
        (genomes["wide"], dataclasses.replace(real["wide"], worst_case_ap=0.99)),
        (genomes["H1"], dataclasses.replace(real["H1"], worst_case_ap=0.50)),
    ]
    reflex = next(s for s in sp.speciate(elites, heldout) if s.niche == "reflex")
    assert not reflex.universal_admissible
    assert reflex.species_digest == genomes["H1"].digest
    assert reflex.reference == "phi-oracle-floor"
    floor = evaluate(phi_oracle_genome(), heldout, meter=WorkMeter()).worst_case_ap
    assert reflex.reference_heldout_worst_ap == floor
    assert reflex.gain == pytest.approx(reflex.species_heldout_worst_ap - floor)
    helps = reflex.gain >= sp.SPECIES_MARGIN and reflex.technique_recall_drops == ()
    assert (reflex.verdict == "SPECIALIZATION_HELPS") == helps


def test_speciation_without_any_admissible_elite_says_so(
    genomes: dict[str, ComputationalGenomeV1], train: EvaluationSuite, heldout: EvaluationSuite
) -> None:
    elites = [(genomes["wide"], _records({"w": genomes["wide"]}, train)["w"])]
    by_niche = {s.niche: s for s in sp.speciate(elites, heldout)}
    assert by_niche["reflex"].verdict == "NO_ADMISSIBLE_SPECIES"
    assert by_niche["full"].verdict == "UNIVERSAL_SUFFICES"
    with pytest.raises(ContractError):
        sp.speciate([], heldout)


def test_morphogenesis_returns_only_prevalidated_genomes_from_the_pool(
    genomes: dict[str, ComputationalGenomeV1], train: EvaluationSuite
) -> None:
    pool = list(zip(genomes.values(), _records(genomes, train).values(), strict=True))
    for n in sp.NICHES:
        chosen = sp.morphogenesis(n, pool)
        if not n.measurable:
            assert chosen is None
        elif chosen is not None:
            assert any(chosen is g for g, _ in pool)  # identity: nothing was synthesised
            assert sp.admissible(chosen, n)
    wide_only = [(genomes["wide"], pool[3][1])]
    assert sp.morphogenesis(sp.niche_by_name("reflex"), wide_only) is None
    with pytest.raises(ContractError):
        sp.morphogenesis(sp.niche_by_name("full"), [(genomes["H1"], pool[0][1])])


def test_compare_morphogenesis_is_unmeasured_without_a_measurable_comparison() -> None:
    unmeasured = sp.Speciation(
        niche="desktop", species_digest=None, universal_digest="sha256:" + "0" * 64,
        species_heldout_worst_ap=None, universal_admissible=True,
        universal_heldout_worst_ap=0.5, verdict="UNMEASURED",
    )  # fmt: skip
    assert sp.compare_morphogenesis([unmeasured]).verdict is MechanismVerdict.UNMEASURED
    with pytest.raises(ContractError):
        dataclasses.replace(unmeasured, verdict="SPECIALIZATION_HELPS", gain=0.001)


# --- hardware-in-loop --------------------------------------------------------------------------


def _meminfo_total() -> int:
    for line in Path("/proc/meminfo").read_text(encoding="ascii").splitlines():
        if line.startswith("MemTotal:"):
            return int(line.split()[1]) * 1024
    raise AssertionError("no MemTotal")


@pytest.mark.skipif(not Path("/proc/meminfo").exists(), reason="Linux /proc required")
def test_hardware_measurement_on_a_tiny_split_is_measured_and_labelled(
    genomes: dict[str, ComputationalGenomeV1], train: EvaluationSuite
) -> None:
    m = hil.measure_phenotype(genomes["phi"], train.clean.dataset)
    assert m.peak_sampled_rss_bytes is not None and m.incremental_rss_bytes is not None
    assert m.incremental_rss_bytes >= 0
    assert m.cpu_seconds_per_event is not None and m.wall_us_per_event is not None
    assert m.phi_oracle_wall_us_per_event is not None and m.ratio_to_phi_oracle is not None
    assert (m.cache_misses, m.wakeups, m.disk_writes) == (None, None, None)
    assert m.event_loss == 0 and m.events == train.clean.dataset.transition_count
    assert m.host_mem_total_bytes == _meminfo_total()
    expected_reference = _meminfo_total() <= 2 * 1024**3 * 1.10
    assert m.is_reference_target is expected_reference
    assert m.is_reference_target is False  # this wave's host has 16 GB (spec M0.13)
    assert m.loadavg_before[0] >= 0.0
    payload = m.to_dict()
    assert payload["unmeasured"] == ["cache_misses", "wakeups", "disk_writes"]
    assert payload["event_loss_basis"] == "REPLAY_NO_LOSS_POSSIBLE"


def test_hardware_measurement_refuses_invented_or_contradictory_figures() -> None:
    base = {
        "genome_digest": "sha256:" + "0" * 64, "host_mem_total_bytes": 16 * 1024**3,
        "is_reference_target": False, "events": 1, "wu_per_event": 3,
        "peak_sampled_rss_bytes": None, "incremental_rss_bytes": None,
        "cpu_seconds_per_event": None, "wall_us_per_event": None,
        "phi_oracle_wall_us_per_event": None, "ratio_to_phi_oracle": None,
    }  # fmt: skip
    hil.HardwareMeasurement(**base)  # type: ignore[arg-type]
    for bad in ({"cache_misses": 12}, {"event_loss": 1}, {"is_reference_target": True},
                {"incremental_rss_bytes": -5}, {"host_mem_total_bytes": None}):  # fmt: skip
        with pytest.raises(ContractError):
            hil.HardwareMeasurement(**{**base, **bad})  # type: ignore[arg-type]


def test_reference_target_verdict_follows_meminfo_and_is_none_when_unreadable(
    tmp_path: Path,
) -> None:
    big, small, broken = tmp_path / "big", tmp_path / "small", tmp_path / "broken"
    big.write_text("MemTotal:       16066696 kB\nMemFree: 1 kB\n", encoding="ascii")
    small.write_text("MemTotal:        2040000 kB\n", encoding="ascii")
    broken.write_text("MemFree: 1 kB\n", encoding="ascii")
    assert hil.host_mem_total_bytes(big) == 16066696 * 1024
    assert hil.host_is_reference_target(big) is False
    assert hil.host_is_reference_target(small) is True
    assert hil.host_is_reference_target(broken) is None
    assert hil.host_is_reference_target(tmp_path / "missing") is None


def test_proxy_correlation_is_spearman_and_none_when_undefined() -> None:
    assert hil.spearman([1, 2, 3, 4], [10, 20, 30, 45]) == pytest.approx(1.0)
    assert hil.spearman([1, 2, 3], [3, 2, 1]) == pytest.approx(-1.0)
    # Average ranks (1, 2.5, 2.5, 4) vs (1, 3, 2, 4): rho = 4.5 / sqrt(4.5 * 5) = 3 / sqrt(10).
    assert hil.spearman([1, 2, 2, 3], [1, 3, 2, 4]) == pytest.approx(3 / math.sqrt(10))
    assert hil.spearman([1, 1, 1], [1, 2, 3]) is None
    assert hil.spearman([1, 2], [1, 2]) is None
    assert hil.proxy_vs_real([]) == hil.ProxyCorrelation(spearman_wu_vs_wall=None, n=0)


def test_tcn_pareto_point_labels_its_cost_analytic_and_refuses_missing_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vector, reason = hil.tcn_pareto_point()
    if vector is None:
        assert reason.startswith("TCN point refused")
    else:
        assert vector.wu_per_event == 3 * 96 * 24 + 3 * 24
        assert "ANALYTIC" in reason and "CLEAN AP" in reason and "count 60" in reason
    monkeypatch.setattr(hil, "load_frontier", lambda: (None, "no evidence file"))
    refused, why = hil.tcn_pareto_point()
    assert refused is None and "no evidence file" in why


# --- the §67 programme -------------------------------------------------------------------------


def test_programme_lists_exactly_124_ids_with_verbatim_titles_and_resolvable_runners() -> None:
    ids = [e.experiment_id for e in prog.S9_EXPERIMENTS]
    assert len(ids) == len(set(ids)) == 124
    assert ids == [f"S9X-{n:03d}" for n in range(1, 125)]
    text = (REPO / "docs/architecture/sources/stage-09-ontogenesis.md").read_text(encoding="utf-8")
    arch = dict(re.findall(r"^(S9X-\d{3})\s+(.*?)\s*$", text, flags=re.MULTILINE))
    assert {e.experiment_id: e.title for e in prog.S9_EXPERIMENTS} == arch
    assert prog.resolve_runners() == ()
    for e in prog.S9_EXPERIMENTS:
        if e.status in (prog.ExperimentStatus.RUN_BY_GATE, prog.ExperimentStatus.RUN_BY_CLI):
            assert ":" in e.runner
        else:
            assert e.runner == "" and e.reason
    blocked_2gb = {"S9X-109", "S9X-110", "S9X-115", "S9X-116", "S9X-117", "S9X-118"}
    for experiment_id in blocked_2gb:
        assert prog.experiment(experiment_id).status is prog.ExperimentStatus.BLOCKED_NO_2GB_TARGET
    assert prog.experiment("S9X-122").status is prog.ExperimentStatus.BLOCKED_STAGE8
    counts = prog.status_counts()
    assert sum(counts.values()) == 124 and set(counts) == {s.value for s in prog.ExperimentStatus}


def test_programme_rows_refuse_a_run_without_runner_or_a_block_without_reason() -> None:
    with pytest.raises(ContractError):
        prog.S9Experiment("S9X-001", "t", prog.ExperimentStatus.RUN_BY_GATE, "", "")
    with pytest.raises(ContractError):
        prog.S9Experiment("S9X-001", "t", prog.ExperimentStatus.NOT_BUILT, "a.b:c", "why")
    with pytest.raises(ContractError):
        prog.S9Experiment("S9X-001", "t", prog.ExperimentStatus.NOT_BUILT, "", "")
    with pytest.raises(ContractError):
        prog.S9Experiment("S9X-1", "t", prog.ExperimentStatus.NOT_BUILT, "", "why")


def test_resolve_runners_reports_a_runner_that_names_missing_code(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ghost = (
        prog.S9Experiment("S9X-001", "x", prog.ExperimentStatus.RUN_BY_CLI,
                          "runtime.homeostatic:no_such_function", ""),
        prog.S9Experiment("S9X-002", "y", prog.ExperimentStatus.RUN_BY_GATE,
                          "no_such.module:run", ""),
    )  # fmt: skip
    monkeypatch.setattr(prog, "S9_EXPERIMENTS", ghost)
    problems = prog.resolve_runners()
    assert len(problems) == 2
    assert problems[0].startswith("S9X-001") and "no attribute" in problems[0]
    assert "does not import" in problems[1]


# --- the reproducibility manifest --------------------------------------------------------------


@pytest.fixture(scope="module")
def tiny_variant() -> CompiledVariant:
    return compile_variant(count=6, seed=3)


@pytest.fixture(scope="module")
def manifest(tiny_variant: CompiledVariant) -> rep.ReproducibilityManifest:
    return rep.build_manifest(
        seeds=SeedSet(7),
        split_digests={repr(tiny_variant.key): tiny_variant.content_digest},
        genome_digests=(phi_oracle_genome().digest,),
        experiment_ids=("PS-S9-20260926-H5-search-0001",),
    )


def test_manifest_digest_verifies_and_the_split_recompiles_byte_identically(
    manifest: rep.ReproducibilityManifest, tiny_variant: CompiledVariant
) -> None:
    assert manifest.content_digest == manifest.compute_digest()
    assert rep.verify_manifest(manifest, recompile=[repr(tiny_variant.key)]) == ()
    assert set(manifest.schema_versions) == {
        "genome", "successor", "compile_candidate", "experience_capsule",
    }  # fmt: skip
    assert manifest.schema_versions["genome"] == "1.0.0"
    assert manifest.corpus_versions == rep.current_corpus_versions()
    assert "pocketsec-stage0 gate" in manifest.stage_gate_entrypoints
    assert manifest.environment["seeds"]["master"] == 7
    assert rep.parse_split_key(repr(tiny_variant.key)) == tiny_variant.key


def test_manifest_digest_changes_when_any_field_changes(
    manifest: rep.ReproducibilityManifest,
) -> None:
    changes = {
        "environment": {**manifest.environment, "python_version": "0.0"},
        "seeds": {**manifest.seeds, "master": 8},
        "corpus_versions": {**manifest.corpus_versions, "ambiguous": "x"},
        "encoder_version": "other",
        "schema_versions": {**manifest.schema_versions, "genome": "9.9.9"},
        "schema_version_basis": {**manifest.schema_version_basis, "genome": "ABSENT:x"},
        "stage_gate_entrypoints": (),
        "split_digests": {},
        "genome_digests": (),
        "experiment_ids": (),
    }
    assert set(changes) == set(manifest.payload())
    for name, value in changes.items():
        tampered = dataclasses.replace(manifest, **{name: value})
        assert tampered.compute_digest() != manifest.content_digest, name
        problems = rep.verify_manifest(tampered)
        assert any("content digest mismatch" in p for p in problems), name


def test_manifest_detects_a_resealed_wrong_split_digest(
    manifest: rep.ReproducibilityManifest, tiny_variant: CompiledVariant
) -> None:
    key = repr(tiny_variant.key)
    forged = dataclasses.replace(manifest, split_digests={key: "sha256:" + "1" * 64})
    resealed = dataclasses.replace(forged, content_digest=forged.compute_digest())
    assert rep.verify_manifest(resealed) == ()  # the digest alone cannot tell ...
    problems = rep.verify_manifest(resealed, recompile=[key])  # ... the recompile can
    assert len(problems) == 1 and "recompiled to" in problems[0]
    assert "not in the manifest" in rep.verify_manifest(resealed, recompile=["SplitKey()"])[0]


def test_build_manifest_refuses_malformed_inputs(tiny_variant: CompiledVariant) -> None:
    good = {repr(tiny_variant.key): tiny_variant.content_digest}
    for kwargs in (
        {"split_digests": {"clean": tiny_variant.content_digest}},
        {"split_digests": {repr(tiny_variant.key): "md5:abc"}},
        {"genome_digests": ("not-a-digest",)},
        {"experiment_ids": ("S9-whatever",)},
    ):
        args = {"seeds": SeedSet(1), "split_digests": good, "genome_digests": (),
                "experiment_ids": (), **kwargs}  # fmt: skip
        with pytest.raises((ContractError, ValueError)):
            rep.build_manifest(**args)  # type: ignore[arg-type]


def test_stage_gate_entrypoints_come_from_project_scripts_for_stages_0_to_9(tmp_path: Path) -> None:
    pyproject = tmp_path / "pyproject.toml"
    pyproject.write_text(
        '[project.scripts]\npocketsec-stage12 = "a:b"\npocketsec-stage9 = "a:b"\n'
        'pocketsec-stage0 = "a:b"\nother = "a:b"\n',
        encoding="utf-8",
    )
    expected = ("pocketsec-stage0 gate", "pocketsec-stage9 gate")
    assert rep.stage_gate_entrypoints(pyproject) == expected
    with pytest.raises(ContractError):
        rep.stage_gate_entrypoints(tmp_path / "absent.toml")
