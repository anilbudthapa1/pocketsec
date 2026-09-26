"""The Stage 8 gate itself (integrator): every check runs, none passes on nothing.

The real gate (``pocketsec-stage8 gate``) runs the spec's full sweep and takes tens of minutes;
these tests build ONE reduced context (``GateConfig.small``) and prove the properties that
make the gate's verdict trustworthy rather than re-deriving its numbers:

* a reduced run is never a verdict — every one of its twelve checks FAILS, labelled;
* G8.12 cannot pass on synthetic data — by construction, with the reason in the detail;
* the gate never writes ``experiments/registry.jsonl``;
* every ADR cited under ``pocketsec/stage8`` or in ``docs/stage-8-*.md`` exists (lesson 10);
* the seams the integrator fixed stay fixed (a population member folded out of the ledger is
  evicted and counted, not a crash; an ORACLE prune retires the theory).
"""

from __future__ import annotations

import hashlib
import re

import pytest

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.gate import REPO_ROOT, GateReport
from pocketsec.stage8.ecology.population import HypothesisPopulation
from pocketsec.stage8.gate import (
    REGISTRY_PATH,
    GateConfig,
    Stage8GateContext,
    flood_texts,
    run_gate,
)
from pocketsec.stage8.gate_construction import (
    DECLARED_STRING_FIELDS,
    control_genome,
    free_text_fields,
    malformed_genomes,
)
from pocketsec.stage8.gate_measured import ADR_BLOCK, missing_adrs
from pocketsec.stage8.governor.budget import ResearchBudget, ResearchGovernor
from pocketsec.stage8.ledger.theory import LedgerError, TheoryLedger, TheoryStatus

ADR_TOKEN = re.compile(r"ADR-(\d{4})")


def _digest() -> str | None:
    return hashlib.sha256(REGISTRY_PATH.read_bytes()).hexdigest() if REGISTRY_PATH.exists() \
        else None


@pytest.fixture(scope="module")
def built() -> tuple[Stage8GateContext, str | None, str | None]:
    before = _digest()
    ctx = Stage8GateContext.build(config=GateConfig.small())
    return ctx, before, _digest()


@pytest.fixture(scope="module")
def report(built: tuple[Stage8GateContext, str | None, str | None]) -> GateReport:
    return run_gate(built[0])


def test_the_default_config_is_the_spec_sweep() -> None:
    full = GateConfig()
    assert full.full and not GateConfig.small().full
    assert full.null_seeds == 20 and full.search_seeds == 3 and full.endurance_cycles == 12
    assert dict(full.counts)[next(iter(dict(full.counts)))] > 0
    assert full.sensitivity and len(full.ablation_flags) >= 17


def test_twelve_checks_in_spec_order_and_a_reduced_run_is_never_a_verdict(
        report: GateReport) -> None:
    assert [c.id for c in report.checks] == [f"G8.{n}" for n in range(1, 13)]
    assert not report.passed
    assert all(not c.passed and c.detail.startswith("NOT THE GATE") for c in report.checks)


def test_g8_12_fails_by_construction_on_synthetic_data(report: GateReport) -> None:
    g812 = next(c for c in report.checks if c.id == "G8.12")
    assert "FAILS BY CONSTRUCTION" in g812.detail and "synthetic_data True" in g812.detail


def test_the_injection_falsifier_f14_is_reported_beside_g8_2(report: GateReport) -> None:
    g82 = next(c for c in report.checks if c.id == "G8.2")
    assert "F14 " in g82.detail and "UNMEASURED" not in g82.detail.split("F14", 1)[1][:20]


def test_every_build_step_ran_without_raising(
        built: tuple[Stage8GateContext, str | None, str | None]) -> None:
    ctx = built[0]
    assert ctx.errors == {}, ctx.errors
    assert ctx.main is not None and ctx.main.ledger is not None and ctx.main.lineage is not None
    assert ctx.flood is not None and ctx.flood.budget_exhausted


def test_the_gate_never_writes_the_experiment_registry(
        built: tuple[Stage8GateContext, str | None, str | None]) -> None:
    _, before, after = built
    assert before == after


def test_every_cited_adr_exists() -> None:
    """Lesson 10: Stage 7 cited ADR-0060..0066 77 times and never wrote them."""
    sources = [p for p in (REPO_ROOT / "pocketsec" / "stage8").rglob("*.py")
               if "__pycache__" not in p.parts]
    sources += sorted((REPO_ROOT / "docs").glob("stage-8-*.md"))
    cited = {m for p in sources for m in ADR_TOKEN.findall(p.read_text(encoding="utf-8"))}
    files = {p.name[:4] for p in (REPO_ROOT / "docs" / "adr").glob("[0-9][0-9][0-9][0-9]-*.md")}
    assert cited, "no ADR is cited: the check would pass vacuously"
    assert sorted(cited - files) == []
    assert missing_adrs() == [], "every number in the Stage 8 block 0070-0079 must be written"
    assert len(ADR_BLOCK) == 10


def test_malformed_genomes_are_six_and_all_refused() -> None:
    cases = malformed_genomes()
    assert len(cases) == 6
    for _, build in cases:
        with pytest.raises(ContractError):
            control_genome("SINGLE(SPAWN)", falsifiers=build())


def test_the_state_modules_have_no_undeclared_string_field() -> None:
    assert free_text_fields() == []
    assert "FailureCondition.detail" in DECLARED_STRING_FIELDS


def test_the_flood_is_ten_thousand_deterministic_defensive_texts() -> None:
    texts = flood_texts()
    assert len(texts) == 10_000 and texts == flood_texts()


def test_a_member_folded_out_of_the_ledger_is_evicted_and_counted_not_a_crash() -> None:
    """Integration defect found by run_endurance (cycle 8, 'is not in the ledger').

    Since the fix wave (F5 / S8-RES-1) a folded id keeps a tombstone, so its status still
    answers; the eviction of a member whose record was folded must still not crash."""
    ledger = TheoryLedger(max_theories=2)  # no negative memory: only the tombstone remains
    population = HypothesisPopulation(ledger=ledger, capacity=1,
                                      governor=ResearchGovernor(ResearchBudget()))
    first = control_genome("SINGLE(SPAWN)")
    assert population.add(first)
    ledger.set_status(first.hypothesis_id, TheoryStatus.FOSSILIZED, reason="gate_test")
    filler = control_genome("SINGLE(LOAD)")
    ledger.record_birth(filler)
    ledger.record_birth(control_genome("SINGLE(READ)"))  # the ledger folds the terminal record
    assert ledger.status(first.hypothesis_id) is TheoryStatus.FOSSILIZED  # the tombstone
    with pytest.raises(LedgerError):
        ledger.genome(first.hypothesis_id)                                 # the record is gone
    with pytest.raises(LedgerError):
        ledger.record_birth(first)                                         # never born again
    ledger.set_status(filler.hypothesis_id, TheoryStatus.FOSSILIZED, reason="gate_test")
    population.add(control_genome("SINGLE(WRITE)"))  # born (filler folds); evicts `first`
    stats = population.stats()
    # `first` is FOSSILIZED (tombstone), not PROPOSED: its eviction is counted, nothing is set.
    assert stats["evicted_not_proposed"] == 1 and stats["evicted_folded"] == 0
