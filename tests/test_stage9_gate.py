"""The Stage 9 gate (spec §6): its shape, its refusals, and the bookkeeping it depends on.

The gate context is built ONCE per module on :meth:`GateConfig.small` (ambiguous count 12, one
seed, a 0.9M WU budget) so every check's code path runs in well under a minute. A reduced run
is never the gate's verdict: ``pocketsec-stage9 gate`` always uses the default configuration,
and ``register`` refuses a reduced report. Every test is named after the invariant it protects.
"""

from __future__ import annotations

import json
import re
from dataclasses import replace
from pathlib import Path

import pytest

from pocketsec.stage0.gate import REPO_ROOT, GateReport
from pocketsec.stage9 import gate_criteria as criteria
from pocketsec.stage9.cli import main as cli_main
from pocketsec.stage9.gate import (
    EXPERIMENT_ID,
    REGISTRY_PATH,
    build_context,
    registry_digest,
    report_for,
)
from pocketsec.stage9.gate_state import GateConfig, Stage9GateContext
from pocketsec.stage9.labs.one_twenty_experiments import S9_EXPERIMENTS, ExperimentStatus
from pocketsec.stage9.labs.splits import HEADROOM_COUNT, HELDOUT_SEED, SATURATED_COUNT, TRAIN_SEED
from pocketsec.stage9.ontogenesis.search import SEARCH_BUDGET_WU, SEARCH_SEEDS
from pocketsec.stage9.spec.mssc import DetectorComparison, MechanismVerdict

SPEC_IDS = tuple(f"G9.{n}" for n in range(1, 11))
ADR_DIR = REPO_ROOT / "docs" / "adr"
ADR_CITATION = re.compile(r"ADR-(\d{4})")
#: A citation that does NOT resolve is legal only when the text says, right there, that the ADR
#: was never written (docs/stage-9-spec.md reports ADR-0011/0012 as absent; it does not cite
#: them as authority). Anything else unresolved is the Stage 7 failure mode (lesson 10).
_ABSENCE = re.compile(r"(was\s+never\s+written|never\s+written|does\s+not\s+exist)")


@pytest.fixture(scope="module")
def built() -> tuple[Stage9GateContext, GateReport, str | None]:
    before = registry_digest()
    ctx = build_context(GateConfig.small())
    return ctx, report_for(ctx), before


# --- shape ---------------------------------------------------------------------------------------


def test_the_default_config_is_the_spec_gate() -> None:
    config = GateConfig()
    assert (config.count, config.saturated_count) == (HEADROOM_COUNT, SATURATED_COUNT) == (240, 60)
    assert (config.train_seed, config.heldout_seed) == (TRAIN_SEED, HELDOUT_SEED) == (3, 11)
    assert config.budget_wu == SEARCH_BUDGET_WU == 96_000_000
    assert config.seeds == SEARCH_SEEDS == (101, 202, 303)
    assert config.full and not GateConfig.small().full


def test_ten_checks_in_spec_order_and_every_build_step_ran(
        built: tuple[Stage9GateContext, GateReport, str | None]) -> None:
    ctx, report, _ = built
    assert tuple(check.id for check in report.checks) == SPEC_IDS
    assert ctx.errors == {}, ctx.errors
    assert not ctx.refused
    assert [name for name, *_ in ctx.timings] == [
        "splits", "audit", "references", "expressibility", "search", "comparisons", "argus",
        "physics", "laws", "abstractions", "runtime", "hardware", "successor", "isolation"]


def test_the_gate_never_writes_the_experiment_registry(
        built: tuple[Stage9GateContext, GateReport, str | None]) -> None:
    ctx, _, before = built
    assert ctx.registry_before == ctx.registry_after == before == registry_digest()


# --- the criteria that fail by construction ------------------------------------------------------


def test_g9_1_is_blocked_on_stage8_whatever_the_search_found(
        built: tuple[Stage9GateContext, GateReport, str | None]) -> None:
    g91 = built[1].checks[0]
    assert not g91.passed and g91.detail.startswith("BLOCKED_ON_STAGE8")
    assert "pre-conditions" in g91.detail and "Pareto" in g91.detail


def test_g9_4_fails_on_a_host_that_is_not_a_2gb_reference_target(
        built: tuple[Stage9GateContext, GateReport, str | None]) -> None:
    ctx, report, _ = built
    assert ctx.measurements and all(m.is_reference_target is not True for m in ctx.measurements)
    assert not report.checks[3].passed


# --- vacuity and refusal -------------------------------------------------------------------------


def test_zero_objects_fail_as_vacuous() -> None:
    empty = Stage9GateContext(config=GateConfig.small(), registry_before=None)
    for check in (criteria.check_g9_2, criteria.check_g9_4, criteria.check_g9_6,
                  criteria.check_g9_8):
        result = check(empty)
        assert not result.passed and "VACUOUS" in result.detail, result
    assert not criteria.check_g9_3(empty).passed
    assert not criteria.check_g9_5(empty).passed


def test_a_refused_context_fails_every_check_that_reads_it() -> None:
    refused = Stage9GateContext(config=GateConfig.small(), registry_before=None,
                                refused="corpus audit failed: fixture")
    for check in (criteria.check_g9_1, criteria.check_g9_2, criteria.check_g9_3,
                  criteria.check_g9_6, criteria.check_g9_8):
        result = check(refused)
        assert not result.passed and "refused" in result.detail


def test_a_step_error_fails_the_check_that_reads_it_with_the_error(
        built: tuple[Stage9GateContext, GateReport, str | None]) -> None:
    ctx = replace(built[0], errors={"successor": "RuntimeError: fixture"})
    result = criteria.check_g9_6(ctx)
    assert not result.passed and "RuntimeError: fixture" in result.detail


def test_g9_6_refuses_a_rollback_that_cannot_be_told_from_no_rollback(
        built: tuple[Stage9GateContext, GateReport, str | None]) -> None:
    """Pins S9-R5 / S9-FC-05: the rollback parent is the Φ-oracle and one gate successor IS
    the Φ-oracle, so "restored scores == parent scores" held whatever the registry did. G9.6
    must see what the registry held, and must not pass on vacuous rollbacks alone."""
    ctx = built[0]
    assert ctx.successors
    for s in ctx.successors:
        assert s.active_after_install == s.installed_digest != ""
        assert s.active_after_rollback == s.parent_digest == s.restored_digest
    vacuous = [replace(s, installed_digest=s.parent_digest,
                       installed_scores_digest=s.parent_scores_digest) for s in ctx.successors]
    result = criteria.check_g9_6(replace(ctx, successors=vacuous))
    assert not result.passed and "every rollback is vacuous" in result.detail
    elsewhere = "sha256:" + "0" * 64  # the registry did not end on the parent
    stuck = [replace(s, active_after_rollback=elsewhere) for s in ctx.successors]
    result = criteria.check_g9_6(replace(ctx, successors=stuck))
    assert not result.passed and "registry active after install" in result.detail


def test_g9_9_fails_when_an_unjustified_flag_would_ship_on_or_is_unmeasured(
        built: tuple[Stage9GateContext, GateReport, str | None],
        monkeypatch: pytest.MonkeyPatch) -> None:
    ctx = built[0]
    flag = "pocketsec.stage9.runtime.homeostatic:HYSTERESIS_DEFAULT_ENABLED"
    monkeypatch.setattr(criteria, "flag_value", lambda f: f == flag)
    assert "reads True" in criteria.check_g9_9(ctx).detail
    monkeypatch.undo()
    unmeasured = DetectorComparison(flag, "m", None, (), MechanismVerdict.UNMEASURED, 0, "")
    ctx2 = replace(ctx, comparisons={**ctx.comparisons, flag: unmeasured})
    result = criteria.check_g9_9(ctx2)
    assert not result.passed and "HYSTERESIS_DEFAULT_ENABLED: UNMEASURED" in result.detail


def test_every_optional_flag_got_a_verdict_this_run(
        built: tuple[Stage9GateContext, GateReport, str | None]) -> None:
    detail = built[1].checks[8].detail
    assert "no verdict this run" not in detail


# --- bookkeeping the gate depends on -------------------------------------------------------------


def _cited(paths: list[Path]) -> list[tuple[str, str, str]]:
    found = []
    for path in paths:
        text = " ".join(path.read_text(encoding="utf-8").split())
        for match in ADR_CITATION.finditer(text):
            found.append((str(path.relative_to(REPO_ROOT)), match.group(1),
                          text[match.end(): match.end() + 60]))
    return found


def test_every_adr_cited_under_stage9_and_in_its_docs_resolves_to_a_file() -> None:
    """Lesson 10: Stage 7 cited ADR-0060..0066 77 times and never wrote them."""
    paths = sorted((REPO_ROOT / "pocketsec" / "stage9").rglob("*.py"))
    paths += sorted((REPO_ROOT / "docs").glob("stage-9-*.md"))
    existing = {p.name[:4] for p in ADR_DIR.glob("[0-9][0-9][0-9][0-9]-*.md")}
    unresolved = [(where, number) for where, number, after in _cited(paths)
                  if number not in existing and not _ABSENCE.search(after)]
    assert unresolved == []


def test_the_stage9_adr_block_is_written_and_uses_only_its_own_numbers() -> None:
    block = {f"{n:04d}" for n in range(80, 90)}
    present = {p.name[:4] for p in ADR_DIR.glob("008*.md")}
    assert present == block
    for path in ADR_DIR.glob("008*.md"):
        text = path.read_text(encoding="utf-8")
        assert "## Options considered" in text and "measured" in text.lower(), path.name


def test_the_findings_document_ends_with_the_honesty_ledger() -> None:
    text = criteria.FINDINGS_PATH.read_text(encoding="utf-8")
    positions = [text.find(heading) for heading in criteria.FINDINGS_HEADINGS]
    assert -1 not in positions and positions == sorted(positions)


def test_every_run_by_gate_runner_is_really_run_by_the_gate() -> None:
    """A RUN_BY_GATE row whose runner the gate never calls is a catalogue richer than its
    consumer (lesson 3). Two runners are reached through the function the gate calls."""
    indirect = {"genesis.variation:mutate": ("ontogenesis/search.py", "mutate("),
                "foundry.promotion:reproduces_seed": ("foundry/promotion.py", "reproduces_seed(")}
    source = "".join(p.read_text(encoding="utf-8")
                     for p in (REPO_ROOT / "pocketsec" / "stage9").glob("gate*.py"))
    missing = []
    for row in S9_EXPERIMENTS:
        if row.status is not ExperimentStatus.RUN_BY_GATE:
            continue
        runner = row.runner.split(":")[1]
        if row.runner in indirect:
            caller, call = indirect[row.runner]
            text = (REPO_ROOT / "pocketsec" / "stage9" / caller).read_text(encoding="utf-8")
            if call not in text:
                missing.append(row.experiment_id)
        elif f"{runner}(" not in source:
            missing.append(f"{row.experiment_id} {row.runner}")
    assert missing == []


def test_pyproject_exposes_the_stage9_entry_point() -> None:
    text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'pocketsec-stage9 = "pocketsec.stage9.cli:main"' in text


# --- the CLI -------------------------------------------------------------------------------------


def test_register_refuses_a_reduced_report_and_leaves_the_ledger_alone(
        built: tuple[Stage9GateContext, GateReport, str | None], tmp_path: Path) -> None:
    report = built[1]
    saved = tmp_path / "small.json"
    saved.write_text(json.dumps({**report.to_dict(), "gate": "stage-9", "summary": {
        "experiment_id": EXPERIMENT_ID, "full_config": False, "splits": {}}}), encoding="utf-8")
    before = registry_digest()
    assert cli_main(["register", "--report", str(saved)]) == 2
    assert registry_digest() == before
    assert REGISTRY_PATH.is_file()


def test_cli_catalogue_resolves_every_runner() -> None:
    assert cli_main(["catalogue"]) == 0
