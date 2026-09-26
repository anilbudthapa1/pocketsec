"""The Stage 6 gate (spec §4.23, §6): thirteen checks, each able to fail, none writing the ledger.

Spec Rule B: *a check must exercise the mechanism it names*, and a check that cannot fail is
evidence of nothing. So besides asserting the shape of the report, this file builds, for
every check, one non-compliant fixture — a Stage 6 tree with a boundary breach, a learner
that learned nothing, a poison report in which Stage 6 was poisoned, a controller that logs
a probation regression instead of rolling back, an unmeasurable RSS — and asserts the check
reports FAILED on it.

One shared context is built at reduced size (one poison multiplier, one year) because the
full-size context takes minutes; the reduced size changes the figures, never the code path.
``pocketsec-stage6 gate`` runs the full size.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from pocketsec.stage0.gate import GateCheck
from pocketsec.stage6 import gate_construction as construction
from pocketsec.stage6 import gate_measured as measured
from pocketsec.stage6.gate import Stage6GateContext, registry_digest, run_gate
from pocketsec.stage6.labs.endurance import EnduranceReport, StageSixLearner
from pocketsec.stage6.labs.poison_suite import PoisonReport
from pocketsec.stage6.promotion.controller import LearningPromotionController

EXPECTED_IDS = [f"G6.{n}" for n in range(1, 14)]


@pytest.fixture(scope="module")
def ctx() -> Iterator[Stage6GateContext]:
    before = registry_digest()
    context = Stage6GateContext.build(multipliers=(1,), cycles=1)
    yield context
    context.close()
    assert registry_digest() == before, "building the gate context wrote the experiment ledger"


@pytest.fixture(scope="module")
def report(ctx: Stage6GateContext) -> tuple[GateCheck, ...]:
    return run_gate(ctx).checks


def test_the_gate_has_thirteen_checks_in_architecture_order(
    report: tuple[GateCheck, ...],
) -> None:
    assert [check.id for check in report] == EXPECTED_IDS
    assert all(check.detail for check in report)


def test_the_gate_never_writes_the_experiment_registry(ctx: Stage6GateContext) -> None:
    before = registry_digest()
    run_gate(ctx)
    assert registry_digest() == before == ctx.registry_before


def test_ablation_survival_fails_by_construction_on_synthetic_data(
    report: tuple[GateCheck, ...],
) -> None:
    g613 = report[12]
    assert not g613.passed and "synthetic True" in g613.detail


def test_every_check_that_would_be_vacuous_says_so_rather_than_passing(
    report: tuple[GateCheck, ...],
) -> None:
    for check in report:
        if "VACUOUS" in check.detail or "NOT MEASURABLE" in check.detail:
            assert not check.passed, check.id


# --- Rule B: one non-compliant fixture per check ----------------------------------------


def _fresh(ctx: Stage6GateContext) -> Stage6GateContext:
    """The context with a Stage 6 learner that has seen nothing: it learned nothing."""
    empty = StageSixLearner(ctx.compiled.genesis, seed=ctx.seed, name="stage6")
    return dataclasses.replace(ctx, stage6=empty, year_learner=empty)


def _poisoned(ctx: Stage6GateContext, arm: str) -> Stage6GateContext:
    rows = tuple(dataclasses.replace(r, poisoned_promotions=1)
                 if r.arm_id == arm and r.learner == "stage6" else r for r in ctx.poison.rows)
    return dataclasses.replace(ctx, poison=PoisonReport(rows, ctx.poison.arm_verdicts))


def _breach(tmp_path: Path, source: str) -> Path:
    """A Stage 6 tree holding one offending module; the scans read their root at call time."""
    root = tmp_path / "pocketsec" / "stage6"
    (root / "memory").mkdir(parents=True)
    (root / "memory" / "leak.py").write_text(source, encoding="utf-8")
    return root


def _overgrown_year(ctx: Stage6GateContext) -> Stage6GateContext:
    points = list(ctx.year.checkpoints)
    points[-1] = dataclasses.replace(points[-1], store_counts={
        **points[-1].store_counts, "controller": 10**6})
    return dataclasses.replace(ctx, year=dataclasses.replace(ctx.year,
                                                             checkpoints=tuple(points)))


Breaker = Callable[[Stage6GateContext, pytest.MonkeyPatch, Path], Stage6GateContext]


def _g61(ctx: Stage6GateContext, mp: pytest.MonkeyPatch, tmp: Path) -> Stage6GateContext:
    root = _breach(tmp, "def sneak(mind, state):\n    return TrustedMind(state)\n")
    mp.setattr(construction, "POCKETSEC_ROOT", root.parent)
    return ctx


def _g66(ctx: Stage6GateContext, mp: pytest.MonkeyPatch, tmp: Path) -> Stage6GateContext:
    mp.setattr(construction, "require_transition", lambda current, target: None)
    return ctx


def _g67(ctx: Stage6GateContext, mp: pytest.MonkeyPatch, tmp: Path) -> Stage6GateContext:
    root = _breach(tmp, "from dataclasses import dataclass\n@dataclass\nclass Row:\n"
                        "    transaction_id: str\n")
    mp.setattr(construction, "STAGE6_ROOT", root)
    return ctx


def _g68(ctx: Stage6GateContext, mp: pytest.MonkeyPatch, tmp: Path) -> Stage6GateContext:
    mp.setattr(LearningPromotionController, "observe_probation", lambda self, session: None)
    return ctx


def _g610(ctx: Stage6GateContext, mp: pytest.MonkeyPatch, tmp: Path) -> Stage6GateContext:
    mp.setattr(measured, "_measure_in_subprocess", lambda context: None)
    return ctx


def _g611(ctx: Stage6GateContext, mp: pytest.MonkeyPatch, tmp: Path) -> Stage6GateContext:
    root = _breach(tmp, "from pocketsec.stage6.labs import endurance\n")
    mp.setattr(construction, "STAGE6_ROOT", root)
    return ctx


BREAKERS: dict[str, tuple[Callable[[Stage6GateContext], GateCheck], Breaker]] = {
    "G6.1": (construction.check_raw_telemetry_cannot_modify, _g61),
    "G6.2": (measured.check_provenance_and_lineage, lambda c, m, t: _fresh(c)),
    "G6.3": (measured.check_historical_capability_bounds, lambda c, m, t: _fresh(c)),
    "G6.4": (measured.check_repetition_is_not_normality, lambda c, m, t: _poisoned(c, "P1")),
    "G6.5": (measured.check_epoch_adaptation, lambda c, m, t: _poisoned(c, "P5")),
    "G6.6": (construction.check_isolated_evaluation, _g66),
    "G6.7": (construction.check_no_authority_path, _g67),
    "G6.8": (construction.check_rollback_restores, _g68),
    "G6.9": (measured.check_poisoning_coverage, lambda c, m, t: _poisoned(c, "P2b")),
    "G6.10": (measured.check_resource_envelope, _g610),
    "G6.11": (construction.check_retraining_off_endpoint, _g611),
    "G6.12": (measured.check_bounded_growth, lambda c, m, t: _overgrown_year(c)),
    "G6.13": (measured.check_ablation_survival, lambda c, m, t: c),
}


def test_the_breaker_table_covers_every_check() -> None:
    assert list(BREAKERS) == EXPECTED_IDS


@pytest.mark.parametrize("check_id", EXPECTED_IDS)
def test_every_gate_check_can_fail(
    check_id: str, ctx: Stage6GateContext, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    check, breaker = BREAKERS[check_id]
    result = check(breaker(ctx, monkeypatch, tmp_path))
    assert result.id == check_id
    assert not result.passed, f"{check_id} passed on a non-compliant fixture: {result.detail}"


def test_the_year_report_is_an_endurance_report(ctx: Stage6GateContext) -> None:
    """Guards the G6.12 breaker: it must alter the report the check actually reads."""
    assert isinstance(ctx.year, EnduranceReport) and ctx.year.checkpoints


# --- review F4 (correctness and honesty): G6.3 sees the threshold and refuses a vacuous PASS ---


def _g63_pool(tag: str) -> list:
    from pocketsec.stage6 import gate_rig as rig

    pool = [(rig.f1_steps(f"{tag}f1{i}"), "F1", rig.CTX) for i in range(6)]
    pool += [(rig.f3_steps(f"{tag}f3{i}"), "F3", rig.CTX) for i in range(6)]
    pool += [(rig._benign_steps(f"{tag}b{i}"), None, rig.CTX) for i in range(24)]
    return pool


def test_g63_fails_a_threshold_only_promotion_that_blinds_every_family() -> None:
    """F4: recall@FPR re-chooses its own threshold, so raising the THRESHOLD above every
    detector weight showed 0 violations while operating recall fell from 1.0 to 0.0."""
    from pocketsec.stage6 import gate_rig as rig

    state = rig.promote_f1_f3(rig.build_world())
    blind = state.with_changes(threshold=0.91)
    useful, violations = measured.pair_regressions(state, blind, _g63_pool("t"))
    assert useful
    assert any("F1 operating recall 1.0 -> 0.0" in v for v in violations), violations
    assert not any("recall@FPR" in v for v in violations)  # the old metric alone was blind


def test_g63_calls_a_promotion_that_could_not_regress_uninformative() -> None:
    """Honesty F4: the 12-month run's one examined promotion had identical items and a 0.0
    baseline in every family, and G6.3 printed PASS on it."""
    from pocketsec.stage6 import gate_rig as rig

    world = rig.build_world()
    genesis = world.controller.mind.current()
    assert measured.pair_regressions(genesis, genesis, _g63_pool("u")) == (False, [])
    state = rig.promote_f1_f3(world)
    useful, _ = measured.pair_regressions(genesis, state, _g63_pool("u"))
    assert not useful  # genesis detected nothing: a bound over zero cannot be broken
    assert measured.pair_regressions(state, state, _g63_pool("u"))[0] is False


def test_g61_catches_an_observe_that_writes_trusted_state_behind_the_installer(
    ctx: Stage6GateContext, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Review F1 (medium): G6.1 used to pass when observe() wrote raw telemetry straight into
    trusted state, because every digest it watched was the mind's cached one and no probe
    compared the digest across observe(). (d) now recomputes it on every observe()."""
    from pocketsec.stage6.promotion import controller as pc

    real = StageSixLearner.observe

    def leaky(self, capsule, *, sequence):  # noqa: ANN001, ANN202
        real(self, capsule, sequence=sequence)
        mind = self.controller.mind
        forged = mind.current().with_changes(threshold=0.99)
        object.__setattr__(mind, pc.SEALED_NAMES[1], forged)

    monkeypatch.setattr(StageSixLearner, "observe", leaky)
    result = construction.check_raw_telemetry_cannot_modify(ctx)
    assert not result.passed and "(d)" in result.detail, result.detail
