"""The Stage 7 gate itself (integrator): every check runs, none passes on nothing.

The real gate (``pocketsec-stage7 gate``) runs the spec's full sweep and takes many minutes;
these tests build ONE reduced context (``GateConfig.small``) and prove the properties that
make the gate's verdict trustworthy rather than re-deriving its numbers:

* a reduced run is never a verdict — every one of its checks FAILS, labelled;
* a check over zero objects is VACUOUS and FAILS (G7.1, G7.8, G7.9);
* G7.8 cannot pass while Stage 6 admits no foreign capsule, and G7.11 cannot pass on
  synthetic data — both by construction, both with the reason in the detail;
* the wire-key fuzz is live: a parser that let an authority key through is caught;
* the gate never writes ``experiments/registry.jsonl``.
"""

from __future__ import annotations

import dataclasses
import hashlib

import pytest

from pocketsec.stage0.gate import GateReport
from pocketsec.stage7 import gate_construction, gate_measured
from pocketsec.stage7.capsule.knowledge_capsule import KnowledgeCapsuleV1
from pocketsec.stage7.gate import (
    REGISTRY_PATH,
    GateConfig,
    Stage7GateContext,
    registry_digest,
    run_gate,
)
from pocketsec.stage7.labs.fleet_corpus import build_fleet_corpus


def _digest() -> str | None:
    return hashlib.sha256(REGISTRY_PATH.read_bytes()).hexdigest() if REGISTRY_PATH.exists() else None


@pytest.fixture(scope="module")
def built() -> tuple[Stage7GateContext, str | None, str | None]:
    before = _digest()
    ctx = Stage7GateContext.build(config=GateConfig.small())
    return ctx, before, _digest()


@pytest.fixture(scope="module")
def report(built: tuple[Stage7GateContext, str | None, str | None]) -> GateReport:
    return run_gate(built[0])


def test_the_default_config_is_the_spec_sweep() -> None:
    full = GateConfig()
    assert full.full and not GateConfig.small().full
    assert full.hosts == 24 and full.rounds == 12 and full.flood_identities == 1000
    assert full.scale_peers[-1] == 10_000 and full.ablations and full.sensitivity


def test_eleven_checks_in_spec_order_and_a_reduced_run_is_never_a_verdict(
        report: GateReport) -> None:
    assert [c.id for c in report.checks] == [f"G7.{n}" for n in range(1, 12)]
    assert not report.passed
    assert all(not c.passed and c.detail.startswith("NOT THE GATE") for c in report.checks)


def test_every_build_step_ran(built: tuple[Stage7GateContext, str | None, str | None]) -> None:
    ctx = built[0]
    assert ctx.errors == {}
    assert ctx.suite is not None and ctx.observations and ctx.unanimous is not None
    assert ctx.flood is not None and ctx.churn is not None and ctx.campaign is not None
    assert all(len(t[2]) == 3 for t in ctx.timings)  # loadavg beside every timing


def test_the_gate_never_writes_the_registry(
        built: tuple[Stage7GateContext, str | None, str | None]) -> None:
    ctx, before, after = built
    assert before == after == ctx.registry_before == registry_digest()


def test_boundary_evidence_holds_on_the_reduced_run(
        built: tuple[Stage7GateContext, str | None, str | None]) -> None:
    ctx = built[0]
    unanimous = ctx.unanimous
    assert unanimous is not None
    sent, held = dict(unanimous.sent), dict(unanimous.held)
    assert set(sent) >= {"revoke", "contest", "authority", "support_fp"}
    assert sent == held and unanimous.min_senders >= 64
    assert unanimous.revocations_accepted == 0 and unanimous.local_intact == unanimous.receivers
    assert sum(o.created for o in ctx.observations) == sum(o.gateway_offered
                                                           for o in ctx.observations) > 0


def test_a_leaking_parser_is_caught_by_the_wire_fuzz(
        built: tuple[Stage7GateContext, str | None, str | None],
        monkeypatch: pytest.MonkeyPatch) -> None:
    samples = list(built[0].capsule_samples.values())
    injections, refused, controls, leaks = gate_construction.wire_key_fuzz(samples)
    assert injections == refused > 0 and controls == len(samples) and leaks == []
    real = KnowledgeCapsuleV1.from_dict.__func__  # type: ignore[attr-defined]

    def lenient(cls, payload):  # type: ignore[no-untyped-def]
        cleaned = {k: v for k, v in payload.items() if k != "sudo"}
        return real(cls, cleaned)

    monkeypatch.setattr(KnowledgeCapsuleV1, "from_dict", classmethod(lenient))
    _, refused_now, _, leaks_now = gate_construction.wire_key_fuzz(samples[:1])
    assert any(leak.endswith("<top>.sudo") for leak in leaks_now)


def test_zero_objects_fail_as_vacuous() -> None:
    corpus = build_fleet_corpus(hosts=8, episodes_per_host=16, seed=7)
    empty = Stage7GateContext(corpus=corpus, receivers=("h000",), preconditions=(),
                              registry_before=None)
    g71 = gate_construction.check_g7_1(empty)
    assert not g71.passed and "VACUOUS" in g71.detail
    g79 = gate_construction.check_g7_9(empty)
    assert not g79.passed and "VACUOUS" in g79.detail
    g78 = gate_measured.check_g7_8(empty)
    assert not g78.passed and "B7-1" in g78.detail
    assert not gate_measured.check_g7_4(empty).passed  # no suite: fails, says why


def test_g7_8_cannot_pass_without_foreign_promotion(
        built: tuple[Stage7GateContext, str | None, str | None]) -> None:
    ctx = built[0]
    check = gate_measured.check_g7_8(ctx)
    assert not check.passed and ("B7-1" in check.detail or "NOT MEASURABLE" in check.detail)


def test_g7_11_fails_by_construction_on_synthetic_data(
        built: tuple[Stage7GateContext, str | None, str | None]) -> None:
    ctx = built[0]
    assert ctx.suite is not None and ctx.suite.synthetic is True
    check = gate_measured.check_g7_11(ctx)
    assert not check.passed and "FAILS by construction" in check.detail


def test_an_unreadable_rss_is_unmeasured_and_fails(
        built: tuple[Stage7GateContext, str | None, str | None]) -> None:
    ctx = built[0]
    assert ctx.flood is not None
    blind = dataclasses.replace(ctx.flood.resources, peak_sampled_rss_bytes=None,
                                incremental_rss_bytes=None, within_ceiling=None)
    unmeasured = dataclasses.replace(ctx, flood=dataclasses.replace(ctx.flood, resources=blind))
    check = gate_measured.check_g7_10(unmeasured)
    assert not check.passed and "within ceiling None" in check.detail
