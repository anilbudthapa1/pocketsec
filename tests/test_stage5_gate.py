"""The Stage 5 gate, and the seams the integrator closed to make it one stage.

Three groups.

1. **Shape**: fifteen checks, ids G5.1-G5.15, one shared corpus run, the CLI's exit code.
2. **§4.9 Rule B — every check can fail.** For each check, one deliberately non-compliant
   input — usually a monkeypatch that breaks the *subsystem* the check names, never the
   check itself — and an assertion that the check reports FAILED. A check that could
   not be made to fail would be a check that asserts a type exists, which both prior
   stages shipped.
3. **Integrator seam fixes**, each pinned: restoration operators are never incident
   responses; SENTINEL's evidence-retention reading counts only an accepted bundle; the
   restoration id set has one derivation.

The mutation-edit test at the bottom runs each PROVEN_BY_CONSTRUCTION row's *text*
mutation against a scratch copy of the repository and asserts the row's named test
fails. It lives here, outside ``pocketsec/stage5/``, because trust rule P2 forbids a
process launcher anywhere under the package. The gate does NOT replay these edits: its
G5.13 run (``gate_assurance.mutation_results``) probes each row's behaviour in-process,
a self-consistency check that replaced a circular one (finding F2).
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.gate import REPO_ROOT, GateCheck
from pocketsec.stage5 import gate as gate_module
from pocketsec.stage5 import gate_construction as construction
from pocketsec.stage5 import gate_measured as measured
from pocketsec.stage5 import gate_runtime as runtime
from pocketsec.stage5.assurance import properties as assurance

GATE_IDS = tuple(f"G5.{index}" for index in range(1, 16))


@pytest.fixture(scope="module")
def ctx() -> gate_module.Stage5GateContext:
    return gate_module.Stage5GateContext.build()


@pytest.fixture(scope="module")
def report(ctx: gate_module.Stage5GateContext) -> Any:
    return gate_module.run_gate(ctx)


# --- shape ---------------------------------------------------------------------------


def test_the_gate_has_fifteen_checks_in_order(report: Any) -> None:
    assert tuple(check.id for check in report.checks) == GATE_IDS
    assert all(isinstance(check, GateCheck) and check.detail for check in report.checks)


def test_the_two_real_host_criteria_fail_by_construction(report: Any) -> None:
    """§6.1: G5.7 and G5.11 must fail while the only host is SimulatedHost (ADR-0046)."""
    by_id = {check.id: check for check in report.checks}
    assert not by_id["G5.7"].passed and "UNMEASURED" in by_id["G5.7"].detail
    assert not by_id["G5.11"].passed and "simulated=True" in by_id["G5.11"].detail


def test_the_gate_does_not_pass_fifteen_of_fifteen(report: Any) -> None:
    """A 15/15 here would be evidence a check cannot fail (§6.1), not success."""
    assert not report.passed


def test_the_gate_leaves_the_experiment_ledger_byte_identical(
    ctx: gate_module.Stage5GateContext, report: Any
) -> None:
    del report
    assert gate_module.registry_digest() == ctx.registry_before


def test_the_cli_gate_exits_non_zero_when_the_gate_fails() -> None:
    from pocketsec.stage5.cli import main

    assert main(["gate"]) == 1


# --- §4.9 Rule B: every check can fail ------------------------------------------------


@pytest.fixture
def patch() -> Iterator[Callable[[Any, str, Any], None]]:
    undo: list[tuple[Any, str, Any]] = []

    def apply(owner: Any, name: str, value: Any) -> None:
        undo.append((owner, name, getattr(owner, name)))
        setattr(owner, name, value)

    yield apply
    for owner, name, value in reversed(undo):
        setattr(owner, name, value)


def test_g5_1_fails_on_a_missing_seam_symbol(ctx: Any, patch: Any) -> None:
    patch(construction, "SEAM_SYMBOLS", {"pocketsec.stage0.gate": ("NoSuchSymbol",)})
    assert not construction.check_frozen_upstream(ctx).passed


def test_g5_2_fails_when_the_executor_entry_stops_refusing(ctx: Any, patch: Any) -> None:
    from pocketsec.stage5.executor import transactional

    patch(transactional, "_refuse_untyped", lambda operator, token: None)
    check = construction.check_typed_operators_only(ctx)
    assert not check.passed, check.detail


def test_g5_3_fails_when_one_sentinel_check_goes_quiet(patch: Any) -> None:
    from pocketsec.stage5.sentinel.kernel import SentinelKernel

    patch(SentinelKernel, "_check_scope", lambda self, request: ())
    assert not construction.check_sentinel_independent_denial().passed


def test_g5_4_fails_when_policy_may_mint_a_human_operator(ctx: Any, patch: Any) -> None:
    from pocketsec.stage5.authority.tokens import TokenStore

    patch(TokenStore, "_refuse_bad_grant", lambda self, grant, spec, required: None)
    check = construction.check_no_text_grants_authority(ctx)
    # G5.4 already fails on clause (a) (see ADR-0042); assert the *broken* clause is seen.
    assert not check.passed and "POLICY grant refused for 0/" in check.detail


def test_g5_5_fails_when_revalidation_always_matches(ctx: Any, patch: Any) -> None:
    from pocketsec.stage5.executor import transactional
    from pocketsec.stage5.executor.identity import IdentityRevalidation

    patch(transactional, "revalidate", lambda expected, observed: IdentityRevalidation.MATCH)
    assert not construction.check_identity_revalidated(ctx).passed


def test_g5_6_fails_when_the_sweeper_does_nothing(ctx: Any, patch: Any) -> None:
    from pocketsec.stage5.executor.lease import LeaseSweeper

    patch(LeaseSweeper, "sweep", lambda self, *, now: ())
    assert not runtime.check_interventions_leased(ctx).passed


def test_g5_7_cannot_pass_on_the_simulated_host(ctx: Any) -> None:
    assert not runtime.check_rollback_reliability(ctx).passed


def test_g5_8_fails_when_the_evidence_gate_preserves_everything(ctx: Any, patch: Any) -> None:
    from pocketsec.stage5.evidence.preservation_gate import (
        EvidencePreservationGate,
        PreservationDecision,
    )

    original = EvidencePreservationGate.evaluate

    def permissive(self: Any, **kwargs: Any) -> Any:
        verdict = original(self, **kwargs)
        object.__setattr__(verdict, "decision", PreservationDecision.PRESERVED)
        return verdict

    patch(EvidencePreservationGate, "evaluate", permissive)
    assert not runtime.check_evidence_and_invariants(ctx).passed


def test_g5_9_fails_on_a_degenerate_split(ctx: Any, patch: Any) -> None:
    patch(measured, "saturation_check", lambda outcomes: (True, "DEGENERATE: forced"))
    check = measured.check_multi_world_collateral(ctx)
    assert not check.passed and "DEGENERATE: forced" in check.detail


def test_g5_10_fails_when_verification_reports_everything_effective(patch: Any) -> None:
    from pocketsec.stage5.executor import verify
    from pocketsec.stage5.executor.verify import VerificationOutcome

    patch(verify, "verification_outcome", lambda results: VerificationOutcome.EFFECTIVE)
    assert not runtime.check_post_action_verification().passed


def test_g5_11_cannot_pass_on_the_simulated_host(ctx: Any) -> None:
    assert not runtime.check_safe_recovery(ctx).passed


def test_g5_12_fails_when_an_adversarial_suite_breaks_its_bound(ctx: Any, patch: Any) -> None:
    from pocketsec.stage5.labs import adversarial_load
    from pocketsec.stage5.labs.adversarial_load import AdversarialReport

    broken = AdversarialReport("forced", 9, 8, False, "forced over bound", 1)
    patch(adversarial_load, "run_all", lambda: (broken,))
    check = measured.check_bounded_under_load(ctx)
    # G5.12 also fails on the UNMEASURED resource rows; assert the broken bound is seen.
    assert not check.passed and "fan-out bounds held: False" in check.detail


def test_g5_13_fails_on_a_proven_row_whose_mutation_breaks_nothing(patch: Any) -> None:
    rows = (*assurance.proven(), assurance.PROPERTIES_BY_ID["P3"])
    patch(assurance, "proven", lambda: rows)
    check = measured.check_assurance_table()
    assert not check.passed and "P3" in check.detail


def test_g5_13_fails_when_the_entry_guard_is_deleted_and_sentinel_is_switched_off(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Finding F2, the verifier's scenario, in-process.

    The executor's entry guard is deleted and SENTINEL gains a module flag that returns
    PASS before any check. The old G5.13 still passed with "8/8 hold unmutated and fail
    under their mutation", because every probe read only the surface its own patch
    edited. The behavioural probes must see both breaks as behaviour broken on today's
    code, and the check must fail naming P1 and P6.
    """
    import inspect as _inspect

    from pocketsec.stage5.sentinel import kernel

    transactional = _inspect.getmodule(gate_module.TransactionalExecutor)
    monkeypatch.setattr(transactional, "_refuse_untyped", lambda operator, token: None)
    monkeypatch.setattr(kernel, "ENFORCING", False, raising=False)
    original_run = kernel.SentinelKernel._run

    def flagged(self: Any, request: Any, operator_id: str, target_digest: str) -> Any:
        if not kernel.ENFORCING:  # type: ignore[attr-defined]
            return kernel.SentinelVerdict(kernel.Decision.PASS, (), "off", operator_id,
                                          target_digest, kernel.CHECK_ORDER)
        return original_run(self, request, operator_id, target_digest)

    monkeypatch.setattr(kernel.SentinelKernel, "_run", flagged)
    check = measured.check_assurance_table()
    assert not check.passed
    broken = check.detail.split("behaviour broken on today's code ")[1].split("]")[0]
    assert "P1" in broken and "P6" in broken, check.detail


def test_g5_13_p5_sees_the_identity_check_deleted_not_only_a_catalog_edit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Finding F2: P5's old probe only asked whether CATALOG held an O7 entry.

    With ``DefensiveOperator``'s checks removed a forged O7 spec becomes an operator while
    CATALOG still holds no O7 — the old probe stayed green. The behavioural probe tries to
    build an O7 operator by every route and must now fail.
    """
    from pocketsec.stage5.operators.algebra import DefensiveOperator

    from pocketsec.stage5 import gate_assurance

    assert gate_assurance._p5()[0] is True, "the probe must hold on today's code"
    monkeypatch.setattr(DefensiveOperator, "__post_init__", lambda self: None)
    assert gate_assurance._p5()[0] is False


def test_g5_13_p7_sees_expiry_that_waits_for_a_sweep(monkeypatch: pytest.MonkeyPatch) -> None:
    """Finding F2: P7's old probe patched ``Lease.expired`` and then called it.

    A registry that reports nothing expired until somebody sweeps is the "expiry only
    when something else calls in" failure the lead named; the probe must see it.
    """
    from pocketsec.stage5 import gate_assurance
    from pocketsec.stage5.executor.lease import LeaseRegistry

    assert gate_assurance._p7()[0] is True, "the probe must hold on today's code"
    monkeypatch.setattr(LeaseRegistry, "expired", lambda self, now: ())
    assert gate_assurance._p7()[0] is False


def test_g5_14_fails_when_an_ablation_is_unmeasured(ctx: Any, patch: Any) -> None:
    from pocketsec.stage5.labs.fifty_experiments import AblationRow, AblationVerdict

    def unmeasured(cases: Any, *, flag: str, core_id: str, build_executor: Any) -> Any:
        return AblationRow(core_id, flag, "m", None, None, None, AblationVerdict.UNMEASURED,
                           "S5X-49")

    patch(measured, "run_ablation", unmeasured)
    check = measured.check_ablation_survival(ctx)
    assert not check.passed and "0/11 OPTIONAL ids carry a measured delta" in check.detail


def test_g5_15_fails_on_a_novelty_claim(ctx: Any, patch: Any, tmp_path: Path) -> None:
    findings = tmp_path / "findings.md"
    findings.write_text(
        "\n".join(measured.HONESTY_HEADINGS) + "\n\nAEGIS is the first planner of its kind.\n",
        encoding="utf-8",
    )
    patch(measured, "FINDINGS_PATH", findings)
    check = measured.check_no_novelty_claim(ctx)
    assert not check.passed and "first" in check.detail


def test_the_novelty_rule_accepts_an_explicit_disclaimer() -> None:
    text = "AEGIS is not the first such planner; no novelty claim is made here."
    assert measured.novelty_offenders(text) == []


# --- integrator seam fixes ------------------------------------------------------------


def test_no_restoration_operator_is_ever_an_incident_response(ctx: Any) -> None:
    """A restoration raises capability on purpose; proposing one against an incident is
    proposing to undo a containment that does not exist. Measured before the fix: AEGIS
    chose RELEASE_LOCAL_SOCKET as "containment" on every hostile benchmark case."""
    from pocketsec.stage5.labs.baselines import build_rig
    from pocketsec.stage5.operators.catalog import RESTORATION_OPERATOR_IDS

    assert {
        "RESUME_PROCESS", "RELEASE_LOCAL_SOCKET", "STOP_TRACE", "RELEASE_SERVICE"
    } == RESTORATION_OPERATOR_IDS
    for case in ctx.corpus:
        proposed = {c.operator.spec.operator_id for c in build_rig(case).field.candidates}
        assert not proposed & RESTORATION_OPERATOR_IDS, (case.case_id, proposed)


def test_the_restoration_set_has_one_derivation() -> None:
    """Four modules used to derive this set separately (§4.9 Rule A); now one object."""
    from pocketsec.stage5.executor import lease, verify
    from pocketsec.stage5.host import simulated
    from pocketsec.stage5.labs import baselines
    from pocketsec.stage5.operators.catalog import RESTORATION_OPERATOR_IDS

    assert lease.RESTORATION_OPERATOR_IDS is RESTORATION_OPERATOR_IDS
    assert verify.RESTORING_OPERATOR_IDS is RESTORATION_OPERATOR_IDS
    assert simulated._ROLLBACK_OPERATOR_IDS is RESTORATION_OPERATOR_IDS
    assert baselines.RESTORATION_OPERATOR_IDS is RESTORATION_OPERATOR_IDS


def test_sentinel_counts_only_an_accepted_bundle_as_preservation() -> None:
    """MI-04 clears only on signals in a bundle the evidence gate accepted.

    Built on the G5.3 compliant case: the target holds ``process_memory_map``, which
    MI-04 retains. With the gate's PRESERVED bundle the suspension passes; with the same
    bundle under a refusal, SENTINEL denies on MISSION_INVARIANT as well — a refused
    bundle preserves nothing.
    """
    from pocketsec.stage5.evidence.preservation_gate import (
        EvidencePreservationVerdict,
        PreservationDecision,
    )
    from pocketsec.stage5.labs import adversarial_load as fixtures
    from pocketsec.stage5.sentinel.kernel import Decision, DenyReason

    case = construction._Case("SUSPEND_PROCESS")
    resolution = fixtures.build_resolution(supports=(1.0,), uncertainty=0.0)
    # Listed but never captured: preserves nothing, so MI-04 denies (F4 / S5-SEC-01).
    case.snapshot = fixtures.build_snapshot(volatile=("process_memory_map",))
    case.evidence = fixtures.preserved_verdict(case.operator, resolution, case.snapshot)
    assert "process_memory_map" not in case.evidence.bundle.volatile_preserved
    uncaptured = case.verify()
    assert uncaptured.decision is Decision.DENY
    assert DenyReason.MISSION_INVARIANT in uncaptured.reasons
    # Captured by a preservation operator: the accepted bundle carries it and it passes.
    case.snapshot = fixtures.build_snapshot(
        volatile=("process_memory_map",), preserved=("process_memory_map",)
    )
    case.evidence = fixtures.preserved_verdict(case.operator, resolution, case.snapshot)
    assert "process_memory_map" in case.evidence.bundle.volatile_preserved
    assert case.verify().decision is Decision.PASS
    case.evidence = EvidencePreservationVerdict(
        PreservationDecision.INSUFFICIENT_EVIDENCE, case.evidence.bundle, (), ("x",), None,
        "refused by the gate",
    )
    verdict = case.verify()
    assert verdict.decision is Decision.DENY
    assert DenyReason.MISSION_INVARIANT in verdict.reasons


def test_the_executor_entry_refuses_a_deep_copied_operator(ctx: Any) -> None:
    """``copy.deepcopy`` skips ``__post_init__``; the entry guard must still refuse it."""
    import copy

    from pocketsec.stage5.labs.baselines import build_rig

    rig = build_rig(ctx.corpus[0])
    operator = rig.field.candidates[0].operator
    token = _token(rig, operator)
    calls = rig.host.apply_calls
    with pytest.raises(ContractError):
        gate_module.executor_for_rig(rig).execute(
            copy.deepcopy(operator), token, resolution=rig.case.resolution
        )
    assert rig.host.apply_calls == calls


def _token(rig: Any, operator: Any) -> Any:
    from pocketsec.stage5.labs import adversarial_load as fixtures

    return fixtures.mint_token(rig.tokens, operator, action_id="act.deep.copy")


def test_the_gate_imports_the_executor_only_where_adr_0041_permits() -> None:
    """``gate_*`` modules reach the executor through ``gate.py``'s factories only."""
    for name in ("gate_construction.py", "gate_runtime.py", "gate_measured.py"):
        text = (REPO_ROOT / "pocketsec" / "stage5" / name).read_text(encoding="utf-8")
        forbidden = "from pocketsec.stage5.executor.transactional import TransactionalExecutor"
        assert forbidden not in text


# --- the text mutations, run for real against a scratch copy --------------------------


def _scratch_repository(root: Path) -> Path:
    for part in ("pocketsec", "tests", "contracts", "docs", "experiments", "pyproject.toml"):
        source = REPO_ROOT / part
        if source.is_dir():
            shutil.copytree(source, root / part,
                            ignore=shutil.ignore_patterns("__pycache__", "research"))
        elif source.is_file():
            (root / part).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, root / part)
    return root


def _run_named_test(root: Path, test_name: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": str(root), "PYTHONHASHSEED": "0"}
    return subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-x", test_name],
        cwd=root, env=env, capture_output=True, text=True, timeout=600, check=False,
    )


@pytest.mark.slow
@pytest.mark.parametrize(
    "property_id", sorted({*assurance.MUTATION_EDITS, *assurance.SENSITIVITY_EDITS})
)
def test_every_mutation_edit_breaks_its_named_test(property_id: str, tmp_path: Path) -> None:
    """The out-of-package half of G5.13: the row's own pytest test, on mutated source.

    The control run on an unmutated scratch copy must PASS first, so a copy that cannot
    even collect the test is not mistaken for a mutation that broke it.
    """
    row = assurance.PROPERTIES_BY_ID[property_id]
    control = _run_named_test(_scratch_repository(tmp_path / "control"), row.test_name)
    assert control.returncode == 0, f"control run failed:\n{control.stdout[-2000:]}"
    scratch = _scratch_repository(tmp_path / "mutated")
    relative, _anchor, _replacement = {**assurance.SENSITIVITY_EDITS,
                                       **assurance.MUTATION_EDITS}[property_id]
    target = scratch / relative
    target.write_text(assurance.mutated_source(property_id, target.read_text(encoding="utf-8")),
                      encoding="utf-8")
    result = _run_named_test(scratch, row.test_name)
    assert result.returncode != 0, (
        f"{property_id}'s mutation left {row.test_name} passing:\n{result.stdout[-2000:]}"
    )


def test_memory_does_not_carry_the_retracted_playbook_verdict_uncorrected() -> None:
    """Finding F6: ``planning/MEMORY.md`` is read first by every session.

    It stated "the fixed playbook beat SAFE/AEGIS ... B7 (twin/cone off) contains 10/10"
    as a durable fact after the measurement wave had retracted both halves (B2 equals the
    truth label on 20 of 20; B7 is not single-world). The original line is kept as
    history, so the test asserts the correction sits in the same Stage 5 section and
    cites the two ledger rows that carry the retraction.
    """
    text = (REPO_ROOT / "planning" / "MEMORY.md").read_text(encoding="utf-8")
    start = text.index("## Durable Stage 5 facts")
    end = text.find("\n## ", start + 1)
    section = text[start:] if end == -1 else text[start:end]
    if "the fixed playbook beat SAFE/AEGIS" not in section:
        return
    assert "RETRACTED" in section
    assert "PS-S5-20260926-BASE-corpus-audit-0003" in section
    assert "PS-S5-20260926-BASE-b7-identifiability-0010" in section
    assert "Do not ship B2 behind SENTINEL" in section


def test_g5_14_counts_inert_ablation_flags_as_unmeasured(
    ctx: Any, report: Any, patch: Any
) -> None:
    """Finding R7: four OPTIONAL ids read "carry a measured delta" at 0.0 by construction.

    ``enable_residual`` and ``enable_d3fend`` have no reader anywhere in the package, and
    ``enable_response_cells`` switches a field the generator never reads. G5.14 counted all
    four as measured because it only treated ``delta is None`` as unmeasured — the lead's
    lesson 4. The inert set is now measured (an AST read scan and a tripwire the generator
    must touch), and the detectors can each see the opposite case. The gate's own G5.14 is
    read from the module's single gate run: calling it twice would register the same
    ablation ids twice in the run's temporary ledger.
    """
    from pocketsec.stage5.core_ids import ABLATION_FLAGS
    from pocketsec.stage5.labs.fifty_experiments import AblationRow, AblationVerdict
    from pocketsec.stage5.safe import action_field

    assert measured.unread_ablation_flags() == ("enable_d3fend", "enable_residual")
    assert measured.cells_consulted(ctx) is False
    rows = {core: AblationRow(core, flag, "m", 0.0, 0.0, 0.0,
                              AblationVerdict.NOT_YET_JUSTIFIED, "S5X-49")
            for core, flag in ABLATION_FLAGS.items()}
    assert measured._inert_ids(ctx, rows) == ["SAFE-F16", "SAFE-F21", "SAFE-F22", "SAFE-F23"]
    g514 = {check.id: check for check in report.checks}["G5.14"]
    assert "7/11 OPTIONAL ids carry a measured delta" in g514.detail
    assert "'SAFE-F16', 'SAFE-F21', 'SAFE-F22', 'SAFE-F23'" in g514.detail

    original = action_field._prepare

    def reads_cells(resolution: Any, snapshot: Any, *, cells: Any) -> Any:
        getattr(cells, "cells", None)
        return original(resolution, snapshot, cells=cells)

    patch(action_field, "_prepare", reads_cells)
    assert measured.cells_consulted(ctx) is True
