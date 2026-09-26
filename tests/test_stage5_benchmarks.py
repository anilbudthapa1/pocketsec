"""Stage 5 package 8 — the measurement layer, and the three corpus defects it refuses.

Every test here either exercises a failure path or pins a claim this wave would
otherwise be taking on trust. The three corpus honesty tests come first, because each
of them is a defect this repository has already paid for in a retracted result.
"""

from __future__ import annotations

import dataclasses
import json
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.experiments.registry import ExperimentRegistry
from pocketsec.stage0.gate import REPO_ROOT
from pocketsec.stage4.identifiability.resolution import IDENTIFIABILITY_MARGIN

# Imported as a module, not by name: pytest collects any module-level callable whose name
# starts with "test", and ``properties.tested`` would be collected as a test that returns
# a tuple. Reaching it through the module keeps the collector out of it.
from pocketsec.stage5.assurance import properties as assurance_properties
from pocketsec.stage5.assurance.properties import (
    EXECUTOR_PROPERTIES,
    VERIFICATION_WORDS,
    AssuranceKind,
    ExecutorProperty,
    counts,
    proven,
    resolve_construction,
    unearned_verification_language,
    unmeasured,
    unresolvable_constructions,
)
from pocketsec.stage5.evidence.preservation_gate import EvidencePreservationGate
from pocketsec.stage5.executor.transactional import (
    Outcome,
    TransactionalExecutor,
    TransactionReceipt,
)
from pocketsec.stage5.host.simulated import HostKind
from pocketsec.stage5.labs.baselines import (
    BASELINES,
    REFERENCE_ARM_ID,
    BaselineOutcome,
    BaselineRig,
    _mint,
    always_isolate,
    build_rig,
    fixed_playbook,
    primary_metric_value,
    reference_arm,
    run_arm,
    run_baselines,
)
from pocketsec.stage5.labs.fifty_experiments import (
    EXPERIMENTS,
    PRIMARY_METRIC,
    SATURATION_EPSILON,
    STAGE5_EXPERIMENTS_VERSION,
    STAGE5_HYPOTHESIS,
    AblationRow,
    AblationVerdict,
    BlockedReason,
    ExperimentSpec,
    ablation_row,
    blocked_experiments,
    experiment_id_for,
    record_ablation,
    run_ablation,
    runnable_experiments,
    saturation_check,
    verdict_for,
)
from pocketsec.stage5.labs.response_corpus import (
    AMBIGUOUS_SUPPORT_GAP,
    MAX_CASE_PROCESSES,
    MAX_CORPUS_CASES,
    RESPONSE_CORPUS_VERSION,
    GroundTruthResponse,
    build_action_flood,
    build_ambiguous_pairs,
    build_critical_service_baits,
    build_evidence_destroying_cases,
    build_response_corpus,
    build_toctou_cases,
    build_two_epoch_corpus,
    corpus_digest,
    corpus_identities,
    operator_vocabulary,
)
from pocketsec.stage5.operators.algebra import OperatorClass
from pocketsec.stage5.operators.catalog import CATALOG
from pocketsec.stage5.resources import (
    AGGREGATE_COMPONENTS,
    STAGE5_COMPONENTS,
    STAGE5_NORMAL_INCREMENTAL_RSS_BYTES,
    Stage5ResourceReport,
    loadavg,
    measure_stage5_resources,
    unmeasured_stage5_resources,
)
from pocketsec.stage5.sentinel.kernel import SentinelKernel
from pocketsec.stage5.stage6_interface import (
    FORBIDDEN_SEAM_TOKENS,
    SEAM_AUTHORITY_EXEMPTIONS,
    VERIFIED_OUTCOME,
    ResponseRecordV1,
    build_record,
    receipt_row,
    write_record,
)
from pocketsec.stage5.theory import (
    DEFINITIONS,
    MEI_TERM_ATTRIBUTES,
    mei_terms_summed,
    resolve_binding,
    sections_covered,
    unbound_terms,
)

STAGE5_ROOT = REPO_ROOT / "pocketsec" / "stage5"

#: One seed for every corpus in this file, so two tests never disagree about what they
#: measured. Small counts: these are structural tests, and a slow suite is a suite
#: nobody runs before pushing.
SEED = 7
COUNT = 6


def _executor(rig: BaselineRig) -> TransactionalExecutor:
    """The real privileged executor, assembled here because only a test may name it.

    Spec §5.1 rule 4 keeps ``TransactionalExecutor`` out of ``labs/``, so the lab is
    handed this factory. Everything in it comes from the rig, which was built from
    ``FROZEN_CONSTITUTION`` — there is no permissive kernel to substitute.
    """
    return TransactionalExecutor(
        kernel=rig.kernel,
        host=rig.host,
        journal=rig.journal,
        gate=rig.gate,
        governor=rig.governor,
        leases=rig.leases,
        probe=rig.probe,
        clock=rig.clock,
        tokens=rig.tokens,
    )


def _capture(monkeypatch: pytest.MonkeyPatch, owner: type, name: str) -> list[Any]:
    """Wrap ``owner.name`` so every value it returns is recorded, then returned unchanged.

    Observation only: the original runs with the original arguments. This is how a test
    counts what the *real* kernel, gate and executor did, instead of trusting a figure the
    harness computed about them.
    """
    seen: list[Any] = []
    original = getattr(owner, name)

    def recorder(self: Any, *args: Any, **kwargs: Any) -> Any:
        result = original(self, *args, **kwargs)
        seen.append(result)
        return result

    monkeypatch.setattr(owner, name, recorder)
    return seen


def _executed(case: Any, policy: Callable[[BaselineRig], Any]) -> tuple[BaselineRig, Any]:
    """One policy's choice on one case, executed through the real executor."""
    rig = build_rig(case)
    choice = policy(rig)
    assert choice.candidate is not None, "the policy must act for this test to test anything"
    token = _mint(rig, choice)
    assert token is not None
    return rig, _executor(rig).execute(
        choice.candidate.operator, token, resolution=rig.case.resolution
    )


def _all_cases() -> list[Any]:
    """One case list covering every builder, with **one member per ambiguous pair**.

    Both members of a pair hold the *same* process by design, so including both would
    make the uniqueness test fail on the corpus's own central property.
    """
    pairs = build_ambiguous_pairs(count=COUNT, seed=SEED)
    return [
        *build_response_corpus(count=COUNT, seed=SEED),
        *(pair[0] for pair in pairs),
        *build_critical_service_baits(count=COUNT, seed=SEED),
        *build_toctou_cases(count=COUNT, seed=SEED),
        *build_evidence_destroying_cases(count=COUNT, seed=SEED),
        *build_action_flood(count=2, seed=SEED),
        *build_two_epoch_corpus(count=COUNT, seed=SEED),
    ]


# --- the three mandatory corpus honesty tests --------------------------------


def test_response_corpus_uses_session_unique_identities() -> None:
    """The corpus trap: a reused identity silently erases the signal it carries.

    Stage 1 carries lineage state across scenarios, so a corpus that reuses process
    identities between sessions produces median dPhi 0.00 for *both* classes — and the
    +0.042 result built on one had to be retracted (``planning/MEMORY.md``). Uniqueness
    in ``(pid, start_time_ticks)`` is the property, and it has to hold across every
    builder at once, not one builder at a time.
    """
    identities = corpus_identities(_all_cases())
    assert identities, "the corpus must hold processes at all"
    duplicates = sorted({row for row in identities if identities.count(row) > 1})
    assert not duplicates, f"reused (pid, start_time_ticks) pairs: {duplicates}"
    # The one sanctioned exception, asserted rather than silently excluded: both members
    # of an ambiguous pair are the *same* session under two truths, because the lineage
    # rows they share carry the target pid and must be byte-identical. Only pair[0] is in
    # _all_cases(); pair[1] must hold exactly pair[0]'s identities and nothing else.
    pairs = build_ambiguous_pairs(count=COUNT, seed=SEED)
    for first, second in pairs:
        assert corpus_identities([first]) == corpus_identities([second])
    assert len({corpus_identities([pair[0]]) for pair in pairs}) == len(pairs)


def test_response_corpus_identities_stay_unique_across_seeds() -> None:
    """Two seeds must not collide either: a corpus is often built twice in one run."""
    both = corpus_identities(
        [*build_response_corpus(count=COUNT, seed=SEED), *build_response_corpus(count=COUNT, seed=SEED + 1)]
    )
    assert len(set(both)) == len(both), "two seeds produced the same identity"


def test_response_corpus_carries_no_operator_vocabulary_signal() -> None:
    """The vocabulary leak, which happened twice in Stage 2.

    If the ambiguous and unambiguous halves name different operators, a bag-of-operators
    control wins for free and every comparison downstream is meaningless. The
    vocabularies must be *identical*, not merely overlapping — a stronger property than
    the spec asks for, and one the corpus can actually guarantee by construction.
    """
    cases = _all_cases()
    ambiguous = [case for case in cases if case.ambiguous]
    unambiguous = [case for case in cases if not case.ambiguous]
    assert ambiguous and unambiguous, "the split must have both halves"
    assert operator_vocabulary(ambiguous) == operator_vocabulary(unambiguous)
    harmful_amb = {op for case in ambiguous for op in case.truth.harmful_operator_ids}
    harmful_un = {op for case in unambiguous for op in case.truth.harmful_operator_ids}
    assert harmful_amb & harmful_un, "the harmful multisets must overlap across the split"
    sufficient_amb = {op for case in ambiguous for op in case.truth.sufficient_operator_ids}
    sufficient_un = {op for case in unambiguous for op in case.truth.sufficient_operator_ids}
    assert sufficient_amb & sufficient_un, "the sufficient multisets must overlap too"


def test_ambiguous_pairs_are_indistinguishable_from_the_resolution_alone() -> None:
    """A pair whose resolutions differ tests reading, not ambiguity.

    The two members must be byte-identical everywhere a planner can look: the claim
    graph, the evidence lineage, the whole exported resolution, the host rows and the
    harm model. Only ``truth`` may differ — and ``truth`` is never a planner input.
    """
    pairs = build_ambiguous_pairs(count=COUNT, seed=SEED)
    assert len(pairs) == COUNT
    for benign, compromised in pairs:
        assert benign.resolution.claim_graph == compromised.resolution.claim_graph
        assert benign.resolution.evidence_lineage == compromised.resolution.evidence_lineage
        assert benign.resolution.to_dict() == compromised.resolution.to_dict()
        assert benign.host.snapshot().to_dict() == compromised.host.snapshot().to_dict()
        assert benign.harm == compromised.harm, "the harm model must not leak the answer"
        assert benign.truth != compromised.truth
        assert benign.truth.benign_admin is True
        assert compromised.truth.benign_admin is False
        supports = sorted(
            (float(row["support"]) for row in benign.resolution.hypotheses), reverse=True
        )
        assert supports[0] - supports[1] == pytest.approx(AMBIGUOUS_SUPPORT_GAP, abs=1e-6)
        # Against Stage 4's own margin, imported rather than restated: a corpus constant
        # that drifted past it would stop producing ambiguity while every other line of
        # this test kept passing.
        assert supports[0] - supports[1] < IDENTIFIABILITY_MARGIN


def test_observation_never_counts_as_containment() -> None:
    """Looking at a hostile process is not containing it.

    An earlier revision listed an observation operator as *sufficient* on compromised
    cases, which scored any arm that declined to intervene as having contained the
    incident — a free win for exactly the cautious planner the ambiguous pairs exist to
    test. Every sufficient operator on a compromised case must change host state.
    """
    for case in _all_cases():
        if case.truth.benign_admin:
            continue
        classes = {CATALOG[op].operator_class for op in case.truth.sufficient_operator_ids}
        assert classes, case.case_id
        assert min(classes) >= OperatorClass.O2_REVERSIBLE_RESTRICT, case.case_id


def test_a_committing_arm_is_wrong_on_exactly_half_of_the_ambiguous_pairs() -> None:
    """The pair's whole point, measured through the real executor rather than asserted.

    B4 commits on every case, so it cannot tell the members apart: it must contain every
    compromised member and harm every benign one — collateral equal to containment, and
    both equal to the number of pairs. If this ever reads otherwise, the pair leaks.
    """
    pairs = build_ambiguous_pairs(count=COUNT, seed=SEED)
    outcome = run_arm(
        always_isolate,
        [case for pair in pairs for case in pair],
        baseline_id="B4",
        build_executor=_executor,
    )
    assert outcome.actions_taken == 2 * COUNT
    assert outcome.incidents_contained == COUNT
    assert outcome.collateral_incidents == COUNT


def test_a_harm_model_that_read_truth_would_break_this_test() -> None:
    """The invariant behind the pair, stated as the thing that must stay true.

    If somebody rewrote the corpus's harm table to derive from
    ``GroundTruthResponse.harmful_operator_ids``, the two members of a pair would get
    different harm models, a multi-world planner would separate them, and every G5.9
    number would be measuring the leak. This asserts the two harm models are the same
    object's worth of data for every pair — which is the smallest statement that fails
    the moment the derivation changes.
    """
    for benign, compromised in build_ambiguous_pairs(count=COUNT, seed=SEED):
        assert benign.harm.unacceptable == compromised.harm.unacceptable
        assert benign.truth.harmful_operator_ids != compromised.truth.harmful_operator_ids


# --- corpus bounds and refusals ----------------------------------------------


def test_the_corpus_refuses_an_out_of_range_count_and_seed() -> None:
    with pytest.raises(ContractError):
        build_response_corpus(count=0, seed=SEED)
    with pytest.raises(ContractError):
        build_response_corpus(count=MAX_CORPUS_CASES + 1, seed=SEED)
    with pytest.raises(ContractError):
        build_response_corpus(count=COUNT, seed=1000)


def test_a_flood_case_is_bounded_at_max_case_processes() -> None:
    for case in build_action_flood(count=2, seed=SEED):
        assert len(case.host.snapshot().processes) == MAX_CASE_PROCESSES


def test_ground_truth_refuses_an_operator_the_catalog_cannot_build() -> None:
    """Stage 3 shipped seven operator forms with no interpreter and measured nothing."""
    with pytest.raises(ContractError):
        GroundTruthResponse(
            harmful_operator_ids=frozenset({"REBOOT_THE_PLANET"}),
            sufficient_operator_ids=frozenset(),
            critical_units=frozenset(),
            uniquely_necessary_evidence=frozenset(),
            true_mechanism_id="m",
            benign_admin=False,
        )


def test_respawn_gives_each_arm_a_pristine_host() -> None:
    """Without this, arm two measures the host arm one left behind."""
    case = build_response_corpus(count=1, seed=SEED)[0]
    first, second = case.respawn(), case.respawn()
    assert first.host is not second.host
    assert first.host.snapshot().to_dict() == second.host.snapshot().to_dict()


def test_two_epoch_corpus_actually_spans_two_epochs() -> None:
    """``MIN_DISTINCT_EPOCHS_TO_CRYSTALLIZE`` is 2, and Stage 2's corpus had one."""
    epochs = {case.resolution.epoch_id for case in build_two_epoch_corpus(count=4, seed=SEED)}
    assert epochs == {1, 2}


def test_evidence_destroying_cases_carry_uniquely_necessary_signals() -> None:
    """Otherwise the preservation gate has nothing to refuse and the builder is a no-op."""
    for case in build_evidence_destroying_cases(count=COUNT, seed=SEED):
        volatile = {
            signal for row in case.host.snapshot().processes for signal in row.volatile_signals
        }
        assert volatile & case.truth.uniquely_necessary_evidence


def test_critical_service_baits_target_a_protected_unit() -> None:
    for case in build_critical_service_baits(count=COUNT, seed=SEED):
        units = {row.unit for row in case.host.snapshot().processes}
        assert units & case.invariants.critical_units()


def test_toctou_cases_arm_the_pid_reuse_fault() -> None:
    for case in build_toctou_cases(count=COUNT, seed=SEED):
        assert case.faults.pid_reuse_rate == 1.0


def test_corpus_digest_is_stable_and_moves_with_truth() -> None:
    """The ledger's dataset digest must name the corpus, including the answer key."""
    cases = build_response_corpus(count=COUNT, seed=SEED)
    digest = corpus_digest(cases)
    assert re.fullmatch(r"[0-9a-f]{64}", digest)
    assert corpus_digest(build_response_corpus(count=COUNT, seed=SEED)) == digest
    benign, compromised = build_ambiguous_pairs(count=1, seed=SEED)[0]
    assert corpus_digest([benign]) != corpus_digest([compromised]), "truth must be covered"
    with pytest.raises(ContractError):
        corpus_digest(())


# --- the fifty-experiment register -------------------------------------------


def test_exactly_fifty_experiments_with_dense_ids() -> None:
    assert len(EXPERIMENTS) == 50
    assert [row.experiment_id for row in EXPERIMENTS] == [f"S5X-{n:02d}" for n in range(1, 51)]
    assert len({row.title for row in EXPERIMENTS}) == 50, "titles must be distinct"


def test_experiment_titles_are_verbatim_from_architecture_section_41() -> None:
    """"Verbatim" checked against the source document, not against a copy of it."""
    source = (
        REPO_ROOT / "docs" / "architecture" / "sources" / "stage-05-safe-aegis-sentinel.md"
    ).read_text(encoding="utf-8")
    section = source.split("# 41. Expanded 50-Experiment Program", 1)[1].split("# 42.", 1)[0]
    titles = dict(re.findall(r"(S5X-\d{2})\s+(.+?)(?=S5X-\d{2}|\n|$)", section))
    assert len(titles) == 50
    assert {row.experiment_id: row.title for row in EXPERIMENTS} == {
        key: value.strip() for key, value in titles.items()
    }


def test_runnable_and_blocked_are_mutually_exclusive() -> None:
    for row in EXPERIMENTS:
        assert row.runnable != (row.blocked_reason is not None)
    assert len(runnable_experiments()) + len(blocked_experiments()) == 50
    assert {row.blocked_reason for row in blocked_experiments()} <= set(BlockedReason)


@pytest.mark.parametrize(
    ("runnable", "reason"),
    [(True, BlockedReason.NEEDS_REAL_HOST), (False, None)],
)
def test_an_experiment_that_is_both_or_neither_is_refused(
    runnable: bool, reason: BlockedReason | None
) -> None:
    """A row that is both runnable and blocked is a row nobody has to resolve."""
    with pytest.raises(ContractError):
        ExperimentSpec(
            experiment_id="S5X-01",
            title="t",
            deliverable="D5.19",
            runnable=runnable,
            blocked_reason=reason,
            metric="m",
        )


def test_blocked_reason_is_a_closed_vocabulary() -> None:
    """An open reason field is where 'we did not get to it' hides behind 'it is blocked'."""
    assert set(BlockedReason) == {
        BlockedReason.NEEDS_REAL_HOST,
        BlockedReason.NEEDS_REAL_TELEMETRY,
        BlockedReason.NEEDS_D3FEND_SNAPSHOT,
        BlockedReason.NEEDS_TWO_EPOCHS,
        BlockedReason.NEEDS_NUMPY_FORBIDDEN_HERE,
    }


def test_the_experiments_version_names_the_corpus_it_describes() -> None:
    assert RESPONSE_CORPUS_VERSION in STAGE5_EXPERIMENTS_VERSION


def test_stage5_mints_no_hypothesis() -> None:
    """Stage 5's claims are about a control boundary, not about a learned model."""
    assert STAGE5_HYPOTHESIS == "BASE"
    assert experiment_id_for(1).startswith("PS-S5-") and "-BASE-" in experiment_id_for(1)


# --- baselines ----------------------------------------------------------------


#: The arms that must act on a corpus holding hostile cases. B1 never acts by definition
#: and B5 acts never by degeneracy (no D3FEND snapshot), so neither can consult SENTINEL:
#: an arm that takes no action has nothing for the kernel to judge. That is the one place
#: "every baseline produced a verdict" cannot hold, and the exclusion is named here.
_ACTING_ARMS: frozenset[str] = frozenset({"B2", "B3", "B4", "B6", "B7", "B8", "B9", REFERENCE_ARM_ID})


def test_every_baseline_runs_through_the_real_sentinel(monkeypatch: pytest.MonkeyPatch) -> None:
    """A baseline that bypassed the kernel would measure a different system.

    Counted at the kernel, not at the harness. ``SentinelKernel.verify`` is wrapped, so
    the figure is the number of times the real kernel actually ran for each arm; the
    harness's own ``sentinel_verdicts`` may never exceed it. An earlier version of this
    test asserted a verdict only ``if outcome.actions_taken`` — and actions were derived
    from receipts, which always carry a verdict, so it could not fail.
    """
    calls = _capture(monkeypatch, SentinelKernel, "verify")
    cases = [*build_response_corpus(count=COUNT, seed=SEED), *build_evidence_destroying_cases(count=2, seed=SEED)]
    policies = {**BASELINES, REFERENCE_ARM_ID: reference_arm}
    for arm_id, policy in policies.items():
        before = len(calls)
        outcome = run_arm(policy, cases, baseline_id=arm_id, build_executor=_executor)
        kernel_calls = len(calls) - before
        assert outcome.planner_faults == 0, f"{arm_id} faulted; a broken arm is not a result"
        assert outcome.sentinel_verdicts <= kernel_calls, f"{arm_id} reports verdicts no kernel issued"
        if arm_id in _ACTING_ARMS:
            assert kernel_calls >= 1, f"{arm_id} acted without the real SENTINEL"
            assert outcome.sentinel_verdicts >= 1, arm_id
        else:
            assert outcome.actions_taken == 0 and kernel_calls == 0, arm_id


def test_the_sentinel_count_catches_an_executor_that_skips_the_kernel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The check above must be able to fail. Here is the input that fails it.

    A factory whose executor replays one genuine receipt instead of running the
    transaction produces a harness figure of one verdict per case while the real kernel
    runs zero times — so ``sentinel_verdicts <= kernel_calls`` is violated, exactly as it
    would be for any executor that stopped consulting SENTINEL.
    """
    case = build_response_corpus(count=2, seed=SEED)[1]
    _rig, genuine = _executed(case, fixed_playbook)

    class _Replaying:
        def execute(self, operator: Any, token: Any, *, resolution: Any) -> TransactionReceipt:
            return genuine

    calls = _capture(monkeypatch, SentinelKernel, "verify")
    outcome = run_arm(fixed_playbook, [case], baseline_id="B2", build_executor=lambda _rig: _Replaying())
    assert len(calls) == 0
    assert outcome.sentinel_verdicts == 1 > len(calls), "the replay must be visible as a surplus"


def test_no_arm_violates_a_mission_invariant_or_destroys_required_evidence() -> None:
    """§42 sets both at zero, and a single violation fails the criterion."""
    cases = [
        *build_response_corpus(count=COUNT, seed=SEED),
        *build_critical_service_baits(count=COUNT, seed=SEED),
        *build_evidence_destroying_cases(count=COUNT, seed=SEED),
    ]
    for arm_id, outcome in run_baselines(cases, build_executor=_executor).items():
        assert outcome.mission_invariant_violations == 0, arm_id
        assert outcome.evidence_violations == 0, arm_id


def test_the_act_never_arms_take_no_action_and_report_no_rate() -> None:
    """B1 by design and B5 by degeneracy: with no D3FEND snapshot, nothing is mapped.

    ``collateral_per_1000`` must be ``None`` and never 0.0 — ADR-0004's rule, and the
    reason :func:`primary_metric_value` exists as a separate function.
    """
    outcomes = run_baselines(build_response_corpus(count=COUNT, seed=SEED), build_executor=_executor)
    for arm_id in ("B1", "B5"):
        assert outcomes[arm_id].actions_taken == 0, arm_id
        assert outcomes[arm_id].collateral_per_1000() is None, arm_id
        assert primary_metric_value(outcomes[arm_id]) == 0.0


def test_a_baseline_outcome_refuses_impossible_counts() -> None:
    with pytest.raises(ContractError):
        BaselineOutcome("X", -1, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    with pytest.raises(ContractError):
        BaselineOutcome("X", 0, 0, 0, 0, 0, 0, 5, 1, 0, 0)


def test_rollback_figures_are_named_for_the_simulator_that_produced_them() -> None:
    """A number a simulator produced is a property of that simulator (ADR-0046)."""
    fields = set(BaselineOutcome.__dataclass_fields__)
    assert "simulated_rollback_successes" in fields
    assert "simulated_rollback_attempts" in fields
    assert not {name for name in fields if name.startswith("rollback_")}


# --- saturation and ablation --------------------------------------------------


def _outcome(arm_id: str, *, actions: int, collateral: int, contained: int) -> BaselineOutcome:
    return BaselineOutcome(
        baseline_id=arm_id,
        actions_taken=actions,
        collateral_incidents=collateral,
        mission_invariant_violations=0,
        evidence_violations=0,
        incidents_contained=contained,
        incidents_missed=0,
        simulated_rollback_successes=0,
        simulated_rollback_attempts=0,
        work_units=1,
        human_escalations=0,
        sentinel_verdicts=actions,
    )


def test_saturation_check_refuses_a_degenerate_split() -> None:
    """Best and median within epsilon means nothing can be shown, so nothing is recorded."""
    flat = {
        arm: _outcome(arm, actions=10, collateral=1, contained=5)
        for arm in ("B1", "B2", "AEGIS")
    }
    degenerate, reason = saturation_check(flat)
    assert degenerate is True
    assert "DEGENERATE" in reason and PRIMARY_METRIC in reason


def test_saturation_check_fires_when_a_degenerate_control_ties_the_best() -> None:
    """B4 reaching the best containment at the best collateral is a split with no headroom."""
    outcomes = {
        "B4": _outcome("B4", actions=10, collateral=0, contained=9),
        "B2": _outcome("B2", actions=10, collateral=5, contained=4),
        "AEGIS": _outcome("AEGIS", actions=10, collateral=9, contained=3),
    }
    degenerate, reason = saturation_check(outcomes)
    assert degenerate is True and "B4" in reason


def test_saturation_check_passes_a_split_with_headroom() -> None:
    """The check must be able to say 'not degenerate', or it is not a check."""
    outcomes = {
        "B1": _outcome("B1", actions=0, collateral=0, contained=0),
        "B2": _outcome("B2", actions=10, collateral=5, contained=9),
        "AEGIS": _outcome("AEGIS", actions=10, collateral=1, contained=9),
    }
    degenerate, reason = saturation_check(outcomes)
    assert degenerate is False, reason


def test_saturation_check_does_not_hide_a_containment_difference() -> None:
    """Equal collateral is not saturation when containment differs.

    The regression this pins: a collateral-only check called this split DEGENERATE,
    because arms that contain nothing also harm nothing. Measured on
    ``build_response_corpus(count=20, seed=11)`` the full planner and the fixed playbook
    both scored 0.0 collateral while containing 0 and 10 incidents respectively — the
    single most important comparison in §7, suppressed as "no headroom".
    """
    outcomes = {
        "B1": _outcome("B1", actions=0, collateral=0, contained=0),
        "B2": _outcome("B2", actions=10, collateral=0, contained=10),
        "B7": _outcome("B7", actions=20, collateral=0, contained=0),
        "AEGIS": _outcome("AEGIS", actions=20, collateral=0, contained=0),
    }
    degenerate, reason = saturation_check(outcomes)
    assert degenerate is False, reason
    assert "B2" in reason


def test_saturation_check_refuses_too_few_arms_to_have_a_median() -> None:
    degenerate, reason = saturation_check({"B1": _outcome("B1", actions=1, collateral=0, contained=0)})
    assert degenerate is True and "too few" in reason


@pytest.mark.parametrize(
    ("delta", "expected"),
    [
        (1.0, AblationVerdict.JUSTIFIED),
        (0.0, AblationVerdict.NOT_YET_JUSTIFIED),
        (SATURATION_EPSILON, AblationVerdict.NOT_YET_JUSTIFIED),
        (-1.0, AblationVerdict.HARMFUL),
    ],
)
def test_the_ablation_verdict_discriminates(delta: float, expected: AblationVerdict) -> None:
    """NOT_YET_JUSTIFIED is not HARMFUL and neither is UNMEASURED (ADR-0009)."""
    assert verdict_for(delta) is expected


@pytest.mark.parametrize(
    ("delta", "containment_delta", "expected"),
    [
        (0.0, 5, AblationVerdict.JUSTIFIED),
        (0.0, -5, AblationVerdict.HARMFUL),
        (-100.0, 5, AblationVerdict.NOT_YET_JUSTIFIED),
        (100.0, -5, AblationVerdict.NOT_YET_JUSTIFIED),
        (100.0, 0, AblationVerdict.JUSTIFIED),
    ],
)
def test_containment_decides_before_collateral(
    delta: float, containment_delta: int, expected: AblationVerdict
) -> None:
    """The primary metric is collateral *at equal containment*; the verdict honours that."""
    assert verdict_for(delta, containment_delta) is expected


def test_a_mechanism_that_blocks_containment_is_harmful_not_free() -> None:
    """The shape falsifier-hunting needs: zero collateral bought by containing nothing.

    With the mechanism on, the arm acts but contains nothing; with it off, it contains
    every hostile case at the same zero collateral. A collateral-only verdict would read
    this as NOT_YET_JUSTIFIED. It is HARMFUL, and the row carries both counts.
    """
    on = _outcome("AEGIS+flag", actions=10, collateral=0, contained=0)
    off = _outcome("AEGIS-flag", actions=10, collateral=0, contained=5)
    row = ablation_row(on, off, core_id="SAFE-F06", flag="enable_shadow_gate")
    assert row.verdict is AblationVerdict.HARMFUL
    assert (row.with_contained, row.without_contained) == (0, 5)
    never = _outcome("AEGIS-never", actions=0, collateral=0, contained=0)
    assert ablation_row(on, never, core_id="SAFE-F06", flag="enable_shadow_gate").verdict is (
        AblationVerdict.UNMEASURED
    )


def test_an_ablation_row_is_keyed_by_a_core_id_that_owns_its_flag() -> None:
    """§4.9 Rule A: the row's key must be one G5.14's join can find."""
    cases = build_response_corpus(count=2, seed=SEED)
    assert run_ablation(cases, flag="enable_twin", build_executor=_executor).core_id == "SAFE-F04"
    with pytest.raises(ContractError, match="name the core id"):
        run_ablation(cases, flag="enable_response_cells", build_executor=_executor)
    with pytest.raises(ContractError, match="not switched by"):
        run_ablation(cases, flag="enable_twin", build_executor=_executor, core_id="SAFE-F05")
    with pytest.raises(ContractError, match="baseline arm"):
        run_ablation(cases, flag="enable_multi_world", build_executor=_executor)


def test_record_ablation_writes_only_to_the_registry_it_is_handed(tmp_path: Path) -> None:
    """The real ledger is append-only and G5.15 asserts it byte-identical across a gate."""
    ledger = REPO_ROOT / "experiments" / "registry.jsonl"
    before = ledger.read_bytes()
    registry = ExperimentRegistry(tmp_path / "registry.jsonl")
    cases = build_response_corpus(count=2, seed=SEED)
    row = ablation_row(
        _outcome("on", actions=4, collateral=0, contained=2),
        _outcome("off", actions=4, collateral=2, contained=2),
        core_id="SAFE-F04",
        flag="enable_twin",
    )
    digest = corpus_digest(cases)
    experiment_id = record_ablation(registry, row, sequence=1, seeds={"corpus": SEED}, dataset_sha256=digest)
    assert experiment_id == experiment_id_for(1)
    (entry,) = registry.all()
    assert entry.dataset_sha256 == digest and entry.hypothesis == "BASE" and entry.synthetic_data
    with pytest.raises(ContractError, match="64 lowercase hex"):
        record_ablation(registry, row, sequence=2, seeds={}, dataset_sha256="")
    unmeasured = AblationRow("SAFE-F04", "enable_twin", PRIMARY_METRIC, None, None, None, AblationVerdict.UNMEASURED, "S5X-49")
    with pytest.raises(ContractError, match="UNMEASURED"):
        record_ablation(registry, unmeasured, sequence=3, seeds={}, dataset_sha256=digest)
    assert ledger.read_bytes() == before


def test_an_unmeasured_ablation_cannot_claim_a_verdict() -> None:
    """A missing measurement is not a passing one (ADR-0004)."""
    with pytest.raises(ContractError):
        AblationRow("SAFE-F04", "enable_twin", PRIMARY_METRIC, None, None, None, AblationVerdict.JUSTIFIED, "S5X-49")
    with pytest.raises(ContractError):
        AblationRow("SAFE-F04", "enable_twin", PRIMARY_METRIC, 1.0, 1.0, 0.0, AblationVerdict.UNMEASURED, "S5X-49")
    with pytest.raises(ContractError):
        AblationRow("SAFE-F04", "enable_twin", PRIMARY_METRIC, None, None, None, AblationVerdict.UNMEASURED, "S5X-99")


def test_run_ablation_measures_a_real_flag_and_refuses_an_invented_one() -> None:
    """The measurement path runs, and only a flag the planner understands can be ablated."""
    cases = build_response_corpus(count=4, seed=SEED)
    row = run_ablation(cases, flag="enable_twin", build_executor=_executor, core_id="SAFE-F04")
    assert row.flag == "enable_twin" and row.metric == PRIMARY_METRIC
    assert (row.delta is None) is (row.verdict is AblationVerdict.UNMEASURED)
    with pytest.raises(ContractError):
        run_ablation(cases, flag="enable_telepathy", build_executor=_executor)


# --- the assurance table ------------------------------------------------------


def test_a_proven_property_names_a_resolvable_construction_and_a_mutation() -> None:
    """A construction nobody can point at is a claim, not a proof."""
    assert proven(), "the table must claim at least one construction property"
    for row in proven():
        assert row.construction and row.mutation
        assert resolve_construction(row.construction) is not None
    assert unresolvable_constructions() == ()


def test_a_tested_statement_contains_no_verification_word() -> None:
    """'verified' may not describe a property whose only evidence is that no test broke it."""
    for row in (*assurance_properties.tested(), *unmeasured()):
        lowered = row.statement.lower()
        assert not {word for word in VERIFICATION_WORDS if word in lowered}, row.property_id
    with pytest.raises(ContractError):
        ExecutorProperty("PX", "this is formally proven", AssuranceKind.TESTED, "", "", "t", "")


def test_unmeasured_requires_a_why_not() -> None:
    for row in unmeasured():
        assert row.why_not.strip()
        assert "what would measure it" in row.why_not.lower() or "measure it" in row.why_not.lower()
    with pytest.raises(ContractError):
        ExecutorProperty("PX", "a thing", AssuranceKind.UNMEASURED, "", "", "", "")


def test_a_proven_row_without_a_mutation_is_refused() -> None:
    """The mutation is what makes 'proven by construction' falsifiable."""
    with pytest.raises(ContractError):
        ExecutorProperty("PX", "a thing", AssuranceKind.PROVEN_BY_CONSTRUCTION, "m:S", "", "", "")
    with pytest.raises(ContractError):
        ExecutorProperty("PX", "a thing", AssuranceKind.PROVEN_BY_CONSTRUCTION, "", "delete it", "", "")


def test_a_tested_row_without_a_test_name_is_refused() -> None:
    with pytest.raises(ContractError):
        ExecutorProperty("PX", "a thing", AssuranceKind.TESTED, "", "", "", "")


def test_the_assurance_counts_are_reported_not_assumed() -> None:
    """The counts are whatever they are; this pins the arithmetic, not the split."""
    table = counts()
    assert table["TOTAL"] == len(EXECUTOR_PROPERTIES)
    assert (
        table[AssuranceKind.PROVEN_BY_CONSTRUCTION.value]
        + table[AssuranceKind.TESTED.value]
        + table[AssuranceKind.UNMEASURED.value]
        == table["TOTAL"]
    )
    assert table["TOTAL"] == 15


def test_every_proven_mutation_is_an_exact_edit_that_still_applies() -> None:
    """A mutation that edits nothing leaves its test green and reads as "not broken".

    Each PROVEN row carries an exact edit whose anchor must occur exactly once in the
    current source; if another package moves the construction, this fails and the row
    has to be re-established rather than silently keeping its label. The runs themselves
    are exercised out of package by ``tests/test_stage5_gate.py``; P1, P2 and P3 are TESTED.
    """
    from pocketsec.stage5.assurance.properties import DOWNGRADED, MUTATION_EDITS, mutated_source

    assert set(MUTATION_EDITS) == {row.property_id for row in proven()}
    from pocketsec.stage5.assurance.properties import SENSITIVITY_EDITS

    # A sensitivity edit belongs to a TESTED row and never promotes it (F5-honesty).
    assert set(SENSITIVITY_EDITS) <= {row.property_id for row in assurance_properties.tested()}
    assert not set(SENSITIVITY_EDITS) & set(MUTATION_EDITS)
    for property_id, (path, _anchor, _replacement) in SENSITIVITY_EDITS.items():
        source = (REPO_ROOT / path).read_text(encoding="utf-8")
        assert mutated_source(property_id, source) != source, property_id
    for property_id, (path, _anchor, _replacement) in MUTATION_EDITS.items():
        source = (REPO_ROOT / path).read_text(encoding="utf-8")
        assert mutated_source(property_id, source) != source, property_id
    with pytest.raises(ContractError, match="only proven rows"):
        mutated_source("P14", "")
    with pytest.raises(ContractError, match="occurs 0 times"):
        mutated_source("P1", "no anchor here")
    for property_id in DOWNGRADED:
        assert assurance_properties.PROPERTIES_BY_ID[property_id].kind is AssuranceKind.TESTED


def test_every_property_cites_a_test_that_exists() -> None:
    """A ``test_name`` pointing at nothing is evidence that was never collected.

    Four PROVEN rows once cited a whole test *file*, which no mutation run can check
    against, and P13 cited a journal-chain test that never looked at a bundle digest.
    Every cited name must be ``file::function`` and the function must be defined there.
    """
    for row in EXECUTOR_PROPERTIES:
        if row.kind is AssuranceKind.UNMEASURED:
            continue
        path, _, function = row.test_name.partition("::")
        assert function, f"{row.property_id} cites a file, not a test: {row.test_name}"
        source = (REPO_ROOT / path).read_text(encoding="utf-8")
        assert re.search(rf"^def {re.escape(function)}\(", source, re.MULTILINE), (
            f"{row.property_id} cites {row.test_name}, which does not exist"
        )


def test_a_transaction_receipt_cannot_omit_whether_it_was_simulated() -> None:
    """P9's test, and the one its mutation breaks.

    ``host_kind`` and ``simulated`` must carry no default — a default is how a simulated
    receipt becomes a real one by omission three stages later — and a receipt whose two
    fields disagree must be unconstructible.
    """
    fields = {field.name: field for field in dataclasses.fields(TransactionReceipt)}
    for name in ("host_kind", "simulated"):
        assert fields[name].default is dataclasses.MISSING, f"{name} must not be defaulted"
        assert fields[name].default_factory is dataclasses.MISSING, name
    _rig, receipt = _executed(build_response_corpus(count=2, seed=SEED)[1], fixed_playbook)
    assert receipt.host_kind is HostKind.SIMULATED and receipt.simulated is True
    with pytest.raises(ContractError):
        dataclasses.replace(receipt, simulated=False)


def test_every_receipt_resolves_to_a_digest_in_the_bundle(monkeypatch: pytest.MonkeyPatch) -> None:
    """P13's test: evidence lineage survives every transaction that touched the host.

    The real gate is wrapped so every bundle it produced is kept. Each host-touching
    receipt must name one of those bundles by digest, the bundle must belong to the
    receipt's incident, and it must still carry every evidence digest the resolution's
    lineage cited — over every arm, on a corpus that includes evidence-destroying cases.
    """
    verdicts = _capture(monkeypatch, EvidencePreservationGate, "evaluate")
    receipts = _capture(monkeypatch, TransactionalExecutor, "execute")
    cases = [*build_response_corpus(count=COUNT, seed=SEED), *build_evidence_destroying_cases(count=COUNT, seed=SEED)]
    for arm_id, policy in {**BASELINES, REFERENCE_ARM_ID: reference_arm}.items():
        run_arm(policy, cases, baseline_id=arm_id, build_executor=_executor)
    bundles = {v.bundle.integrity_digest: v.bundle for v in verdicts if v.bundle is not None}
    lineage = {
        case.resolution.incident_id: {row["digest"] for row in case.resolution.evidence_lineage}
        for case in cases
    }
    touched = [receipt for receipt in receipts if receipt.reached_host()]
    assert touched, "no transaction reached the host, so the property was not exercised"
    for receipt in touched:
        bundle = bundles.get(receipt.evidence_bundle_digest)
        assert bundle is not None, f"{receipt.receipt_id} names no bundle the gate produced"
        assert bundle.incident_id == receipt.incident_id
        assert lineage[receipt.incident_id] <= {ref.digest for ref in bundle.evidence_refs}


def test_unearned_verification_language_finds_a_naked_claim_and_clears_a_backed_one() -> None:
    naked = "The rollback path is formally proven.\nNothing here cites anything."
    assert unearned_verification_language(naked)
    backed = (
        "pocketsec.stage5.executor.lease:Lease.expired\n"
        "reads only frozen fields, so lease expiry is proven by construction."
    )
    assert unearned_verification_language(backed) == ()
    # A path that is no longer a construction backs nothing: P2 was downgraded to TESTED
    # (finding S5-SEC-09), so "proven" beside its scanner is now an unearned claim.
    downgraded = (
        "pocketsec.stage5.operators.algebra:no_arbitrary_command_path\n"
        "returns no rows, so the no-shell property is proven by construction."
    )
    assert unearned_verification_language(downgraded) == ("2:proven",)


# --- the Stage 6 seam ---------------------------------------------------------


def _record(**overrides: Any) -> ResponseRecordV1:
    payload: dict[str, Any] = {
        "record_id": "REC-0001",
        "incident_id": "INC-0001",
        "epoch_id": 1,
        "resolution_id": "RES-0001",
        "plan_decision": "ACT",
        "receipts": (),
        "residuals": (),
        "effectiveness_rows": (),
        "melt_reports": (),
        "leases_expired": (),
        "sentinel_denials": (),
        "monitor_findings": (),
        "governor_spend": {"TOTAL": 3},
        "host_kind": "SIMULATED",
        "simulated": True,
        "truncations": (),
    }
    payload.update(overrides)
    return ResponseRecordV1(**payload)


def _simulated_row(**overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "receipt_id": "RCPT-1",
        "tx_id": "TX-1",
        "outcome": "COMMITTED_UNVERIFIED",
        "postconditions": [{"kind": "PROCESS_SUSPENDED", "satisfied": True, "observed": "ok"}],
        "host_kind": "SIMULATED",
        "simulated": True,
    }
    row.update(overrides)
    return row


def test_seam_authority_exemptions_has_exactly_four_members() -> None:
    """An exemption list that can grow silently is the trap this pins shut."""
    assert frozenset(
        {"operator_id", "operator_class", "authority", "rollback_operator_id"}
    ) == SEAM_AUTHORITY_EXEMPTIONS
    assert len(SEAM_AUTHORITY_EXEMPTIONS) == 4
    assert len(FORBIDDEN_SEAM_TOKENS) == 18


def test_response_record_refuses_a_stage5_class_name_key() -> None:
    record = _record(receipts=(_simulated_row(sentinel_verdict={"decision": "PASS"}),))
    with pytest.raises(ContractError, match="Stage 5 class names"):
        record.to_dict()


def test_response_record_refuses_an_unexempted_authority_key() -> None:
    """``action_id`` names an action, so the seam refuses it and ``tx_id`` is used."""
    record = _record(receipts=(_simulated_row(action_id="ACT-1"),))
    with pytest.raises(ContractError, match="authority-named keys"):
        record.to_dict()


def test_response_record_refuses_a_verified_outcome_with_an_unverifiable_postcondition() -> None:
    """``None`` means unverifiable, and unverifiable is not complete (§2, ADR-0004)."""
    record = _record(
        receipts=(
            _simulated_row(
                outcome=VERIFIED_OUTCOME,
                postconditions=[{"kind": "TRAJECTORY_REDUCED", "satisfied": None, "observed": "?"}],
            ),
        )
    )
    with pytest.raises(ContractError, match="unverifiable"):
        record.to_dict()


def test_response_record_accepts_a_verified_outcome_whose_postconditions_all_hold() -> None:
    """The refusal must be about the None, not about the outcome name."""
    record = _record(receipts=(_simulated_row(outcome=VERIFIED_OUTCOME),))
    assert record.to_dict()["receipts"][0]["outcome"] == VERIFIED_OUTCOME


def test_response_record_refuses_a_simulated_mismatch() -> None:
    """A simulator's record cannot become a real host's record by omission (ADR-0046)."""
    with pytest.raises(ContractError, match="simulated=False"):
        _record(simulated=False).to_dict()
    with pytest.raises(ContractError, match="simulated=False"):
        _record(receipts=(_simulated_row(simulated=False),)).to_dict()
    with pytest.raises(ContractError, match="omits"):
        _record(receipts=({"receipt_id": "R", "outcome": "ROLLED_BACK", "host_kind": "SIMULATED"},)).to_dict()


def test_response_record_requires_an_explicit_simulated_bool() -> None:
    with pytest.raises(ContractError):
        _record(simulated="yes")


def test_response_record_round_trips() -> None:
    record = _record(
        receipts=(_simulated_row(),),
        residuals=({"residual_distance": 0.25},),
        sentinel_denials=({"reason": "MISSION_INVARIANT"},),
        truncations=({"what": "candidate", "reason": "bounded"},),
    )
    payload = record.to_dict()
    rebuilt = ResponseRecordV1.from_dict(payload)
    assert rebuilt.to_dict() == payload
    assert rebuilt.digest() == record.digest()


def test_response_record_refuses_a_non_json_member() -> None:
    with pytest.raises(ContractError):
        _record(receipts=({"receipt_id": object(), "simulated": True},))


def test_write_record_returns_the_digest_and_refuses_a_bad_record(tmp_path: Path) -> None:
    record = _record(receipts=(_simulated_row(),))
    digest = write_record(record, tmp_path / "record.json")
    assert digest == record.digest()
    written = json.loads((tmp_path / "record.json").read_text(encoding="utf-8"))
    assert written == record.to_dict()
    bad = _record(simulated=False)
    with pytest.raises(ContractError):
        write_record(bad, tmp_path / "bad.json")
    assert not (tmp_path / "bad.json").exists(), "a refused record must never reach the disk"


def test_receipt_row_is_seam_safe_for_a_real_receipt() -> None:
    """The projection has to survive the seam for a receipt the executor actually produced."""
    _rig, receipt = _executed(build_response_corpus(count=2, seed=SEED)[1], fixed_playbook)
    row = receipt_row(receipt)
    record = _record(receipts=(row,))
    assert record.to_dict()["receipts"][0]["simulated"] is True
    # Authority and the undo path are fixed by the catalog entry; exporting None for
    # them told an auditor the most important facts were unknown.
    entry = CATALOG[receipt.operator_id]
    assert row["authority"] == str(entry.authority) and row["authority"] is not None
    assert row["rollback_operator_id"] == entry.rollback_operator_id is not None


def test_from_dict_judges_the_wire_value_rather_than_coercing_it() -> None:
    """``bool("false")`` is ``True``; a reader that coerced would invert the claim."""
    payload = _record(receipts=(_simulated_row(),)).to_dict()
    for field, bad in (("simulated", "false"), ("epoch_id", "1"), ("schema_id", "other.v1")):
        with pytest.raises(ContractError):
            ResponseRecordV1.from_dict({**payload, field: bad})
    with pytest.raises(ContractError, match="missing"):
        ResponseRecordV1.from_dict({k: v for k, v in payload.items() if k != "truncations"})


def test_an_evidence_refusal_is_recorded_before_anything_touches_the_host() -> None:
    """The preservation gate refuses first, and the record cannot leave the refusal out.

    ``build_record`` derives ``sentinel_denials`` from the receipts, so the refusal is in
    the record because the refusal happened — not because a caller remembered to list it.
    """
    case = build_evidence_destroying_cases(count=1, seed=SEED)[0]
    rig, receipt = _executed(case, always_isolate)
    assert receipt.outcome is Outcome.REFUSED_EVIDENCE
    assert not receipt.reached_host()
    assert rig.host.snapshot().to_dict() == rig.before.to_dict(), "the host must be untouched"
    record = build_record(
        record_id="REC-evidence",
        incident_id=receipt.incident_id,
        epoch_id=receipt.epoch_id,
        resolution_id=receipt.resolution_id,
        plan_decision="ACT",
        host_kind=HostKind.SIMULATED,
        receipts=(receipt,),
        governor_spend={"TOTAL": receipt.work_units},
    )
    (denial,) = record.to_dict()["sentinel_denials"]
    assert denial["outcome"] == "REFUSED_EVIDENCE" and denial["kernel_ran"] is False
    assert record.simulated is True
    with pytest.raises(ContractError, match="disagrees"):
        build_record(
            record_id="REC-mixed",
            incident_id="INC-some-other-incident",
            epoch_id=receipt.epoch_id,
            resolution_id=receipt.resolution_id,
            plan_decision="ACT",
            host_kind=HostKind.SIMULATED,
            receipts=(receipt,),
            governor_spend={},
        )


# --- resources ----------------------------------------------------------------


def test_within_target_is_none_when_nothing_was_measured() -> None:
    """Unmeasured is not within target, and the constructor refuses to represent the lie."""
    report = unmeasured_stage5_resources("no sampler on this host")
    assert report.within_target is None
    assert report.peak_rss_bytes is None
    assert report.over_peak_ceiling is None
    assert set(report.component_bytes) == set(STAGE5_COMPONENTS)
    with pytest.raises(ContractError, match="unmeasured is not within target"):
        Stage5ResourceReport(
            peak_rss_bytes=None,
            incremental_rss_bytes=None,
            component_bytes={},
            within_target=True,
            profile=None,
            loadavg=loadavg(),
            detail="a report that claims a pass it did not measure",
        )


def test_an_unmeasured_report_must_say_why() -> None:
    with pytest.raises(ContractError):
        unmeasured_stage5_resources("   ")


def test_over_budget_excludes_the_process_wide_aggregate_rows() -> None:
    """The fix for the defect above, asserted rather than trusted.

    A report whose process peak is far over §43's ceiling must still report an empty
    ``over_budget``, because that row is an aggregate of the whole interpreter and not a
    Stage 5 component. ``over_peak_ceiling`` is where that fact is reported instead.
    """
    report = Stage5ResourceReport(
        peak_rss_bytes=616_726_528,
        incremental_rss_bytes=1024,
        component_bytes={"peak_without_optional_lm": 616_726_528, "aegis_planning_state": 8},
        within_target=None,
        profile=None,
        loadavg=loadavg(),
        detail="a shared process holding every other stage's resident state",
    )
    assert report.over_budget == ()
    assert report.over_peak_ceiling is True
    assert set(AGGREGATE_COMPONENTS) <= set(STAGE5_COMPONENTS)


def test_a_report_refuses_a_component_the_architecture_does_not_budget() -> None:
    with pytest.raises(ContractError):
        Stage5ResourceReport(
            peak_rss_bytes=1,
            incremental_rss_bytes=1,
            component_bytes={"quantum_cache": 1},
            within_target=None,
            profile=None,
            loadavg=loadavg(),
            detail="probe",
        )


def test_measured_resources_come_from_the_stage0_sampler_and_stay_in_budget() -> None:
    """Real bytes over the whole loop, and only the figure attributable to Stage 5.

    ``peak_sampled_rss_bytes`` is the **whole interpreter's** peak, so inside a shared
    process it carries every other stage's resident state; it is asserted only to have
    been observed. ``incremental_rss_bytes`` is the Stage 5 figure and is asserted against
    §43's bound. The measured block runs the planner through the real executor, so the
    rollback row is a journal that was actually written to.
    """
    report = measure_stage5_resources(
        build_response_corpus(count=COUNT, seed=SEED), build_executor=_executor
    )
    assert report.peak_rss_bytes is not None and report.peak_rss_bytes > 0
    assert report.incremental_rss_bytes is not None
    assert report.incremental_rss_bytes <= STAGE5_NORMAL_INCREMENTAL_RSS_BYTES
    assert report.over_peak_ceiling is not None, "the peak was observed, so this is not None"
    measured = report.component_bytes
    for name in ("aegis_planning_state", "twin_dependency_state", "rollback_evidence_hot_state"):
        assert measured[name] is not None and measured[name] > 0, name
    assert report.over_budget == (), (
        "over_budget is a per-component verdict and excludes the two process-wide "
        "aggregate rows; a non-empty result here is a real Stage 5 component over §43"
    )
    assert report.within_target is None, "two §43 rows have no self-reported footprint"
    assert "full loop" in report.detail and "unmeasured rows" in report.detail
    assert report.loadavg[0] >= 0.0, "this host reports a load average"


def test_a_row_nothing_filled_is_unmeasured_not_zero() -> None:
    """A field-only pass writes no journal, so the rollback row is ``None``, never 0.

    An earlier revision reported the 0 bytes of a journal the measured block never
    touched — true of an unused structure, and read by every consumer as the footprint
    of a used one.
    """
    report = measure_stage5_resources(build_response_corpus(count=2, seed=SEED))
    assert report.component_bytes["rollback_evidence_hot_state"] is None
    assert report.component_bytes["twin_dependency_state"] is not None
    assert "field pass only" in report.detail
    # And the case the field pass cannot reach: a journal that exists but was never
    # written to — what a run whose planner never acted leaves behind.
    from pocketsec.stage5.executor.journal import RollbackJournal
    from pocketsec.stage5.resources import component_bytes

    empty = component_bytes(journal=RollbackJournal())
    assert empty["rollback_evidence_hot_state"] is None
    assert empty["aegis_planning_state"] is None, "no field was generated, so none is measured"


def test_the_budget_verdict_needs_every_row_and_fails_on_any_one_over() -> None:
    """The only path to ``within_target=True``, exercised directly because no corpus reaches it.

    Two §43 rows have no self-reported footprint, so a real measurement never has every
    row and ``within_target`` is always ``None``. The verdict function must still be
    right for the day those rows exist: every row at budget passes, any one row over
    fails, and a missing row is a refusal rather than a pass.
    """
    from pocketsec.stage5.resources import STAGE5_BUDGET_BYTES, _within_budget

    at_budget = dict(STAGE5_BUDGET_BYTES)
    assert _within_budget(at_budget) is True
    for name in STAGE5_BUDGET_BYTES:
        assert _within_budget({**at_budget, name: at_budget[name] + 1}) is False, name
    with pytest.raises(ContractError, match="UNMEASURED"):
        _within_budget({**at_budget, "simulation_workspace": None})


def test_measuring_no_cases_is_unmeasured_rather_than_zero() -> None:
    report = measure_stage5_resources(())
    assert report.within_target is None and report.peak_rss_bytes is None


# --- theory -------------------------------------------------------------------


def test_theory_has_no_unbound_terms() -> None:
    """A definition table nobody can execute is prose, and prose has cost real answers."""
    assert unbound_terms() == ()
    assert len(DEFINITIONS) >= 30


def test_theory_covers_every_section_it_claims() -> None:
    cited = " ".join(sections_covered())
    for section in ("§3", "§7", "§10", "§11", "§23", "§26"):
        assert section in cited


def test_every_definition_names_a_falsifier() -> None:
    for entry in DEFINITIONS:
        assert entry.falsified_if.strip(), entry.term
        assert entry.measurable_as.strip(), entry.term


def test_the_binding_resolver_raises_on_a_name_that_does_not_exist() -> None:
    """Missing and bound-to-None must stay distinguishable."""
    with pytest.raises((ImportError, AttributeError)):
        resolve_binding("pocketsec.stage5.safe.action_field.NoSuchThing")


def test_the_six_minimum_intervention_terms_are_never_summed() -> None:
    """§11's six terms are an objective vector, not a score.

    §12 says AEGIS removes dominated actions *first*; a scalarisation would hide the
    trade-off the frontier exists to expose. This is the AST check that keeps the claim
    true across the whole package rather than in a docstring.
    """
    assert len(MEI_TERM_ATTRIBUTES) == 6
    assert mei_terms_summed(STAGE5_ROOT) == ()


def test_the_never_summed_check_catches_its_own_violation(tmp_path: Path) -> None:
    """A rule that cannot catch its own negative fixture is enforcing nothing."""
    offender = tmp_path / "offender.py"
    offender.write_text(
        "def score(c):\n    return c.scope_size + c.expected_operational_delta\n",
        encoding="utf-8",
    )
    assert mei_terms_summed(tmp_path)


# --- §4.9 Rule A: the key spaces the ablation joins ---------------------------


def test_every_optional_core_id_maps_to_a_flag_the_planner_understands() -> None:
    """The ablation's key-space join, asserted structurally identical.

    G5.14 joins ``AblationRow.core_id`` to ``core_ids.OPTIONAL_IDS`` and reads each row's
    verdict. That join has two key spaces — the SAFE-F core ids and ``PlannerConfig``'s
    flag names — and Stage 2 lost a whole result to a join between two key spaces that
    could never match (S2-FC-01). §4.9 Rule A therefore makes this test mandatory: every
    OPTIONAL core id must name a flag the planner actually has an off switch for, and
    every flag the ablation can set must be reachable from a core id or be explicitly
    listed as unmapped with a reason.
    """
    from pocketsec.stage5.aegis.planner import ABLATION_FLAG_FIELDS, UNMAPPED_PLANNER_FLAGS
    from pocketsec.stage5.core_ids import ABLATION_FLAGS, OPTIONAL_IDS

    assert set(ABLATION_FLAGS) == set(OPTIONAL_IDS), "every OPTIONAL id needs a flag"
    assert set(ABLATION_FLAGS.values()) <= set(ABLATION_FLAG_FIELDS), (
        "an OPTIONAL core id names a flag PlannerConfig does not have, so its ablation "
        "would silently measure nothing"
    )
    unreachable = set(ABLATION_FLAG_FIELDS) - set(ABLATION_FLAGS.values()) - set(
        UNMAPPED_PLANNER_FLAGS
    )
    assert not unreachable, f"flags reachable by neither a core id nor the unmapped list: {unreachable}"


def test_the_ablation_covers_every_optional_core_id() -> None:
    """A row per OPTIONAL id, joined by core id rather than counted.

    Stage 2's G2.12 read "1 of 12" only after a defect-repair wave replaced a bare row
    count with a join. This runs the real ablation for every OPTIONAL id's flag and
    asserts each produced a row bearing that id — which is the join, exercised.
    """
    from pocketsec.stage5.core_ids import ABLATION_FLAGS, OPTIONAL_IDS

    cases = build_response_corpus(count=2, seed=SEED)
    seen: dict[str, AblationRow] = {}
    for core_id in OPTIONAL_IDS:
        row = run_ablation(
            cases, flag=ABLATION_FLAGS[core_id], build_executor=_executor, core_id=core_id
        )
        seen[core_id] = row
    assert set(seen) == set(OPTIONAL_IDS)
    for core_id, row in seen.items():
        assert row.core_id == core_id
        assert row.verdict in set(AblationVerdict)


def test_the_unbuilt_baselines_map_onto_the_closed_reason_set() -> None:
    """An absent baseline nobody wrote down becomes one somebody assumes was beaten."""
    from pocketsec.stage5.labs.baselines import UNBUILT_BASELINES
    from pocketsec.stage5.labs.fifty_experiments import UNBUILT_BASELINE_REASONS

    assert {row.baseline_id for row in UNBUILT_BASELINES} == set(UNBUILT_BASELINE_REASONS)
    for row in UNBUILT_BASELINES:
        assert UNBUILT_BASELINE_REASONS[row.baseline_id] in set(BlockedReason)
        assert row.why_not.strip()


def test_an_arm_counts_executor_work_once() -> None:
    """Finding F10: executor spend was counted twice in ``BaselineOutcome.work_units``.

    The executor spends ``HOST_CALL`` on ``rig.governor``; ``_score_receipt`` added the
    receipt's delta and ``run_arm`` then added the whole ``rig.governor`` TOTAL, which
    already contains it. The arm's figure must equal the two governors' totals exactly.
    """
    cases = build_response_corpus(count=COUNT, seed=SEED)
    hostile = next(case for case in cases if not case.truth.benign_admin)
    totals: list[int] = []

    def observe(rig: BaselineRig) -> None:
        totals.append(rig.governor.spend_report()["TOTAL"]
                      + rig.planner_governor.spend_report()["TOTAL"])

    outcome = run_arm(fixed_playbook, [hostile], baseline_id="B2", build_executor=_executor,
                      observe=observe)
    assert outcome.actions_taken >= 1, "the check needs a transaction that spent work"
    assert outcome.work_units == sum(totals)


def test_incremental_rss_is_never_negative_when_the_block_frees_memory() -> None:
    """Pins the gate crash of 2026-09-26: end RSS below start RSS gave a negative
    ``normal_incremental_rss`` and ``component_bytes`` raised ContractError, so the
    Stage 5 gate died on whichever run the allocator returned pages."""
    from dataclasses import replace

    from pocketsec.stage0.benchmark.resource_metrics import ResourceSampler
    from pocketsec.stage5.resources import component_bytes, incremental_rss

    with ResourceSampler() as sampler:
        pass
    base = sampler.result(events_processed=1, startup_seconds=None)
    if base.idle_rss_bytes is None:
        assert incremental_rss(base) is None
        return
    start = base.idle_rss_bytes
    shrank = replace(base, delta_rss_bytes=-4096, peak_sampled_rss_bytes=start)
    assert incremental_rss(shrank) == 0
    component_bytes(incremental_rss_bytes=incremental_rss(shrank))
    spiked = replace(base, delta_rss_bytes=-4096, peak_sampled_rss_bytes=start + 8192)
    assert incremental_rss(spiked) == 8192
    unread = replace(base, idle_rss_bytes=None)
    assert incremental_rss(unread) is None
