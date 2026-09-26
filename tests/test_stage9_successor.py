"""Stage 9 successor package (D9.11, D9.17): DAEDALUS, the proof-carrying successor, the
lab registry's rollback, and the one Stage 6 exit.

Every test is named after the invariant it protects. The Stage 6 gateway is a REAL
``QuarantineGateway`` bound to ``genesis_state``, built HERE (the Stage 7 lab precedent,
ADR-0061); runtime code never constructs one. The splits are tiny ambiguous-corpus
compilations (count 6/12) so the file runs in seconds: they test behaviour, not quality.
"""

from __future__ import annotations

import ast
import copy
import dataclasses
import json
import math
from pathlib import Path
from typing import Any

import pytest

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.contracts.threat_prediction_v1 import FORBIDDEN_AUTHORITY_FIELDS
from pocketsec.stage1.epoch.model import Epoch, SystemIdentity
from pocketsec.stage1.labs.ambiguous_corpus import build_ambiguous_corpus
from pocketsec.stage3.bytecode.isa import load_sets
from pocketsec.stage3.bytecode.verifier import verify
from pocketsec.stage6.capsule.experience_capsule import LabelOrigin, SourceClass
from pocketsec.stage6.capsule.quarantine import QuarantineGateway, QuarantineVerdict
from pocketsec.stage6.fossils.lineage import KnowledgeLineageDAG
from pocketsec.stage6.memory.semantic import genesis_state
from pocketsec.stage6.provenance.ledger import ProvenanceLedger
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
from pocketsec.stage9.daedalus.synthesizer import (
    PCB_MASK_DOMAIN,
    SPECIALIZE_MUTATION,
    lower_to_pcb,
    permute_actor_slots_reversed,
    specialize,
    synthesize,
)
from pocketsec.stage9.genome.computational import ComputationalGenomeV1, build_genome
from pocketsec.stage9.genome.expressibility import hand_designed_genomes, phi_oracle_genome
from pocketsec.stage9.labs.splits import CompiledVariant, compile_scenarios, split_key
from pocketsec.stage9.ontogenesis.fitness import (
    EvaluationSuite,
    FitnessRecord,
    evaluate,
    scores_digest,
    session_scores,
)
from pocketsec.stage9.successor import stage6_exit
from pocketsec.stage9.successor.proof_carrying import (
    MAX_COUNTEREXAMPLES,
    CandidateRegistry,
    ComputationContract,
    ProofCarryingSuccessorV1,
    build_successor,
    content_digest,
    tampered_successor,
)
from pocketsec.stage9.successor.stage6_exit import (
    MAX_EXIT_CAPSULES,
    Stage6Exit,
    exit_provenance,
)

IDENTITY = SystemIdentity(kernel_id="k-stage9-lab")
F, INT, B = IRType.FLOAT, IRType.INT, IRType.BOOL


def _n(kind: NodeKind, type_: IRType, **kw: Any) -> IRNode:
    return IRNode(kind=kind, type=type_, **kw)


def _genome(update: tuple[IRNode, ...], outputs: tuple[int, ...], readout: tuple[IRNode, ...],
            registers: tuple[RegisterSpec, ...] = (RegisterSpec(F),),
            aggregation: SessionAggregation = SessionAggregation.MAX,
            min_events: int = 1) -> ComputationalGenomeV1:
    return build_genome(
        registers=registers,
        update=IRProgram(ProgramPhase.UPDATE, update, outputs),
        readout=IRProgram(ProgramPhase.READOUT, readout, (len(readout) - 1,)),
        aggregation=aggregation, min_events_for_score=min_events,
    )


REG0 = _n(NodeKind.REG, F, index=0)
READ_R0 = (REG0,)
CONST_READOUT = (_n(NodeKind.CONST, F, value=0.0),)


def _variant(count: int, seed: int, *, keep: bool = False) -> CompiledVariant:
    return compile_scenarios(build_ambiguous_corpus(count=count, seed=seed),
                             key=split_key(count=count, seed=seed), keep_results=keep)


@pytest.fixture(scope="module")
def train() -> CompiledVariant:
    return _variant(6, 3)


@pytest.fixture(scope="module")
def heldout() -> CompiledVariant:
    return _variant(6, 11, keep=True)


def _records(genome: ComputationalGenomeV1, train: CompiledVariant,
             heldout: CompiledVariant) -> tuple[FitnessRecord, FitnessRecord]:
    meter = WorkMeter(budget=10**9)
    return (evaluate(genome, EvaluationSuite(name="train", clean=train, attacked=()), meter=meter),
            evaluate(genome, EvaluationSuite(name="heldout", clean=heldout, attacked=()),
                     meter=meter))


@pytest.fixture(scope="module")
def successor(train: CompiledVariant, heldout: CompiledVariant) -> ProofCarryingSuccessorV1:
    genome, parent = hand_designed_genomes()["H2"], phi_oracle_genome()
    train_record, heldout_record = _records(genome, train, heldout)
    return build_successor(
        synthesize(genome, heldout.dataset), train=train_record, heldout=heldout_record,
        parent=parent, parent_scores_digest=scores_digest(session_scores(parent, heldout.dataset)),
        counterexamples=[s.sample_id for s in heldout.dataset.samples[:2]], invariance=(),
        measured=None, experiment_id=None, base_rate=heldout.dataset.base_rate,
    )


def _resigned(payload: dict[str, Any]) -> dict[str, Any]:
    payload["signatures"] = [["sha256-content", content_digest(payload)]]
    return payload


# --- DAEDALUS: specialisation --------------------------------------------------------------------


def _foldable_genome() -> ComputationalGenomeV1:
    """r0' = MAX(r0, MUL(F[73], DIV(6, 3))) plus a dead ABS(DELTA_PHI) branch."""
    update = (
        REG0, _n(NodeKind.INPUT, F, source=InputSource.FEATURE, index=73),
        _n(NodeKind.CONST, F, value=6.0), _n(NodeKind.CONST, F, value=3.0),
        _n(NodeKind.APPLY, F, primitive="DIV", args=(2, 3)),
        _n(NodeKind.APPLY, F, primitive="MUL", args=(1, 4)),
        _n(NodeKind.INPUT, F, source=InputSource.DELTA_PHI),
        _n(NodeKind.APPLY, F, primitive="ABS", args=(6,)),
        _n(NodeKind.APPLY, F, primitive="MAX", args=(0, 5)),
    )
    return _genome(update, (8,), READ_R0)


def test_specialize_folds_constants_and_drops_dead_nodes_with_identical_scores(
        heldout: CompiledVariant) -> None:
    genome = _foldable_genome()
    special = specialize(genome)
    primitives = {n.primitive for n in special.update.nodes}
    assert "DIV" not in primitives and "ABS" not in primitives
    assert len(special.update.nodes) < len(genome.update.nodes)
    assert special.bounds.update_wu_per_event < genome.bounds.update_wu_per_event
    assert special.digest != genome.digest
    assert special.parent_digests == (genome.digest,)
    assert SPECIALIZE_MUTATION in special.mutation
    assert session_scores(special, heldout.dataset) == session_scores(genome, heldout.dataset)


def test_specialize_returns_the_same_genome_when_there_is_nothing_to_do() -> None:
    genome = phi_oracle_genome()
    assert specialize(genome) is genome


def test_specialize_clamps_a_folded_value_exactly_as_the_phenotype_does(
        heldout: CompiledVariant) -> None:
    big = _n(NodeKind.CONST, F, value=9e11)
    update = (REG0, big, big, _n(NodeKind.APPLY, F, primitive="ADD", args=(1, 2)),
              _n(NodeKind.APPLY, F, primitive="MAX", args=(0, 3)))
    genome = _genome(update, (4,), READ_R0)
    special = specialize(genome)
    assert any(n.kind is NodeKind.CONST and n.value == 1e12 for n in special.update.nodes)
    assert session_scores(special, heldout.dataset) == session_scores(genome, heldout.dataset)


def test_specialize_never_deletes_a_side_table_primitive(heldout: CompiledVariant) -> None:
    """FIRST_SEEN mutates a per-session table: a node whose value is unused still counts."""
    mask = _n(NodeKind.INPUT, INT, source=InputSource.STATE_DELTA_MASK)
    update = (REG0, mask, _n(NodeKind.APPLY, B, primitive="FIRST_SEEN", args=(1,)),
              _n(NodeKind.APPLY, F, primitive="POPCOUNT", args=(1,)),
              _n(NodeKind.APPLY, F, primitive="MAX", args=(0, 3)))
    genome = _genome(update, (4,), READ_R0)
    special = specialize(genome)
    assert "FIRST_SEEN" in {n.primitive for n in special.update.nodes}
    assert session_scores(special, heldout.dataset) == session_scores(genome, heldout.dataset)


# --- DAEDALUS: PCB lowering ----------------------------------------------------------------------


def test_lower_to_pcb_reports_the_phi_oracle_not_expressible_with_named_reasons() -> None:
    lowering = lower_to_pcb(phi_oracle_genome())
    assert lowering.expressible is False
    assert lowering.verifier_report is None and lowering.program is None
    named = " | ".join(lowering.unsupported)
    assert "REG r0" in named and "MAX" in named and "FEATURE[73]" in named
    assert lowering.reason.startswith("not expressible in PCB (M0.10)")


def test_lower_to_pcb_names_every_arithmetic_min_div_and_popcount_op() -> None:
    mask = _n(NodeKind.INPUT, INT, source=InputSource.STATE_DELTA_MASK)
    update = (REG0, mask, _n(NodeKind.APPLY, F, primitive="POPCOUNT", args=(1,)),
              _n(NodeKind.CONST, F, value=2.0),
              _n(NodeKind.APPLY, F, primitive="DIV", args=(2, 3)),
              _n(NodeKind.APPLY, F, primitive="ADD", args=(0, 4)),
              _n(NodeKind.APPLY, F, primitive="MIN", args=(5, 3)))
    lowering = lower_to_pcb(_genome(update, (6,), READ_R0))
    named = " | ".join(lowering.unsupported)
    for op in ("POPCOUNT", "DIV", "ADD", "MIN", "REG r0"):
        assert op in named, op
    assert lowering.expressible is False


def _mask_genome(value: int, *, primitive: str = "EQ_I") -> ComputationalGenomeV1:
    """Register-free: r0' = EQ_I(AND(mask, K), K) (or STATE_DELTA(mask, K)); readout 0.0."""
    mask = _n(NodeKind.INPUT, INT, source=InputSource.STATE_DELTA_MASK)
    const = _n(NodeKind.CONST, INT, value=value)
    if primitive == "EQ_I":
        update = (mask, const, _n(NodeKind.APPLY, INT, primitive="AND", args=(0, 1)),
                  _n(NodeKind.APPLY, B, primitive="EQ_I", args=(2, 1)))
    else:
        update = (mask, const, _n(NodeKind.APPLY, B, primitive="STATE_DELTA", args=(0, 1)))
    return _genome(update, (len(update) - 1,), CONST_READOUT,
                   registers=(RegisterSpec(B, init=False),))


def test_lower_to_pcb_lowers_a_register_free_mask_genome_through_stage3_verifier() -> None:
    lowering = lower_to_pcb(_mask_genome(0x1F0))
    assert lowering.expressible is True, lowering.reason
    assert lowering.program is not None and verify(lowering.program).ok
    assert lowering.verifier_report is not None and lowering.verifier_report["ok"] is True
    (members,) = load_sets(lowering.program.table)
    # Independent expectation, written by hand: all of bits 4..8 raised.
    expected = {m for m in range(PCB_MASK_DOMAIN) if m & 0x1F0 == 0x1F0}
    assert set(members) == expected and len(expected) == 16
    assert "never a session scorer" in lowering.reason


def test_lower_to_pcb_refuses_a_predicate_too_wide_for_a_pcb_set_literal() -> None:
    lowering = lower_to_pcb(_mask_genome(3, primitive="STATE_DELTA"))
    assert lowering.expressible is False
    assert any("256 of 512" in reason for reason in lowering.unsupported)


# --- DAEDALUS: synthesis -------------------------------------------------------------------------


def test_synthesize_passes_unit_and_metamorphic_checks_on_h2(heldout: CompiledVariant) -> None:
    system = synthesize(hand_designed_genomes()["H2"], heldout.dataset)
    assert system.unit_checks_passed, system.unit_checks
    report = system.metamorphic
    assert report.sessions == len(heldout.dataset.samples)
    assert report.deterministic and report.specialization_preserves_scores
    assert report.actor_slot_permutation_invariant is True
    assert system.pcb.expressible is False
    assert system.phenotype_digest == system.specialized.phenotype().digest


def test_synthesize_specialises_and_proves_scores_preserved(heldout: CompiledVariant) -> None:
    genome = _foldable_genome()
    system = synthesize(genome, heldout.dataset)
    assert system.genome_digest == genome.digest != system.specialized.digest
    assert system.metamorphic.specialization_preserves_scores
    assert system.metamorphic.specialization_score_changes == 0


def test_synthesize_refuses_an_empty_sample(heldout: CompiledVariant) -> None:
    empty = dataclasses.replace(heldout.dataset, samples=())
    with pytest.raises(ContractError, match="vacuously"):
        synthesize(phi_oracle_genome(), empty)


def test_the_abstention_path_is_reachable_and_checked(heldout: CompiledVariant) -> None:
    genome = _genome(phi_oracle_genome().update.nodes, (2,), READ_R0, min_events=5)
    system = synthesize(genome, heldout.dataset)
    assert dict(system.unit_checks)["abstains_below_min_events"] is True
    assert genome.phenotype().run_session(heldout.dataset.samples[0].steps[:4]).score is None


def test_actor_slot_permutation_actually_relabels_multi_lineage_sessions(
        heldout: CompiledVariant) -> None:
    """The metamorphic check fires only if the permutation moves something."""
    permuted = permute_actor_slots_reversed(heldout.dataset)
    moved = 0
    for before, after in zip(heldout.dataset.samples, permuted.samples, strict=True):
        slots = [s.actor_slot for s in before.steps]
        assert sorted(set(slots)) == sorted({s.actor_slot for s in after.steps})
        assert [s.features for s in before.steps] == [s.features for s in after.steps]
        moved += slots != [s.actor_slot for s in after.steps]
    assert moved > 0


# --- the proof-carrying successor ----------------------------------------------------------------


def test_successor_round_trip_is_exact(successor: ProofCarryingSuccessorV1) -> None:
    payload = successor.to_dict()
    again = ProofCarryingSuccessorV1.from_dict(json.loads(json.dumps(payload)))
    assert again == successor and again.to_dict() == payload
    assert again.content_digest == successor.content_digest
    assert successor.contracts.max_event_latency_us is None
    assert successor.security_metrics["base_rate"] is not None
    assert successor.rollback_artifact.parent_digest == phi_oracle_genome().digest


def test_every_one_of_four_tamperings_is_refused(successor: ProofCarryingSuccessorV1) -> None:
    finding = tampered_successor(successor)
    assert finding.kind == "DEFENCE" and finding.total == 4
    assert finding.fired == finding.total, finding.detail
    assert not finding.inert and "ACCEPTED" not in finding.detail


def test_each_tampering_written_by_hand_is_refused(successor: ProofCarryingSuccessorV1) -> None:
    """Independent of tampered_successor: the test builds each edit itself."""
    base = successor.to_dict()
    metric = copy.deepcopy(base)
    metric["security_metrics"]["heldout_worst_case_ap"] = 0.99
    parent = copy.deepcopy(base)
    parent["rollback_artifact"]["parent_genome"] = hand_designed_genomes()["H1"].to_dict()
    genome = copy.deepcopy(base)
    genome["computational_genome"] = hand_designed_genomes()["H1"].to_dict()
    signature = copy.deepcopy(base)
    signature["signatures"] = [["sha256-content", "sha256:" + "f" * 64]]
    for payload, check in ((metric, "signature"), (parent, "parent_digest"),
                           (genome, "genome_digest"), (signature, "signature")):
        with pytest.raises(ContractError, match=check):
            ProofCarryingSuccessorV1.from_dict(payload)


def test_a_resigned_edit_is_accepted_integrity_not_authenticity(
        successor: ProofCarryingSuccessorV1) -> None:
    """ADR-0088's honest limit, pinned: the content digest has no key, so an author who
    recomputes it passes. If this ever fails, someone added authenticity: update the ADR."""
    edited = _resigned(copy.deepcopy(successor.to_dict()))
    edited["security_metrics"]["heldout_worst_case_ap"] = 0.99
    accepted = ProofCarryingSuccessorV1.from_dict(_resigned(edited))
    assert accepted.security_metrics["heldout_worst_case_ap"] == 0.99


@pytest.mark.parametrize("key", ["suggested_action", "quarantine_hint", "privilege"])
def test_an_authority_named_key_anywhere_is_refused_even_when_signed(
        successor: ProofCarryingSuccessorV1, key: str) -> None:
    payload = copy.deepcopy(successor.to_dict())
    payload["uncertainty_profile"] = {**payload["uncertainty_profile"], "nested": {key: 1}}
    with pytest.raises(ContractError, match="authority"):
        ProofCarryingSuccessorV1.from_dict(_resigned(payload))


def test_a_non_json_payload_is_refused(successor: ProofCarryingSuccessorV1) -> None:
    payload = copy.deepcopy(successor.to_dict())
    payload["security_metrics"]["gap"] = math.nan
    with pytest.raises(ContractError):
        ProofCarryingSuccessorV1.from_dict(payload)
    payload = copy.deepcopy(successor.to_dict())
    payload["measured_resources"] = {"peak": {1, 2}}
    with pytest.raises(ContractError, match="strict JSON"):
        ProofCarryingSuccessorV1.from_dict(payload)


def test_a_weakened_contract_is_refused_even_when_signed(
        successor: ProofCarryingSuccessorV1) -> None:
    payload = copy.deepcopy(successor.to_dict())
    payload["contracts"]["max_rss"] = 16
    with pytest.raises(ContractError, match="max_rss"):
        ProofCarryingSuccessorV1.from_dict(_resigned(payload))


def test_the_contract_check_catches_an_over_budget_genome() -> None:
    contract = ComputationContract.for_genome(phi_oracle_genome())
    assert contract.check(phi_oracle_genome()) == ()
    wide = tuple(RegisterSpec(F, ring=8) for _ in range(4))
    update = (REG0, *(_n(NodeKind.REG, F, index=i) for i in range(1, 4)))
    bigger = _genome(update, (0, 1, 2, 3), READ_R0, registers=wide)
    violations = contract.check(bigger)
    assert any(v.startswith("max_rss") for v in violations), violations
    h2 = contract.check(hand_designed_genomes()["H2"])
    assert any("undeclared inputs ['STATE_DELTA_MASK']" in v for v in h2)


def test_the_contract_refuses_weakened_or_guessed_fields() -> None:
    contract = ComputationContract.for_genome(phi_oracle_genome())
    shortened = dataclasses.replace(
        contract, forbidden_authority_edges=tuple(sorted(FORBIDDEN_AUTHORITY_FIELDS))[1:])
    assert any("weakened" in v for v in shortened.check(phi_oracle_genome()))
    other = dataclasses.replace(contract, failure_behavior="GUESS")
    assert any("failure_behavior" in v for v in other.check(phi_oracle_genome()))
    for latency in (0.0, math.nan, -1.0):
        with pytest.raises(ContractError, match="UNMEASURED"):
            dataclasses.replace(contract, max_event_latency_us=latency)


def test_counterexamples_are_bounded(successor: ProofCarryingSuccessorV1) -> None:
    payload = copy.deepcopy(successor.to_dict())
    payload["counterexample_suite"] = [f"s{i}" for i in range(MAX_COUNTEREXAMPLES + 1)]
    with pytest.raises(ContractError, match="MAX_COUNTEREXAMPLES"):
        ProofCarryingSuccessorV1.from_dict(_resigned(payload))


def test_build_successor_truncates_counterexamples_and_says_so(
        train: CompiledVariant, heldout: CompiledVariant) -> None:
    genome, parent = hand_designed_genomes()["H2"], phi_oracle_genome()
    train_record, heldout_record = _records(genome, train, heldout)
    built = build_successor(
        synthesize(genome, heldout.dataset), train=train_record, heldout=heldout_record,
        parent=parent, parent_scores_digest="sha256:" + "0" * 64,
        counterexamples=[f"s{i:03d}" for i in range(MAX_COUNTEREXAMPLES + 6)], invariance=(),
        measured=None, experiment_id=None)
    assert len(built.counterexample_suite) == MAX_COUNTEREXAMPLES
    assert any("6 counterexample(s)" in d for d in built.failure_domains)
    assert built.security_metrics["base_rate"] is None  # unmeasured, never guessed


def test_build_successor_refuses_metrics_measured_on_another_genome(
        train: CompiledVariant, heldout: CompiledVariant) -> None:
    train_record, heldout_record = _records(hand_designed_genomes()["H1"], train, heldout)
    with pytest.raises(ContractError, match="not this genome"):
        build_successor(
            synthesize(hand_designed_genomes()["H2"], heldout.dataset), train=train_record,
            heldout=heldout_record, parent=phi_oracle_genome(),
            parent_scores_digest="sha256:" + "0" * 64, counterexamples=(), invariance=(),
            measured=None, experiment_id=None)


# --- rollback in Stage 9's own lab registry ------------------------------------------------------


def test_install_then_rollback_restores_byte_identical_heldout_scores(
        successor: ProofCarryingSuccessorV1, heldout: CompiledVariant) -> None:
    registry = CandidateRegistry()
    receipt = registry.install(successor)
    installed = registry.active()
    assert installed is not None and installed.digest == successor.genome_digest
    parent_digest = successor.rollback_artifact.parent_scores_digest
    # The install mattered: the successor scores differently from its parent.
    assert scores_digest(session_scores(installed, heldout.dataset)) != parent_digest
    restored = registry.rollback(receipt)
    assert registry.active() is restored
    assert restored.digest == successor.rollback_artifact.parent_digest
    assert scores_digest(session_scores(restored, heldout.dataset)) == parent_digest


def test_rollback_refuses_a_superseded_a_repeated_or_an_evicted_install(
        successor: ProofCarryingSuccessorV1) -> None:
    registry = CandidateRegistry(capacity=2)
    first, second = registry.install(successor), registry.install(successor)
    assert second.previous_digest == first.installed_digest
    registry.install(successor)
    assert len(registry) == 2 and registry.evictions == 1
    with pytest.raises(ContractError, match="evicted"):
        registry.rollback(first)
    with pytest.raises(ContractError, match="active"):
        registry.rollback(second)
    latest = registry.history()[-2]
    assert latest.kind == "INSTALL"


def test_rollback_cannot_be_repeated(successor: ProofCarryingSuccessorV1) -> None:
    registry = CandidateRegistry()
    receipt = registry.install(successor)
    registry.rollback(receipt)
    with pytest.raises(ContractError):
        registry.rollback(receipt)


def test_the_registry_reverifies_an_in_memory_tampered_successor(
        successor: ProofCarryingSuccessorV1) -> None:
    forged = copy.copy(successor)
    object.__setattr__(forged, "genome_digest", "sha256:" + "a" * 64)
    with pytest.raises(ContractError):
        CandidateRegistry().install(forged)


def test_the_registry_holds_no_more_than_its_bound(successor: ProofCarryingSuccessorV1) -> None:
    registry = CandidateRegistry(capacity=3)
    for _ in range(10):
        registry.install(successor)
    assert len(registry) == 3 and registry.evictions == 7
    assert len(registry.history()) <= 4 * 3
    with pytest.raises(ContractError):
        CandidateRegistry(capacity=10_000)


# --- the one Stage 6 exit ------------------------------------------------------------------------


class _SpyGateway(QuarantineGateway):
    """A REAL gateway that also records what it was offered and what it answered."""

    def __init__(self) -> None:
        super().__init__(ledger=ProvenanceLedger(), lineage=KnowledgeLineageDAG())
        state = genesis_state(identity=IDENTITY)
        self.bind_trusted_view(lambda: state)
        self.offered: list[Any] = []
        self.answered: list[QuarantineVerdict] = []

    def admit(self, capsule: Any) -> QuarantineVerdict:
        self.offered.append(capsule)
        verdict = super().admit(capsule)
        self.answered.append(verdict)
        return verdict


def _epoch() -> Epoch:
    return Epoch(epoch_id=1, identity=IDENTITY, key=IDENTITY.key(), opened_at_ns=0)


def test_stage6_exit_offers_exactly_the_capsules_built_and_records_verdicts_verbatim(
        successor: ProofCarryingSuccessorV1, heldout: CompiledVariant) -> None:
    gateway = _SpyGateway()
    receipt = Stage6Exit(gateway).hand_over(successor, evidence=heldout.results,
                                           epoch=_epoch(), sequence=100)
    assert receipt.offered == len(gateway.offered) == len(heldout.results) > 0
    assert receipt.unbuilt == () and receipt.truncated_evidence == 0
    assert receipt.verdicts == tuple(
        (v.capsule_id, v.bucket.value, v.reasons) for v in gateway.answered)
    assert receipt.successor_digest == successor.content_digest
    expected = exit_provenance(successor.content_digest)
    for capsule in gateway.offered:
        assert capsule.source_provenance == expected
        assert capsule.source_provenance.source_class is SourceClass.DERIVED_INFERENCE
        assert capsule.source_provenance.label_origin is LabelOrigin.NONE
        assert capsule.label is None


def test_stage6_exit_offers_at_most_eight_and_counts_the_rest(
        successor: ProofCarryingSuccessorV1) -> None:
    evidence = _variant(12, 11, keep=True).results
    assert len(evidence) > MAX_EXIT_CAPSULES
    gateway = _SpyGateway()
    exit_ = Stage6Exit(gateway)
    receipt = exit_.hand_over(successor, evidence=evidence, epoch=_epoch(), sequence=0)
    assert receipt.offered == len(gateway.offered) == MAX_EXIT_CAPSULES
    assert receipt.truncated_evidence == len(evidence) - MAX_EXIT_CAPSULES
    assert exit_.offered_total == MAX_EXIT_CAPSULES


def test_stage6_exit_refuses_anything_but_a_real_gateway() -> None:
    with pytest.raises(ContractError):
        Stage6Exit(object())  # type: ignore[arg-type]


def test_stage6_exit_refuses_a_tampered_successor_before_offering_anything(
        successor: ProofCarryingSuccessorV1, heldout: CompiledVariant) -> None:
    forged = copy.copy(successor)
    object.__setattr__(forged, "genome_digest", "sha256:" + "b" * 64)
    gateway = _SpyGateway()
    with pytest.raises(ContractError):
        Stage6Exit(gateway).hand_over(forged, evidence=heldout.results, epoch=_epoch(),
                                      sequence=0)
    assert gateway.offered == []


def test_stage6_exit_touches_the_gateway_only_through_admit() -> None:
    """AST: every use of the stored gateway is ``.admit``; the module builds no gateway."""
    tree = ast.parse(Path(stage6_exit.__file__).read_text(encoding="utf-8"))
    uses = [node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Attribute) and node.value.attr == "_gateway"]
    assert uses == ["admit"]
    built = [node for node in ast.walk(tree) if isinstance(node, ast.Call)
             and isinstance(node.func, ast.Name) and node.func.id == "QuarantineGateway"]
    assert built == []
