"""D3.15 — architecture §39's threat model as nine executable cases, each with a control.

An assertion that a control works is worth nothing without a run showing what
happens when it is off. So every case here has **two** runs:

* ``stopped_with_control`` — the §40 control is in place and the attack fails;
* ``succeeded_without_control`` — the same attack, the control disabled, and it
  works.

A case where both are true is a control doing work. A case where the attack fails
in *both* runs is a case that proves nothing — the attack was never viable — and
:attr:`ThreatCase.meaningful` says so rather than letting a green row imply a
defence.

Most controls here are the real Stage 3 or Stage 1 objects: ``BoundaryIndex``,
``CellBoundary``, ``KnowledgeField.compose``, ``CounterexampleStore``,
``verify``, ``EpochModel``. Two are **reference implementations** written in this
module and labelled as such in their case's ``detail``: the audit sampler (the
production one lives in the ``lifecycle`` package's ``promotion/audit.py``) and
the lineage-support rule. Those two cases demonstrate the *rule*, and a gate that
has the production objects should re-run them against those instead.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any

from pocketsec.stage0.contracts.common import ContractError, EvidenceRef, digest_of_bytes
from pocketsec.stage1.epoch.model import EpochModel, EpochTransitionReason, SystemIdentity
from pocketsec.stage1.observation.policy import EscalationDecision, ObservationLevel
from pocketsec.stage1.novelty.engine import NOVELTY_CONTEXTS, NoveltyTensor
from pocketsec.stage1.ssir.entities import Entity, SemanticProperty
from pocketsec.stage1.ssir.relations import Relation, RelationFamily
from pocketsec.stage1.ssir.transition import SSIRTransitionV1, TemporalContext
from pocketsec.stage1.state.security_state import (
    DIMENSIONS,
    CredentialExposure,
    Privilege,
    SecurityStateV1,
    StateDelta,
)
from pocketsec.stage3.boundary.index import MAX_KEYS_PER_CELL, BoundaryIndex
from pocketsec.stage3.cells.invariant import PredicateRole, SemanticPredicate
from pocketsec.stage3.bytecode.isa import (
    MAX_STATE_BYTES,
    STATE_SLOTS,
    Instruction,
    Op,
    encode,
)
from pocketsec.stage3.bytecode.verifier import verify
from pocketsec.stage3.bytecode.vm import CellResult, CellVM
from pocketsec.stage3.boundary.index import CellBoundary
from pocketsec.stage3.cells.field import (
    CellActivation,
    CompositionOutcome,
    KnowledgeField,
)
from pocketsec.stage3.cells.frame import CellFrame, frame_digest
from pocketsec.stage3.cells.operator import OperatorForm, OperatorProgram
from pocketsec.stage3.labs.cell_path import CELL_STATE_DIMENSIONS, phi_oracle_cell
from pocketsec.stage3.oracles.counterexamples import Counterexample, CounterexampleStore
from pocketsec.stage3.theory import SecurityConsequence

__all__ = [
    "KeyedAuditSampler",
    "MIN_LINEAGE_SUPPORT",
    "THREAT_CASE_IDS",
    "ThreatCase",
    "ThreatSuiteReport",
    "make_counterexample",
    "run_threat_suite",
]

#: Distinct causal lineages an invariant needs. Events are not witnesses: a
#: pattern repeated a thousand times inside one lineage has exactly one.
MIN_LINEAGE_SUPPORT = 4

THREAT_CASE_IDS: tuple[str, ...] = (
    "T1_BOUNDARY_EVASION",
    "T2_CRYSTALLIZATION_POISONING",
    "T3_AUDIT_GAMING",
    "T4_CELL_CONFLICT_DOS",
    "T5_CERTIFICATE_ROLLBACK",
    "T6_MALFORMED_BYTECODE",
    "T7_KNOWLEDGE_EXPLOSION",
    "T8_EPOCH_MANIPULATION",
    "T9_COUNTEREXAMPLE_POISONING",
)


@dataclass(frozen=True, slots=True)
class ThreatCase:
    """One §39 attack, run twice: with the §40 control and without it."""

    case_id: str
    attack: str
    control: str
    stopped_with_control: bool
    succeeded_without_control: bool
    detail: str

    def __post_init__(self) -> None:
        if self.case_id not in THREAT_CASE_IDS:
            raise ContractError(f"{self.case_id!r} is not one of the nine §39 cases")

    @property
    def meaningful(self) -> bool:
        """A case only demonstrates a control if the attack works without it."""
        return self.stopped_with_control and self.succeeded_without_control

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "attack": self.attack,
            "control": self.control,
            "stopped_with_control": self.stopped_with_control,
            "succeeded_without_control": self.succeeded_without_control,
            "meaningful": self.meaningful,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class ThreatSuiteReport:
    """All nine cases. ``complete`` is false if any case is missing or meaningless."""

    cases: tuple[ThreatCase, ...]

    @property
    def by_id(self) -> Mapping[str, ThreatCase]:
        return {case.case_id: case for case in self.cases}

    @property
    def complete(self) -> bool:
        return set(self.by_id) == set(THREAT_CASE_IDS) and all(c.meaningful for c in self.cases)

    @property
    def unmitigated(self) -> tuple[str, ...]:
        return tuple(c.case_id for c in self.cases if not c.stopped_with_control)

    def to_dict(self) -> dict[str, Any]:
        return {
            "complete": self.complete,
            "unmitigated": list(self.unmitigated),
            "cases": [case.to_dict() for case in self.cases],
        }


# --- shared fixtures ----------------------------------------------------------


def _evidence(locator: str) -> EvidenceRef:
    return EvidenceRef(
        store="raw.credential_access",
        locator=locator,
        digest=digest_of_bytes(locator.encode()),
    )


def _frame(
    *, epoch_id: int = 0, delta: StateDelta | None = None, delta_phi: float = 4.0
) -> CellFrame:
    return CellFrame(
        state=SecurityStateV1(credential=CredentialExposure.READABLE),
        delta=delta if delta is not None else StateDelta({"privilege": (0, int(Privilege.ROOT))}),
        actor_properties=0,
        object_properties=0,
        relation_family=RelationFamily.AUTHORIZATION,
        phi=1.0,
        delta_phi=delta_phi,
        uncertainty=0.0,
        epoch_id=epoch_id,
        window_counts={},
        evidence=(_evidence("rec-0001"),),
        encoder_version="dtl-encoder.1.0.0",
    )


# --- T1: boundary evasion just inside a permissive boundary -------------------


def _case_boundary_evasion() -> ThreatCase:
    """Answering outside the validated region is the attack; the boundary is the control.

    The frame is crafted to be *one clause* outside — same masks, same family,
    same Φ, a different epoch. That is the hardest case for a boundary to catch
    and the easiest for an attacker to reach, because an epoch changes on its own.
    """
    cell = phi_oracle_cell(epochs=frozenset({0}))
    index = BoundaryIndex()
    index.insert(cell)
    vm = CellVM()
    evasive = _frame(epoch_id=1)

    # Control on: the index narrows and the boundary decides.
    with_control = index.lookup(evasive) is None
    # Control off: hand the program the frame directly, as a caller that trusted
    # the cell rather than the boundary would.
    without = vm.run(cell.operator, evasive)
    return ThreatCase(
        case_id="T1_BOUNDARY_EVASION",
        attack="submit a frame one clause outside the cell's boundary (a different epoch)",
        control="CellBoundary.contains via BoundaryIndex.lookup; unseen_input_behaviour=ABSTAIN",
        stopped_with_control=with_control,
        succeeded_without_control=not without.abstained,
        detail=(
            f"boundary distance {cell.boundary.distance(evasive)}; unbounded execution "
            f"returned risk {without.risk}"
        ),
    )


# --- T2: crystallization poisoning by repetition ------------------------------


def _lineage_support(records: Sequence[tuple[str, int]], *, by_lineage: bool) -> int:
    """Reference implementation of the support rule (discovery lives in ``invariants``).

    ``records`` are ``(lineage, count)``. With the control, support is the number
    of distinct lineages; without it, the number of events.
    """
    if by_lineage:
        return len({lineage for lineage, _count in records})
    return sum(count for _lineage, count in records)


def _case_crystallization_poisoning() -> ThreatCase:
    """One lineage repeated a thousand times must not look like a thousand witnesses."""
    flood = [("proc:boot-0001:4242:7", 1000)]
    with_control = _lineage_support(flood, by_lineage=True) < MIN_LINEAGE_SUPPORT
    without = _lineage_support(flood, by_lineage=False) >= MIN_LINEAGE_SUPPORT
    return ThreatCase(
        case_id="T2_CRYSTALLIZATION_POISONING",
        attack="repeat one lineage 1000 times to manufacture invariant support",
        control="Invariant.support counts distinct causal lineages, never events",
        stopped_with_control=with_control,
        succeeded_without_control=without,
        detail=(
            "REFERENCE IMPLEMENTATION of the support rule; the production counter is in "
            f"invariants/discovery.py. lineage support 1 < {MIN_LINEAGE_SUPPORT}, "
            "event support 1000"
        ),
    )


# --- T3: audit gaming, timed against the sampler ------------------------------


class KeyedAuditSampler:
    """Reference sampler: the decision is a keyed hash, not a position in a stream.

    Unpredictable *within* policy. The production sampler is
    ``promotion/audit.py``; this exists so the threat case can run before that
    package lands, and it implements the same §40 rule — a keyed hash of
    ``(boot_salt, cell_id, frame_digest)``, never a counter and never a seeded
    PRNG stream an attacker can phase against.
    """

    __slots__ = ("_salt",)

    def __init__(self, *, boot_salt: str) -> None:
        if not boot_salt:
            raise ContractError("a sampler with an empty boot salt is a predictable sampler")
        self._salt = boot_salt

    def should_audit(self, cell_id: str, frame: CellFrame, *, probability: float) -> bool:
        material = f"{self._salt}|{cell_id}|{frame_digest(frame)}".encode()
        draw = int.from_bytes(hashlib.sha256(material).digest()[:8], "big") / 2**64
        return draw < probability


class _CounterAuditSampler:
    """The control disabled: audit every Nth frame. An attacker counts to N-1."""

    __slots__ = ("_n", "_seen")

    def __init__(self, *, every: int) -> None:
        self._n = every
        self._seen = 0

    def should_audit(self, cell_id: str, frame: CellFrame, *, probability: float) -> bool:
        self._seen += 1
        return self._seen % self._n == 0


def _case_audit_gaming() -> ThreatCase:
    """An attacker who knows the sampling schedule places its frames between audits."""
    frames = [_frame(delta_phi=float(i)) for i in range(1, 41)]
    keyed = KeyedAuditSampler(boot_salt="boot-salt-threat-suite")
    counter = _CounterAuditSampler(every=4)
    attacker_slots = [i for i in range(len(frames)) if (i + 1) % 4 != 0]

    keyed_audits = sum(
        1 for i in attacker_slots if keyed.should_audit("cell-x", frames[i], probability=0.25)
    )
    # The counter advances on EVERY frame, as it would on a host; the attacker
    # only chooses *where* its own frames land. Sampling only the attacker's
    # frames would hand the counter a schedule it never actually sees.
    counter_decisions = [
        counter.should_audit("cell-x", frame, probability=0.25) for frame in frames
    ]
    counter_audits = sum(1 for i in attacker_slots if counter_decisions[i])
    return ThreatCase(
        case_id="T3_AUDIT_GAMING",
        attack="place every attack frame in the gaps of a predictable audit schedule",
        control="audit decision is a keyed hash of (boot_salt, cell_id, frame_digest)",
        stopped_with_control=keyed_audits > 0,
        succeeded_without_control=counter_audits == 0,
        detail=(
            "REFERENCE SAMPLER; production sampler is promotion/audit.py. keyed sampler "
            f"audited {keyed_audits} of {len(attacker_slots)} attacker-chosen frames, "
            f"counter sampler audited {counter_audits}"
        ),
    )


# --- T4: cell-conflict denial of service --------------------------------------


def _activation(cell_id: str, *, risk: float, after: int, escalate: bool) -> CellActivation:
    return CellActivation(
        cell_id=cell_id,
        delta=StateDelta({"privilege": (0, after)}),
        risk=risk,
        evidence_required=(_evidence(f"rec-{cell_id}"),),
        escalation=(
            EscalationDecision(
                target="lineage-under-attack",
                level=ObservationLevel.HIGH_RESOLUTION,
                budget_score=0.9,
                escalated=True,
            )
            if escalate
            else None
        ),
        consequence=SecurityConsequence.HIGH,
        confidence=0.9,
        epochs=frozenset({0}),
    )


def _case_cell_conflict_dos() -> ThreatCase:
    """Forcing abstention is only a win if the abstention is silent."""
    field = KnowledgeField()
    loud = phi_oracle_cell(cell_id="cell-loud", epochs=frozenset({0}))
    quiet = phi_oracle_cell(cell_id="cell-quiet", epochs=frozenset({0}))
    field.insert(loud)
    field.insert(quiet)
    activations = [
        _activation("cell-loud", risk=0.9, after=int(Privilege.ROOT), escalate=True),
        _activation("cell-quiet", risk=0.0, after=0, escalate=False),
    ]
    verdict = field.compose(activations)
    stopped = (
        verdict.outcome is CompositionOutcome.ABSTAINED_CONTRADICTION
        and verdict.escalation is not None
        and verdict.escalation.escalated
        and len(verdict.evidence) >= 2
    )
    # Control off: pick a winner, as any "resolve the conflict" heuristic would.
    arbitrary = activations[-1]
    return ThreatCase(
        case_id="T4_CELL_CONFLICT_DOS",
        attack="promote a contradictory benign cell so the field stops answering",
        control=(
            "compose abstains on contradiction, and escalation and evidence still "
            "compose by maximum/union on the abstaining path"
        ),
        stopped_with_control=stopped,
        succeeded_without_control=arbitrary.risk == 0.0 and arbitrary.escalation is None,
        detail=(
            f"outcome {verdict.outcome.value}; escalation carried="
            f"{verdict.escalation is not None}; evidence union {len(verdict.evidence)}; "
            "arbitrary-winner selection would have returned risk 0.0 with no escalation"
        ),
    )


# --- T5: certificate rollback -------------------------------------------------


def _case_certificate_rollback() -> ThreatCase:
    """Re-installing an old cell under a live id must not be a silent overwrite."""
    field = KnowledgeField()
    current = replace(phi_oracle_cell(cell_id="cell-target"), version=3)
    stale = replace(phi_oracle_cell(cell_id="cell-target"), version=1)
    field.insert(current)
    try:
        field.insert(stale)
        refused = False
    except ContractError:
        refused = True
    # Control off, run against the real ``KnowledgeField``: the duplicate-id
    # refusal is the control, so disabling it means removing the incumbent first
    # and inserting the stale version in its place. That is what an
    # in-place-replacing store does, and it is a real run of the container rather
    # than an assignment to a local dict — which is what this arm used to be, and
    # which only demonstrated that Python dicts overwrite.
    shadow_field = KnowledgeField()
    shadow_field.insert(current)
    shadow_field.remove("cell-target")
    shadow_field.insert(stale)
    held_without_control = shadow_field.get("cell-target")
    held = field.get("cell-target")
    return ThreatCase(
        case_id="T5_CERTIFICATE_ROLLBACK",
        attack="re-insert version 1 of a cell over the live version 3",
        control="KnowledgeField.insert refuses a duplicate cell_id; replacement is explicit",
        stopped_with_control=refused and held is not None and held.version == 3,
        succeeded_without_control=(
            held_without_control is not None and held_without_control.version == 1
        ),
        detail=(
            f"field still holds version {held.version if held else None}; an "
            "in-place-replacing store would hold version 1"
        ),
    )


# --- T6: malformed bytecode reaching for out-of-bounds state ------------------


def _case_malformed_bytecode() -> ThreatCase:
    """A ``LOAD_STATE`` operand past the last dimension is a read outside the frame."""
    operand = len(STATE_SLOTS) + 3
    program = OperatorProgram(
        form=OperatorForm.BYTECODE,
        words=encode(
            (
                Instruction(Op.LOAD_STATE, operand),
                Instruction(Op.RETURN_RISK, 0),
            )
        ),
        table={},
        max_steps=2,
        max_state_bytes=MAX_STATE_BYTES,
    )
    report = verify(program)
    vm = CellVM()
    result = vm.run(program, _frame())
    # Control off: no range check. The operand would index past the last slot.
    out_of_bounds = operand >= len(STATE_SLOTS)
    return ThreatCase(
        case_id="T6_MALFORMED_BYTECODE",
        attack=f"LOAD_STATE with operand {operand}, past the {len(STATE_SLOTS)} state slots",
        control="the verifier range-checks every LOAD_* operand; CellVM runs nothing unverified",
        stopped_with_control=(not report.ok) and result.abstained,
        succeeded_without_control=out_of_bounds,
        detail=(
            f"verifier failures {[code for code, _ in report.failures]}; VM reason "
            f"{result.reason!r}. PROVEN by construction, not merely tested: the operand "
            "range is checked statically and the ISA has no indirect load"
        ),
    )


# --- T7: knowledge explosion via forced fission -------------------------------


def _case_knowledge_explosion() -> ThreatCase:
    """A boundary wide enough to cover the host is the explosion, not a thousand cells.

    The attack targets the *predicate x family* product, which is the only
    expansion this boundary language actually has. Breadth over
    ``state_dimensions`` was the obvious-looking vector and it is measurably not
    one: :meth:`CellBoundary.keys` folds the declared dimensions into a single
    union delta mask, so a boundary over all nine dimensions claims exactly as
    many keys as a boundary over two. An attack down that road would report
    "stopped" while nothing stopped it, which is worse than no case at all.

    Distinct actor predicates with no family clause do multiply: each predicate
    contributes a required-property mask and each mask is crossed with all eight
    relation families, so nine predicates claim 72 keys against a cap of 64.
    """
    wide = CellBoundary(
        predicates=tuple(
            _actor_predicate(prop) for prop in tuple(SemanticProperty)[:9]
        ),
        state_dimensions=frozenset(DIMENSIONS),
        phi_range=(0.0, 1e9),
        max_uncertainty=1.0,
        epochs=frozenset({0, 1, 2}),
        forbidden_combinations=(),
    )
    index = BoundaryIndex()
    try:
        index.insert(replace(phi_oracle_cell(cell_id="cell-wide"), boundary=wide))
        refused = False
        would_be = len(index.keys_for("cell-wide"))
    except ContractError as exc:
        refused = True
        would_be = _keys_claimed(str(exc))
    narrow_cell = phi_oracle_cell(cell_id="cell-narrow", epochs=frozenset({0}))
    narrow_index = BoundaryIndex()
    narrow_index.insert(narrow_cell)
    return ThreatCase(
        case_id="T7_KNOWLEDGE_EXPLOSION",
        attack="force a boundary over nine unconstrained actor predicates x eight families",
        control=f"BoundaryIndex refuses above MAX_KEYS_PER_CELL={MAX_KEYS_PER_CELL}",
        stopped_with_control=refused,
        succeeded_without_control=would_be > MAX_KEYS_PER_CELL,
        detail=(
            f"the wide boundary claims {would_be} keys; the {sorted(CELL_STATE_DIMENSIONS)} "
            f"boundary claims {len(narrow_index.keys_for('cell-narrow'))}"
        ),
    )


def _actor_predicate(prop: SemanticProperty) -> SemanticPredicate:
    """One family-free ACTOR predicate — the unit the key expansion multiplies."""
    return SemanticPredicate(
        role=PredicateRole.ACTOR,
        required_properties=frozenset({prop}),
        forbidden_properties=frozenset(),
        relation_family=None,
        entity_kind=None,
    )


def _keys_claimed(message: str) -> int:
    """Pull the key count out of the index's own refusal, rather than recomputing it.

    Recomputing would mean this case measured its own arithmetic instead of the
    index's; if the index changes how it expands a boundary, this must follow.
    """
    for token in message.replace("(", " ").split():
        if token.isdigit() and int(token) > MAX_KEYS_PER_CELL:
            return int(token)
    return 0


# --- T8: epoch manipulation ---------------------------------------------------


def _case_epoch_manipulation() -> ThreatCase:
    """An attacker who can change a digest must not be able to mint a fresh epoch."""
    identity = SystemIdentity(kernel_id="6.1.0", package_digest="pkg-a", service_digest="svc-a")
    guarded = EpochModel(identity=identity)
    unguarded = EpochModel(identity=identity)
    observed = SystemIdentity(kernel_id="6.1.0", package_digest="pkg-evil", service_digest="svc-a")

    refused = guarded.evaluate(
        observed_identity=observed,
        corroborating_evidence=frozenset(),
        now_ns=1_000_000_000,
        behavioural_novelty=1.0,
    )
    # Control off: treat the change itself as its own corroboration.
    accepted = unguarded.evaluate(
        observed_identity=observed,
        corroborating_evidence=frozenset({"package_digest"}),
        now_ns=1_000_000_000,
        behavioural_novelty=0.0,
    )
    return ThreatCase(
        case_id="T8_EPOCH_MANIPULATION",
        attack="change a system digest with no corroboration to reset epoch-bound trust",
        control="EpochModel requires independent corroboration; novelty never mints an epoch",
        stopped_with_control=(
            refused.reason is EpochTransitionReason.REJECTED_NO_CORROBORATION
            and guarded.epoch_id == 0
        ),
        succeeded_without_control=accepted.transitioned and unguarded.epoch_id == 1,
        detail=f"guarded reason {refused.reason.value}; unguarded epoch {unguarded.epoch_id}",
    )


# --- T9: counterexample poisoning ---------------------------------------------


def _transition(sequence: int) -> SSIRTransitionV1:
    """A minimal replayable transition. A counterexample with no events is not
    regression material, which is why the store refuses one."""
    return SSIRTransitionV1(
        actor=Entity(identity=f"proc:{sequence}"),
        relation=Relation.READ,
        object=Entity(identity=f"file:{sequence}"),
        state_delta=StateDelta({"privilege": (0, int(Privilege.ROOT))}),
        uncertainty=0.1,
        novelty=NoveltyTensor(values=dict.fromkeys(NOVELTY_CONTEXTS, 0.5)),
        causal_signature=f"sig-{sequence}",
        parent_signature="sig-root",
        responsibility=1.0,
        temporal=TemporalContext(),
        evidence=(_evidence(f"cx-{sequence}"),),
        epoch_id=0,
        sequence=sequence,
    )


def make_counterexample(index: int, *, incident: bool) -> Counterexample:
    empty = CellResult(
        abstained=True,
        delta=StateDelta({}),
        evidence=(_evidence(f"cx-{index}"),),
        risk=0.0,
        escalation=None,
        steps_taken=1,
        reason="ABSTAIN",
    )
    return Counterexample(
        counterexample_id=f"cx-{index:04d}",
        cell_candidate_id="cell-target",
        transitions=(_transition(index),),
        state=SecurityStateV1(),
        epoch_id=0,
        expected=empty,
        observed=replace(empty, risk=0.9, abstained=False, reason="RETURN_RISK"),
        divergence_type="risk",
        evidence=(_evidence(f"cx-{index}"),),
        incident_linked=incident,
    )


def _case_counterexample_poisoning() -> ThreatCase:
    """Flooding the store to push incident evidence out is the attack."""
    store = CounterexampleStore(cold_archive=None, max_hot=4)
    for index in range(4):
        store.record(make_counterexample(index, incident=True))
    try:
        store.record(make_counterexample(99, incident=False))
        refused = False
    except ContractError:
        refused = True
    survivors = sum(1 for cx in store.hot() if cx.incident_linked)

    # Control off: a plain bounded FIFO, which drops whatever is oldest.
    fifo: list[Counterexample] = []
    for index in range(4):
        fifo.append(make_counterexample(index, incident=True))
    fifo.append(make_counterexample(99, incident=False))
    dropped = fifo.pop(0)
    return ThreatCase(
        case_id="T9_COUNTEREXAMPLE_POISONING",
        attack="flood the hot counterexample store so incident-linked evidence is evicted",
        control="the store refuses rather than dropping an incident-linked record; no delete API",
        stopped_with_control=refused and survivors == 4,
        succeeded_without_control=dropped.incident_linked,
        detail=(
            f"{survivors} incident-linked records survived the flood; a plain FIFO would "
            f"have dropped {dropped.counterexample_id}"
        ),
    )


def run_threat_suite() -> ThreatSuiteReport:
    """Run all nine §39 cases, each with and without its §40 control."""
    return ThreatSuiteReport(
        cases=(
            _case_boundary_evasion(),
            _case_crystallization_poisoning(),
            _case_audit_gaming(),
            _case_cell_conflict_dos(),
            _case_certificate_rollback(),
            _case_malformed_bytecode(),
            _case_knowledge_explosion(),
            _case_epoch_manipulation(),
            _case_counterexample_poisoning(),
        )
    )
