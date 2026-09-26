"""D6.17 / HEL-F22..F24 — THE ONE WRITER of trusted cognition, and the only way back.

Spec §1 in one sentence: *there is exactly one function in the repository that changes
the endpoint's trusted cognitive state.* It is :meth:`TrustedMind._install_trusted`, it
lives in this file, and boundary rule 4 (``tests/test_stage6_boundary.py``) fails the
build if its name, or ``_trusted_state``, or a ``TrustedMind(...)`` construction, appears
anywhere else under ``pocketsec/`` (ADR-0052).

Every argument that reaches it was minted, in order, by the quarantine gateway (verdicts),
the evolution chamber (the candidate, checked with ``chamber.issued``), the conservation
gate (run *here*, never accepted from a caller), the shadow and the canary. Every change
it makes is fossilised first and reversible to a byte-identical prior state named by its
digest. What it refuses:

* **Anything not minted upstream.** A raw ``EncodedTransition``, a hand-built or altered
  candidate, a candidate built on a stale base, a conservation verdict supplied by the
  caller (there is no parameter for one), a rollback target this fossil store never held.
* **Skipping a state.** ``require_transition`` guards every lifecycle move;
  ``CANDIDATE -> TRUSTED`` raises.
* **A decision it did not mint.** ``_install_trusted`` consumes a decision id from the
  module-private ``_issued_decisions`` registry, bound to this mind's token and to the
  exact before/after digests. A caller holding the mind and naming the private method
  with a forged, replayed or re-targeted decision is refused (tested).
* **A state whose items lack lineage.** The installer re-reads the state from its
  canonical bytes *with the lineage DAG*, so an item without provenance is refused at
  load time, exactly as a fossil would be.
* **Logging a regression instead of acting on it.** A canary regression rejects the
  candidate the moment it appears; a probation regression calls :meth:`rollback_learning`
  itself (architecture §41 "bad canary automatically reverts").
* **Deleting the evidence of failure.** Rollback records ROLLBACK and REJECTION nodes and
  leaves the failed state's fossil in the store (unpinned, so bounded eviction may take it
  later, with a tombstone). Architecture §44: rollback does not delete why it happened.
* **A change it cannot record.** Lineage is written before every install; a DAG at
  capacity refuses the change (trusted state untouched), except that a refused rollback
  runs :meth:`collect_lineage` and retries, so a full DAG never keeps a regressed state.

Rollback depth is bounded by the fossil store (``MAX_FOSSILS``); a state older than every
retained fossil cannot be restored, and the store's tombstone says so (ADR-0052). Lineage
is bounded by :meth:`collect_lineage`, which never folds the lineage of an item any retained
fossil holds. An explicit rollback target is restored exactly or refused — never
substituted — and a digest this controller rolled back is never re-trusted by rollback
(``promotion.restore``). A context transition is installed only if
``KnowledgeContextRegistry.open_new_epoch`` minted it. A canary or probation is passed only
with benign-labelled evidence, and a detection dropped on unlabelled protected traffic is a
regression (``shadow.canary``).
"""

from __future__ import annotations

import hashlib
import json
import secrets
from collections import OrderedDict, deque
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage6.capsule.experience_capsule import EncodedStep
from pocketsec.stage6.capsule.quarantine import QuarantineGateway
from pocketsec.stage6.chamber.evolution import EvolutionCandidate, EvolutionChamber
from pocketsec.stage6.conservation.gate import (
    ConservationVerdict,
    complete_with_shadow,
    context_validation,
    default_meter,
    lineage_gaps,
    offline_validation,
)
from pocketsec.stage6.constitution.learning import LifecycleState, require_transition
from pocketsec.stage6.fossils.lineage import (
    KnowledgeLineageDAG,
    LineageCapacityError,
    LineageNode,
    NodeKind,
)
from pocketsec.stage6.fossils.store import FossilIntegrityError, FossilReason, FossilStore
from pocketsec.stage6.homeostasis.drift import EpochTransition, consume_issued_transition
from pocketsec.stage6.memory.episodic import EpisodeSkeleton
from pocketsec.stage6.memory.semantic import (
    SessionScore,
    TrustedKnowledgeState,
    score_session,
)
from pocketsec.stage6.promotion.restore import select_restore_target
from pocketsec.stage6.resources import WorkMeter
from pocketsec.stage6.shadow.canary import CanaryEvaluator, CanaryObservation, CanaryPolicy
from pocketsec.stage6.shadow.mind import ShadowMind, ShadowReport, ShadowSession

__all__ = [
    "SEALED_NAMES",
    "GENESIS_NODE",
    "GENESIS_PROMOTION_NODE",
    "MAX_CANDIDATE_RECORDS",
    "MAX_DECISION_LOG",
    "MAX_PENDING_CANDIDATES",
    "MAX_ROLLBACK_LOG",
    "ControllerStats",
    "LearningPromotionController",
    "LearningRollback",
    "PromotionDecision",
    "RollbackTrigger",
    "TrustedMind",
]

#: The names only this file may mention (boundary rules 4 and 5, ADR-0052). Declared by
#: the owner so the gate can scan for them without spelling them itself: a gate that
#: wrote these strings would be the breach it looks for.
SEALED_NAMES: tuple[str, ...] = (
    "_install_trusted", "_trusted_state", "_issue_decision", "_issued_decisions",
)
MAX_DECISION_LOG: int = 256
MAX_ROLLBACK_LOG: int = 64
#: Not in the §4.21 table; added because the controller must bound what it remembers
#: about candidates. In flight (CANDIDATE…CANARY) each holds a full proposed state, so
#: that count is small; terminal records keep only digests, so that count can be larger.
MAX_PENDING_CANDIDATES: int = 4
MAX_CANDIDATE_RECORDS: int = 64

GENESIS_NODE = "genesis"
GENESIS_PROMOTION_NODE = "promotion-genesis"

_S = LifecycleState
_IN_FLIGHT = frozenset({_S.CANDIDATE, _S.OFFLINE_VALIDATED, _S.SHADOW, _S.CANARY})
_TERMINAL = frozenset({_S.REJECTED, _S.ROLLED_BACK, _S.RETIRED})
_MAX_OUTSTANDING_DECISIONS = 8
_DEFAULT_POLICY = CanaryPolicy()  # frozen: sharing one default instance is safe


@dataclass(frozen=True, slots=True)
class PromotionDecision:
    decision_id: str
    candidate_id: str
    from_state: LifecycleState
    to_state: LifecycleState
    conservation_digest: str | None
    shadow_digest: str | None
    canary_digest: str | None
    trusted_before: str
    trusted_after: str
    reason: str
    sequence: int

    def to_dict(self) -> dict[str, Any]:
        return {"decision_id": self.decision_id, "candidate_id": self.candidate_id,
                "from_state": self.from_state.value, "to_state": self.to_state.value,
                "conservation_digest": self.conservation_digest,
                "shadow_digest": self.shadow_digest, "canary_digest": self.canary_digest,
                "trusted_before": self.trusted_before, "trusted_after": self.trusted_after,
                "reason": self.reason, "sequence": self.sequence}


#: decision_id -> (mind token, the exact decision minted). Module-private and sealed by
#: boundary rule 5: only this file may name it. An entry lives for one install call.
_issued_decisions: OrderedDict[str, tuple[str, PromotionDecision]] = OrderedDict()


class RollbackTrigger(StrEnum):
    CANARY_REGRESSION = "CANARY_REGRESSION"
    PROBATION_REGRESSION = "PROBATION_REGRESSION"
    FOSSIL_CORRUPTION = "FOSSIL_CORRUPTION"
    #: A skipped fossil's bytes were intact but its items' lineage was folded: it is
    #: unverifiable, not corrupt (review S6-R1 / honesty F2).
    LINEAGE_UNVERIFIABLE = "LINEAGE_UNVERIFIABLE"
    INTEGRITY_FAILURE = "INTEGRITY_FAILURE"
    OPERATOR_REQUEST = "OPERATOR_REQUEST"


def _digest(payload: Any) -> str:
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class LearningRollback:
    """Architecture §44. The failed state is not deleted; this record says why it left."""

    rollback_id: str
    trigger: RollbackTrigger
    candidate_id: str | None
    from_digest: str
    to_digest: str
    restored_bytes_identical: bool  # canonical_bytes() == the fossil's verified payload
    skipped_fossils: tuple[str, ...]  # fossils passed over because they did not verify
    evidence: tuple[str, ...]  # the report digests that triggered it
    sequence: int

    def to_dict(self) -> dict[str, Any]:
        return {"rollback_id": self.rollback_id, "trigger": self.trigger.value,
                "candidate_id": self.candidate_id, "from_digest": self.from_digest,
                "to_digest": self.to_digest,
                "restored_bytes_identical": self.restored_bytes_identical,
                "skipped_fossils": list(self.skipped_fossils), "evidence": list(self.evidence),
                "sequence": self.sequence}

    def digest(self) -> str:
        return _digest(self.to_dict())


@dataclass(frozen=True, slots=True)
class ControllerStats:
    decisions_logged: int
    decisions_dropped: int
    rollbacks_logged: int
    rollbacks_dropped: int
    submitted: int
    promoted: int
    rejected: int
    rolled_back: int
    context_transitions: int
    submissions_refused: int
    candidates_tracked: int
    canary_active: bool
    probation_active: bool


class TrustedMind:
    """The endpoint's current trusted state. Read by anyone; changed only by its installer."""

    __slots__ = ("_lineage", "_token", "_trusted_digest", "_trusted_state")

    def __init__(self, state: TrustedKnowledgeState, *, lineage: KnowledgeLineageDAG,
                 token: str) -> None:
        verified = TrustedKnowledgeState.from_canonical_bytes(state.canonical_bytes(),
                                                              lineage=lineage)
        for name, value in (("_lineage", lineage), ("_token", token),
                            ("_trusted_state", verified), ("_trusted_digest", verified.digest())):
            object.__setattr__(self, name, value)

    def __setattr__(self, name: str, value: object) -> None:
        """Refused: ``SEALED_NAMES`` is public, so ``setattr(mind, SEALED_NAMES[1], state)``
        would otherwise write trusted state without spelling the name the boundary scan
        looks for (review S6-AUTH-04). Only the installer below writes, and it says so."""
        raise ContractError(f"refused: TrustedMind.{name} is written only by its installer")

    def current(self) -> TrustedKnowledgeState:
        return self._trusted_state

    def digest(self) -> str:
        return self._trusted_digest

    def score(self, steps: Sequence[EncodedStep], *, context_id: str,
              meter: WorkMeter | None = None) -> SessionScore:
        return score_session(self._trusted_state, steps, context_id=context_id, meter=meter)

    def _install_trusted(self, state: TrustedKnowledgeState, *,
                         decision: PromotionDecision) -> None:
        """The only mutation of trusted cognition in the repository."""
        decision_id = getattr(decision, "decision_id", None)
        entry = _issued_decisions.pop(decision_id, None) if isinstance(decision_id, str) else None
        if entry is None or entry[0] != self._token or entry[1] != decision:
            raise ContractError("refused: this decision was not minted for this mind")
        if not isinstance(state, TrustedKnowledgeState):
            raise ContractError("refused: only a TrustedKnowledgeState can be installed")
        if (decision.trusted_before, decision.trusted_after) != (self._trusted_digest,
                                                                  state.digest()):
            raise ContractError("refused: the decision names different before/after digests")
        # Re-read from bytes WITH lineage: an item without provenance never becomes trusted.
        verified = TrustedKnowledgeState.from_canonical_bytes(state.canonical_bytes(),
                                                              lineage=self._lineage)
        if verified.digest() != decision.trusted_after:
            raise ContractError("refused: the state does not round-trip to its digest")
        object.__setattr__(self, "_trusted_state", verified)
        object.__setattr__(self, "_trusted_digest", decision.trusted_after)


@dataclass(slots=True)
class _Record:
    """What the controller remembers about one candidate. Heavy fields drop at terminal."""

    candidate_id: str
    base_digest: str
    proposed_digest: str
    state: LifecycleState
    candidate: EvolutionCandidate | None
    verdict: ConservationVerdict | None = None
    report: ShadowReport | None = None
    hostile: tuple[EpisodeSkeleton, ...] = ()
    nodes: dict[str, str] = field(default_factory=dict)  # stage -> lineage node id


@dataclass(slots=True)
class _Watch:
    """An active canary or probation: whose, compared against what, and for how long."""

    candidate_id: str
    evaluator: CanaryEvaluator
    reference_digest: str
    observed: int = 0


def _fingerprint(state: TrustedKnowledgeState) -> str:
    """Digest of the state's replay of its own rehearsal set: a fossil's fingerprint."""
    rows = [[e.episode_id, round(score_session(state, e.steps, context_id=e.context_id).score, 6)]
            for e in state.rehearsal]
    return _digest(rows)


def _epoch_range(state: TrustedKnowledgeState) -> tuple[int, int]:
    epochs = {e.epoch_id for e in state.rehearsal}
    for item in state.items:
        epochs |= set(item.validation.epochs_seen)
    return (min(epochs), max(epochs)) if epochs else (0, 0)


class LearningPromotionController:
    """Owns the one :class:`TrustedMind`; walks candidates QUARANTINED→…→TRUSTED or REJECTED."""

    def __init__(self, *, genesis: TrustedKnowledgeState, fossils: FossilStore,
                 lineage: KnowledgeLineageDAG, gateway: QuarantineGateway,
                 chamber: EvolutionChamber, shadow: ShadowMind,
                 policy: CanaryPolicy = _DEFAULT_POLICY) -> None:
        if not isinstance(genesis, TrustedKnowledgeState):
            raise ContractError("the controller starts from a TrustedKnowledgeState genesis")
        if not isinstance(policy, CanaryPolicy):
            raise ContractError("the controller needs a CanaryPolicy")
        self._fossils, self._lineage = fossils, lineage
        self._chamber, self._shadow, self._policy = chamber, shadow, policy
        self._token = secrets.token_hex(16)
        lineage.bind_genesis_threshold(genesis.threshold())
        self._mind = TrustedMind(genesis, lineage=lineage, token=self._token)
        self._sequence = 0
        self._genesis_digest = self._mind.digest()
        self._pinned: set[str] = set()
        self._node(LineageNode(GENESIS_NODE, NodeKind.GENESIS, self._genesis_digest, 0,
                               "trusted genesis"), (), reason="genesis")
        self._node(LineageNode(GENESIS_PROMOTION_NODE, NodeKind.PROMOTION, self._genesis_digest,
                               0, "genesis installed"), (GENESIS_NODE,),
                   reason="genesis_installed", parent_versions=(self._genesis_digest,))
        self._head = GENESIS_PROMOTION_NODE
        self._probation: _Watch | None = None
        self._fossilise(self._mind.current(), FossilReason.GENESIS, pin=True)
        self._repin()
        self._records: OrderedDict[str, _Record] = OrderedDict()
        self._installed_by: OrderedDict[str, str] = OrderedDict({self._genesis_digest: "genesis"})
        self._bad_digests: OrderedDict[str, None] = OrderedDict()
        self._decisions: deque[PromotionDecision] = deque(maxlen=MAX_DECISION_LOG)
        self._rollbacks: deque[LearningRollback] = deque(maxlen=MAX_ROLLBACK_LOG)
        self._canary: _Watch | None = None
        self._counts = dict.fromkeys(("decisions", "rollbacks", "submitted", "promoted",
                                      "rejected", "context", "refused"), 0)
        gateway.bind_trusted_view(self._mind.current)
        # The gateway folds through here when its lineage writes would hit the DAG's cap,
        # instead of raising on every admit until the next consolidation (review S6-R2).
        gateway.bind_lineage_collector(self.collect_lineage)

    @property
    def mind(self) -> TrustedMind:
        return self._mind

    # --- the pipeline, in lifecycle order ------------------------------------------------

    def submit(self, candidate: EvolutionCandidate, *, holdout: Sequence[EpisodeSkeleton],
               hostile: Sequence[EpisodeSkeleton], variant_seed: int) -> PromotionDecision:
        """CANDIDATE -> OFFLINE_VALIDATED | REJECTED. The conservation gate runs here, always."""
        if not isinstance(candidate, EvolutionCandidate):
            raise ContractError(f"submit takes a chamber-issued EvolutionCandidate, got "
                                f"{type(candidate).__name__}")
        if not self._chamber.issued(candidate):
            self._counts["refused"] += 1
            raise ContractError(f"refused: {candidate.candidate_id} was not issued by the chamber "
                                "or was altered after issue")
        if candidate.candidate_id in self._records:
            raise ContractError(f"{candidate.candidate_id} was already submitted")
        if not self._lineage.has(candidate.candidate_id):
            raise ContractError(f"refused: {candidate.candidate_id} has no CANDIDATE lineage node")
        self._make_room()
        record = _Record(candidate.candidate_id, candidate.base_digest,
                         candidate.proposed.digest(), _S.CANDIDATE, candidate,
                         hostile=tuple(hostile))
        self._records[candidate.candidate_id] = record
        self._counts["submitted"] += 1
        if candidate.base_digest != self._mind.digest():
            return self._reject(record, candidate.candidate_id, "stale_base", "FAIL:stale_base")
        verdict = offline_validation(candidate, trusted=self._mind.current(),
                                     lineage=self._lineage, fossils=self._fossils,
                                     holdout=holdout, hostile=hostile, variant_seed=variant_seed,
                                     meter=default_meter())
        record.verdict = verdict
        record.nodes["conservation"] = self._stage_node(
            record, "conservation", NodeKind.CONSERVATION, verdict.verdict_digest,
            candidate.candidate_id, passed=verdict.offline_passed(),
            failed=[c for c in verdict.failed_checks() if c != "G8_SHADOW"])
        if not verdict.offline_passed():
            return self._reject(record, record.nodes["conservation"], "conservation_failed",
                                "FAIL:" + ",".join(verdict.failed_checks()))
        return self._advance(record, _S.OFFLINE_VALIDATED, "offline_validated")

    def run_shadow(self, candidate_id: str, sessions: Iterable[ShadowSession]) -> PromotionDecision:
        """OFFLINE_VALIDATED -> SHADOW | REJECTED, by completing G8 from a fresh ShadowReport."""
        record = self._require(candidate_id, _S.OFFLINE_VALIDATED)
        if record.base_digest != self._mind.digest():
            return self._reject(record, record.nodes["conservation"], "stale_base",
                                "FAIL:stale_base")
        assert record.candidate is not None and record.verdict is not None
        report = self._shadow.run_shadow_mind(record.candidate.proposed, self._mind.current(),
                                              sessions, hostile=record.hostile)
        record.hostile = ()
        record.report = report
        record.verdict = complete_with_shadow(record.verdict, report)
        passed = record.verdict.passed
        record.nodes["shadow"] = self._stage_node(
            record, "shadow", NodeKind.SHADOW, report.digest(), record.nodes["conservation"],
            passed=passed, failed=list(record.verdict.failed_checks()))
        if not passed:
            return self._reject(record, record.nodes["shadow"], "shadow_failed",
                                "FAIL:" + ",".join(record.verdict.failed_checks()))
        return self._advance(record, _S.SHADOW, "shadow_passed")

    def promote_canary(self, candidate_id: str) -> PromotionDecision:
        """HEL-F22. SHADOW -> CANARY: candidate evidence on a deterministic share of sessions."""
        record = self._require(candidate_id, _S.SHADOW)
        if self._canary is not None or self._probation is not None:
            raise ContractError("one canary or probation at a time; finish the active one first")
        if record.base_digest != self._mind.digest():
            return self._reject(record, record.nodes["shadow"], "stale_base", "FAIL:stale_base")
        assert record.candidate is not None and record.verdict is not None
        if not record.verdict.passed:
            raise ContractError("refused: the conservation verdict is not complete and passed")
        evaluator = CanaryEvaluator(candidate=record.candidate.proposed,
                                    trusted=self._mind.current(), policy=self._policy)
        self._canary = _Watch(candidate_id, evaluator, self._mind.digest())
        return self._advance(record, _S.CANARY, "canary_started")

    def observe_canary(self, session: ShadowSession) -> CanaryObservation | PromotionDecision:
        """One canary session. Returns REJECTED the moment the report regresses."""
        if self._canary is None:
            raise ContractError("no canary is active")
        watch = self._canary
        observation = watch.evaluator.observe(session)
        watch.observed += 1
        report = watch.evaluator.report()
        if not report.regressed:
            return observation
        record = self._records[watch.candidate_id]
        self._canary = None
        record.nodes["canary"] = self._stage_node(
            record, "canary", NodeKind.CANARY, report.digest(), record.nodes["shadow"],
            passed=False, failed=["canary_regression"])
        return self._reject(record, record.nodes["canary"], "canary_regression: "
                            + "; ".join(report.reasons), "FAIL:canary_regression")

    def promote_trusted(self, candidate_id: str) -> PromotionDecision:
        """HEL-F23. CANARY -> TRUSTED: fossilise both ends, record PROMOTION, install, probation."""
        record = self._require(candidate_id, _S.CANARY)
        watch = self._canary
        if watch is None or watch.candidate_id != candidate_id:
            raise ContractError(f"{candidate_id} is not the active canary")
        report = watch.evaluator.report()
        if report.regressed or (not report.window_complete
                                and report.observations < self._policy.window_sessions):
            raise ContractError("refused: the canary window is incomplete or regressed")
        assert record.candidate is not None and record.verdict is not None
        self._canary = None
        if not report.window_complete:  # enough sessions, too few labelled (S6-AUTH-03)
            return self._reject(record, record.nodes["shadow"],
                                f"canary_unlabelled: malicious {report.labelled_malicious}, "
                                f"benign {report.labelled_benign}", "FAIL:canary_unlabelled")
        if record.base_digest != self._mind.digest():
            return self._reject(record, record.nodes["shadow"], "stale_base", "FAIL:stale_base")
        proposed = record.candidate.proposed
        gaps = lineage_gaps(proposed, candidate_id=candidate_id, lineage=self._lineage)
        if not record.verdict.passed or gaps:
            return self._reject(record, record.nodes["shadow"], f"lineage gaps {gaps[:4]}",
                                "FAIL:G1_INTEGRITY")
        before = self._mind.current()
        self._fossilise(before, FossilReason.PRE_PROMOTION, pin=True)
        self._fossilise(proposed, FossilReason.PROMOTION, pin=True)
        record.nodes["canary"] = self._stage_node(record, "canary", NodeKind.CANARY,
                                                  report.digest(), record.nodes["shadow"],
                                                  passed=True, failed=[])
        self._record_promotion(record, proposed, report.digest())
        decision = self._issue_decision(record.candidate_id, _S.CANARY, _S.TRUSTED,
                                        "promoted", before.digest(), proposed.digest(),
                                        record=record, canary=report.digest(), install=True)
        self._install(proposed, decision)
        record.state, record.candidate = _S.TRUSTED, None
        self._remember_installer(proposed.digest(), candidate_id)
        self._head = record.nodes["promotion"]
        evaluator = CanaryEvaluator(candidate=proposed, trusted=before, policy=self._policy)
        self._probation = _Watch(candidate_id, evaluator, before.digest())
        self._counts["promoted"] += 1
        self._repin()
        return decision

    def observe_probation(self, session: ShadowSession) -> LearningRollback | None:
        """Compare the promoted state with the pinned pre-promotion state; regression rolls back."""
        watch = self._probation
        if watch is None:
            return None
        watch.evaluator.observe(session)
        watch.observed += 1
        report = watch.evaluator.report()
        if report.regressed:
            return self._rollback(RollbackTrigger.PROBATION_REGRESSION, None, (report.digest(),))
        # Passed only once benign-labelled evidence exists; unlabelled traffic keeps the
        # probation open (and still able to roll back), never ends it (S6-AUTH-03).
        if watch.observed >= self._policy.probation_sessions and report.evidence_complete:
            self._probation = None
            self._repin()
        return None

    def rollback_learning(self, *, trigger: RollbackTrigger,
                          to_digest: str | None = None) -> LearningRollback:
        """HEL-F24. Restore a verified fossil byte-identically; record why; delete nothing.

        With ``to_digest`` that exact fossil is restored or ``ContractError`` is raised; a
        digest rolled back earlier is refused (``promotion.restore``)."""
        return self._rollback(RollbackTrigger(trigger), to_digest, ())

    def apply_context_transition(self, transition: EpochTransition) -> PromotionDecision:
        """Install an active-context change after G1, G2, G7, G9. Item changes are refused here."""
        if not isinstance(transition, EpochTransition):
            raise ContractError("apply_context_transition takes an EpochTransition")
        delta = transition.proposal
        target = delta.active_context
        if (delta.added or delta.removed or delta.replaced or delta.threshold is not None
                or delta.rehearsal_added or delta.rehearsal_removed or target is None):
            raise ContractError("refused: a context transition may change the active context "
                                "only; item changes go through the chamber as a candidate")
        if target != transition.current or target == self._mind.current().active_context:
            raise ContractError("refused: the proposal does not name a new active context")
        if transition.previous != self._mind.current().active_context:
            raise ContractError("refused: the transition's previous context is not the "
                                "trusted active context")
        if self._probation is not None:
            raise ContractError("refused during probation: rollback would undo the context")
        # Last: consuming the mint is the commitment (review S6-AUTH-05). A hand-built
        # EpochTransition skips Stage 1's corroboration refusal, so it is refused here.
        if not consume_issued_transition(transition):
            self._counts["refused"] += 1
            raise ContractError("refused: this transition was not minted by "
                                "KnowledgeContextRegistry.open_new_epoch, or was already used")
        current = self._mind.current()
        proposed = current.with_changes(active_context=target)
        transition_id = "ctxt-" + _digest([current.digest(), target])[7:39]
        verdict = context_validation(transition_id=transition_id, trusted=current,
                                     proposed=proposed, active_context=target,
                                     lineage=self._lineage, fossils=self._fossils,
                                     meter=default_meter())
        return self._install_context(transition_id, current, proposed, verdict,
                                     transition.previous)

    def collect_lineage(self) -> int:
        """Bound the DAG on a long run: fold what nothing here still cites; return the count.

        The DAG keeps what the items it is given reach. Only this controller knows the full
        list: the current state, every pinned rollback target (the probation target's items
        may have left the current state), in-flight candidates' nodes and proposed items,
        and the head the next ROLLBACK hangs from. A raw ``KnowledgeLineageDAG.collect``
        given only the current items strands the probation target (tested). The fold is
        recorded in the DAG's tombstone.
        """
        self._repin()
        live = list(self._mind.current().items)
        # Every RETAINED fossil, not only pinned ones: an operator may roll back to any held
        # digest, and folding an unpinned fossil's lineage made that rollback impossible
        # (review S6-R1). Loaded without the DAG — its lineage is what is being kept.
        for fossil in self._fossils.fossils():
            if fossil.artifact_hash == self._mind.digest():
                continue
            try:
                live += self._fossils.load(fossil.artifact_hash).items
            except (FossilIntegrityError, ContractError):
                continue  # corrupt: rollback skips it and says so
        anchors = [self._head, *sorted(self._pinned)]
        for record in self._records.values():
            if record.state in _IN_FLIGHT:
                anchors += [record.candidate_id, *record.nodes.values()]
                if record.candidate is not None:
                    live += record.candidate.proposed.items
        return self._lineage.collect(live_items=live, pinned_fossils=anchors)

    # --- read side --------------------------------------------------------------------------

    def decisions(self) -> tuple[PromotionDecision, ...]:
        return tuple(self._decisions)

    def rollbacks(self) -> tuple[LearningRollback, ...]:
        return tuple(self._rollbacks)

    def lifecycle(self, candidate_id: str) -> LifecycleState | None:
        record = self._records.get(candidate_id)
        return None if record is None else record.state

    def stats(self) -> ControllerStats:
        c = self._counts
        return ControllerStats(
            decisions_logged=len(self._decisions),
            decisions_dropped=c["decisions"] - len(self._decisions),
            rollbacks_logged=len(self._rollbacks),
            rollbacks_dropped=c["rollbacks"] - len(self._rollbacks),
            submitted=c["submitted"], promoted=c["promoted"], rejected=c["rejected"],
            rolled_back=c["rollbacks"], context_transitions=c["context"],
            submissions_refused=c["refused"], candidates_tracked=len(self._records),
            canary_active=self._canary is not None, probation_active=self._probation is not None,
        )

    def memory_bytes(self) -> int:
        """Serialised size of what the controller holds besides the mind (logs and records)."""
        logs = sum(len(json.dumps(d.to_dict())) for d in self._decisions)
        logs += sum(len(json.dumps(r.to_dict())) for r in self._rollbacks)
        held = sum(r.candidate.proposed.byte_size() for r in self._records.values()
                   if r.candidate is not None)
        return logs + held + 256 * len(self._records) + 96 * len(self._installed_by)

    # --- lifecycle bookkeeping ----------------------------------------------------------------

    def _require(self, candidate_id: str, state: LifecycleState) -> _Record:
        record = self._records.get(candidate_id)
        if record is None:
            raise ContractError(f"unknown candidate {candidate_id!r}; submit it first")
        if record.state is not state:
            raise ContractError(f"{candidate_id} is {record.state.value}, not {state.value}: "
                                "a lifecycle state cannot be skipped")
        return record

    def _make_room(self) -> None:
        """Refuse newcomers rather than forget in-flight candidates (Stage 2's rule)."""
        in_flight = sum(1 for r in self._records.values() if r.state in _IN_FLIGHT)
        if in_flight >= MAX_PENDING_CANDIDATES:
            self._counts["refused"] += 1
            raise ContractError(f"refused: {in_flight} candidates in flight "
                                f"(cap {MAX_PENDING_CANDIDATES})")
        watched = {w.candidate_id for w in (self._canary, self._probation) if w is not None}
        while len(self._records) >= MAX_CANDIDATE_RECORDS:
            victim = next((cid for cid, r in self._records.items()
                           if r.state not in _IN_FLIGHT and cid not in watched), None)
            if victim is None:
                self._counts["refused"] += 1
                raise ContractError("refused: candidate records full of live candidates")
            del self._records[victim]  # its history stays in the lineage DAG

    def _issue_decision(self, candidate_id: str, from_state: LifecycleState,
                        to_state: LifecycleState, reason: str, before: str, after: str, *,
                        record: _Record | None = None, canary: str | None = None,
                        install: bool = False) -> PromotionDecision:
        require_transition(from_state, to_state)
        self._sequence += 1
        verdict = None if record is None else record.verdict
        report = None if record is None else record.report
        body = [candidate_id, from_state.value, to_state.value, reason, before, after,
                self._sequence, self._token]
        decision = PromotionDecision(
            decision_id="dec-" + _digest(body)[7:39], candidate_id=candidate_id,
            from_state=from_state, to_state=to_state,
            conservation_digest=None if verdict is None else verdict.verdict_digest,
            shadow_digest=None if report is None else report.digest(), canary_digest=canary,
            trusted_before=before, trusted_after=after, reason=reason, sequence=self._sequence,
        )
        if install:
            _issued_decisions[decision.decision_id] = (self._token, decision)
            while len(_issued_decisions) > _MAX_OUTSTANDING_DECISIONS:
                _issued_decisions.popitem(last=False)
        else:
            self._log(decision)
        return decision

    def _install(self, state: TrustedKnowledgeState, decision: PromotionDecision) -> None:
        try:
            self._mind._install_trusted(state, decision=decision)
        finally:
            _issued_decisions.pop(decision.decision_id, None)
        self._log(decision)

    def _log(self, decision: PromotionDecision) -> None:
        self._decisions.append(decision)
        self._counts["decisions"] += 1

    def _advance(self, record: _Record, target: LifecycleState, reason: str) -> PromotionDecision:
        digest = self._mind.digest()
        decision = self._issue_decision(record.candidate_id, record.state, target, reason,
                                        digest, digest, record=record)
        record.state = target
        return decision

    def _reject(self, record: _Record, parent: str, reason: str,
                gate_result: str) -> PromotionDecision:
        """Back to quarantine: a REJECTION node, the trusted digest untouched, nothing deleted."""
        digest = self._mind.digest()
        decision = self._issue_decision(record.candidate_id, record.state, _S.REJECTED, reason,
                                        digest, digest, record=record)
        # A refusal is always recordable: if an outside collection folded the parent, the
        # REJECTION hangs from a live anchor instead (the fold is in the DAG's tombstone).
        parent = parent if self._lineage.has(parent) else self._anchor()
        self._node(LineageNode(f"rejection-{self._sequence}-{record.candidate_id}",
                               NodeKind.REJECTION, record.proposed_digest, self._sequence,
                               reason[:200]), (parent,), reason="rejected",
                   parent_versions=(record.base_digest,), gate_result=gate_result)
        record.state, record.candidate, record.hostile = _S.REJECTED, None, ()
        self._counts["rejected"] += 1
        return decision

    # --- lineage and fossils ------------------------------------------------------------------

    def _node(self, node: LineageNode, parents: Sequence[str], *, reason: str,
              **edge: Any) -> str:
        self._lineage.update_lineage_dag(node=node, parents=parents, reason=reason, **edge)
        return node.node_id

    def _stage_node(self, record: _Record, stage: str, kind: NodeKind, digest: str,
                    parent: str, *, passed: bool, failed: Sequence[str]) -> str:
        gate = "PASS" if passed else "FAIL:" + (",".join(failed) or "unspecified")
        return self._node(LineageNode(f"{stage}-{record.candidate_id}", kind, digest,
                                      self._sequence, stage), (parent,), reason=stage,
                          tests=(digest,), parent_versions=(record.base_digest,),
                          transformation=f"promotion.controller:{stage}", gate_result=gate)

    def _record_promotion(self, record: _Record, proposed: TrustedKnowledgeState,
                          canary_digest: str) -> None:
        assert record.verdict is not None and record.report is not None
        evidence = sorted({d for item in proposed.items
                           if item.lineage.candidate_id == record.candidate_id
                           for d in item.lineage.evidence_digests})
        parents = (record.candidate_id, record.nodes["conservation"], record.nodes["shadow"],
                   record.nodes["canary"])
        record.nodes["promotion"] = self._node(
            LineageNode(f"promotion-{record.candidate_id}", NodeKind.PROMOTION,
                        proposed.digest(), self._sequence, "promote_trusted"),
            parents, reason="promoted", evidence=tuple(evidence[:16]),
            tests=(record.verdict.verdict_digest, record.report.digest(), canary_digest),
            parent_versions=(record.base_digest,),
            transformation="promotion.controller:promote_trusted")

    def _fossilise(self, state: TrustedKnowledgeState, reason: FossilReason, *, pin: bool) -> str:
        fossil = self._fossils.create_fossil(state, reason=reason, fingerprint=_fingerprint(state),
                                             epoch_range=_epoch_range(state),
                                             sequence=self._sequence, pin=pin)
        if pin:
            self._pinned.add(fossil.artifact_hash)
        return fossil.artifact_hash

    def _repin(self) -> None:
        """Pinned = genesis + the current state + the probation rollback target. Nothing else."""
        desired = {self._genesis_digest, self._mind.digest()}
        if self._probation is not None:
            desired.add(self._probation.reference_digest)
        for artifact in sorted(self._pinned - desired):
            if self._fossils.get(artifact) is not None:
                self._fossils.unpin(artifact)
            self._pinned.discard(artifact)
        for artifact in sorted(desired - self._pinned):
            if self._fossils.get(artifact) is not None:
                self._fossils.pin(artifact)
                self._pinned.add(artifact)

    def _anchor(self) -> str:
        """The head of the trusted history if still live, else the never-folded genesis node."""
        return self._head if self._lineage.has(self._head) else GENESIS_PROMOTION_NODE

    def _remember_installer(self, digest: str, candidate_id: str) -> None:
        self._installed_by[digest] = candidate_id
        self._installed_by.move_to_end(digest)
        while len(self._installed_by) > MAX_CANDIDATE_RECORDS:
            self._installed_by.popitem(last=False)

    # --- rollback -----------------------------------------------------------------------------

    def _rollback(self, trigger: RollbackTrigger, to_digest: str | None,
                  evidence: tuple[str, ...]) -> LearningRollback:
        from_digest = self._mind.digest()
        if to_digest is not None and self._fossils.get(to_digest) is None:
            raise ContractError(f"refused: {to_digest} is not a fossil this store holds")
        if to_digest == from_digest:
            raise ContractError("refused: that is already the trusted state")
        refused = {*self._bad_digests, *(r.proposed_digest for r in self._records.values()
                                          if r.state is _S.ROLLED_BACK)}
        chosen = select_restore_target(
            self._fossils, self._lineage, requested=to_digest, from_digest=from_digest,
            preferred=[] if self._probation is None else [self._probation.reference_digest],
            refused=refused)
        target, restored, skipped = chosen.digest, chosen.state, chosen.skipped
        candidate_id = self._installed_by.get(from_digest, "unknown")
        record = self._records.get(candidate_id)
        from_life = record.state if record is not None and record.state in (
            _S.TRUSTED, _S.DORMANT) else _S.TRUSTED
        decision = self._issue_decision(candidate_id, from_life, _S.ROLLED_BACK,
                                        f"rollback:{trigger.value}", from_digest, target,
                                        record=record, install=True)
        recorded = (RollbackTrigger.FOSSIL_CORRUPTION if chosen.corrupt
                    else RollbackTrigger.LINEAGE_UNVERIFIABLE if skipped else trigger)
        try:  # lineage first: a restore that cannot be recorded does not happen
            self._record_rollback_lineage(record, candidate_id, recorded, trigger, target,
                                          from_digest, evidence, skipped)
        except BaseException:
            _issued_decisions.pop(decision.decision_id, None)
            raise
        self._install(restored, decision)
        identical = self._mind.current().canonical_bytes() == self._fossils.payload(target)
        if not identical:  # the installer re-read these exact bytes; this is an assertion
            raise FossilIntegrityError("restored state is not byte-identical to its fossil")
        if record is not None:
            record.state = _S.ROLLED_BACK
        self._bad_digests[from_digest] = None
        while len(self._bad_digests) > MAX_ROLLBACK_LOG:
            self._bad_digests.popitem(last=False)
        self._probation = None
        self._repin()
        rollback = LearningRollback(
            rollback_id="rb-" + _digest([from_digest, target, self._sequence])[7:39],
            trigger=recorded, candidate_id=None if record is None else candidate_id,
            from_digest=from_digest, to_digest=target, restored_bytes_identical=identical,
            skipped_fossils=skipped, evidence=evidence, sequence=self._sequence)
        self._rollbacks.append(rollback)
        self._counts["rollbacks"] += 1
        return rollback

    def _record_rollback_lineage(self, *args: Any) -> None:
        """A full DAG must not stop a rollback: collect once, retry under fresh ids (a node
        from the failed attempt may have been folded, and a folded id is never reissued)."""
        try:
            self._record_rollback_nodes(*args, suffix="")
        except LineageCapacityError:
            self.collect_lineage()
            self._record_rollback_nodes(*args, suffix="-retry")

    def _record_rollback_nodes(self, record: _Record | None, candidate_id: str,
                               recorded: RollbackTrigger, requested: RollbackTrigger,
                               target: str, from_digest: str, evidence: tuple[str, ...],
                               skipped: tuple[str, ...], *, suffix: str) -> None:
        node_id = self._node(
            LineageNode(f"rollback-{self._sequence}{suffix}", NodeKind.ROLLBACK, target,
                        self._sequence, f"trigger={recorded.value};requested={requested.value};"
                        f"skipped={len(skipped)}"),
            (self._anchor(),), reason="rollback_learning", evidence=evidence + skipped,
            tests=evidence, parent_versions=(from_digest,),
            transformation="promotion.controller:rollback_learning")
        if record is not None:
            promotion = record.nodes.get("promotion", node_id)
            parents = (promotion if self._lineage.has(promotion) else node_id, node_id)
            self._node(LineageNode(f"rejection-{self._sequence}-{candidate_id}{suffix}",
                                   NodeKind.REJECTION, from_digest, self._sequence,
                                   f"rolled back: {recorded.value}"),
                       tuple(dict.fromkeys(parents)), reason="rolled_back",
                       parent_versions=(from_digest,), gate_result=f"FAIL:{recorded.value}")
        self._head = node_id

    # --- context transitions ------------------------------------------------------------------

    def _install_context(self, transition_id: str, current: TrustedKnowledgeState,
                         proposed: TrustedKnowledgeState, verdict: ConservationVerdict,
                         previous: str) -> PromotionDecision:
        passed = verdict.passed
        gate = "PASS" if passed else "FAIL:" + ",".join(verdict.failed_checks())
        self._sequence += 1
        cons_node = self._node(
            LineageNode(f"conservation-{self._sequence}-{transition_id}", NodeKind.CONSERVATION,
                        verdict.verdict_digest, self._sequence, "context transition"),
            (self._anchor(),), reason="context_validation", tests=(verdict.verdict_digest,),
            parent_versions=(current.digest(),), gate_result=gate)
        digest = current.digest()
        if not passed:
            decision = self._issue_decision(transition_id, _S.CANDIDATE, _S.REJECTED,
                                            "context_transition_failed", digest, digest)
            self._node(LineageNode(f"rejection-{self._sequence}-{transition_id}",
                                   NodeKind.REJECTION, proposed.digest(), self._sequence,
                                   "context transition refused"), (cons_node,),
                       reason="rejected", gate_result=gate)
            self._counts["rejected"] += 1
            return decision
        self._issue_decision(transition_id, _S.CANDIDATE, _S.OFFLINE_VALIDATED,
                             "context_validated", digest, digest)
        self._fossilise(proposed, FossilReason.CONTEXT_DORMANCY, pin=True)
        fossil_node = self._node(
            LineageNode(f"fossil-{self._sequence}-{transition_id}", NodeKind.FOSSIL,
                        proposed.digest(), self._sequence, f"context {previous} dormant"),
            (cons_node,), reason="context_installed", parent_versions=(digest,),
            transformation="promotion.controller:apply_context_transition")
        decision = self._issue_decision(f"context:{previous}", _S.TRUSTED, _S.DORMANT,
                                        "context_dormant", digest, proposed.digest(),
                                        install=True)
        self._install(proposed, decision)
        self._head = fossil_node
        self._remember_installer(proposed.digest(), transition_id)
        self._counts["context"] += 1
        self._repin()
        return decision
