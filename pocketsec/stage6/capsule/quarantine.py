"""D6.2 (gateway half) / HEL-F02 — ``QuarantineGateway.admit``: the one door into learning.

Every experience that may ever change what this endpoint trusts — local telemetry,
analyst labels, Stage 4 resolutions, Stage 5 outcomes and, one day, foreign
knowledge from Stages 7–12 — enters here and nowhere else (integration plan §3.2,
trust rule T3). ``admit`` never writes trusted state: it sorts experience into four
buckets and, for normality, hands Stage 2's gate a register to write into instead of
a trusted store. The one trusted writer is ``promotion/controller.py``.

**Reuse, not duplication (ADR-0051).** This module owns exactly one Stage 2
``QuarantineBuffer`` and exactly one ``PromotionController`` and re-implements none
of their logic: the risk rule, the fixed-anchor consistency rule, the epoch rule, the
frequency refusal, the delay and the expiry are Stage 2's and their refusal reasons
surface here verbatim. The controller's ``quantizer`` is ``_CandidateRegister``, so
Stage 2's "write" lands in a bounded candidate register, never in trusted memory.

**What Stage 6 adds, and only that.** Stage 2's ``AdaptationSample`` carries no
source, so one attacker lineage repeating an escalation-free step across two
corroborated epochs is promoted (spec §0: 3 promotions in 240 offers). The
source-independence check (ADR-0054) runs *before* Stage 2's controller is called
and refuses a pattern seen from fewer than ``min_independent_groups`` independence
groups with the reason ``single_source_repetition``. Independence is tracked per
(Stage 2 pattern key, exact meaning): Stage 2's key is the relation alone, and
counting groups per relation would let one attacker free-ride on groups earned by
unrelated legitimate behaviour that shares the relation.

**What it refuses to do.** It refuses to evict: every bounded map here refuses the
newcomer when full and counts it (only the issued set and the episode index forget
their oldest, counted; the independence tracks retire their least recently seen, counted),
and an overflow never promotes. A full lineage DAG is folded once through the controller's
collector; if it is still full the capsule gets a counted, unissued ``lineage_full``
DISCARD — never an exception on every admit. It refuses to learn from a
hostile capsule, and it refuses to drop one silently: a HOSTILE_SUSPECT verdict is the
instruction to keep the capsule as evidence in episodic memory's hostile tier. It refuses labels on
episodes it never admitted, lets no TEACHER or WEAK label vote, and lets no foreign
capsule rise above UNCERTAIN without local corroboration (under the §4.21 parameters
FOREIGN_ORIGIN caps provenance below ``MIN_PROVENANCE_SCORE``, so today none rises at
all and the corroboration branch is INERT).

Stdlib plus the allow-listed upstream modules (ADR-0053).
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import sys
from collections import Counter, OrderedDict
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from pocketsec.stage0.contracts.common import ContractError, digest_of_bytes
from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage1.epoch.model import EpochDecision
from pocketsec.stage1.state.security_state import SecurityStateV1
from pocketsec.stage2.adaptation.promotion import PromotionController, PromotionRecord
from pocketsec.stage2.adaptation.quarantine import (
    AdaptationSample,
    QuarantineBuffer,
    meaning_vector,
    pattern_key,
)
from pocketsec.stage2.encoder.ssir_encoder import EncodedTransition
from pocketsec.stage5.stage6_interface import authority_violations, seam_violations
from pocketsec.stage6.capsule.experience_capsule import (
    EXPERIENCE_CAPSULE_V1_VERSION,
    CapsuleKind,
    EncodedStep,
    ExperienceCapsuleV1,
    PrivacyClass,
)
from pocketsec.stage6.constitution.learning import (
    MIN_INDEPENDENT_GROUPS,
    MIN_INDEPENDENT_LABEL_GROUPS,
    touches_protected,
)
from pocketsec.stage6.fossils.lineage import KnowledgeLineageDAG, LineageNode, NodeKind
from pocketsec.stage6.homeostasis.poisoning import (
    LabelHistory,
    LabelQuorum,
    NormalizationFinding,
    PoisonSuspicion,
    SourceIndependence,
    asserts_normality,
    detect_semantic_normalization_attack,
    escalating_steps,
    estimate_poison_suspicion,
    honoured_origin,
    motif_key,
    stage2_would_refuse,
    track_key,
)
from pocketsec.stage6.memory.semantic import MAX_ITEM_CAPSULE_REFS, TrustedKnowledgeState
from pocketsec.stage6.provenance.ledger import ProvenanceLedger, TrustRecord
from pocketsec.stage6.provenance.trust import (
    MIN_PROVENANCE_SCORE,
    DependenceReport,
    detect_evidence_dependence,
    score_provenance,
)

__all__ = [
    "SEALED_NAMES",
    "GATEWAY_ROOT_NODE",
    "MAX_CANDIDATE_REGISTER",
    "MAX_GROUPS_TRACKED_PER_PATTERN",
    "MAX_INDEXED_STEPS_PER_EPISODE",
    "MAX_ISSUED_VERDICTS",
    "MAX_PATTERNS_TRACKED",
    "MAX_PENDING_LABEL_EPISODES",
    "REASON_SINGLE_SOURCE",
    "CandidateAdmission",
    "GatewayStats",
    "QuarantineBucket",
    "QuarantineGateway",
    "QuarantineVerdict",
]

#: Chosen parameters (spec §4.21), not measurements.
MAX_ISSUED_VERDICTS: int = 4096
MAX_CANDIDATE_REGISTER: int = 64
MAX_PATTERNS_TRACKED: int = 512
MAX_GROUPS_TRACKED_PER_PATTERN: int = 16
MAX_PENDING_LABEL_EPISODES: int = 256

#: Escalating steps kept per indexed episode so a later LABEL_ASSERTION can be
#: screened against the trusted detectors. Not in the spec's §4.21 table: it bounds
#: an index the spec implies (labels arrive without steps) but does not size.
MAX_INDEXED_STEPS_PER_EPISODE: int = 8

REASON_SINGLE_SOURCE = "single_source_repetition"
#: The minting names only this file may mention (boundary rule 5), declared by the owner
#: so the gate can scan for them without spelling them itself.
SEALED_NAMES: tuple[str, ...] = ("_issue_verdict", "_issued_verdicts")
GATEWAY_ROOT_NODE = "gateway-root"
#: Most lineage nodes (and edges) one admit writes: the root once, the CAPSULE, the VERDICT.
_ADMIT_NODES = 3

#: The documented placeholder of spec §D6.2 step 6. Neither Stage 2's buffer nor
#: ``_CandidateRegister`` reads ``AdaptationSample.state``; a test proves the
#: register's output is identical for two different states.
_PLACEHOLDER_STATE = SecurityStateV1()

_COMMITTAL: frozenset[Verdict] = frozenset({Verdict.MALICIOUS, Verdict.BENIGN})


class QuarantineBucket(StrEnum):
    """Architecture §6: the four places an experience can land."""

    TRUSTED_CANDIDATE = "TRUSTED_CANDIDATE"
    UNCERTAIN = "UNCERTAIN"
    HOSTILE_SUSPECT = "HOSTILE_SUSPECT"
    DISCARD = "DISCARD"


@dataclass(frozen=True, slots=True)
class CandidateAdmission:
    """A normality pattern that cleared Stage 2's controller — a candidate, not knowledge."""

    pattern_key: str
    anchor: tuple[float, ...]
    context_id: str
    capsule_ids: tuple[str, ...]
    evidence_digests: tuple[str, ...]
    independent_groups: int
    stage2_reason: str
    sequence: int


@dataclass(frozen=True, slots=True)
class QuarantineVerdict:
    """Stage 6's ingress verdict; distinct from Stage 2's ``QuarantineVerdict``.

    The last three fields are additions to the spec's field list, all defaulted:
    ``pattern_keys``/``protected_keys`` are what ``homeostasis.drift`` needs to
    measure breadth and semantic stability from a window of verdicts, and
    ``target_episode`` names the episode a label or resolution decided, so the
    chamber need not re-open the capsule.
    """

    verdict_id: str
    capsule_id: str
    kind: CapsuleKind
    bucket: QuarantineBucket
    reasons: tuple[str, ...]
    trust: TrustRecord
    dependence: DependenceReport
    suspicion: PoisonSuspicion
    normalization: NormalizationFinding | None
    stage2_outcomes: tuple[tuple[str, int], ...]
    admissions: tuple[CandidateAdmission, ...]
    sequence: int
    pattern_keys: tuple[str, ...] = ()
    protected_keys: tuple[str, ...] = ()
    target_episode: str = ""


@dataclass(frozen=True, slots=True)
class GatewayStats:
    """Every bound and every refusal, as named counts. Nothing here is a claim."""

    counts: tuple[tuple[str, int], ...]
    memory_bytes: int

    def get(self, name: str) -> int:
        """A named count; 0 for a counter that never moved."""
        return dict(self.counts).get(name, 0)


# --- the Stage 2 adapter -----------------------------------------------------


@dataclass(frozen=True, slots=True)
class _Staging:
    """What the gateway knows about a promote call that Stage 2's protocol cannot carry."""

    context_id: str
    capsule_ids: tuple[str, ...]
    evidence: tuple[str, ...]
    groups: int


@dataclass(frozen=True, slots=True)
class _Written:
    pattern_key: str
    anchor: tuple[float, ...]
    sequence: int
    staging: _Staging


class _CandidateRegister:
    """Stage 2's ``TrustedQuantizer`` protocol, pointed at a bounded candidate register.

    Stage 2's controller believes it is writing a trusted atom. It is recording a
    pending BASELINE admission that still has to pass the chamber, the conservation
    gate, the shadow and the canary. It never reads ``state`` (the placeholder),
    holds no trusted atom (``get`` is always ``None``), refuses and counts when full,
    and records nothing for a call the gateway did not stage.
    """

    def __init__(self, *, capacity: int = MAX_CANDIDATE_REGISTER) -> None:
        self._capacity = capacity
        self._pending: OrderedDict[tuple[str, str], CandidateAdmission] = OrderedDict()
        self._staged: list[CandidateAdmission] = []
        self._staging: _Staging | None = None
        self._last: _Written | None = None
        self.refused = 0
        self.unstaged = 0
        self.aborted = 0
        self.taken = 0

    def stage(self, staging: _Staging) -> None:
        self._staging = staging
        self._last = None

    def unstage(self) -> None:
        self._staging = None

    def quantize_behaviour_atom(
        self, encoded: EncodedTransition, *, state: SecurityStateV1, epoch_id: int, sequence: int
    ) -> int:
        del state, epoch_id  # never read: see _PLACEHOLDER_STATE
        key = pattern_key(encoded)
        staging = self._staging
        atom_id = _stable_atom_id(key, staging.context_id if staging else "")
        if staging is None:
            self.unstaged += 1
            return atom_id
        slot = (key, staging.context_id)
        occupied = len(self._pending) + len(self._staged)
        staged = {(a.pattern_key, a.context_id) for a in self._staged}
        known = slot in self._pending or slot in staged
        if occupied >= self._capacity and not known:
            self.refused += 1
            return atom_id
        self._last = _Written(key, meaning_vector(encoded), sequence, staging)
        return atom_id

    def admit_last(self, stage2_reason: str) -> CandidateAdmission | None:
        written, self._last = self._last, None
        if written is None:
            return None
        staging = written.staging
        admission = CandidateAdmission(
            pattern_key=written.pattern_key, anchor=written.anchor, context_id=staging.context_id,
            capsule_ids=staging.capsule_ids, evidence_digests=staging.evidence,
            independent_groups=staging.groups, stage2_reason=stage2_reason,
            sequence=written.sequence,
        )
        self._staged.append(admission)
        return admission

    def commit(self) -> None:
        for admission in self._staged:
            slot = (admission.pattern_key, admission.context_id)
            prior = self._pending.pop(slot, None)
            self._pending[slot] = admission if prior is None else _merge(prior, admission)
        self._staged = []

    def abort(self) -> None:
        self.aborted += len(self._staged)
        self._staged = []
        self._staging = None
        self._last = None

    def drain(self) -> tuple[CandidateAdmission, ...]:
        out = tuple(self._pending.values())
        self._pending.clear()
        self.taken += len(out)
        return out

    def get(self, atom_id: int) -> None:
        del atom_id
        return None

    def __len__(self) -> int:
        return len(self._pending)

    def memory_bytes(self) -> int:
        return sum(_admission_bytes(a) for a in self._pending.values())


def _stable_atom_id(key: str, context_id: str) -> int:
    return int(hashlib.sha256(f"{context_id}|{key}".encode()).hexdigest()[:12], 16)


def _merge(old: CandidateAdmission, new: CandidateAdmission) -> CandidateAdmission:
    """Same pattern, same context: one pending admission with the union of its lineage."""
    return dataclasses.replace(
        old,
        capsule_ids=_bounded_union(old.capsule_ids, new.capsule_ids),
        evidence_digests=_bounded_union(old.evidence_digests, new.evidence_digests),
        independent_groups=max(old.independent_groups, new.independent_groups),
        stage2_reason=new.stage2_reason,
        sequence=new.sequence,
    )


def _bounded_union(left: tuple[str, ...], right: tuple[str, ...]) -> tuple[str, ...]:
    merged = list(dict.fromkeys(left + right))
    return tuple(merged[-MAX_ITEM_CAPSULE_REFS:])


def _admission_bytes(admission: CandidateAdmission) -> int:
    strings = admission.capsule_ids + admission.evidence_digests
    return 8 * len(admission.anchor) + sum(sys.getsizeof(s) for s in strings) + 160


# --- bounded bookkeeping -----------------------------------------------------


@dataclass(frozen=True, slots=True)
class _EpisodeFacts:
    steps: tuple[EncodedStep, ...]
    motif: str
    epoch_id: int


@dataclass
class _Call:
    """Mutable accumulator for one ``admit`` call; never outlives it."""

    capsule: ExperienceCapsuleV1
    sequence: int
    reasons: list[str] = field(default_factory=list)
    outcomes: Counter[str] = field(default_factory=Counter)
    admissions: list[CandidateAdmission] = field(default_factory=list)
    pattern_keys: set[str] = field(default_factory=set)
    protected_keys: set[str] = field(default_factory=set)
    target: str = ""

    def add(self, reason: str) -> None:
        if reason not in self.reasons:
            self.reasons.append(reason)


# --- the gateway -------------------------------------------------------------


class QuarantineGateway:
    """HEL-F02. Sorts experience into four buckets; writes nothing trusted."""

    def __init__(
        self,
        *,
        ledger: ProvenanceLedger,
        lineage: KnowledgeLineageDAG,
        buffer: QuarantineBuffer | None = None,
        controller: PromotionController | None = None,
        min_independent_groups: int = MIN_INDEPENDENT_GROUPS,
        independence_check: bool = True,
        homeostasis: bool = True,
        ground_truth_groups: Iterable[str] = (),
    ) -> None:
        """``ground_truth_groups``: the independence groups this deployment authenticated
        as lab ground truth. Empty on an endpoint; a GROUND_TRUTH claim from any other
        group is acted on as ANALYST (``poisoning.honoured_origin``, review S6-AUTH-01)."""
        if min_independent_groups < 2:
            raise ValueError(
                "min_independent_groups below 2 lets one group corroborate itself, "
                "which is promotion on frequency under another name"
            )
        self._ledger = ledger
        self._lineage = lineage
        # Default constructors on purpose: Stage 2's thresholds are Stage 2's (ADR-0051).
        self._buffer = buffer if buffer is not None else QuarantineBuffer()
        self._controller = controller if controller is not None else PromotionController()
        self._min_groups = min_independent_groups
        self._independence_check = independence_check
        self._homeostasis = homeostasis
        self._ground_truth = frozenset(ground_truth_groups)
        self._register = _CandidateRegister()
        self._history = LabelHistory()
        self._view: Callable[[], TrustedKnowledgeState] | None = None
        self._collector: Callable[[], int] | None = None
        self._issued_verdicts: OrderedDict[str, str] = OrderedDict()
        self._issued_capsules: OrderedDict[str, None] = OrderedDict()
        self._independence = SourceIndependence(
            max_patterns=MAX_PATTERNS_TRACKED,
            max_groups=MAX_GROUPS_TRACKED_PER_PATTERN,
            max_refs=MAX_ITEM_CAPSULE_REFS,
        )
        self._quorum = LabelQuorum(capacity=MAX_PENDING_LABEL_EPISODES)
        self._episodes: OrderedDict[str, _EpisodeFacts] = OrderedDict()
        self._sequence = 0
        self._step_sequence = 0
        self._n: Counter[str] = Counter()

    # --- binding and epochs ------------------------------------------------

    def bind_trusted_view(self, view: Callable[[], TrustedKnowledgeState]) -> None:
        """Bind the read-only view of trusted state, once. The gateway reads, never writes."""
        if self._view is not None:
            raise ContractError("the trusted view is bound once; a second binding is refused")
        if not callable(view):
            raise ContractError("the trusted view must be a callable returning the trusted state")
        self._view = view

    def bind_lineage_collector(self, collector: Callable[[], int]) -> None:
        """Bind, once, the fold the gateway may run when its lineage writes would not fit.

        The controller binds its own ``collect_lineage`` — only it knows which lineage the
        trusted state, the retained fossils and in-flight candidates still need.
        """
        if self._collector is not None:
            raise ContractError("the lineage collector is bound once; a second binding "
                                "is refused")
        if not callable(collector):
            raise ContractError("the lineage collector must be callable")
        self._collector = collector

    def _lineage_room(self) -> bool:
        """Room for this admit's nodes (root, capsule, verdict) and edges; fold once if not."""
        if self._lineage.has_room(nodes=_ADMIT_NODES, edges=_ADMIT_NODES):
            return True
        if self._collector is not None:
            self._n["lineage_folds_at_admit"] += 1
            self._collector()
        return self._lineage.has_room(nodes=_ADMIT_NODES, edges=_ADMIT_NODES)

    def record_epoch_decision(self, decision: EpochDecision) -> bool:
        """Forward to BOTH Stage 2 objects; each applies Stage 1's corroboration rule itself."""
        buffered = self._buffer.record_epoch_decision(decision)
        controlled = self._controller.record_epoch_decision(decision)
        return buffered and controlled

    # --- admission -----------------------------------------------------------

    def admit(self, capsule: ExperienceCapsuleV1) -> QuarantineVerdict:
        """HEL-F02 — integration plan §3.2's exact one-argument signature."""
        if self._view is None:
            raise ContractError("QuarantineGateway.admit before a trusted view was bound")
        if not isinstance(capsule, ExperienceCapsuleV1):
            name = type(capsule).__name__
            raise ContractError(f"only an ExperienceCapsuleV1 may enter learning, not {name}")
        if capsule.schema_version != EXPERIENCE_CAPSULE_V1_VERSION:
            raise ContractError(f"unsupported capsule schema {capsule.schema_version!r}")
        self._sequence += 1
        self._n["offered"] += 1
        call = _Call(capsule=capsule, sequence=self._sequence)
        trusted = self._view()
        if not self._lineage_room():
            # Refuse and count, never raise: a full DAG must not stop the learning door
            # for every capsule until the next consolidation (review S6-R2). The verdict is
            # DISCARD and is NOT issued, so nothing downstream can learn from it.
            self._n["lineage_full_refused"] += 1
            return self._early_discard(call, "lineage_full")
        try:
            verdict = self._decide(call, trusted)
            self._record_lineage(capsule, verdict, trusted)
        except Exception:
            self._register.abort()
            self._n["aborted_calls"] += 1
            raise
        self._register.commit()
        self._issue_verdict(verdict)
        return verdict

    def _decide(self, call: _Call, trusted: TrustedKnowledgeState) -> QuarantineVerdict:
        capsule = call.capsule
        if capsule.privacy_class is PrivacyClass.SECRET_BEARING:
            return self._early_discard(call, "secret_bearing")
        if capsule.capsule_id in self._issued_capsules or self._lineage.has(capsule.capsule_id):
            self._n["duplicates"] += 1
            return self._early_discard(call, "duplicate")
        score = score_provenance(capsule)
        trust = self._ledger.record(capsule, score=score)
        low_provenance = score.score < MIN_PROVENANCE_SCORE
        if low_provenance:
            call.add("low_provenance")
        call.target, target_steps = self._target_of(capsule)
        dependence = self._dependence(capsule, trust, call.target)
        suspicion = estimate_poison_suspicion(
            capsule, trust=trust, dependence=dependence, trusted=trusted,
            history=self._history, target_steps=target_steps,
            ground_truth_groups=self._ground_truth,
        )
        finding = None
        if self._homeostasis:
            finding = detect_semantic_normalization_attack(
                capsule, trusted=trusted, target_steps=target_steps,
                ground_truth_groups=self._ground_truth,
            )
        self._index_episode(capsule)
        if suspicion.is_hostile() or finding is not None:
            return self._hostile(call, trust, dependence, suspicion, finding)
        if low_provenance:
            return self._verdict(call, QuarantineBucket.UNCERTAIN, trust, dependence, suspicion)
        bucket = self._route(call)
        self._observe_label(capsule, target_steps)
        return self._verdict(call, bucket, trust, dependence, suspicion)

    def _route(self, call: _Call) -> QuarantineBucket:
        """Steps 6–9: exactly one path per capsule kind and label direction."""
        capsule = call.capsule
        kind = capsule.kind
        if kind is CapsuleKind.RESPONSE_OUTCOME:
            return self._response_path(call)
        if kind is CapsuleKind.FOREIGN_PACKAGE:
            return self._foreign_path(call)
        if kind is CapsuleKind.TRANSITION_EPISODE:
            if asserts_normality(capsule):
                return self._normality_path(call)
            if capsule.label is not None and capsule.label.verdict is Verdict.MALICIOUS:
                return self._threat_path(call)
            call.add("non_committal_label")
            return QuarantineBucket.UNCERTAIN
        return self._threat_path(call)

    # --- step 6: normality -------------------------------------------------

    def _normality_path(self, call: _Call) -> QuarantineBucket:
        capsule = call.capsule
        for step in capsule.steps:
            self._offer_step(call, step)
        benign_settled = False
        if capsule.label is not None:
            benign_settled = self._vote(call, capsule.capsule_id, Verdict.BENIGN)
        if call.admissions:
            call.add("normality_admitted")
            return QuarantineBucket.TRUSTED_CANDIDATE
        return QuarantineBucket.TRUSTED_CANDIDATE if benign_settled else QuarantineBucket.UNCERTAIN

    def _offer_step(self, call: _Call, step: EncodedStep) -> None:
        encoded = step.to_encoded()
        stage2_key = pattern_key(encoded)
        call.pattern_keys.add(stage2_key)
        self._n["steps_offered"] += 1
        if touches_protected(step.object_property_mask, step.state_delta_mask):
            call.protected_keys.add(stage2_key)
            if self._homeostasis and not stage2_would_refuse(step):
                # Protected meaning Stage 2's four properties do not cover: Stage 2
                # would HOLD it and could promote it, so it never reaches Stage 2.
                self._n["protected_withheld"] += 1
                self._n["beyond_stage2"] += 1
                call.add("protected_meaning_withheld")
                return
            if self._homeostasis:
                self._n["stage2_equivalent"] += 1
        self._step_sequence += 1
        sample = AdaptationSample(
            encoded=encoded, state=_PLACEHOLDER_STATE, epoch_id=step.epoch_id,
            delta_phi=step.delta_phi, uncertainty=step.uncertainty, evidence=step.evidence,
            received_at_sequence=self._step_sequence, causal_signature=step.causal_signature,
            parent_signature=step.parent_signature,
        )
        stage2 = self._buffer.quarantine_adaptation_sample(sample)
        key = track_key(encoded)
        tracked = self._independence.observe(key, call.capsule.capsule_id)
        if not stage2.eligible:
            self._promote(call, stage2, sample, key, 0)
            return
        groups = None
        if tracked:
            groups = self._independence.record_group(
                key, group=step.source_group, capsule_id=call.capsule.capsule_id,
                evidence=(*step.evidence, *call.capsule.evidence_refs),
            )
        if groups is None:
            call.add("pattern_register_full")
            return
        if self._independence_check and groups < self._min_groups:
            self._n["single_source_refusals"] += 1
            call.add(REASON_SINGLE_SOURCE)
            return
        self._promote(call, stage2, sample, key, groups)

    def _promote(
        self, call: _Call, stage2: Any, sample: AdaptationSample, key: str, groups: int
    ) -> None:
        """Hand one sample to Stage 2's controller. Ineligible samples go too, so its
        refusal reasons (``frequency_alone``, ``retained_as_evidence``) surface verbatim;
        by Stage 2's own ``_blocking_reason`` they can never write."""
        capsule_ids, evidence = self._independence.lineage(key)
        fallback = tuple(call.capsule.evidence_refs)[:MAX_ITEM_CAPSULE_REFS]
        own = (call.capsule.capsule_id,)
        self._register.stage(
            _Staging(call.capsule.context_id, capsule_ids or own, evidence or fallback, groups)
        )
        try:
            record: PromotionRecord = self._controller.promote(
                stage2, sample, quantizer=self._register, lattice=None
            )
        finally:
            self._register.unstage()
        if not record.promoted:
            call.outcomes[record.reason] += 1
            call.add(record.reason)
            return
        call.outcomes["PROMOTED"] += 1
        self._n["stage2_promotions"] += 1
        admission = self._register.admit_last(record.reason)
        if admission is None:
            call.add("candidate_register_full")
            return
        call.admissions.append(admission)

    # --- step 7: threat (label quorum) ------------------------------------

    def _threat_path(self, call: _Call) -> QuarantineBucket:
        capsule = call.capsule
        verdict = capsule.label.verdict if capsule.label is not None else capsule.resolution_state
        if verdict not in _COMMITTAL:
            call.add("non_committal_label")
            return QuarantineBucket.UNCERTAIN
        if not call.target:
            call.add("label_target_missing")
            return QuarantineBucket.UNCERTAIN
        settled = self._vote(call, call.target, verdict)
        return QuarantineBucket.TRUSTED_CANDIDATE if settled else QuarantineBucket.UNCERTAIN

    def _vote(self, call: _Call, target: str, verdict: Verdict) -> bool:
        """Record one group's vote on an admitted episode; True iff it settles ``verdict``."""
        capsule = call.capsule
        if target not in self._episodes:
            self._n["label_target_unknown"] += 1
            call.add("label_target_unknown")
            return False
        origin = honoured_origin(capsule, ground_truth_groups=self._ground_truth)
        if origin is not (capsule.label.origin if capsule.label is not None
                          else capsule.source_provenance.label_origin):
            self._n["ground_truth_demoted"] += 1
            call.add("ground_truth_unauthenticated")
        settled, reason = self._quorum.vote(
            target,
            verdict,
            group=capsule.source_provenance.independence_group,
            origin=origin,
            label_capsule="" if capsule.capsule_id == target else capsule.capsule_id,
        )
        call.add(reason)
        return settled

    # --- steps 8 and 9: response and foreign --------------------------------

    def _response_path(self, call: _Call) -> QuarantineBucket:
        rows = call.capsule.procedure_rows
        if not rows:
            call.add("procedure_rows_empty")
            return QuarantineBucket.UNCERTAIN
        dirty = [row for row in rows if seam_violations(row) or authority_violations(row)]
        if dirty:
            call.add("procedure_rows_failed_stage5_screens")
            return QuarantineBucket.UNCERTAIN
        call.add("procedure_rows_screened")
        return QuarantineBucket.TRUSTED_CANDIDATE

    def _foreign_path(self, call: _Call) -> QuarantineBucket:
        """At most UNCERTAIN unless a LOCAL independent group already showed the same thing.

        Foreign steps never enter Stage 2's buffer or the group tracks: a remote
        majority must not be able to manufacture the local corroboration it needs.
        """
        capsule = call.capsule
        steps = capsule.steps
        by_pattern = bool(steps) and all(
            self._independence.groups(track_key(step.to_encoded())) > 0 for step in steps
        )
        verdict = capsule.label.verdict if capsule.label is not None else None
        key = motif_key(steps)
        by_motif = (
            verdict in _COMMITTAL and bool(key) and self._history.supporters(key, verdict) > 0
        )
        if by_pattern or by_motif:
            call.add("foreign_locally_corroborated")
            return QuarantineBucket.TRUSTED_CANDIDATE
        call.add("foreign_uncorroborated")
        return QuarantineBucket.UNCERTAIN

    # --- steps 1–5 helpers ---------------------------------------------------

    def _early_discard(self, call: _Call, reason: str) -> QuarantineVerdict:
        """Secret-bearing or duplicate: provenance is still recorded, nothing else runs."""
        capsule = call.capsule
        call.add(reason)
        trust = self._ledger.get(capsule.capsule_id)
        if trust is None:
            trust = self._ledger.record(capsule, score=score_provenance(capsule))
        dependence = detect_evidence_dependence((trust,), min_groups=self._min_groups)
        suspicion = PoisonSuspicion(
            source_control=float(trust.contamination_risk), dependence=0.0,
            protected_conflict=False, label_shift=0.0, trigger_concentration=0.0,
            cross_epoch_inconsistency=0.0,
        )
        return self._verdict(call, QuarantineBucket.DISCARD, trust, dependence, suspicion)

    def _hostile(
        self, call: _Call, trust: TrustRecord, dependence: DependenceReport,
        suspicion: PoisonSuspicion, finding: NormalizationFinding | None,
    ) -> QuarantineVerdict:
        """Kept as evidence, never learned from, never silently dropped."""
        call.add("hostile_suspect")
        for reason in suspicion.hostile_reasons():
            call.add(reason)
        if finding is not None:
            self._n["normalization_findings"] += 1
            call.add(f"normalization:{finding.rule}")
        bucket = QuarantineBucket.HOSTILE_SUSPECT
        return self._verdict(call, bucket, trust, dependence, suspicion, finding)

    def _target_of(self, capsule: ExperienceCapsuleV1) -> tuple[str, tuple[EncodedStep, ...]]:
        """The episode this capsule speaks about, and its indexed escalating steps."""
        if capsule.kind is CapsuleKind.TRANSITION_EPISODE:
            return capsule.capsule_id, ()
        if capsule.kind in (CapsuleKind.LABEL_ASSERTION, CapsuleKind.WORLD_RESOLUTION):
            target = capsule.label.target_capsule_id if capsule.label is not None else ""
            facts = self._episodes.get(target)
            return target, (facts.steps if facts is not None else ())
        return "", ()

    def _dependence(
        self, capsule: ExperienceCapsuleV1, trust: TrustRecord, target: str
    ) -> DependenceReport:
        """Step 4: votes on the same episode (labels), or capsules on the same patterns."""
        if capsule.label is not None or capsule.kind is CapsuleKind.WORLD_RESOLUTION:
            related: tuple[str, ...] = self._quorum.label_capsules(target)
            min_groups = MIN_INDEPENDENT_LABEL_GROUPS
        else:
            keys = sorted({track_key(step.to_encoded()) for step in capsule.steps})
            related = self._independence.related(keys)
            min_groups = self._min_groups
        records = [r for r in self._ledger.records_for(related) if r.capsule_id != trust.capsule_id]
        return detect_evidence_dependence((*records, trust), min_groups=min_groups)

    def _index_episode(self, capsule: ExperienceCapsuleV1) -> None:
        """Bounded index of recent episodes so labels can name them (oldest forgotten)."""
        if capsule.kind is not CapsuleKind.TRANSITION_EPISODE:
            return
        escalating = escalating_steps(capsule.steps)
        # One step per (actor, relation, masks) keeps every distinct signature a motif
        # or a motif key can use; the cap is counted, never silent.
        signature = {
            (s.actor_slot, s.relation, s.object_property_mask, s.state_delta_mask): s
            for s in reversed(escalating)
        }
        distinct = tuple(signature.values())[::-1]
        if len(distinct) > MAX_INDEXED_STEPS_PER_EPISODE:
            self._n["indexed_steps_truncated"] += 1
        self._episodes[capsule.capsule_id] = _EpisodeFacts(
            steps=distinct[:MAX_INDEXED_STEPS_PER_EPISODE],
            motif=motif_key(escalating),
            epoch_id=capsule.epoch_id,
        )
        while len(self._episodes) > MAX_PENDING_LABEL_EPISODES:
            self._episodes.popitem(last=False)
            self._n["episodes_forgotten"] += 1

    def _observe_label(
        self, capsule: ExperienceCapsuleV1, target_steps: tuple[EncodedStep, ...]
    ) -> None:
        """Only non-hostile, adequately-sourced local verdicts enter the label history."""
        if capsule.kind is CapsuleKind.FOREIGN_PACKAGE:
            return
        verdict = capsule.label.verdict if capsule.label is not None else None
        if verdict is None and capsule.kind is CapsuleKind.WORLD_RESOLUTION:
            verdict = capsule.resolution_state
        if verdict not in _COMMITTAL:
            return
        key = motif_key(tuple(capsule.steps) or target_steps)
        group = capsule.source_provenance.independence_group
        self._history.observe(key, verdict, group=group, epoch_id=capsule.epoch_id)

    # --- step 10: verdict, lineage, issuance ---------------------------------

    def _verdict(
        self, call: _Call, bucket: QuarantineBucket, trust: TrustRecord,
        dependence: DependenceReport, suspicion: PoisonSuspicion,
        finding: NormalizationFinding | None = None,
    ) -> QuarantineVerdict:
        reasons = tuple(call.reasons)
        payload = json.dumps([call.capsule.capsule_id, bucket.value, list(reasons), call.sequence])
        self._n[f"bucket:{bucket.value}"] += 1
        return QuarantineVerdict(
            verdict_id="qv-" + digest_of_bytes(payload.encode("utf-8")).split(":", 1)[1][:32],
            capsule_id=call.capsule.capsule_id, kind=call.capsule.kind, bucket=bucket,
            reasons=reasons,
            trust=trust, dependence=dependence, suspicion=suspicion, normalization=finding,
            stage2_outcomes=tuple(sorted(call.outcomes.items())), admissions=tuple(call.admissions),
            sequence=call.sequence, pattern_keys=tuple(sorted(call.pattern_keys)),
            protected_keys=tuple(sorted(call.protected_keys)), target_episode=call.target,
        )

    def _record_lineage(
        self,
        capsule: ExperienceCapsuleV1,
        verdict: QuarantineVerdict,
        trusted: TrustedKnowledgeState,
    ) -> None:
        """CAPSULE then VERDICT nodes. Only after both exist is the verdict issued."""
        if not self._lineage.has(GATEWAY_ROOT_NODE):
            self._lineage.update_lineage_dag(
                node=LineageNode(
                    node_id=GATEWAY_ROOT_NODE, kind=NodeKind.GENESIS,
                    digest=digest_of_bytes(GATEWAY_ROOT_NODE.encode("utf-8")),
                    created_sequence=0, detail="quarantine gateway root",
                ),
                parents=(), reason="gateway_root",
            )
        evidence = tuple(capsule.evidence_refs)
        if not self._lineage.has(capsule.capsule_id):
            self._lineage.update_lineage_dag(
                node=LineageNode(
                    node_id=capsule.capsule_id, kind=NodeKind.CAPSULE, digest=capsule.digest(),
                    created_sequence=verdict.sequence, detail=capsule.kind.value,
                ),
                parents=(GATEWAY_ROOT_NODE,), reason="capsule_offered", evidence=evidence,
                transformation="stage6.capsule.experience_capsule",
            )
        passed = verdict.bucket is QuarantineBucket.TRUSTED_CANDIDATE
        self._lineage.update_lineage_dag(
            node=LineageNode(
                node_id=verdict.verdict_id, kind=NodeKind.VERDICT, digest=_seal(verdict),
                created_sequence=verdict.sequence, detail=verdict.bucket.value,
            ),
            parents=(capsule.capsule_id,), reason="quarantine_verdict", evidence=evidence,
            parent_versions=(trusted.digest(),),
            transformation="stage6.capsule.quarantine:QuarantineGateway.admit",
            gate_result="PASS" if passed else f"FAIL:{verdict.bucket.value}",
        )

    def _issue_verdict(self, verdict: QuarantineVerdict) -> None:
        self._issued_verdicts[verdict.verdict_id] = _seal(verdict)
        self._issued_capsules[verdict.capsule_id] = None
        for store, counter in ((self._issued_verdicts, "issued_forgotten"),
                               (self._issued_capsules, "capsule_ids_forgotten")):
            while len(store) > MAX_ISSUED_VERDICTS:
                store.popitem(last=False)
                self._n[counter] += 1

    def issued(self, verdict: QuarantineVerdict) -> bool:
        """True only for a verdict this gateway minted, unaltered, still in the issued set."""
        if not isinstance(verdict, QuarantineVerdict):
            return False
        return self._issued_verdicts.get(verdict.verdict_id) == _seal(verdict)

    # --- draining and reporting ----------------------------------------------

    def take_admissions(self) -> tuple[CandidateAdmission, ...]:
        """Drain the candidate register. Admissions are candidates, not knowledge."""
        return self._register.drain()

    def pending_label_episodes(self) -> tuple[str, ...]:
        return self._quorum.pending()

    def label_history(self) -> LabelHistory:
        return self._history

    def memory_bytes(self) -> int:
        """Upper-bound estimate of everything this gateway holds, Stage 2's objects included."""
        controller = self._controller.stats()
        issued = sum(sys.getsizeof(k) + 113 for k in self._issued_verdicts)
        issued += sum(sys.getsizeof(k) + 16 for k in self._issued_capsules)
        episodes = sum(3200 * len(f.steps) + 160 for f in self._episodes.values())
        return (
            self._buffer.memory_bytes()
            + 160 * (controller.delayed_pending + len(self._controller.refusals()))
            + self._register.memory_bytes()
            + issued
            + self._independence.memory_bytes()
            + self._quorum.memory_bytes()
            + episodes
            + self._history.memory_bytes()
        )

    def stats(self) -> GatewayStats:
        counts = Counter(self._n)
        counts.update(
            {
                "issued": len(self._issued_verdicts),
                "admissions_pending": len(self._register),
                "admissions_taken": self._register.taken,
                "register_refused": self._register.refused,
                "register_unstaged": self._register.unstaged,
                "register_aborted": self._register.aborted,
                "patterns_tracked": len(self._independence),
                "pattern_overflow": self._independence.pattern_overflow,
                "pattern_evictions": self._independence.pattern_evictions,
                "group_overflow": self._independence.group_overflow + self._quorum.voter_overflow,
                "label_episodes": len(self._quorum),
                "label_overflow": self._quorum.overflow,
                "indexed_episodes": len(self._episodes),
                "label_history_forgotten": self._history.forgotten(),
            }
        )
        return GatewayStats(counts=tuple(sorted(counts.items())), memory_bytes=self.memory_bytes())


def _seal(verdict: QuarantineVerdict) -> str:
    """Content seal of a whole verdict: a hand-edited copy with a real id fails ``issued``."""
    return digest_of_bytes(repr(verdict).encode("utf-8"))
