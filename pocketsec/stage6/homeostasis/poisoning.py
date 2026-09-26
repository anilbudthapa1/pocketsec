"""D6.15 — Semantic Homeostasis: the poisoning suspicion vector and the normalisation detector.

An adaptive endpoint can be taught to ignore an attack. The attacker does not need
to break the learner; they only need to repeat, relabel or near-miss their way into
what the learner calls normal. This module exists to name those attempts *before*
the gateway lets anything reach the normality learner, and it refuses two things
outright:

* **Protected meaning never adapts from frequency** (architecture §21). The three
  normalisation rules below read masks, labels and the trusted detector set. No
  count, rate or repetition enters any of them — a rule that fired "after N
  benign observations" would be the exact attack it is meant to stop, run
  backwards. Baseline *frequency* may adapt (Stage 2's buffer); the anchors may not.
* **Suspicion is a structured vector, not one scalar** (architecture §34). A
  reviewer asking *why* a capsule was held hostile gets eight named components,
  not a number that has already averaged the reason away.

What the vector does NOT carry, and why: ``dependence`` is the dependence of the
capsule's **votes** — the label it asserts. Unlabelled telemetry asserts nothing,
so its vote dependence is 0.0. Its repetition dependence is real, but it is
enforced by the gateway's source-independence check (ADR-0054), which refuses with
the reason ``single_source_repetition`` rather than branding the capsule hostile.
Branding single-lineage routine behaviour hostile would flood the bounded hostile
tier with cron jobs and evict genuine hostile evidence — a flooding attack the
defence would perform on itself (arm P6). The full repetition picture still
travels on ``QuarantineVerdict.dependence``.

Two pieces of gateway bookkeeping live here because they are poisoning defences,
not plumbing: ``LabelQuorum`` (label poisoning — one group is one vote, TEACHER and
WEAK never vote) and ``SourceIndependence`` (ADR-0054 — independence groups per
Stage 2 pattern and meaning). Both are bounded and refuse newcomers when full.

``historical_regression`` and ``counterfactual_instability`` are ``None`` here:
they are measured by the conservation gate (G2, G4) against replay, which this
module has no access to and must not guess. ``None`` is UNMEASURED, never zero.

Stdlib only.
"""

from __future__ import annotations

import hashlib
import sys
from collections import OrderedDict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage2.adaptation.quarantine import ESCALATION_MASK, MAX_EPOCHS_PER_PATTERN
from pocketsec.stage6.capsule.experience_capsule import (
    GROUND_TRUTH_SOURCES,
    CapsuleKind,
    EncodedStep,
    ExperienceCapsuleV1,
    LabelOrigin,
)
from pocketsec.stage6.constitution.learning import MIN_INDEPENDENT_LABEL_GROUPS, touches_protected
# Re-exported: ADR-0054's bookkeeping lives in ``homeostasis.independence``; the gateway and
# the tests import it from here.
from pocketsec.stage6.homeostasis.independence import SourceIndependence, track_key
from pocketsec.stage6.memory.semantic import (
    ItemKind,
    ItemStatus,
    KnowledgeItem,
    TrustedKnowledgeState,
    is_escalating,
    match_motif,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from pocketsec.stage6.provenance.ledger import TrustRecord
    from pocketsec.stage6.provenance.trust import DependenceReport

__all__ = [
    "HOSTILE_DEPENDENCE",
    "HOSTILE_LABEL_SHIFT",
    "HOSTILE_TRIGGER_CONCENTRATION",
    "MAX_LABEL_HISTORY",
    "MAX_VOTERS_PER_MOTIF",
    "RULE_BENIGN_LABEL_ON_PROTECTED_DETECTOR",
    "RULE_NORMALITY_ON_PROTECTED_MEANING",
    "RULE_REMOVE_PROTECTED_DETECTOR",
    "VOTING_ORIGINS",
    "LabelHistory",
    "LabelQuorum",
    "NormalizationFinding",
    "PoisonSuspicion",
    "SourceIndependence",
    "asserts_normality",
    "detect_semantic_normalization_attack",
    "escalating_steps",
    "estimate_poison_suspicion",
    "honoured_origin",
    "label_quorum_met",
    "motif_key",
    "near_miss",
    "stage2_would_refuse",
    "track_key",
]

#: Chosen parameters (spec §4.21), not measurements.
HOSTILE_DEPENDENCE: float = 0.8
HOSTILE_TRIGGER_CONCENTRATION: float = 0.5
HOSTILE_LABEL_SHIFT: float = 0.5
MAX_LABEL_HISTORY: int = 512

#: Distinct voting groups remembered per motif key. Mirrors the gateway's
#: ``MAX_GROUPS_TRACKED_PER_PATTERN`` (16); a separate name because this module
#: may not import the gateway (the gateway imports it). Past the cap a new group's
#: vote is not recorded and the refusal is counted, never silent.
MAX_VOTERS_PER_MOTIF: int = 16

RULE_BENIGN_LABEL_ON_PROTECTED_DETECTOR = "benign_label_on_protected_detector"
RULE_NORMALITY_ON_PROTECTED_MEANING = "normality_on_protected_meaning"
RULE_REMOVE_PROTECTED_DETECTOR = "remove_protected_detector"

_COMMITTAL: frozenset[Verdict] = frozenset({Verdict.MALICIOUS, Verdict.BENIGN})
_OPPOSITE: dict[Verdict, Verdict] = {
    Verdict.MALICIOUS: Verdict.BENIGN, Verdict.BENIGN: Verdict.MALICIOUS
}


# --- step predicates ---------------------------------------------------------


def stage2_would_refuse(step: EncodedStep) -> bool:
    """True when Stage 2's own risk rule already refuses this step as evidence.

    Used to count Stage 6 findings honestly: a homeostasis refusal on a step Stage 2
    would have refused anyway is ``stage2_equivalent`` and adds nothing.
    """
    return bool(step.object_property_mask & ESCALATION_MASK) or bool(step.state_delta_mask)


def _touches(step: EncodedStep) -> tuple[str, ...]:
    return touches_protected(step.object_property_mask, step.state_delta_mask)


def escalating_steps(steps: Sequence[EncodedStep]) -> tuple[EncodedStep, ...]:
    """Steps carrying security consequence, by ``memory.semantic.is_escalating``.

    Reused, not re-derived, so the label-history key, the episode index and the
    trusted score can never disagree about which steps matter.
    """
    return tuple(step for step in steps if is_escalating(step))


def motif_key(steps: Sequence[EncodedStep]) -> str:
    """An episode's label-history key: its escalating step signatures, order-free.

    Built from masks only — never actor identity, time or features — so two
    sessions of one attack family share a key and a benign twin differing by one
    property bit does not. ``""`` means the episode has no escalating step and
    therefore nothing a label could shift.
    """
    signature = sorted(
        {(s.relation, s.object_property_mask, s.state_delta_mask) for s in escalating_steps(steps)}
    )
    if not signature:
        return ""
    material = ";".join(f"{r}/{m}/{d}" for r, m, d in signature)
    return "motif:" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]


def near_miss(step: EncodedStep, item: KnowledgeItem) -> bool:
    """True when ``step`` is exactly one object-property bit away from a motif step.

    One bit away means: the same relation, the raised requirement met, and either
    one required property missing or one forbidden property present — the shape
    of a staging step crafted to sit just outside a trusted detector (arm P4c).
    """
    for motif_step in item.motif:
        if step.relation != motif_step.relation:
            continue
        if (step.state_delta_mask & motif_step.require_raised) != motif_step.require_raised:
            continue
        missing = motif_step.require_properties & ~step.object_property_mask
        forbidden = motif_step.forbid_properties & step.object_property_mask
        if bin(missing).count("1") + bin(forbidden).count("1") == 1:
            return True
    return False


def asserts_normality(capsule: ExperienceCapsuleV1) -> bool:
    """True when the capsule offers its steps as *normal* rather than as an attack.

    A TRANSITION_EPISODE or FOREIGN_PACKAGE whose label is absent or BENIGN. A
    SUSPICIOUS/UNKNOWN label asserts neither direction and is not normality.
    """
    if capsule.kind not in (CapsuleKind.TRANSITION_EPISODE, CapsuleKind.FOREIGN_PACKAGE):
        return False
    return capsule.label is None or capsule.label.verdict is Verdict.BENIGN


def _asserted_verdict(capsule: ExperienceCapsuleV1) -> Verdict | None:
    if capsule.label is not None:
        return capsule.label.verdict
    if capsule.kind is CapsuleKind.WORLD_RESOLUTION:
        return capsule.resolution_state
    return None


def _asserted_origin(capsule: ExperienceCapsuleV1) -> LabelOrigin:
    if capsule.label is not None:
        return capsule.label.origin
    return capsule.source_provenance.label_origin


def honoured_origin(
    capsule: ExperienceCapsuleV1, *, ground_truth_groups: frozenset[str] = frozenset()
) -> LabelOrigin:
    """The label origin the gateway acts on: GROUND_TRUTH only from an authenticated group.

    GROUND_TRUTH settles an episode alone and is exempt from the benign-label and
    label-shift rules, so it cannot be a self-asserted enum value (review S6-AUTH-01).
    Both ``source_class`` and ``independence_group`` are declared by the capsule, so the
    authentication is the deployment's list of lab groups; a claim from any other group,
    or from a source class that may not declare it, is demoted to ANALYST — one validated
    opinion that needs a second independent group, and is screened like any other.
    The default (no group authenticated) is the endpoint's: a real host has no lab.
    """
    origin = _asserted_origin(capsule)
    if origin is not LabelOrigin.GROUND_TRUTH:
        return origin
    provenance = capsule.source_provenance
    if (provenance.source_class in GROUND_TRUTH_SOURCES
            and provenance.independence_group in ground_truth_groups):
        return origin
    return LabelOrigin.ANALYST


def _active_detectors(trusted: TrustedKnowledgeState) -> tuple[KnowledgeItem, ...]:
    return tuple(
        item
        for item in trusted.items
        if item.kind is ItemKind.DETECTOR and item.status is ItemStatus.ACTIVE
    )


# --- the suspicion vector ----------------------------------------------------


@dataclass(frozen=True, slots=True)
class PoisonSuspicion:
    """Architecture §34 — eight components, each a separate reason to distrust."""

    source_control: float
    dependence: float
    protected_conflict: bool
    label_shift: float
    trigger_concentration: float
    cross_epoch_inconsistency: float
    historical_regression: float | None = None
    counterfactual_instability: float | None = None

    def summary(self) -> float:
        """Max over the numeric components; 1.0 on a protected conflict. ``None`` is skipped."""
        if self.protected_conflict:
            return 1.0
        values = [
            self.source_control,
            self.dependence,
            self.label_shift,
            self.trigger_concentration,
            self.cross_epoch_inconsistency,
        ]
        measured_later = (self.historical_regression, self.counterfactual_instability)
        values.extend(v for v in measured_later if v is not None)
        return max(values)

    def is_hostile(self) -> bool:
        """The four hostility rules. No single weak component is enough.

        ``dependence >= HOSTILE_DEPENDENCE`` carries its own minimum-observation
        requirement: ``1 - groups / observations >= 0.8`` needs at least five votes
        per group, so a pair of agreeing votes can never be branded dependent.
        """
        return (
            self.protected_conflict
            or self.dependence >= HOSTILE_DEPENDENCE
            or self.trigger_concentration >= HOSTILE_TRIGGER_CONCENTRATION
            or self.label_shift >= HOSTILE_LABEL_SHIFT
        )

    def hostile_reasons(self) -> tuple[str, ...]:
        """Which hostility rule(s) fired, as reason tokens for the verdict."""
        reasons: list[str] = []
        if self.protected_conflict:
            reasons.append("suspicion:protected_conflict")
        if self.dependence >= HOSTILE_DEPENDENCE:
            reasons.append("suspicion:dependence")
        if self.trigger_concentration >= HOSTILE_TRIGGER_CONCENTRATION:
            reasons.append("suspicion:trigger_concentration")
        if self.label_shift >= HOSTILE_LABEL_SHIFT:
            reasons.append("suspicion:label_shift")
        return tuple(reasons)


# --- label history -----------------------------------------------------------


@dataclass
class _MotifVotes:
    """Per motif key: which groups asserted which verdict, and in which epochs."""

    voters: dict[Verdict, set[str]] = field(default_factory=dict)
    epochs: OrderedDict[int, dict[Verdict, int]] = field(default_factory=OrderedDict)

    def memory_bytes(self) -> int:
        groups = sum(sys.getsizeof(g) for voters in self.voters.values() for g in voters)
        return groups + 48 * len(self.epochs) + 64


class LabelHistory:
    """Bounded memory of which verdict each motif received, from whom, and when.

    Bounded twice: at most ``capacity`` motif keys (oldest forgotten, counted) and
    at most ``MAX_VOTERS_PER_MOTIF`` groups and ``MAX_EPOCHS_PER_PATTERN`` epochs per
    key (newcomers refused, counted). Only MALICIOUS and BENIGN are recorded: the
    non-committal verdicts assert nothing a later label could contradict.
    """

    def __init__(self, *, capacity: int = MAX_LABEL_HISTORY) -> None:
        if capacity < 1:
            raise ValueError("a label history must hold at least one motif")
        self._capacity = capacity
        self._motifs: OrderedDict[str, _MotifVotes] = OrderedDict()
        self._forgotten = 0
        self._refused_votes = 0

    def observe(self, motif_key: str, verdict: Verdict, *, group: str, epoch_id: int) -> None:
        if not motif_key or verdict not in _COMMITTAL:
            return
        entry = self._motifs.get(motif_key)
        if entry is None:
            entry = _MotifVotes()
            self._motifs[motif_key] = entry
            while len(self._motifs) > self._capacity:
                self._motifs.popitem(last=False)
                self._forgotten += 1
        self._motifs.move_to_end(motif_key)
        voters = entry.voters.setdefault(verdict, set())
        if group not in voters:
            if sum(len(v) for v in entry.voters.values()) >= MAX_VOTERS_PER_MOTIF:
                self._refused_votes += 1
            else:
                voters.add(group)
        per_epoch = entry.epochs.get(epoch_id)
        if per_epoch is None:
            if len(entry.epochs) >= MAX_EPOCHS_PER_PATTERN:
                self._refused_votes += 1
                return
            per_epoch = {}
            entry.epochs[epoch_id] = per_epoch
        per_epoch[verdict] = per_epoch.get(verdict, 0) + 1

    def opposite_share(self, motif_key: str, verdict: Verdict) -> float:
        """Share of distinct prior voting groups that asserted the opposite verdict."""
        entry = self._motifs.get(motif_key)
        opposite = _OPPOSITE.get(verdict)
        if entry is None or opposite is None:
            return 0.0
        everyone: set[str] = set()
        for voters in entry.voters.values():
            everyone |= voters
        if not everyone:
            return 0.0
        return len(entry.voters.get(opposite, set())) / len(everyone)

    def supporters(self, motif_key: str, verdict: Verdict) -> int:
        """Distinct groups that asserted ``verdict`` on this motif (local corroboration)."""
        entry = self._motifs.get(motif_key)
        return 0 if entry is None else len(entry.voters.get(verdict, set()))

    def epoch_inconsistency(self, motif_key: str) -> float:
        """Share of epochs whose majority verdict differs from the motif's overall one.

        Fewer than two epochs cannot be inconsistent across epochs: 0.0. A tied
        epoch has no majority and counts as inconsistent, because an epoch in
        which the motif was called both things is not evidence for either.
        """
        entry = self._motifs.get(motif_key)
        if entry is None or len(entry.epochs) < 2:
            return 0.0
        totals: dict[Verdict, int] = {}
        for per_epoch in entry.epochs.values():
            for verdict, count in per_epoch.items():
                totals[verdict] = totals.get(verdict, 0) + count
        overall = _majority(totals)
        differing = sum(1 for per_epoch in entry.epochs.values() if _majority(per_epoch) != overall)
        return differing / len(entry.epochs)

    def forgotten(self) -> int:
        return self._forgotten

    def refused_votes(self) -> int:
        return self._refused_votes

    def __len__(self) -> int:
        return len(self._motifs)

    def memory_bytes(self) -> int:
        return sum(sys.getsizeof(k) + v.memory_bytes() for k, v in self._motifs.items())


def _majority(counts: dict[Verdict, int]) -> Verdict | None:
    if not counts:
        return None
    best = max(counts.values())
    leaders = [verdict for verdict, count in counts.items() if count == best]
    return leaders[0] if len(leaders) == 1 else None


# --- the normalisation detector (HEL-F18) ------------------------------------


@dataclass(frozen=True, slots=True)
class NormalizationFinding:
    """A capsule that would move protected meaning toward normal, and the rule it broke."""

    anchors: tuple[str, ...]
    detector_ids: tuple[str, ...]
    rule: str
    detail: str


def _named_protected_detector(
    capsule: ExperienceCapsuleV1, detectors: Sequence[KnowledgeItem]
) -> tuple[str, ...]:
    """Protected detectors whose founding evidence a LABEL/FOREIGN capsule disowns (rule 3).

    A capsule cannot name an item id (capsule references are ``cap-`` ids only), so
    "proposing to retire a protected detector" is expressed the only way it can be:
    a non-MALICIOUS label on, or a contradiction of, a capsule that a protected
    detector's lineage cites. Accepting it would remove the detector's reason to exist.
    """
    if capsule.kind not in (CapsuleKind.LABEL_ASSERTION, CapsuleKind.FOREIGN_PACKAGE):
        return ()
    if capsule.label is not None and capsule.label.verdict is Verdict.MALICIOUS:
        return ()
    disowned = set(capsule.contradiction_history)
    if capsule.label is not None and capsule.label.target_capsule_id:
        disowned.add(capsule.label.target_capsule_id)
    return tuple(
        sorted(
            item.item_id
            for item in detectors
            if item.protected and disowned.intersection(item.lineage.capsule_ids)
        )
    )


def detect_semantic_normalization_attack(
    capsule: ExperienceCapsuleV1,
    *,
    trusted: TrustedKnowledgeState,
    target_steps: Sequence[EncodedStep] = (),
    ground_truth_groups: frozenset[str] = frozenset(),
) -> NormalizationFinding | None:
    """HEL-F18. Three rules; none reads a count, a rate or a repetition.

    ``target_steps`` is the labelled episode's steps when the capsule is a
    LABEL_ASSERTION (the label itself carries none); the gateway supplies them from
    its bounded episode index. Omitting it can only make rules 1 and 2 fire less.

    GROUND_TRUTH is exempt from rules 1 and 2: it is the reference every other
    label is measured against, not a claim to be screened by it. Only an *authenticated*
    GROUND_TRUTH (:func:`honoured_origin`) is exempt; a claimed one is screened.
    """
    origin = honoured_origin(capsule, ground_truth_groups=ground_truth_groups)
    detectors = _active_detectors(trusted)
    removed = _named_protected_detector(capsule, detectors)
    if removed:
        return NormalizationFinding(
            anchors=(),
            detector_ids=removed,
            rule=RULE_REMOVE_PROTECTED_DETECTOR,
            detail="a label/foreign capsule disowns a protected detector's founding evidence",
        )
    steps = tuple(capsule.steps) or tuple(target_steps)
    benign_claim = _benign_claim(capsule, origin)
    if not benign_claim or not steps:
        return None
    matched = tuple(
        sorted(
            item.item_id
            for item in detectors
            if item.protected and match_motif(item.motif, steps)
        )
    )
    anchors = tuple(sorted({anchor for step in steps for anchor in _touches(step)}))
    if matched:
        return NormalizationFinding(
            anchors=anchors,
            detector_ids=matched,
            rule=RULE_BENIGN_LABEL_ON_PROTECTED_DETECTOR,
            detail="a BENIGN assertion on an episode a protected trusted detector matches",
        )
    if anchors:
        equivalent = all(stage2_would_refuse(s) for s in steps if _touches(s))
        return NormalizationFinding(
            anchors=anchors,
            detector_ids=(),
            rule=RULE_NORMALITY_ON_PROTECTED_MEANING,
            detail=f"normality asserted over protected meaning; stage2_equivalent={equivalent}",
        )
    return None


def _benign_claim(capsule: ExperienceCapsuleV1, origin: LabelOrigin) -> bool:
    """A non-GROUND_TRUTH assertion that these steps are normal.

    An explicit BENIGN label (on an episode, a label capsule or a foreign package),
    or a FOREIGN_PACKAGE offering steps with no label at all: foreign steps arrive as
    proposed knowledge, and unlabelled proposed knowledge is a proposal of normality.
    Local unlabelled telemetry asserts nothing; its protected steps are withheld from
    the normality learner by the gateway instead (they are evidence, not an attack).
    """
    if capsule.kind is CapsuleKind.FOREIGN_PACKAGE and capsule.label is None:
        return True
    if capsule.label is None or capsule.label.verdict is not Verdict.BENIGN:
        return False
    return origin is not LabelOrigin.GROUND_TRUTH


# --- the estimator (HEL-F05) ------------------------------------------------


def estimate_poison_suspicion(
    capsule: ExperienceCapsuleV1,
    *,
    trust: TrustRecord,
    dependence: DependenceReport,
    trusted: TrustedKnowledgeState,
    history: LabelHistory,
    target_steps: Sequence[EncodedStep] = (),
    ground_truth_groups: frozenset[str] = frozenset(),
) -> PoisonSuspicion:
    """HEL-F05. Fill the six components this module can measure; leave two ``None``.

    ``protected_conflict`` here is the Stage-2-anchor level: a non-GROUND_TRUTH
    normality claim over a step Stage 2's own risk rule would refuse. The wider
    anchor set and the trusted-detector rules are HEL-F18's, so switching
    homeostasis off degrades exactly to "Stage 2's anchors only" (spec §7).
    """
    steps = tuple(capsule.steps) or tuple(target_steps)
    verdict = _asserted_verdict(capsule)
    origin = honoured_origin(capsule, ground_truth_groups=ground_truth_groups)
    key = motif_key(steps)
    return PoisonSuspicion(
        source_control=float(trust.contamination_risk),
        dependence=_vote_dependence(verdict, dependence),
        protected_conflict=(_benign_claim(capsule, origin)
                            and any(stage2_would_refuse(s) for s in steps)),
        label_shift=_label_shift(key, verdict, origin, history),
        trigger_concentration=_trigger_concentration(capsule, trusted),
        cross_epoch_inconsistency=history.epoch_inconsistency(key) if key else 0.0,
    )


def _vote_dependence(verdict: Verdict | None, report: DependenceReport) -> float:
    if verdict not in _COMMITTAL or report.observations <= 0:
        return 0.0
    return max(0.0, 1.0 - report.independent_groups / max(1, report.observations))


def _label_shift(
    key: str, verdict: Verdict | None, origin: LabelOrigin, history: LabelHistory
) -> float:
    if not key or verdict not in _COMMITTAL or origin is LabelOrigin.GROUND_TRUTH:
        return 0.0
    return history.opposite_share(key, verdict)


def _trigger_concentration(capsule: ExperienceCapsuleV1, trusted: TrustedKnowledgeState) -> float:
    """Share of a normality claim's steps sitting one bit outside a trusted detector.

    Only normality-direction capsules are screened: a MALICIOUS-labelled near-miss
    is a detector refinement opportunity, not an attempt to make an attack normal.
    """
    if not capsule.steps or not asserts_normality(capsule):
        return 0.0
    detectors = _active_detectors(trusted)
    if not detectors:
        return 0.0
    hits = sum(1 for step in capsule.steps if any(near_miss(step, item) for item in detectors))
    return hits / len(capsule.steps)


# --- the label quorum (the label-poisoning defence) --------------------------

#: Label origins that vote. TEACHER and WEAK are weak evidence until validated
#: (architecture §26) and NONE is not a label; one GROUND_TRUTH settles alone.
VOTING_ORIGINS: frozenset[LabelOrigin] = frozenset(
    {LabelOrigin.GROUND_TRUTH, LabelOrigin.ANALYST, LabelOrigin.INFERENCE}
)

#: A group that asserts twice keeps its strongest origin, never its weakest.
_ORIGIN_RANK: dict[LabelOrigin, int] = {
    origin: rank
    for rank, origin in enumerate((
        LabelOrigin.NONE, LabelOrigin.TEACHER, LabelOrigin.WEAK,
        LabelOrigin.INFERENCE, LabelOrigin.ANALYST, LabelOrigin.GROUND_TRUTH,
    ))
}


def label_quorum_met(votes: Mapping[str, LabelOrigin]) -> bool:
    """One GROUND_TRUTH vote, or ``MIN_INDEPENDENT_LABEL_GROUPS`` voting groups.

    ``votes`` maps an independence group to its strongest origin. TEACHER, WEAK and
    NONE never count, alone or in company: a systematically wrong teacher agreeing
    with one analyst is still one validated opinion. A group is one vote however
    many assertions it sends (architecture §7).
    """
    if any(origin is LabelOrigin.GROUND_TRUTH for origin in votes.values()):
        return True
    voting = sum(1 for origin in votes.values() if origin in VOTING_ORIGINS)
    return voting >= MIN_INDEPENDENT_LABEL_GROUPS


@dataclass
class _EpisodeVotes:
    votes: dict[Verdict, dict[str, LabelOrigin]] = field(default_factory=dict)
    label_capsules: list[str] = field(default_factory=list)
    resolved: Verdict | None = None

    def voters(self) -> int:
        return sum(len(v) for v in self.votes.values())

    def memory_bytes(self) -> int:
        strings = [g for v in self.votes.values() for g in v] + self.label_capsules
        return sum(sys.getsizeof(s) for s in strings) + 128


class LabelQuorum:
    """Bounded per-episode label votes; an episode settles only on a quorum.

    Full register: a *settled* episode is forgotten to make room (its verdict was
    already issued); if none is settled the newcomer is refused and counted, so a
    label flood cannot evict episodes still waiting for independent confirmation.
    Both verdicts reaching quorum is a contradiction and settles nothing, unless
    exactly one side holds GROUND_TRUTH.
    """

    def __init__(self, *, capacity: int, max_voters: int = MAX_VOTERS_PER_MOTIF) -> None:
        self._capacity = capacity
        self._max_voters = max_voters
        self._episodes: OrderedDict[str, _EpisodeVotes] = OrderedDict()
        self.overflow = 0
        self.voter_overflow = 0

    def vote(
        self,
        target: str,
        verdict: Verdict,
        *,
        group: str,
        origin: LabelOrigin,
        label_capsule: str = "",
    ) -> tuple[bool, str]:
        """Record one vote. Returns (settled as ``verdict``, reason token)."""
        entry = self._entry(target)
        if entry is None:
            return False, "label_register_full"
        voters = entry.votes.setdefault(verdict, {})
        if group in voters:
            if _ORIGIN_RANK[origin] > _ORIGIN_RANK[voters[group]]:
                voters[group] = origin
        elif entry.voters() >= self._max_voters:
            self.voter_overflow += 1
        else:
            voters[group] = origin
        if label_capsule and label_capsule not in entry.label_capsules:
            entry.label_capsules.append(label_capsule)
            del entry.label_capsules[: -self._max_voters]
        entry.resolved = _settle(entry)
        if entry.resolved is verdict:
            return True, "label_quorum_met"
        both = all(label_quorum_met(entry.votes.get(v, {})) for v in _COMMITTAL)
        return False, "label_contradiction" if both else "awaiting_label_quorum"

    def label_capsules(self, target: str) -> tuple[str, ...]:
        entry = self._episodes.get(target)
        return () if entry is None else tuple(entry.label_capsules)

    def pending(self) -> tuple[str, ...]:
        return tuple(sorted(k for k, v in self._episodes.items() if v.resolved is None))

    def __len__(self) -> int:
        return len(self._episodes)

    def memory_bytes(self) -> int:
        return sum(sys.getsizeof(k) + v.memory_bytes() for k, v in self._episodes.items())

    def _entry(self, target: str) -> _EpisodeVotes | None:
        entry = self._episodes.get(target)
        if entry is not None:
            return entry
        if len(self._episodes) >= self._capacity:
            settled = next((k for k, v in self._episodes.items() if v.resolved is not None), None)
            if settled is None:
                self.overflow += 1
                return None
            del self._episodes[settled]
        entry = _EpisodeVotes()
        self._episodes[target] = entry
        return entry


def _settle(entry: _EpisodeVotes) -> Verdict | None:
    met = {v: label_quorum_met(entry.votes.get(v, {})) for v in (Verdict.MALICIOUS, Verdict.BENIGN)}
    if met[Verdict.MALICIOUS] and met[Verdict.BENIGN]:
        truth = [
            v for v in met
            if any(o is LabelOrigin.GROUND_TRUTH for o in entry.votes.get(v, {}).values())
        ]
        return truth[0] if len(truth) == 1 else None
    for verdict, ok in met.items():
        if ok:
            return verdict
    return None
