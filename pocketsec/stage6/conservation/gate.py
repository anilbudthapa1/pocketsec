"""D6.14 / HEL-F17 — the Knowledge Conservation Gate: nine checks between a candidate and trust.

Architecture §3 states the conservation law (a change is acceptable only if what it adds
outweighs what it risks losing) and §20 turns it into nine checks, G1…G9. This module
computes them against the named bounds of spec §4.21 and nothing else. It is a pure
function of immutable values: it holds no trusted state, writes nothing, and a candidate
that fails "returns to quarantine without affecting production" (§20) because the gate
never had a way to affect production.

What each check refuses, in one line:

* **G1** a candidate whose proposed state is not what its delta applied to its base
  produces (tampered bytes), whose items lack lineage, or which alters a rehearsal
  exemplar's evidence.
* **G2** a candidate that loses per-verdict-class recall on the *trusted* rehearsal set,
  or newly misses any protected exemplar.
* **G3** a candidate that claims utility and cannot show it on the holdout it named.
* **G4** a candidate whose recall on semantics-preserving variants drops.
* **G5** a candidate that lets a hostile-tier episode fall below threshold, or holds a
  BASELINE that explains a step touching a protected anchor.
* **G6** a candidate that degrades calibration (Brier).
* **G7** a candidate past any cap, or growing trusted state too fast.
* **G8** (filled later by :func:`complete_with_shadow`) a shadow that aborted, looked at
  too little, disagreed too much or regressed a protected session.
* **G9** a base state that cannot be restored from a verified fossil.

Two decisions stated because they change outcomes:

* **Vacuous is labelled, not hidden.** G2, G4 and G6 are non-regression checks. When the
  trusted rehearsal set holds nothing they can measure, nothing can regress; they pass
  with ``measured=None`` and a detail beginning ``VACUOUS``. This is exactly the
  rehearsal-gap limit G6.8 demonstrates: what the rehearsal set does not hold, G2 cannot
  protect. G3 is the opposite — a *utility* claim that cannot be measured is refused.
* **The caller cannot choose the holdout.** G3 uses only supplied episodes whose ids the
  candidate itself named in ``holdout_episode_ids`` (when it named any), so a caller
  handing G3 the training split gets those episodes ignored, not counted.

Recall and false-positive rates come from Stage 0's ``confusion_at_threshold``; there is
no second metric implementation. Brier comes from ``shadow.mind.brier`` (Stage 0 has none).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from pocketsec.stage0.benchmark.security_metrics import confusion_at_threshold
from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage2.adaptation.quarantine import meaning_distance, pattern_key
from pocketsec.stage6.capsule.experience_capsule import EncodedStep
from pocketsec.stage6.chamber.evolution import (
    MAX_CHAMBER_WORK_UNITS,
    CandidateKind,
    EvolutionCandidate,
    KnowledgeDelta,
)
from pocketsec.stage6.constitution.learning import touches_protected
from pocketsec.stage6.fossils.lineage import KnowledgeLineageDAG, NodeKind
from pocketsec.stage6.fossils.store import FossilStore
from pocketsec.stage6.memory.episodic import EpisodeSkeleton
from pocketsec.stage6.memory.semantic import (
    MAX_BASELINE_ITEMS,
    MAX_DETECTOR_ITEMS,
    MAX_PROCEDURE_ITEMS,
    MAX_REHEARSAL_EXEMPLARS,
    MAX_TRUSTED_STATE_BYTES,
    ItemKind,
    KnowledgeItem,
    TrustedKnowledgeState,
)
from pocketsec.stage6.rehearsal.counterfactual import generate_counterfactual_replay
from pocketsec.stage6.resources import WorkBudgetExceeded, WorkMeter
from pocketsec.stage6.shadow.mind import (
    MAX_SHADOW_DISAGREEMENT,
    MIN_SHADOW_SESSIONS,
    ShadowReport,
    alert_of,
    brier,
    label_value,
)

__all__ = [
    "EPS_BRIER",
    "EPS_COUNTERFACTUAL",
    "EPS_FP_RATE",
    "EPS_SECURITY",
    "MAX_STATE_GROWTH_BYTES",
    "MIN_UTILITY_GAIN",
    "ConservationCheck",
    "ConservationResult",
    "ConservationVerdict",
    "complete_with_shadow",
    "context_validation",
    "default_meter",
    "lineage_gaps",
    "offline_validation",
]

#: Chosen parameters (§4.21), not measurements.
EPS_SECURITY: float = 0.02
MIN_UTILITY_GAIN: float = 0.01
EPS_FP_RATE: float = 0.01
EPS_BRIER: float = 0.02
EPS_COUNTERFACTUAL: float = 0.05
MAX_STATE_GROWTH_BYTES: int = 65_536

_UTILITY_RECALL = frozenset({CandidateKind.SYMBOLIC})
_UTILITY_FP = frozenset({CandidateKind.STATISTICAL, CandidateKind.CALIBRATION})
_KIND_CAPS = {ItemKind.DETECTOR: MAX_DETECTOR_ITEMS, ItemKind.BASELINE: MAX_BASELINE_ITEMS,
              ItemKind.PROCEDURE: MAX_PROCEDURE_ITEMS, ItemKind.THRESHOLD: 1}
_PENDING_G8 = "PENDING: no ShadowReport yet"
_NOT_APPLICABLE = "NOT APPLICABLE to a context transition (spec D6.17: G1, G2, G7, G9 only)"


class ConservationCheck(StrEnum):
    G1_INTEGRITY = "G1_INTEGRITY"
    G2_HISTORICAL_REPLAY = "G2_HISTORICAL_REPLAY"
    G3_CURRENT_HOLDOUT = "G3_CURRENT_HOLDOUT"
    G4_COUNTERFACTUAL = "G4_COUNTERFACTUAL"
    G5_ADVERSARIAL = "G5_ADVERSARIAL"
    G6_CALIBRATION = "G6_CALIBRATION"
    G7_RESOURCE = "G7_RESOURCE"
    G8_SHADOW = "G8_SHADOW"
    G9_ROLLBACK = "G9_ROLLBACK"


_C = ConservationCheck


@dataclass(frozen=True, slots=True)
class ConservationResult:
    check: ConservationCheck
    passed: bool
    measured: float | None  # None = not computed; never a stand-in for zero
    bound: float | None
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {"check": self.check.value, "passed": self.passed, "measured": self.measured,
                "bound": self.bound, "detail": self.detail}


def _verdict_digest(payload: dict[str, Any]) -> str:
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ConservationVerdict:
    candidate_id: str
    base_digest: str
    proposed_digest: str
    results: tuple[ConservationResult, ...]  # exactly nine, in enum order
    complete: bool  # False until G8 has a ShadowReport
    passed: bool  # complete and all nine passed
    verdict_digest: str
    work_units: int

    def __post_init__(self) -> None:
        if tuple(r.check for r in self.results) != tuple(ConservationCheck):
            raise ContractError("a ConservationVerdict holds exactly nine results, in G1..G9 order")
        if self.passed and not (self.complete and all(r.passed for r in self.results)):
            raise ContractError("a verdict passes only when complete and all nine checks pass")
        if self.verdict_digest != _verdict_digest(self._body()):
            raise ContractError("verdict_digest does not match the verdict's content")

    def _body(self) -> dict[str, Any]:
        return {"candidate_id": self.candidate_id, "base_digest": self.base_digest,
                "proposed_digest": self.proposed_digest,
                "results": [r.to_dict() for r in self.results], "complete": self.complete,
                "passed": self.passed, "work_units": self.work_units}

    def to_dict(self) -> dict[str, Any]:
        return {**self._body(), "verdict_digest": self.verdict_digest}

    def result(self, check: ConservationCheck) -> ConservationResult:
        return self.results[list(ConservationCheck).index(ConservationCheck(check))]

    def offline_passed(self) -> bool:
        """Every check but G8 passed — what OFFLINE_VALIDATED means."""
        return all(r.passed for r in self.results if r.check is not ConservationCheck.G8_SHADOW)

    def failed_checks(self) -> tuple[str, ...]:
        return tuple(r.check.value for r in self.results if not r.passed)


def _make_verdict(candidate_id: str, base: str, proposed: str,
                  results: Sequence[ConservationResult], *, complete: bool,
                  work_units: int) -> ConservationVerdict:
    passed = complete and all(r.passed for r in results)
    body = {"candidate_id": candidate_id, "base_digest": base, "proposed_digest": proposed,
            "results": [r.to_dict() for r in results], "complete": complete, "passed": passed,
            "work_units": work_units}
    return ConservationVerdict(candidate_id, base, proposed, tuple(results), complete, passed,
                               _verdict_digest(body), work_units)


# --- shared measurement helpers ---------------------------------------------------------


def _labelled(episodes: Sequence[EpisodeSkeleton]) -> list[tuple[EpisodeSkeleton, int]]:
    out = []
    for episode in episodes:
        label = label_value(episode.verdict)
        if label is not None:
            out.append((episode, label))
    return out


def _scores(state: TrustedKnowledgeState, labelled: Sequence[tuple[EpisodeSkeleton, int]],
            meter: WorkMeter) -> list[float]:
    return [alert_of(state, e.steps, context_id=e.context_id, meter=meter)[1] for e, _ in labelled]


def _class_recall(state: TrustedKnowledgeState, labelled: Sequence[tuple[EpisodeSkeleton, int]],
                  meter: WorkMeter) -> dict[int, float | None]:
    """Per-class recall at the state's own threshold: MALICIOUS -> TPR, BENIGN -> TNR."""
    labels = [label for _, label in labelled]
    matrix = confusion_at_threshold(labels, _scores(state, labelled, meter), state.threshold())
    fpr = matrix.false_positive_rate
    return {1: matrix.recall, 0: None if fpr is None else 1.0 - fpr}


def _rate(labels: Sequence[int], scores: Sequence[float], threshold: float,
          *, positive: bool) -> float | None:
    matrix = confusion_at_threshold(labels, scores, threshold)
    return matrix.recall if positive else matrix.false_positive_rate


def _capsule_admitted(lineage: KnowledgeLineageDAG, capsule_id: str) -> bool:
    """lineage_complete's own rule, not a copy of it (a copy drifted: review S6-AUTH-06)."""
    return lineage.capsule_admitted(capsule_id)


def _pre_promotion_complete(item: KnowledgeItem, candidate_id: str,
                            lineage: KnowledgeLineageDAG) -> bool:
    """A new item before its PROMOTION exists: its CANDIDATE node and admitted capsules."""
    node = lineage.node(candidate_id)
    return (
        item.lineage.candidate_id == candidate_id
        and node is not None and node.kind is NodeKind.CANDIDATE
        and bool(item.lineage.capsule_ids) and bool(item.lineage.evidence_digests)
        and all(_capsule_admitted(lineage, c) for c in item.lineage.capsule_ids)
    )


def lineage_gaps(proposed: TrustedKnowledgeState, *, candidate_id: str,
                 lineage: KnowledgeLineageDAG) -> tuple[str, ...]:
    """Item ids in ``proposed`` that lack complete lineage; ``()`` means every item is traceable.

    An item passes if :meth:`KnowledgeLineageDAG.lineage_complete` holds (it was admitted
    by an earlier promotion) or it is this candidate's own new item with a CANDIDATE node
    and gateway-admitted capsules — its PROMOTION node is what promote_trusted adds.
    """
    return tuple(
        item.item_id for item in proposed.items
        if not (lineage.lineage_complete(item)
                or _pre_promotion_complete(item, candidate_id, lineage))
    )


# --- G1 … G9 ----------------------------------------------------------------------------


def _replayed(trusted: TrustedKnowledgeState, delta: KnowledgeDelta) -> TrustedKnowledgeState:
    rehearsal = None
    if delta.rehearsal_added or delta.rehearsal_removed:
        gone = set(delta.rehearsal_removed)
        kept = {e.episode_id: e for e in trusted.rehearsal if e.episode_id not in gone}
        for episode in delta.rehearsal_added:
            kept.setdefault(episode.episode_id, episode)
        rehearsal = tuple(kept[key] for key in sorted(kept))
    return trusted.with_changes(add=delta.added, remove=delta.removed, replace=delta.replaced,
                                threshold=delta.threshold, rehearsal=rehearsal,
                                active_context=delta.active_context,
                                threshold_lineage=delta.threshold_lineage)


def _integrity(trusted: TrustedKnowledgeState, proposed: TrustedKnowledgeState,
               delta: KnowledgeDelta, candidate_id: str,
               lineage: KnowledgeLineageDAG) -> ConservationResult:
    problems: list[str] = []
    try:
        if _replayed(trusted, delta).digest() != proposed.digest():
            problems.append("proposed state is not base + delta (altered after issue)")
        if TrustedKnowledgeState.from_canonical_bytes(proposed.canonical_bytes()).digest() != (
                proposed.digest()):
            problems.append("proposed state does not round-trip its canonical bytes")
    except ContractError as exc:  # LineageError / CapacityError are ContractErrors
        problems.append(f"proposed state refused: {exc}")
    gaps = lineage_gaps(proposed, candidate_id=candidate_id, lineage=lineage)
    base = {e.episode_id: e.to_payload() for e in trusted.rehearsal}
    altered = [e.episode_id for e in proposed.rehearsal
               if e.episode_id in base and e.to_payload() != base[e.episode_id]]
    unresolved = [e.episode_id for e in proposed.rehearsal
                  if e.episode_id not in base and not _capsule_admitted(lineage, e.episode_id)]
    problems += [f"item without lineage: {i}" for i in gaps[:4]]
    problems += [f"rehearsal exemplar altered: {i}" for i in altered[:4]]
    problems += [f"rehearsal exemplar not gateway-admitted: {i}" for i in unresolved[:4]]
    items = len(proposed.items)
    complete_share = (items - len(gaps)) / items if items else 1.0
    return ConservationResult(
        _C.G1_INTEGRITY, not problems, complete_share, 1.0,
        "; ".join(problems) if problems else
        f"digest replays; {items}/{items} items traceable; 0 exemplars altered",
    )


def _historical(trusted: TrustedKnowledgeState, proposed: TrustedKnowledgeState,
                meter: WorkMeter) -> ConservationResult:
    labelled = _labelled(trusted.rehearsal)
    if not labelled:
        return ConservationResult(_C.G2_HISTORICAL_REPLAY, True, None, EPS_SECURITY,
                                  "VACUOUS: the trusted rehearsal set holds no labelled exemplar")
    before = _class_recall(trusted, labelled, meter)
    after = _class_recall(proposed, labelled, meter)
    drops: dict[int, float] = {}
    for cls in (0, 1):
        was, now = before[cls], after[cls]
        if was is not None and now is not None:
            drops[cls] = was - now
    newly_missed = [
        e.episode_id for e, label in labelled
        if label == 1 and e.anchors_touched
        and alert_of(trusted, e.steps, context_id=e.context_id, meter=meter)[0]
        and not alert_of(proposed, e.steps, context_id=e.context_id, meter=meter)[0]
    ]
    worst = max(drops.values(), default=0.0)
    passed = worst <= EPS_SECURITY and not newly_missed
    return ConservationResult(
        _C.G2_HISTORICAL_REPLAY, passed, worst, EPS_SECURITY,
        f"malicious recall {before[1]}->{after[1]}; benign recall {before[0]}->{after[0]}; "
        f"protected exemplars newly missed {len(newly_missed)} {newly_missed[:4]}",
    )


def _holdout_rates(state: TrustedKnowledgeState, holdout: Sequence[EpisodeSkeleton],
                   meter: WorkMeter) -> tuple[float | None, float | None]:
    labelled = _labelled(holdout)
    scores = _scores(state, labelled, meter)
    pos = [s for (_, label), s in zip(labelled, scores, strict=True) if label == 1]
    neg = [s for (_, label), s in zip(labelled, scores, strict=True) if label == 0]
    recall = _rate([1] * len(pos), pos, state.threshold(), positive=True) if pos else None
    fp_rate = _rate([0] * len(neg), neg, state.threshold(), positive=False) if neg else None
    return recall, fp_rate


def _utility(candidate: EvolutionCandidate, trusted: TrustedKnowledgeState,
             holdout: Sequence[EpisodeSkeleton], meter: WorkMeter) -> ConservationResult:
    named = set(candidate.holdout_episode_ids)
    # Only the episodes the candidate named: an unnamed holdout is empty, never "whatever
    # the caller passed" — the caller cannot choose the holdout (review F7).
    used = [e for e in holdout if e.episode_id in named]
    fitted = set() if candidate.delta.threshold_lineage is None else set(
        candidate.delta.threshold_lineage.capsule_ids)
    if fitted & named:  # review F5: a threshold scored on the episodes it was fitted to
        return ConservationResult(_C.G3_CURRENT_HOLDOUT, False, None, MIN_UTILITY_GAIN,
                                  f"in-sample: the threshold was fitted on "
                                  f"{len(fitted & named)} holdout episode(s)")
    r_t, f_t = _holdout_rates(trusted, used, meter)
    r_p, f_p = _holdout_rates(candidate.proposed, used, meter)
    recall_gain = None if r_t is None or r_p is None else r_p - r_t
    fp_reduction = None if f_t is None or f_p is None else f_t - f_p
    regressed = ((recall_gain is not None and recall_gain < -EPS_SECURITY)
                 or (fp_reduction is not None and fp_reduction < -EPS_FP_RATE))
    claims = []
    if candidate.kinds & _UTILITY_RECALL:
        claims.append(("recall_gain", recall_gain))
    if candidate.kinds & _UTILITY_FP:
        claims.append(("fp_reduction", fp_reduction))
    detail = (f"holdout used {len(used)}/{len(holdout)}; recall_gain {recall_gain}; "
              f"fp_reduction {fp_reduction}")
    if not claims:
        return ConservationResult(_C.G3_CURRENT_HOLDOUT, not regressed, None, MIN_UTILITY_GAIN,
                                  "no utility claimed; non-regression only; " + detail)
    measured = [gain for _, gain in claims if gain is not None]
    if not measured:
        return ConservationResult(_C.G3_CURRENT_HOLDOUT, False, None, MIN_UTILITY_GAIN,
                                  "UNMEASURED: claimed utility has no holdout to show it; "
                                  + detail)
    best = max(measured)
    passed = best >= MIN_UTILITY_GAIN and not regressed
    return ConservationResult(_C.G3_CURRENT_HOLDOUT, passed, best, MIN_UTILITY_GAIN, detail)


def _counterfactual(trusted: TrustedKnowledgeState, proposed: TrustedKnowledgeState,
                    variant_seed: int, meter: WorkMeter) -> ConservationResult:
    motifs = [item.motif for item in trusted.detectors()]
    variants = [
        v for e in trusted.rehearsal if e.verdict is Verdict.MALICIOUS
        for v in generate_counterfactual_replay(e, seed=variant_seed, motifs=motifs)
        if v.semantics_preserved
    ]
    context = {e.episode_id: e.context_id for e in trusted.rehearsal}
    if not variants:
        return ConservationResult(_C.G4_COUNTERFACTUAL, True, None, EPS_COUNTERFACTUAL,
                                  "VACUOUS: no semantics-preserving variant of a "
                                  "rehearsal positive")
    labels = [1] * len(variants)
    recalls = []
    for state in (trusted, proposed):
        scores = [alert_of(state, v.steps, context_id=context[v.source_episode_id],
                           meter=meter)[1] for v in variants]
        recall = _rate(labels, scores, state.threshold(), positive=True)
        recalls.append(0.0 if recall is None else recall)  # labels are all positive: never None
    drop = recalls[0] - recalls[1]
    return ConservationResult(_C.G4_COUNTERFACTUAL, drop <= EPS_COUNTERFACTUAL, drop,
                              EPS_COUNTERFACTUAL,
                              f"{len(variants)} variants; recall {recalls[0]}->{recalls[1]}")


def _explains_protected(baseline: KnowledgeItem, step: EncodedStep) -> bool:
    return (baseline.pattern_key == pattern_key(step.to_encoded())
            and meaning_distance(step.meaning(), baseline.anchor) <= baseline.weight)


def _adversarial(trusted: TrustedKnowledgeState, proposed: TrustedKnowledgeState,
                 hostile: Sequence[EpisodeSkeleton], pool: Sequence[EpisodeSkeleton],
                 meter: WorkMeter) -> ConservationResult:
    dropped = [
        e.episode_id for e in hostile
        if alert_of(trusted, e.steps, context_id=e.context_id, meter=meter)[0]
        and not alert_of(proposed, e.steps, context_id=e.context_id, meter=meter)[0]
    ]
    protected_steps = [s for e in (*hostile, *pool) for s in e.steps
                       if touches_protected(s.object_property_mask, s.state_delta_mask)]
    baselines = proposed.baselines()
    meter.charge(len(baselines) * len(protected_steps))
    explaining = sorted({b.item_id for b in baselines if b.protected} | {
        b.item_id for b in baselines for s in protected_steps if _explains_protected(b, s)})
    return ConservationResult(
        _C.G5_ADVERSARIAL, not dropped and not explaining, float(len(dropped) + len(explaining)),
        0.0, f"hostile episodes dropped below threshold {len(dropped)} {dropped[:4]}; "
             f"baselines normalising protected meaning {len(explaining)} {explaining[:4]}",
    )


def _calibration(trusted: TrustedKnowledgeState, proposed: TrustedKnowledgeState,
                 holdout: Sequence[EpisodeSkeleton], meter: WorkMeter) -> ConservationResult:
    labelled = _labelled((*trusted.rehearsal, *holdout))
    labels = [label for _, label in labelled]
    before = brier(labels, _scores(trusted, labelled, meter))
    after = brier(labels, _scores(proposed, labelled, meter))
    if before is None or after is None:
        return ConservationResult(_C.G6_CALIBRATION, True, None, EPS_BRIER,
                                  "VACUOUS: no labelled rehearsal or holdout episode")
    increase = after - before
    return ConservationResult(_C.G6_CALIBRATION, increase <= EPS_BRIER, increase, EPS_BRIER,
                              f"Brier {before:.6f}->{after:.6f} over {len(labels)} episodes")


def _resource(trusted: TrustedKnowledgeState, proposed: TrustedKnowledgeState,
              work_units: int) -> ConservationResult:
    size = proposed.byte_size()
    growth = size - trusted.byte_size()
    problems = [f"{kind.value} {n} > {cap}" for kind, cap in _KIND_CAPS.items()
                if (n := sum(1 for i in proposed.items if i.kind is kind)) > cap]
    if len(proposed.rehearsal) > MAX_REHEARSAL_EXEMPLARS:
        problems.append(f"rehearsal {len(proposed.rehearsal)} > {MAX_REHEARSAL_EXEMPLARS}")
    if size > MAX_TRUSTED_STATE_BYTES:
        problems.append(f"state bytes {size} > {MAX_TRUSTED_STATE_BYTES}")
    if work_units > MAX_CHAMBER_WORK_UNITS:
        problems.append(f"candidate work units {work_units} > {MAX_CHAMBER_WORK_UNITS}")
    if growth > MAX_STATE_GROWTH_BYTES:
        problems.append(f"growth {growth} > {MAX_STATE_GROWTH_BYTES}")
    return ConservationResult(_C.G7_RESOURCE, not problems, float(growth),
                              float(MAX_STATE_GROWTH_BYTES),
                              "; ".join(problems) if problems else f"{size} bytes, growth {growth}")


def _rollback(trusted: TrustedKnowledgeState, fossils: FossilStore,
              lineage: KnowledgeLineageDAG) -> ConservationResult:
    try:
        restored = fossils.load(trusted.digest(), lineage=lineage)
    except ContractError as exc:  # unknown, corrupted or lineage-less fossil
        return ConservationResult(_C.G9_ROLLBACK, False, None, None,
                                  f"no verified fossil of the base state: {exc}")
    same = restored.canonical_bytes() == trusted.canonical_bytes()
    return ConservationResult(_C.G9_ROLLBACK, same, None, None,
                              "base state restorable byte-identically" if same
                              else "fossil verifies but is not byte-identical to the base")


# --- the three entry points ----------------------------------------------------------------


def _run(checks: Sequence[tuple[ConservationCheck, Callable[[], ConservationResult]]]
         ) -> list[ConservationResult]:
    """Run checks in order; once the work budget is gone every remaining check fails closed."""
    results: list[ConservationResult] = []
    exhausted = False
    for check, compute in checks:
        if not exhausted:
            try:
                results.append(compute())
                continue
            except WorkBudgetExceeded:
                exhausted = True
        results.append(ConservationResult(check, False, None, None,
                                          "work budget exhausted before this check completed"))
    return results


def _pending_g8() -> ConservationResult:
    return ConservationResult(_C.G8_SHADOW, False, None, MAX_SHADOW_DISAGREEMENT, _PENDING_G8)


def offline_validation(candidate: EvolutionCandidate, *, trusted: TrustedKnowledgeState,
                       lineage: KnowledgeLineageDAG, fossils: FossilStore,
                       holdout: Sequence[EpisodeSkeleton], hostile: Sequence[EpisodeSkeleton],
                       variant_seed: int, meter: WorkMeter) -> ConservationVerdict:
    """HEL-F17. G1-G7 and G9 measured; G8 pending, so the verdict is ``complete=False``."""
    if not isinstance(candidate, EvolutionCandidate):
        raise ContractError(
            f"offline_validation needs an EvolutionCandidate, got {type(candidate)}")
    start = meter.spent
    proposed = candidate.proposed
    holdout, hostile = tuple(holdout), tuple(hostile)
    results = _run((
        (_C.G1_INTEGRITY, lambda: _integrity(trusted, proposed, candidate.delta,
                                             candidate.candidate_id, lineage)),
        (_C.G2_HISTORICAL_REPLAY, lambda: _historical(trusted, proposed, meter)),
        (_C.G3_CURRENT_HOLDOUT, lambda: _utility(candidate, trusted, holdout, meter)),
        (_C.G4_COUNTERFACTUAL, lambda: _counterfactual(trusted, proposed, variant_seed, meter)),
        (_C.G5_ADVERSARIAL, lambda: _adversarial(trusted, proposed, hostile,
                                                 (*trusted.rehearsal, *holdout), meter)),
        (_C.G6_CALIBRATION, lambda: _calibration(trusted, proposed, holdout, meter)),
        (_C.G7_RESOURCE, lambda: _resource(trusted, proposed, candidate.work_units)),
        (_C.G8_SHADOW, _pending_g8),
        (_C.G9_ROLLBACK, lambda: _rollback(trusted, fossils, lineage)),
    ))
    return _make_verdict(candidate.candidate_id, candidate.base_digest, proposed.digest(),
                         results, complete=False, work_units=meter.spent - start)


def _shadow_result(report: ShadowReport) -> ConservationResult:
    problems = []
    if report.aborted:
        problems.append(f"shadow aborted: {report.abort_reason}")
    if report.sessions_sampled < MIN_SHADOW_SESSIONS:
        problems.append(f"sampled {report.sessions_sampled} < {MIN_SHADOW_SESSIONS}")
    rate = report.disagreement_rate
    if rate is None or rate > MAX_SHADOW_DISAGREEMENT:
        problems.append(f"disagreement_rate {rate} not <= {MAX_SHADOW_DISAGREEMENT}")
    if report.protected_regressions:
        problems.append(f"protected_regressions {report.protected_regressions}")
    return ConservationResult(_C.G8_SHADOW, not problems, rate, MAX_SHADOW_DISAGREEMENT,
                              "; ".join(problems) if problems else
                              f"{report.sessions_sampled} sampled; report {report.digest()}")


def complete_with_shadow(verdict: ConservationVerdict, report: ShadowReport) -> ConservationVerdict:
    """Fill G8 from a ShadowReport of *this* candidate against *this* base; refuse any other."""
    if verdict.complete:
        raise ContractError("this conservation verdict is already complete")
    if (report.candidate_digest, report.trusted_digest) != (verdict.proposed_digest,
                                                             verdict.base_digest):
        raise ContractError("the shadow report is for a different candidate or base state")
    results = [(_shadow_result(report) if r.check is _C.G8_SHADOW else r)
               for r in verdict.results]
    return _make_verdict(verdict.candidate_id, verdict.base_digest, verdict.proposed_digest,
                         results, complete=True,
                         work_units=verdict.work_units + report.work_units)


def _not_applicable(check: ConservationCheck) -> ConservationResult:
    return ConservationResult(check, True, None, None, _NOT_APPLICABLE)


def context_validation(*, transition_id: str, trusted: TrustedKnowledgeState,
                       proposed: TrustedKnowledgeState, active_context: str,
                       lineage: KnowledgeLineageDAG, fossils: FossilStore,
                       meter: WorkMeter) -> ConservationVerdict:
    """An active-context change: G1, G2, G7, G9 measured; the rest are not applicable.

    A context transition changes which items *apply*, not which items exist, so there is
    no new utility, no new motif and no candidate to shadow (spec D6.17). G2 still runs
    because a different active context changes which baselines explain a step.
    """
    start = meter.spent
    delta = KnowledgeDelta(active_context=active_context)
    results = _run((
        (_C.G1_INTEGRITY, lambda: _integrity(trusted, proposed, delta, transition_id, lineage)),
        (_C.G2_HISTORICAL_REPLAY, lambda: _historical(trusted, proposed, meter)),
        (_C.G3_CURRENT_HOLDOUT, lambda: _not_applicable(_C.G3_CURRENT_HOLDOUT)),
        (_C.G4_COUNTERFACTUAL, lambda: _not_applicable(_C.G4_COUNTERFACTUAL)),
        (_C.G5_ADVERSARIAL, lambda: _not_applicable(_C.G5_ADVERSARIAL)),
        (_C.G6_CALIBRATION, lambda: _not_applicable(_C.G6_CALIBRATION)),
        (_C.G7_RESOURCE, lambda: _resource(trusted, proposed, 0)),
        (_C.G8_SHADOW, lambda: _not_applicable(_C.G8_SHADOW)),
        (_C.G9_ROLLBACK, lambda: _rollback(trusted, fossils, lineage)),
    ))
    return _make_verdict(transition_id, trusted.digest(), proposed.digest(), results,
                         complete=True, work_units=meter.spent - start)


def default_meter() -> WorkMeter:
    """The controller's validation budget: the chamber's, since both scan the same bounded sets."""
    return WorkMeter(budget=MAX_CHAMBER_WORK_UNITS)

