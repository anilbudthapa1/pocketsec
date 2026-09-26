"""D6.13 / HEL-F16 — the Shadow Mind: a candidate state scored beside production, with no say.

Architecture §19: a candidate "runs on the same inputs as production but has zero
authority". This module is where that sentence is made true by construction rather
than by promise. :class:`ShadowMind` takes two immutable :class:`TrustedKnowledgeState`
values and an iterable of sessions and returns **counts**: how often the candidate
caught what trusted missed, how often it dropped what trusted caught, how its false
alerts and calibration moved. Nothing it returns is a score a caller could act on.

What it refuses to do, and why:

* **It holds no writer.** There is no reference here to Stage 5, to the promotion
  controller, to ``TrustedMind`` or to any store. A shadow that could reach a writer
  would be a second promotion path the moment somebody "just" wired its disagreement
  count into a threshold. Its only output is a frozen :class:`ShadowReport`.
* **It refuses to run past its budget.** Architecture §41: "Shadow Mind OOM terminates
  shadow evaluation before production detection." The shadow runs *after* production
  has scored a session, never before, and when its :class:`WorkMeter` or its byte
  estimate would pass the budget it stops and reports ``aborted=True``. An aborted
  report fails conservation check G8; it never blocks detection, because detection
  never waited for it.
* **It refuses to turn "not computed" into zero.** ``disagreement_rate``,
  ``calibration_delta`` and ``poisoning_sensitivity`` are ``None`` when nothing was
  sampled, nothing was labelled, or no hostile episode was supplied. ``None`` never
  means zero; a gate reading zero there would pass a shadow that looked at nothing.
* **Sampling is deterministic** (every ``sample_every``-th session, 1-based), so two
  runs over the same stream sample the same sessions and a report can be reproduced.

``bytes_estimate`` is a *model* of what the shadow holds resident — the candidate's
canonical bytes plus the session under evaluation at :data:`STEP_BYTES_ESTIMATE` per
step — not an RSS measurement. It is named an estimate because it is one.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from pocketsec.stage0.contracts.common import ContractError, require_identifier
from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage2.encoder.ssir_encoder import FEATURE_WIDTH
from pocketsec.stage6.capsule.experience_capsule import EncodedStep
from pocketsec.stage6.constitution.learning import touches_protected
from pocketsec.stage6.memory.episodic import EpisodeSkeleton
from pocketsec.stage6.memory.semantic import TrustedKnowledgeState, score_session
from pocketsec.stage6.resources import WorkBudgetExceeded, WorkMeter

__all__ = [
    "ABORT_BYTE_BUDGET",
    "ABORT_WORK_BUDGET",
    "MAX_SHADOW_BYTES",
    "MAX_SHADOW_DISAGREEMENT",
    "MAX_SHADOW_WORK_UNITS",
    "MIN_SHADOW_SESSIONS",
    "SHADOW_SAMPLE_EVERY",
    "STEP_BYTES_ESTIMATE",
    "ShadowMind",
    "ShadowReport",
    "ShadowSession",
    "alert_of",
    "brier",
    "label_value",
    "session_touches_protected",
]

#: Every ``SHADOW_SAMPLE_EVERY``-th session is shadowed (chosen, §4.21): a 2 GB host
#: cannot afford to score two states on every session.
SHADOW_SAMPLE_EVERY: int = 4
#: G8 refuses a shadow that sampled fewer sessions than this.
MIN_SHADOW_SESSIONS: int = 32
MAX_SHADOW_WORK_UNITS: int = 200_000
MAX_SHADOW_BYTES: int = 8_388_608
#: G8 refuses a candidate whose alert decisions differ from trusted more often than this.
MAX_SHADOW_DISAGREEMENT: float = 0.10

#: Resident cost model for one step under evaluation: its features as 8-byte floats plus
#: a fixed allowance for the integer fields, signatures and evidence digests. A model,
#: not a measurement; see the module docstring.
STEP_BYTES_ESTIMATE: int = FEATURE_WIDTH * 8 + 256

ABORT_WORK_BUDGET = "work_budget_exhausted"
ABORT_BYTE_BUDGET = "byte_budget_exhausted"


@dataclass(frozen=True, slots=True)
class ShadowSession:
    """One production session as the shadow sees it: steps, context, optional label."""

    session_id: str
    steps: tuple[EncodedStep, ...]
    context_id: str
    label: Verdict | None

    def __post_init__(self) -> None:
        require_identifier(self.session_id, "ShadowSession.session_id")
        steps = tuple(self.steps)
        if not all(isinstance(step, EncodedStep) for step in steps):
            raise ContractError("a ShadowSession holds EncodedStep values only")
        object.__setattr__(self, "steps", steps)
        if not isinstance(self.context_id, str) or not self.context_id.startswith("ctx-"):
            raise ContractError("ShadowSession.context_id comes from context_id_for()")
        if self.label is not None and not isinstance(self.label, Verdict):
            raise ContractError(
                f"ShadowSession.label must be a Verdict or None, got {self.label!r}")


def label_value(label: Verdict | None) -> int | None:
    """MALICIOUS -> 1, BENIGN -> 0, anything else -> None (not a label a metric may use).

    UNKNOWN and the other non-committal verdicts are valid outputs of earlier stages; they
    are not ground truth, so they never enter a recall, FP or Brier figure here.
    """
    if label is Verdict.MALICIOUS:
        return 1
    if label is Verdict.BENIGN:
        return 0
    return None


def session_touches_protected(steps: Sequence[EncodedStep]) -> bool:
    """Whether any step touches a protected anchor — the "protected" in protected regression."""
    return any(touches_protected(s.object_property_mask, s.state_delta_mask) for s in steps)


def alert_of(
    state: TrustedKnowledgeState,
    steps: Sequence[EncodedStep],
    *,
    context_id: str,
    meter: WorkMeter | None,
) -> tuple[bool, float]:
    """(alert, score) of one state on one session, at that state's own threshold."""
    score = score_session(state, steps, context_id=context_id, meter=meter).score
    return score >= state.threshold(), score


def brier(labels: Sequence[int], scores: Sequence[float]) -> float | None:
    """Mean squared error of scores against 0/1 labels; ``None`` when there are no labels.

    Stage 0 has no Brier function and the Stage 2 one lives in a module Stage 6 may not
    import (ADR-0053), so this is the one Stage 6 copy; conservation imports it from here.
    """
    if len(labels) != len(scores):
        raise ContractError("brier needs aligned labels and scores")
    if not labels:
        return None
    squared = sum((score - label) ** 2 for label, score in zip(labels, scores, strict=True))
    return squared / len(labels)


def _canonical_digest(payload: dict[str, Any]) -> str:
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ShadowReport:
    """Architecture §19's comparisons, each a field. Counts and rates only — no scores."""

    candidate_digest: str
    trusted_digest: str
    sessions_seen: int
    sessions_sampled: int
    misses_caught: int  # labelled MALICIOUS: candidate alerts, trusted does not
    regressions: int  # labelled MALICIOUS: trusted alerts, candidate does not
    protected_regressions: int  # regressions on sessions touching a protected anchor
    fp_change: int  # labelled BENIGN: candidate alerts minus trusted alerts
    disagreement_rate: float | None  # None when nothing was sampled
    calibration_delta: float | None  # Brier(candidate) - Brier(trusted); None if unlabelled
    poisoning_sensitivity: float | None  # disagreement on hostile-tier episodes; None if none
    work_units: int
    bytes_estimate: int
    aborted: bool
    abort_reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_digest": self.candidate_digest,
            "trusted_digest": self.trusted_digest,
            "sessions_seen": self.sessions_seen,
            "sessions_sampled": self.sessions_sampled,
            "misses_caught": self.misses_caught,
            "regressions": self.regressions,
            "protected_regressions": self.protected_regressions,
            "fp_change": self.fp_change,
            "disagreement_rate": self.disagreement_rate,
            "calibration_delta": self.calibration_delta,
            "poisoning_sensitivity": self.poisoning_sensitivity,
            "work_units": self.work_units,
            "bytes_estimate": self.bytes_estimate,
            "aborted": self.aborted,
            "abort_reason": self.abort_reason,
        }

    def digest(self) -> str:
        return _canonical_digest(self.to_dict())


class _Tally:
    """The shadow's running counts. Mutable, private, and discarded into a frozen report."""

    __slots__ = (
        "abort_reason",
        "bytes_estimate",
        "candidate_scores",
        "caught",
        "disagreements",
        "fp_change",
        "hostile_disagree",
        "hostile_seen",
        "labels",
        "protected",
        "regressions",
        "sampled",
        "seen",
        "trusted_scores",
    )

    def __init__(self, resident_bytes: int) -> None:
        self.seen = self.sampled = self.caught = self.regressions = 0
        self.protected = self.fp_change = self.disagreements = 0
        self.hostile_seen = self.hostile_disagree = 0
        self.labels: list[int] = []
        self.trusted_scores: list[float] = []
        self.candidate_scores: list[float] = []
        self.bytes_estimate = resident_bytes
        self.abort_reason = ""

    def record(self, label: int | None, trusted: tuple[bool, float],
               candidate: tuple[bool, float], *, protected: bool) -> None:
        self.sampled += 1
        (t_alert, t_score), (c_alert, c_score) = trusted, candidate
        self.disagreements += int(t_alert != c_alert)
        if label is None:
            return
        # Bounded: at most one pair per sampled session, and sampling is capped by budget.
        self.labels.append(label)
        self.trusted_scores.append(t_score)
        self.candidate_scores.append(c_score)
        if label == 1:
            self.caught += int(c_alert and not t_alert)
            lost = t_alert and not c_alert
            self.regressions += int(lost)
            self.protected += int(lost and protected)
        else:
            self.fp_change += int(c_alert) - int(t_alert)


class ShadowMind:
    """Scores a candidate beside trusted on sampled sessions. Returns counts; writes nothing."""

    def __init__(
        self,
        *,
        sample_every: int = SHADOW_SAMPLE_EVERY,
        work_budget: int = MAX_SHADOW_WORK_UNITS,
        byte_budget: int = MAX_SHADOW_BYTES,
    ) -> None:
        for name, value in (("sample_every", sample_every), ("work_budget", work_budget),
                            ("byte_budget", byte_budget)):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ContractError(f"ShadowMind.{name} must be a positive int, got {value!r}")
        self._sample_every = sample_every
        self._work_budget = work_budget
        self._byte_budget = byte_budget

    @property
    def sample_every(self) -> int:
        return self._sample_every

    def run_shadow_mind(
        self,
        candidate: TrustedKnowledgeState,
        trusted: TrustedKnowledgeState,
        sessions: Iterable[ShadowSession],
        *,
        hostile: Sequence[EpisodeSkeleton] = (),
    ) -> ShadowReport:
        """HEL-F16. Deterministic sampling; stops (``aborted=True``) at either budget.

        ``hostile`` is the episodic memory's hostile tier — evidence kept, never learned
        from. The candidate and trusted are scored on each hostile episode and the share
        on which their alert decisions differ is ``poisoning_sensitivity``.
        """
        for name, state in (("candidate", candidate), ("trusted", trusted)):
            if not isinstance(state, TrustedKnowledgeState):
                raise ContractError(f"run_shadow_mind needs a TrustedKnowledgeState {name}")
        meter = WorkMeter(budget=self._work_budget)
        tally = _Tally(candidate.byte_size())
        if tally.bytes_estimate > self._byte_budget:
            tally.abort_reason = ABORT_BYTE_BUDGET
        else:
            self._shadow_sessions(candidate, trusted, sessions, meter, tally)
        if not tally.abort_reason:
            self._shadow_hostile(candidate, trusted, hostile, meter, tally)
        return self._report(candidate, trusted, meter, tally)

    def _shadow_sessions(self, candidate: TrustedKnowledgeState, trusted: TrustedKnowledgeState,
                         sessions: Iterable[ShadowSession], meter: WorkMeter,
                         tally: _Tally) -> None:
        resident = tally.bytes_estimate
        for session in sessions:
            if not isinstance(session, ShadowSession):
                raise ContractError(
                    f"the shadow consumes ShadowSession values, got {type(session)}")
            tally.seen += 1
            if tally.seen % self._sample_every:
                continue
            needed = resident + len(session.steps) * STEP_BYTES_ESTIMATE
            if needed > self._byte_budget:
                tally.abort_reason = ABORT_BYTE_BUDGET
                return
            tally.bytes_estimate = max(tally.bytes_estimate, needed)
            try:
                pair = self._pair(candidate, trusted, session.steps, session.context_id, meter)
            except WorkBudgetExceeded:
                tally.abort_reason = ABORT_WORK_BUDGET
                return
            tally.record(label_value(session.label), pair[0], pair[1],
                         protected=session_touches_protected(session.steps))

    def _shadow_hostile(self, candidate: TrustedKnowledgeState, trusted: TrustedKnowledgeState,
                        hostile: Sequence[EpisodeSkeleton], meter: WorkMeter,
                        tally: _Tally) -> None:
        for episode in hostile:
            if not isinstance(episode, EpisodeSkeleton):
                raise ContractError("hostile episodes are EpisodeSkeleton values")
            try:
                t, c = self._pair(candidate, trusted, episode.steps, episode.context_id, meter)
            except WorkBudgetExceeded:
                tally.abort_reason = ABORT_WORK_BUDGET
                return
            tally.hostile_seen += 1
            tally.hostile_disagree += int(t[0] != c[0])

    @staticmethod
    def _pair(candidate: TrustedKnowledgeState, trusted: TrustedKnowledgeState,
              steps: Sequence[EncodedStep], context_id: str,
              meter: WorkMeter) -> tuple[tuple[bool, float], tuple[bool, float]]:
        # One unit of overhead per pair, so even step-free sessions consume budget: the
        # meter, not the stream length, is what bounds the tally's label list.
        meter.charge(1)
        # Trusted first: it is the comparison the candidate is judged against, and if the
        # budget runs out mid-pair neither half is recorded.
        trusted_result = alert_of(trusted, steps, context_id=context_id, meter=meter)
        candidate_result = alert_of(candidate, steps, context_id=context_id, meter=meter)
        return trusted_result, candidate_result

    @staticmethod
    def _report(candidate: TrustedKnowledgeState, trusted: TrustedKnowledgeState,
                meter: WorkMeter, tally: _Tally) -> ShadowReport:
        brier_c = brier(tally.labels, tally.candidate_scores)
        brier_t = brier(tally.labels, tally.trusted_scores)
        return ShadowReport(
            candidate_digest=candidate.digest(),
            trusted_digest=trusted.digest(),
            sessions_seen=tally.seen,
            sessions_sampled=tally.sampled,
            misses_caught=tally.caught,
            regressions=tally.regressions,
            protected_regressions=tally.protected,
            fp_change=tally.fp_change,
            disagreement_rate=(tally.disagreements / tally.sampled) if tally.sampled else None,
            calibration_delta=(
                None if brier_c is None or brier_t is None else brier_c - brier_t
            ),
            poisoning_sensitivity=(
                tally.hostile_disagree / tally.hostile_seen if tally.hostile_seen else None
            ),
            work_units=meter.spent,
            bytes_estimate=tally.bytes_estimate,
            aborted=bool(tally.abort_reason),
            abort_reason=tally.abort_reason,
        )
