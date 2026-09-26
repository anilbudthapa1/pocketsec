"""D6.17 (canary half) — limited cognitive influence, and the regression test that ends it.

Architecture §43: "Canary does not mean partial unsafe response authority. It means
limited cognitive influence." Here that means exactly one thing: on a deterministic
``share`` of sessions the candidate's score is offered as *secondary evidence* beside the
trusted score, and the emitted score is ``max(trusted, candidate)``. A canary can add
evidence; it can never suppress a detection the trusted state makes. The invariant is a
function (:func:`emitted_score`), so it is testable on every observation.

What it refuses to do:

* **It never emits less than trusted.** A candidate that would have dropped a detection
  during its canary is counted as a *regression* and the detection still fires, because
  the emitted score is the max. That is the difference between a canary and a rollout.
* **It carries no authority.** The emitted score reaches nothing in Stage 5 from here;
  :class:`CanaryReport` is counts, and its ``to_dict`` passes Stage 5's own
  ``authority_violations`` and ``seam_violations`` screens (tested).
* **It stores no scores.** The evaluator keeps counters, so a probation of any length is
  bounded memory. False-positive rates come from Stage 0's ``ConfusionMatrix`` built
  from those counters, not from a second metric implementation.

``regressed`` is decided by :class:`CanaryPolicy` alone: more protected regressions than
``max_protected_regressions`` (0), or a benign false-positive-rate increase above
``max_fp_increase``. Regressions on sessions that touch no protected anchor are counted
and reported but do not end a canary on their own — the policy has no knob for them, and
inventing one here would be a policy nobody chose.

**Live traffic is mostly unlabelled** (review S6-AUTH-03). Two rules keep the canary and
probation from passing on evidence they never saw:

* An *unlabelled* session touching a protected anchor on which trusted alerts and the
  candidate is silent is a protected regression. Dropping a detection there needs no label
  to be seen, and waiting for one would let a candidate silence a family on exactly the
  traffic where it regresses.
* A window is complete only when it also holds at least ``min_labelled_benign``
  BENIGN-labelled sessions: a false-positive increase cannot be seen without them, so a
  window of unlabelled sessions is incomplete, never passed. The malicious side needs no
  such minimum only because of the rule above — the one regression the policy acts on (a
  protected detection dropped) is visible without a label. ``CanaryReport`` says how many
  labelled sessions of each class it saw.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from pocketsec.stage0.benchmark.security_metrics import ConfusionMatrix
from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage0.contracts.threat_prediction_v1 import Verdict
from pocketsec.stage6.memory.semantic import TrustedKnowledgeState
from pocketsec.stage6.shadow.mind import (
    ShadowSession,
    alert_of,
    label_value,
    session_touches_protected,
)

__all__ = [
    "CANARY_MAX_FP_INCREASE",
    "CANARY_SHARE",
    "CANARY_WINDOW_SESSIONS",
    "MAX_PROTECTED_REGRESSIONS",
    "MIN_LABELLED_BENIGN",
    "PROBATION_SESSIONS",
    "CanaryEvaluator",
    "CanaryObservation",
    "CanaryPolicy",
    "CanaryReport",
    "canary_sampled",
    "emitted_score",
]

#: Chosen parameters (§4.21), not measurements.
CANARY_SHARE: float = 0.10
CANARY_WINDOW_SESSIONS: int = 64
CANARY_MAX_FP_INCREASE: float = 0.02
PROBATION_SESSIONS: int = 128
MAX_PROTECTED_REGRESSIONS: int = 0
#: Not in the §4.21 table (review S6-AUTH-03): the fewest BENIGN-labelled sessions a canary
#: window or a probation must hold before it can be judged. Chosen as the smallest
#: non-vacuous value, not tuned.
MIN_LABELLED_BENIGN: int = 1


@dataclass(frozen=True, slots=True)
class CanaryPolicy:
    """The canary's window and its regression bounds. ``share`` — not "fraction" (T5)."""

    share: float = CANARY_SHARE
    window_sessions: int = CANARY_WINDOW_SESSIONS
    max_protected_regressions: int = MAX_PROTECTED_REGRESSIONS
    max_fp_increase: float = CANARY_MAX_FP_INCREASE
    probation_sessions: int = PROBATION_SESSIONS
    min_labelled_benign: int = MIN_LABELLED_BENIGN

    def __post_init__(self) -> None:
        if isinstance(self.share, bool) or not 0.0 < float(self.share) <= 1.0:
            raise ContractError(f"CanaryPolicy.share must be in (0, 1], got {self.share!r}")
        for name in ("window_sessions", "probation_sessions"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise ContractError(f"CanaryPolicy.{name} must be a positive int, got {value!r}")
        for name in ("max_protected_regressions", "min_labelled_benign"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ContractError(f"CanaryPolicy.{name} must be a non-negative int")
        if isinstance(self.max_fp_increase, bool) or not 0.0 <= float(self.max_fp_increase) <= 1.0:
            raise ContractError("CanaryPolicy.max_fp_increase must be in [0, 1]")


def canary_sampled(session_id: str, *, share: float) -> bool:
    """``int(sha256(session_id)[:8], 16) / 2**32 < share`` — deterministic, not random.

    Deterministic so a replay of the same stream routes the same sessions to the canary,
    and so an auditor can recompute which sessions carried candidate evidence.
    """
    if not isinstance(session_id, str) or not session_id:
        raise ContractError("canary_sampled needs a non-empty session id")
    head = hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:8]
    return int(head, 16) / 2**32 < share


def emitted_score(trusted: float, candidate: float, *, sampled: bool) -> float:
    """``max(trusted, candidate)`` if sampled, else ``trusted``: add, never suppress (§43)."""
    return max(trusted, candidate) if sampled else trusted


@dataclass(frozen=True, slots=True)
class CanaryObservation:
    session_id: str
    trusted_score: float
    candidate_score: float
    emitted: float
    sampled: bool
    label: Verdict | None


def _digest(payload: dict[str, Any]) -> str:
    text = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class CanaryReport:
    candidate_digest: str
    observations: int
    sampled: int
    disagreements: int
    regressions: int
    protected_regressions: int
    fp_increase: float | None  # None when no BENIGN-labelled session was observed
    window_complete: bool
    regressed: bool
    reasons: tuple[str, ...]
    labelled_malicious: int = 0
    labelled_benign: int = 0
    unlabelled_protected_drops: int = 0  # counted inside protected_regressions too
    evidence_complete: bool = False  # the BENIGN-labelled minimum was met

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_digest": self.candidate_digest,
            "observations": self.observations,
            "sampled": self.sampled,
            "disagreements": self.disagreements,
            "regressions": self.regressions,
            "protected_regressions": self.protected_regressions,
            "fp_increase": self.fp_increase,
            "window_complete": self.window_complete,
            "regressed": self.regressed,
            "reasons": list(self.reasons),
            "labelled_malicious": self.labelled_malicious,
            "labelled_benign": self.labelled_benign,
            "unlabelled_protected_drops": self.unlabelled_protected_drops,
            "evidence_complete": self.evidence_complete,
        }

    def digest(self) -> str:
        return _digest(self.to_dict())


class CanaryEvaluator:
    """Scores both states on every observed session; emits the candidate only when sampled.

    Both states are scored on every session so regressions are seen on the whole
    window, not only on the canary share — more evidence against the candidate, never
    more influence for it. Also used by the controller for probation, with the
    promoted state as ``candidate`` and the pinned pre-promotion state as ``trusted``.
    """

    def __init__(self, *, candidate: TrustedKnowledgeState, trusted: TrustedKnowledgeState,
                 policy: CanaryPolicy) -> None:
        if not isinstance(policy, CanaryPolicy):
            raise ContractError("CanaryEvaluator needs a CanaryPolicy")
        for name, state in (("candidate", candidate), ("trusted", trusted)):
            if not isinstance(state, TrustedKnowledgeState):
                raise ContractError(f"CanaryEvaluator needs a TrustedKnowledgeState {name}")
        self._candidate = candidate
        self._trusted = trusted
        self._candidate_digest = candidate.digest()
        self._policy = policy
        self._observations = self._sampled = self._disagreements = 0
        self._regressions = self._protected = 0
        self._labelled = [0, 0]  # (BENIGN, MALICIOUS) labelled sessions seen
        self._unlabelled_drops = 0
        # Benign confusion counters for both states: (false positives, true negatives).
        self._benign_trusted = [0, 0]
        self._benign_candidate = [0, 0]

    @property
    def policy(self) -> CanaryPolicy:
        return self._policy

    def observe(self, session: ShadowSession) -> CanaryObservation:
        if not isinstance(session, ShadowSession):
            raise ContractError(f"a canary observes ShadowSession values, got {type(session)}")
        t_alert, t_score = alert_of(self._trusted, session.steps,
                                    context_id=session.context_id, meter=None)
        c_alert, c_score = alert_of(self._candidate, session.steps,
                                    context_id=session.context_id, meter=None)
        sampled = canary_sampled(session.session_id, share=self._policy.share)
        self._observations += 1
        self._sampled += int(sampled)
        self._disagreements += int(t_alert != c_alert)
        label = label_value(session.label)
        if label is not None:
            self._labelled[label] += 1
        if label is None and t_alert and not c_alert and session_touches_protected(
                session.steps):
            # A dropped detection on protected meaning is visible without a label.
            self._regressions += 1
            self._protected += 1
            self._unlabelled_drops += 1
        elif label == 1 and t_alert and not c_alert:
            self._regressions += 1
            self._protected += int(session_touches_protected(session.steps))
        elif label == 0:
            self._benign_trusted[0 if t_alert else 1] += 1
            self._benign_candidate[0 if c_alert else 1] += 1
        return CanaryObservation(
            session_id=session.session_id,
            trusted_score=t_score,
            candidate_score=c_score,
            emitted=emitted_score(t_score, c_score, sampled=sampled),
            sampled=sampled,
            label=session.label,
        )

    def _fp_increase(self) -> float | None:
        trusted = ConfusionMatrix(0, self._benign_trusted[0], self._benign_trusted[1], 0)
        candidate = ConfusionMatrix(0, self._benign_candidate[0], self._benign_candidate[1], 0)
        t_rate, c_rate = trusted.false_positive_rate, candidate.false_positive_rate
        if t_rate is None or c_rate is None:
            return None
        return c_rate - t_rate

    def report(self) -> CanaryReport:
        policy = self._policy
        fp_increase = self._fp_increase()
        reasons: list[str] = []
        if self._protected > policy.max_protected_regressions:
            reasons.append(
                f"protected_regressions {self._protected} > {policy.max_protected_regressions}"
            )
        if fp_increase is not None and fp_increase > policy.max_fp_increase:
            reasons.append(f"fp_increase {fp_increase:.6f} > {policy.max_fp_increase}")
        evidence = self._labelled[0] >= policy.min_labelled_benign
        return CanaryReport(
            candidate_digest=self._candidate_digest,
            observations=self._observations,
            sampled=self._sampled,
            disagreements=self._disagreements,
            regressions=self._regressions,
            protected_regressions=self._protected,
            fp_increase=fp_increase,
            window_complete=self._observations >= policy.window_sessions and evidence,
            regressed=bool(reasons),
            reasons=tuple(reasons),
            labelled_malicious=self._labelled[1],
            labelled_benign=self._labelled[0],
            unlabelled_protected_drops=self._unlabelled_drops,
            evidence_complete=evidence,
        )
