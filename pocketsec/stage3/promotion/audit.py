"""D3.12 (part) — adaptive auditing: how often a promoted cell is re-checked.

Architecture §27 sets the rate; §39/§40 set how the schedule is *drawn*. Both
matter, and they fail differently:

* A rate that does not rise with consequence, stress and boundary proximity
  audits the safe cells as hard as the dangerous ones, and the audit budget is
  spent where it buys nothing.
* A schedule an attacker can predict is worse than no schedule. §39 names audit
  gaming as a threat: if "which event gets audited" is a counter, or a seeded
  PRNG stream whose phase leaks, an adversary waits for the gap. :class:`AuditSampler`
  therefore draws from a **keyed hash** of ``(boot_salt, cell_id, frame_digest)``.
  There is no sequence to phase against — each frame's decision is independent
  of every other frame's, and the key is per boot.

``AuditReport.teacher_cost_us`` is ``float | None`` on purpose. Falsifier F5 asks
whether audit traffic costs more than the cell saves; that question cannot be
answered from a fabricated cost, so an unmeasured teacher costs ``None``, never
0.0.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage3.oracles.teacher import frame_digest
from pocketsec.stage3.theory import SecurityConsequence

if TYPE_CHECKING:  # pragma: no cover - import-time cost, not behaviour
    from pocketsec.stage3.bytecode.vm import CellFrame
    from pocketsec.stage3.cells.schema import KnowledgeCellV1
    from pocketsec.stage3.melting.stress import CellStress
    from pocketsec.stage3.oracles.dual_oracle import DualOracleEvaluator

__all__ = [
    "AGREEMENT_RELIEF",
    "AuditReport",
    "AuditSampler",
    "CONSEQUENCE_AUDIT_WEIGHT",
    "EPOCH_AGE_GAIN",
    "MAX_AUDIT_RATE",
    "MIN_AUDIT_RATE",
    "PROXIMITY_GAIN",
    "STRESS_GAIN",
    "audit_probability",
    "sample_audit",
]

#: A promoted cell that is never audited is an unverified cell with authority,
#: so the floor is above zero. One event in a thousand is not much; zero is a
#: different kind of thing entirely.
MIN_AUDIT_RATE = 0.001

#: The ceiling is 1.0 — auditing every event is legal, and is what a cell under
#: full stress should get just before it melts.
MAX_AUDIT_RATE = 1.0

#: Multiplier on the policy base rate, rising with consequence. Closed over all
#: four levels; checked at import, because a missing level would raise KeyError
#: on the cheap path at exactly the moment a CRITICAL frame arrived.
CONSEQUENCE_AUDIT_WEIGHT: Mapping[SecurityConsequence, float] = MappingProxyType(
    {
        SecurityConsequence.ROUTINE: 0.0,
        SecurityConsequence.ELEVATED: 0.75,
        SecurityConsequence.HIGH: 2.0,
        SecurityConsequence.CRITICAL: 5.0,
    }
)

#: How much measured stress may raise the rate.
STRESS_GAIN = 3.0

#: How much proximity to the edge of validated territory may raise it.
PROXIMITY_GAIN = 1.5

#: How much epochs-since-validation may raise it. This is **not** a time term:
#: an epoch opens only on corroborated system change (``SystemChangeSignal``),
#: so ``epoch_age`` counts untested change, which §28 does treat as eroding
#: trust. ``decay.decay_confidence`` has no time term for the same reason.
EPOCH_AGE_GAIN = 1.0

#: Half-saturation for ``epoch_age``.
EPOCH_AGE_SATURATION = 2.0

#: How much sustained agreement may *lower* it. Strictly below 1.0 so perfect
#: agreement cannot drive the rate to zero — a cell that always agrees is the
#: easiest cell to poison, because nobody is looking.
AGREEMENT_RELIEF = 0.6


@dataclass(frozen=True, slots=True)
class AuditReport:
    """What one sampled audit pass actually did.

    ``teacher_cost_us`` is the measured cost of consulting the teacher for the
    audited frames, or ``None`` when it was not measured. Falsifier F5 compares
    it against the cell's saving; a ``None`` there means F5 is UNMEASURED for
    this run, which is a result, not a pass.
    """

    audits: int
    disagreements: int
    rate_observed: float
    teacher_available: bool
    teacher_cost_us: float | None
    #: Audited frames on which the oracle had **no opinion**: the teacher snapshot
    #: held no answer and no hard constraint fired. These are counted apart from
    #: ``disagreements`` because they are UNMEASURED, not disagreement. Folding
    #: them in made a snapshot built on a different split read as a 1.0
    #: disagreement rate — the maximum — for a cell nothing had been measured
    #: wrong about, and that rate carries the heaviest weight in ``CellStress``.
    teacher_silent: int = 0

    def __post_init__(self) -> None:
        if isinstance(self.audits, bool) or not isinstance(self.audits, int) or self.audits < 0:
            raise ContractError(f"AuditReport.audits must be >= 0, got {self.audits!r}")
        if (
            isinstance(self.disagreements, bool)
            or not isinstance(self.disagreements, int)
            or self.disagreements < 0
        ):
            raise ContractError(
                f"AuditReport.disagreements must be >= 0, got {self.disagreements!r}"
            )
        if self.disagreements > self.audits:
            raise ContractError(
                f"AuditReport reports {self.disagreements} disagreements over {self.audits} "
                "audits; more disagreements than audits means the two were counted over "
                "different populations"
            )
        if not isinstance(self.teacher_available, bool):
            raise ContractError("AuditReport.teacher_available must be a bool")
        _require_count(self.teacher_silent, "AuditReport.teacher_silent")
        if self.teacher_silent > self.audits:
            raise ContractError(
                f"AuditReport reports {self.teacher_silent} silent-teacher audits over "
                f"{self.audits} audits"
            )
        if self.disagreements + self.teacher_silent > self.audits:
            raise ContractError(
                f"AuditReport reports {self.disagreements} disagreements and "
                f"{self.teacher_silent} silent-teacher audits over {self.audits} audits; "
                "the two are disjoint populations and cannot overlap"
            )
        if not 0.0 <= float(self.rate_observed) <= 1.0:
            raise ContractError(
                f"AuditReport.rate_observed must lie in [0, 1], got {self.rate_observed!r}"
            )
        if self.teacher_cost_us is not None:
            cost = float(self.teacher_cost_us)
            if not math.isfinite(cost) or cost < 0.0:
                raise ContractError(
                    f"AuditReport.teacher_cost_us must be finite and >= 0 or None "
                    f"(UNMEASURED), got {self.teacher_cost_us!r}"
                )

    @property
    def measured_audits(self) -> int:
        """Audits on which the oracle had an opinion — the honest denominator."""
        return self.audits - self.teacher_silent

    @property
    def disagreement_rate(self) -> float | None:
        """Disagreements per *measured* audit, or ``None`` when none was measured.

        ``None`` covers both "nothing was audited" and "nothing audited produced
        an opinion". A rate over trials in which the teacher never answered is as
        undefined as a rate over zero trials, and it used to read 1.0.
        """
        measured = self.measured_audits
        return None if measured <= 0 else self.disagreements / measured

    def to_dict(self) -> dict[str, Any]:
        return {
            "audits": self.audits,
            "disagreements": self.disagreements,
            "teacher_silent": self.teacher_silent,
            "measured_audits": self.measured_audits,
            "rate_observed": self.rate_observed,
            "teacher_available": self.teacher_available,
            "teacher_cost_us": self.teacher_cost_us,
            "disagreement_rate": self.disagreement_rate,
        }


def _require_unit(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ContractError(f"{field} must be a real number, got {value!r}")
    number = float(value)
    if not math.isfinite(number) or not 0.0 <= number <= 1.0:
        raise ContractError(f"{field} must lie in [0, 1], got {number!r}")
    return number


def _require_count(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ContractError(f"{field} must be a non-negative int, got {value!r}")
    return value


def audit_probability(
    cell: KnowledgeCellV1,
    *,
    stress: CellStress,
    epoch_age: int,
    boundary_distance: int,
    recent_agreement: float,
) -> float:
    """How likely any one frame resolved by this cell is to be re-checked (§27).

    ``boundary_distance`` is the number of boundary clauses between the frame and
    the *edge* of the cell's validated region, in either direction. Zero means
    "on the edge", which is where the validation supports the answer least, so
    that is where the rate is highest. A frame deep inside a well-covered region
    is the cheapest one to trust.

    The result is clamped into the intersection of the module bounds and the
    cell's own :class:`~pocketsec.stage3.cells.schema.AuditPolicy`. It is never
    zero: a promoted cell that is never re-checked is an unverified cell holding
    the authority of a verified one.
    """
    _require_count(epoch_age, "audit_probability(epoch_age=)")
    _require_count(boundary_distance, "audit_probability(boundary_distance=)")
    agreement = _require_unit(recent_agreement, "audit_probability(recent_agreement=)")
    policy = cell.audit_policy
    consequence = cell.invariant.consequent.consequence
    if consequence not in CONSEQUENCE_AUDIT_WEIGHT:
        raise ContractError(f"no audit weight declared for consequence {consequence!r}")

    proximity = 1.0 / (1.0 + boundary_distance)
    aged = epoch_age / (epoch_age + EPOCH_AGE_SATURATION)
    stress_total = min(max(float(stress.total), 0.0), 1.0)

    rate = policy.base_rate
    rate *= 1.0 + CONSEQUENCE_AUDIT_WEIGHT[consequence]
    rate *= 1.0 + STRESS_GAIN * stress_total
    rate *= 1.0 + PROXIMITY_GAIN * proximity
    rate *= 1.0 + EPOCH_AGE_GAIN * aged
    rate *= 1.0 - AGREEMENT_RELIEF * agreement

    floor = max(MIN_AUDIT_RATE, policy.min_rate)
    ceiling = max(floor, min(MAX_AUDIT_RATE, policy.max_rate))
    return min(max(rate, floor), ceiling)


class AuditSampler:
    """Decides *which* frames get audited, unpredictably but within policy (§40).

    The decision for a frame is a keyed hash of ``(boot_salt, cell_id,
    cell.audit_policy.jitter_salt, frame_digest)``. That is deliberately not a
    counter and not a position in a seeded PRNG stream: both give an observer who
    can see a few decisions the ability to predict the next one, which is the
    audit-gaming threat in §39.

    ``jitter_salt`` is in the message because ``AuditPolicy`` promises a per-cell
    salt and this class used not to read it: the field was validated, serialised
    and carried across the Stage 4 seam while contributing nothing, so the
    documented mitigation — rotate a compromised cell's salt — was provably a
    no-op. It carries no secret (see ``AuditPolicy``); the secrecy is the boot
    salt's, and the jitter salt buys separation between cells and rotation.

    Three consequences the tests pin down:

    * decisions are **reproducible for a given boot salt**, so an audit can be
      replayed and argued about;
    * they are **not reproducible without it**, so an attacker who knows the
      cell id and the frame — everything except the salt — learns nothing; and
    * **re-salting one cell changes that cell's schedule**, so a rotation after a
      suspected compromise does something.
    """

    __slots__ = ("_boot_salt", "_key")

    def __init__(self, boot_salt: str) -> None:
        if not isinstance(boot_salt, str) or not boot_salt.strip():
            raise ContractError(
                "AuditSampler requires a non-empty boot_salt: an unsalted schedule is a "
                "pure function of public data, and public data can be waited out (§39)"
            )
        self._boot_salt = boot_salt
        # blake2b keys cap at 64 bytes; hashing the salt first accepts any length
        # without truncating it, so two long salts cannot collide on their prefix.
        self._key = hashlib.sha256(boot_salt.encode("utf-8")).digest()[:32]

    def draw(self, cell: KnowledgeCellV1, frame: CellFrame) -> float:
        """The frame's position in [0, 1). Exposed so anti-gaming is testable."""
        digest = hashlib.blake2b(key=self._key, digest_size=8)
        digest.update(cell.cell_id.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(cell.audit_policy.jitter_salt.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(frame_digest(frame).encode("utf-8"))
        return int.from_bytes(digest.digest(), "big") / float(1 << 64)

    def should_audit(
        self, cell: KnowledgeCellV1, frame: CellFrame, *, probability: float
    ) -> bool:
        """Audit this frame?

        ``probability`` is clamped into ``[MIN_AUDIT_RATE, MAX_AUDIT_RATE]``
        before the draw, so a caller passing 0.0 still audits at the floor rather
        than silently switching auditing off for that cell.
        """
        rate = _require_unit(probability, "AuditSampler.should_audit(probability=)")
        rate = min(max(rate, MIN_AUDIT_RATE), MAX_AUDIT_RATE)
        return self.draw(cell, frame) < rate


def sample_audit(
    cell: KnowledgeCellV1,
    frames: Sequence[CellFrame],
    *,
    sampler: AuditSampler,
    oracle: DualOracleEvaluator,
    probability: float,
    teacher_cost_us: float | None = None,
) -> AuditReport:
    """Run one sampled audit pass and report what it cost and what it found.

    Only the sampled frames are put to the oracle — that is the whole point of
    sampling, and it is also what makes F5 a real question. ``teacher_cost_us``
    is passed through rather than guessed: this function does not know how to
    time a teacher on a contended host, and a number it invented would be worse
    than none.
    """
    audits = 0
    disagreements = 0
    silent = 0
    teacher_available = True
    for frame in frames:
        if not sampler.should_audit(cell, frame, probability=probability):
            continue
        audits += 1
        verdict = oracle.evaluate(cell, (frame,))
        if not verdict.teacher_available:
            teacher_available = False
        if verdict.passed:
            continue
        # A hard violation is the cell being wrong whatever the teacher says, so
        # it counts as disagreement even with no teacher. A refusal whose only
        # reason is that the snapshot had no entry is UNMEASURED and is counted
        # apart: ``_decide`` returns not-passed for both, and reading the second
        # as disagreement turned a snapshot key miss into the maximum stress
        # signal available.
        if verdict.hard_violations or verdict.teacher_available:
            disagreements += 1
        else:
            silent += 1
    observed = audits / len(frames) if frames else 0.0
    return AuditReport(
        audits=audits,
        disagreements=disagreements,
        teacher_silent=silent,
        rate_observed=observed,
        # Nothing was consulted, so nothing is known about the teacher. Claiming
        # it was available would be an unearned reassurance.
        teacher_available=teacher_available if audits else False,
        teacher_cost_us=teacher_cost_us,
    )


def _assert_audit_weights_are_closed_and_rising() -> None:
    levels = tuple(SecurityConsequence)
    if set(CONSEQUENCE_AUDIT_WEIGHT) != set(levels):
        raise ContractError(
            "CONSEQUENCE_AUDIT_WEIGHT must cover every SecurityConsequence; a missing "
            "level would raise on the cheap path exactly when it mattered"
        )
    weights = [CONSEQUENCE_AUDIT_WEIGHT[level] for level in sorted(levels)]
    if any(later <= earlier for earlier, later in zip(weights, weights[1:], strict=False)):
        raise ContractError(
            f"CONSEQUENCE_AUDIT_WEIGHT must rise strictly with consequence, got {weights}"
        )
    if not 0.0 < MIN_AUDIT_RATE < MAX_AUDIT_RATE <= 1.0:
        raise ContractError("audit rate bounds must satisfy 0 < MIN < MAX <= 1")
    if not 0.0 <= AGREEMENT_RELIEF < 1.0:
        raise ContractError(
            "AGREEMENT_RELIEF must be < 1.0, or perfect agreement would switch auditing off"
        )


_assert_audit_weights_are_closed_and_rising()
