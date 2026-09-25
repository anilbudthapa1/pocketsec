"""Incident identifiability (architecture §19) — the one output this stage exists to get right.

Some incidents cannot be identified from the telemetry a host can afford to collect.
A system that always names a culprit is not doing causal reasoning, it is telling a
story. This module decides which of four things is true of a belief field and refuses
to blur them:

* ``IDENTIFIED`` — one world leads the others by more than the margin.
* ``UNIDENTIFIABLE`` — no affordable observation separates the leaders. **Requires
  ``discriminating_observations == ()``.** That empty tuple is the entire difference
  between "cannot decide" and "have not looked yet", and conflating the two is the
  failure §19 exists to prevent.
* ``INSUFFICIENT_EVIDENCE`` — separable, but the discriminating observation has not
  been made (or no observation plan was supplied, which is *not* evidence of
  non-identifiability).
* ``UNKNOWN`` — the field holds nothing but bounded UNKNOWN worlds, or the world
  that would lead is one. The lifecycle names every novel world after the first
  ``unresolved_novel_mechanism.<sha12>``; all of them are the UNKNOWN family, and
  a field of novelties is not a mechanism that could be identified (S4-REV-05).

Two refusals are structural rather than reviewed:

1. **Stage 4 mints no parallel vocabulary** (ADR-0032). ``to_verdict()`` maps onto
   Stage 0's frozen ``Verdict``; ``UNIDENTIFIABLE`` is ``Verdict.UNIDENTIFIABLE`` and
   nothing new is registered. Stage 0's ``_validate_abstention`` then enforces the
   abstention half of the table inside ``ThreatPredictionV1``.
2. **A tie is broken away from alarm.** When supports are level, the leading world is
   the one with the *lower* consequence. A system whose tie-break favours the scarier
   explanation manufactures threat out of ignorance.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    require_finite_unit_interval,
    require_identifier,
)
from pocketsec.stage0.contracts.threat_prediction_v1 import NON_COMMITTAL_VERDICTS, Verdict

if TYPE_CHECKING:  # pragma: no cover - typing only; no runtime coupling to peers
    from pocketsec.stage4.sensing.active_plan import ObservationPlan
    from pocketsec.stage4.visibility.sensor_shadow import SensorShadow
    from pocketsec.stage4.worlds.field import CausalBeliefField
    from pocketsec.stage4.worlds.world import SecurityWorldV1

__all__ = [
    "AMBIGUOUS",
    "BENIGN",
    "IDENTIFIABILITY_MARGIN",
    "MALICIOUS",
    "MECHANISM_POLARITY",
    "NOVEL",
    "UNKNOWN_MECHANISM_ID",
    "IdentifiabilityState",
    "IdentifiabilityVerdict",
    "is_unknown_mechanism",
    "mechanism_polarity",
    "self_margin",
    "test_identifiability",
]

#: Support gap required to call a single world identified. A chosen parameter, not a
#: measured one (spec §9.11) — it is reported as a parameter in the findings document.
IDENTIFIABILITY_MARGIN: float = 0.15

#: The mechanism id of the bounded UNKNOWN world of §12. Novelty is not maliciousness:
#: a field holding only this world is UNKNOWN, never SUSPICIOUS.
UNKNOWN_MECHANISM_ID: str = "unresolved_novel_mechanism"

MALICIOUS: str = "MALICIOUS"
BENIGN: str = "BENIGN"
AMBIGUOUS: str = "AMBIGUOUS"
#: The UNKNOWN family's polarity. It maps to ``Verdict.UNKNOWN``, never to
#: ``SUSPICIOUS``: novelty is not maliciousness, and a novel world that happened to
#: lead a field was being reported as an alarm (S4-REV-05).
NOVEL: str = "NOVEL"

#: Polarity of the closed mechanism vocabulary the Stage 4 corpus proposes from.
#:
#: The default for an unlisted mechanism is ``AMBIGUOUS``, never ``BENIGN``. That
#: asymmetry is the point: a mechanism this table has never seen must not be able to
#: clear an incident. §29's rule — "it cannot silently simplify into benign" — is
#: violated by a permissive default just as surely as by a bad horizon.
MECHANISM_POLARITY: Mapping[str, str] = MappingProxyType(
    {
        "approved_administration": BENIGN,
        "scheduled_automation_external_sink": BENIGN,
        "compromised_admin_session": MALICIOUS,
        "stolen_credential_reuse": MALICIOUS,
        "coincident_privileged_maintenance": AMBIGUOUS,
        UNKNOWN_MECHANISM_ID: AMBIGUOUS,
    }
)


def is_unknown_mechanism(mechanism_id: str | None) -> bool:
    """True for the bounded UNKNOWN world AND every suffixed novel sibling.

    ``worlds/lifecycle._mechanism_id_for`` names the first novel world
    ``unresolved_novel_mechanism`` and every later one
    ``unresolved_novel_mechanism.<sha12>`` (a field refuses duplicate mechanism
    ids). An exact-match test recognised only the first, so a field of novelties was
    ranked as if it held named mechanisms.
    """
    if not mechanism_id:
        return False
    return mechanism_id == UNKNOWN_MECHANISM_ID or mechanism_id.startswith(
        UNKNOWN_MECHANISM_ID + "."
    )


def mechanism_polarity(mechanism_id: str) -> str:
    """Polarity of a mechanism id, defaulting to ``AMBIGUOUS``.

    Refuses to guess in the benign direction; see ``MECHANISM_POLARITY``. The
    UNKNOWN family is ``NOVEL`` whatever its suffix.
    """
    if is_unknown_mechanism(mechanism_id):
        return NOVEL
    return MECHANISM_POLARITY.get(mechanism_id, AMBIGUOUS)


class IdentifiabilityState(StrEnum):
    """Identifiable(H) of §19, as four outcomes. Three of them are answers."""

    IDENTIFIED = "IDENTIFIED"
    #: No affordable observation separates the leaders.
    UNIDENTIFIABLE = "UNIDENTIFIABLE"
    #: Separable in principle, but not yet observed.
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    #: The field holds only an UNKNOWN world.
    UNKNOWN = "UNKNOWN"


#: The fixed state -> verdict table of ADR-0032. ``IDENTIFIED`` is resolved by the
#: leading mechanism's polarity, so it is handled in ``to_verdict`` rather than here.
_NON_IDENTIFIED_VERDICTS: Mapping[str, Verdict] = MappingProxyType(
    {
        IdentifiabilityState.UNIDENTIFIABLE.value: Verdict.UNIDENTIFIABLE,
        IdentifiabilityState.INSUFFICIENT_EVIDENCE.value: Verdict.INSUFFICIENT_EVIDENCE,
        IdentifiabilityState.UNKNOWN.value: Verdict.UNKNOWN,
    }
)

_IDENTIFIED_VERDICTS: Mapping[str, Verdict] = MappingProxyType(
    {
        MALICIOUS: Verdict.MALICIOUS,
        BENIGN: Verdict.BENIGN,
        AMBIGUOUS: Verdict.SUSPICIOUS,
        NOVEL: Verdict.UNKNOWN,
    }
)


@dataclass(frozen=True, slots=True)
class IdentifiabilityVerdict:
    """Identifiable(H) (§19), with the reason it went that way.

    ``leading_mechanism_id`` is carried beyond the specification's field list because
    ``to_verdict()`` cannot be implemented without it: the IDENTIFIED row of ADR-0032's
    table branches on whether the leading world is malicious, benign or ambiguous, and
    a world id alone does not say. It defaults to ``None``, in which case an
    ``IDENTIFIED`` verdict maps to ``SUSPICIOUS`` — the non-committal-in-spirit answer
    — rather than to ``BENIGN``.
    """

    state: IdentifiabilityState
    leading_world_id: str | None
    support_margin: float
    material_alternatives: tuple[str, ...]
    #: Empty **iff** the case is genuinely non-identifiable. Enforced below.
    discriminating_observations: tuple[str, ...]
    affordable: bool
    shadow_penalty: float
    detail: str
    leading_mechanism_id: str | None = None

    def __post_init__(self) -> None:
        object.__setattr__(self, "state", IdentifiabilityState(self.state))
        require_finite_unit_interval(self.support_margin, "IdentifiabilityVerdict.support_margin")
        require_finite_unit_interval(self.shadow_penalty, "IdentifiabilityVerdict.shadow_penalty")
        if not isinstance(self.affordable, bool):
            raise ContractError("IdentifiabilityVerdict.affordable must be a bool")
        if not isinstance(self.detail, str) or not self.detail:
            raise ContractError(
                "IdentifiabilityVerdict.detail must name the number that decided it; "
                "a verdict with no stated reason cannot be audited"
            )
        if self.leading_world_id is not None:
            require_identifier(self.leading_world_id, "IdentifiabilityVerdict.leading_world_id")
        if self.leading_mechanism_id is not None:
            require_identifier(
                self.leading_mechanism_id, "IdentifiabilityVerdict.leading_mechanism_id"
            )
        object.__setattr__(
            self, "material_alternatives", tuple(str(x) for x in self.material_alternatives)
        )
        object.__setattr__(
            self, "discriminating_observations", tuple(str(x) for x in self.discriminating_observations)
        )
        self._refuse_laundered_non_identifiability()
        self._refuse_leaderless_identification()

    def _refuse_laundered_non_identifiability(self) -> None:
        """THE invariant of §19, enforced by construction.

        ``UNIDENTIFIABLE`` means no affordable observation separates the leaders. If
        the verdict can name one, the honest state is ``INSUFFICIENT_EVIDENCE``: the
        system has not looked yet. Allowing both would let "we did not bother" be
        reported as "it is impossible", which is the exact confusion §19 names.
        """
        if (
            self.state is IdentifiabilityState.UNIDENTIFIABLE
            and self.discriminating_observations
        ):
            raise ContractError(
                "UNIDENTIFIABLE requires discriminating_observations == (); got "
                f"{self.discriminating_observations!r}. A case one observation would "
                "separate is INSUFFICIENT_EVIDENCE, not non-identifiable"
            )

    def _refuse_leaderless_identification(self) -> None:
        if self.state is IdentifiabilityState.IDENTIFIED and self.leading_world_id is None:
            raise ContractError("IDENTIFIED requires a leading_world_id")

    # --- the ADR-0032 mapping -------------------------------------------

    def to_verdict(self) -> Verdict:
        """Map onto Stage 0's frozen enum. Stage 4 invents no vocabulary (ADR-0032)."""
        if self.state is not IdentifiabilityState.IDENTIFIED:
            return _NON_IDENTIFIED_VERDICTS[self.state.value]
        polarity = (
            mechanism_polarity(self.leading_mechanism_id)
            if self.leading_mechanism_id is not None
            else AMBIGUOUS
        )
        return _IDENTIFIED_VERDICTS[polarity]

    def abstains(self) -> bool:
        """True when this verdict asserts nothing about maliciousness.

        Derived from ``NON_COMMITTAL_VERDICTS`` rather than restated, so the abstention
        half of ADR-0032's table cannot drift from the contract that enforces it.
        """
        return self.to_verdict() in NON_COMMITTAL_VERDICTS

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.value,
            "verdict": self.to_verdict().value,
            "abstained": self.abstains(),
            "leading_world_id": self.leading_world_id,
            "leading_mechanism_id": self.leading_mechanism_id,
            "support_margin": round(self.support_margin, 6),
            "material_alternatives": list(self.material_alternatives),
            "discriminating_observations": list(self.discriminating_observations),
            "affordable": self.affordable,
            "shadow_penalty": round(self.shadow_penalty, 6),
            "detail": self.detail,
        }


# --- CBF-F12 ----------------------------------------------------------------


def test_identifiability(
    field: CausalBeliefField,
    *,
    shadow: SensorShadow | None,
    plan: ObservationPlan | None,
) -> IdentifiabilityVerdict:
    """Decide Identifiable(H) for a belief field. CBF-F12.

    ``plan=None`` is legal and means *no plan was computed*. It yields
    ``INSUFFICIENT_EVIDENCE``, never ``UNIDENTIFIABLE``: not having looked is not the
    same as having looked and found nothing, and a planner that failed to run must not
    be able to certify an incident as unresolvable.
    """
    worlds = tuple(getattr(field, "worlds", ()))
    shadow_penalty = _shadow_penalty(shadow)
    unknown = _unknown_verdict(worlds, shadow_penalty)
    if unknown is not None:
        return unknown

    support = dict(field.support_vector())
    ranked = _rank(worlds, support)
    runner_up = ranked[1] if len(ranked) > 1 else None
    raw_margin = _margin(support, ranked[0], runner_up)
    effective_margin = max(0.0, raw_margin - shadow_penalty)

    if effective_margin >= IDENTIFIABILITY_MARGIN:
        if is_unknown_mechanism(ranked[0].mechanism_id):
            return _novel_leader_verdict(ranked, raw_margin, shadow_penalty)
        return _identified_verdict(ranked, raw_margin, effective_margin, shadow_penalty)
    if runner_up is None:
        # One surviving world below the margin against its own support: there is
        # nothing to discriminate between, so this is not UNIDENTIFIABLE — it is a
        # single explanation the evidence has not yet earned (S4-FC-06).
        return _unplanned_verdict(ranked[0], (), raw_margin, shadow_penalty, _LONE_WORLD)

    # Below the margin. Whether that is "cannot decide" or "have not looked" is
    # decided entirely by the plan, which is why plan=None cannot answer it.
    leader = _least_alarming(_contenders(ranked, support))
    alternatives = tuple(w.world_id for w in ranked if w.world_id != leader.world_id)
    if plan is None:
        return _unplanned_verdict(leader, sorted(alternatives), raw_margin, shadow_penalty)
    discriminating = tuple(
        request.sensor_method.value for request in tuple(getattr(plan, "requests", ()))
    )
    if discriminating:
        return _separable_verdict(
            leader, sorted(alternatives), raw_margin, shadow_penalty, plan, discriminating
        )
    if _not_attempted(plan):
        # Every refusal that is about the wiring happens AFTER the action cleared
        # the discrimination threshold, so these are the observations that would
        # separate the worlds. "Not wired to look" is not "nothing to see".
        return _unplanned_verdict(
            leader, sorted(alternatives), raw_margin, shadow_penalty, _NOT_WIRED
        )
    return _unidentifiable_verdict(leader, sorted(alternatives), raw_margin, shadow_penalty, plan)


# --- the five endings, one builder each -------------------------------------


def _unknown_verdict(
    worlds: Sequence[SecurityWorldV1], shadow_penalty: float
) -> IdentifiabilityVerdict | None:
    """UNKNOWN for an empty field or one holding only the bounded UNKNOWN world.

    Returns ``None`` when the field has something to reason about, so the caller reads as
    a sequence of decisions rather than as nested conditionals.
    """
    if not worlds:
        return IdentifiabilityVerdict(
            state=IdentifiabilityState.UNKNOWN,
            leading_world_id=None,
            support_margin=0.0,
            material_alternatives=(),
            discriminating_observations=(),
            affordable=False,
            shadow_penalty=shadow_penalty,
            detail="field holds no worlds",
        )
    if all(is_unknown_mechanism(world.mechanism_id) for world in worlds):
        return IdentifiabilityVerdict(
            state=IdentifiabilityState.UNKNOWN,
            leading_world_id=worlds[0].world_id,
            support_margin=0.0,
            material_alternatives=tuple(sorted(w.world_id for w in worlds[1:])),
            discriminating_observations=(),
            affordable=False,
            shadow_penalty=shadow_penalty,
            detail=(
                f"field holds only UNKNOWN-family worlds ({len(worlds)}); novel residuals "
                "are not mechanisms that could be identified or told apart"
            ),
            leading_mechanism_id=worlds[0].mechanism_id,
        )
    return None


def _novel_leader_verdict(
    ranked: Sequence[SecurityWorldV1], raw_margin: float, shadow_penalty: float
) -> IdentifiabilityVerdict:
    """The world that would be IDENTIFIED is a novel one: answer UNKNOWN, not an alarm."""
    leader = ranked[0]
    return IdentifiabilityVerdict(
        state=IdentifiabilityState.UNKNOWN,
        leading_world_id=leader.world_id,
        support_margin=raw_margin,
        material_alternatives=tuple(sorted(w.world_id for w in ranked[1:])),
        discriminating_observations=(),
        affordable=False,
        shadow_penalty=shadow_penalty,
        detail=(
            f"the leading world ({raw_margin:.4f} margin) is the UNKNOWN world "
            f"{leader.mechanism_id!r}; leading with novelty is not identifying a mechanism"
        ),
        leading_mechanism_id=leader.mechanism_id,
    )


def _not_attempted(plan: ObservationPlan) -> bool:
    """True when the plan refused anything for a wiring reason (see active_plan)."""
    not_attempted = getattr(plan, "not_attempted", None)
    return bool(not_attempted()) if callable(not_attempted) else False


def _identified_verdict(
    ranked: Sequence[SecurityWorldV1],
    raw_margin: float,
    effective_margin: float,
    shadow_penalty: float,
) -> IdentifiabilityVerdict:
    leader = ranked[0]
    return IdentifiabilityVerdict(
        state=IdentifiabilityState.IDENTIFIED,
        leading_world_id=leader.world_id,
        support_margin=raw_margin,
        material_alternatives=tuple(sorted(w.world_id for w in ranked[1:])),
        discriminating_observations=(),
        affordable=True,
        shadow_penalty=shadow_penalty,
        detail=(
            f"support margin {raw_margin:.4f} less shadow penalty {shadow_penalty:.4f} "
            f"= {effective_margin:.4f} >= IDENTIFIABILITY_MARGIN {IDENTIFIABILITY_MARGIN}"
        ),
        leading_mechanism_id=leader.mechanism_id,
    )


#: Why an INSUFFICIENT_EVIDENCE verdict was not UNIDENTIFIABLE, per cause.
_NO_PLAN = "no observation plan was computed"
_LONE_WORLD = "a single surviving world whose own support has not cleared the margin"
_NOT_WIRED = (
    "the planner refused the discriminating actions for a wiring reason (no observation "
    "policy, or an unmeasured or non-positive cost), not for lack of discrimination"
)


def _unplanned_verdict(
    leader: SecurityWorldV1,
    alternatives: Sequence[str],
    raw_margin: float,
    shadow_penalty: float,
    why: str = _NO_PLAN,
) -> IdentifiabilityVerdict:
    """Not established by looking. INSUFFICIENT_EVIDENCE, deliberately not UNIDENTIFIABLE."""
    return IdentifiabilityVerdict(
        state=IdentifiabilityState.INSUFFICIENT_EVIDENCE,
        leading_world_id=leader.world_id,
        support_margin=raw_margin,
        material_alternatives=tuple(alternatives),
        discriminating_observations=(),
        affordable=False,
        shadow_penalty=shadow_penalty,
        detail=(
            f"support margin {raw_margin:.4f} below IDENTIFIABILITY_MARGIN "
            f"{IDENTIFIABILITY_MARGIN} and {why}; "
            "non-identifiability is not established by failing to look"
        ),
        leading_mechanism_id=leader.mechanism_id,
    )


def _separable_verdict(
    leader: SecurityWorldV1,
    alternatives: Sequence[str],
    raw_margin: float,
    shadow_penalty: float,
    plan: ObservationPlan,
    discriminating: tuple[str, ...],
) -> IdentifiabilityVerdict:
    best = plan.best()
    affordable = bool(best is not None and best.worth_spending())
    return IdentifiabilityVerdict(
        state=IdentifiabilityState.INSUFFICIENT_EVIDENCE,
        leading_world_id=leader.world_id,
        support_margin=raw_margin,
        material_alternatives=tuple(alternatives),
        discriminating_observations=discriminating,
        affordable=affordable,
        shadow_penalty=shadow_penalty,
        detail=(
            f"support margin {raw_margin:.4f} below IDENTIFIABILITY_MARGIN "
            f"{IDENTIFIABILITY_MARGIN}; {len(discriminating)} discriminating "
            f"observation(s) available, affordable={affordable}"
        ),
        leading_mechanism_id=leader.mechanism_id,
    )


def _unidentifiable_verdict(
    leader: SecurityWorldV1,
    alternatives: Sequence[str],
    raw_margin: float,
    shadow_penalty: float,
    plan: ObservationPlan,
) -> IdentifiabilityVerdict:
    """The planner ran and every candidate was refused. This is the real thing."""
    refusals = tuple(getattr(plan, "refused", ()))
    return IdentifiabilityVerdict(
        state=IdentifiabilityState.UNIDENTIFIABLE,
        leading_world_id=leader.world_id,
        support_margin=raw_margin,
        material_alternatives=tuple(alternatives),
        discriminating_observations=(),
        affordable=False,
        shadow_penalty=shadow_penalty,
        detail=(
            f"support margin {raw_margin:.4f} below IDENTIFIABILITY_MARGIN "
            f"{IDENTIFIABILITY_MARGIN}; all {len(refusals)} candidate observation(s) "
            "refused, so no affordable observation separates the leaders"
        ),
        leading_mechanism_id=leader.mechanism_id,
    )


# --- helpers ----------------------------------------------------------------


def _shadow_penalty(shadow: SensorShadow | None) -> float:
    """Read the shadow's confidence penalty, clamped into [0, 1].

    A missing shadow contributes 0.0 and not some "unknown" default: the shadow is
    Stage 4's model of what it could not see, and a field with no shadow has made no
    claim about blindness. The penalty is *subtracted* from the margin below, so a
    larger blind region makes identification strictly harder — never easier.
    """
    if shadow is None:
        return 0.0
    penalty = float(shadow.confidence_penalty())
    return max(0.0, min(1.0, penalty))


def _rank(
    worlds: Sequence[SecurityWorldV1], support: Mapping[str, float]
) -> tuple[SecurityWorldV1, ...]:
    """Order worlds by support, descending, with a deterministic id tie-break."""
    return tuple(
        sorted(worlds, key=lambda w: (-float(support.get(w.world_id, 0.0)), w.world_id))
    )


def self_margin(world: SecurityWorldV1) -> float:
    """A lone world's margin against "not this world", from its OWN support.

    The first version returned 1.0 whenever there was no runner-up, so a field
    pruned or killed down to one world was IDENTIFIED with a committal verdict
    whatever that world's support said — including a world at log-odds -32
    (S4-REV-05 / S4-FC-06). Here the world's support is read as a share against its
    complement and the margin is ``2*share - 1``, so even odds give 0.0 and only
    support that actually favours the world clears ``IDENTIFIABILITY_MARGIN``.

    **A comparison on the support scale, not a probability claim** — the same
    status ``support_vector`` has. The share is the probability itself for a
    normalising geometry, the logistic of the point (or of the interval's LOWER end)
    for additive ones, and ``e / (1 + e)`` for an e-value, whose neutral value is 1.
    """
    support = world.support
    probability = support.as_probability()
    if probability is not None:
        share = float(probability)
    elif getattr(support.geometry, "value", "") == "E_VALUE":
        share = float(support.value) / (1.0 + float(support.value))
    else:
        interval = getattr(support, "interval", None)
        point = float(interval[0]) if interval is not None else float(support.value)
        share = 1.0 / (1.0 + math.exp(-point))
    return max(0.0, min(1.0, 2.0 * share - 1.0))


def _margin(
    support: Mapping[str, float],
    leader: SecurityWorldV1,
    runner_up: SecurityWorldV1 | None,
) -> float:
    if runner_up is None:
        return self_margin(leader)
    gap = float(support.get(leader.world_id, 0.0)) - float(support.get(runner_up.world_id, 0.0))
    return max(0.0, min(1.0, gap))


def _contenders(
    ranked: Sequence[SecurityWorldV1], support: Mapping[str, float]
) -> tuple[SecurityWorldV1, ...]:
    """Worlds within one margin of the top. These are the ones still in the race."""
    top = float(support.get(ranked[0].world_id, 0.0))
    return tuple(
        w for w in ranked if top - float(support.get(w.world_id, 0.0)) <= IDENTIFIABILITY_MARGIN
    )


def _least_alarming(contenders: Sequence[SecurityWorldV1]) -> SecurityWorldV1:
    """Pick the contender with the lowest consequence.

    This is the anti-alarm tie-break, and it is a security decision rather than a
    numerical convenience. When the evidence cannot separate two explanations, naming
    the scarier one as "leading" converts ignorance into a threat report. The system
    is allowed to say it does not know; it is not allowed to guess upwards.
    """
    return min(contenders, key=lambda w: (float(w.latent_state.consequence), w.world_id))
