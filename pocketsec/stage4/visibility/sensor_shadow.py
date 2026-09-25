"""D4.3 (part) — the Sensor Shadow: what PocketSec could not observe.

Architecture §6::

    Shadow_t = PotentialSecurityEvidence - ObservableEvidence(A_t, kernel,
                                                              privileges, dropped_events)

Every inference carries its shadow, and the shadow *modifies confidence*. This
module exists so that "we did not see it" is a first-class, weighted,
auditable object rather than a silence in the evidence.

Three properties are enforced here rather than hoped for:

1. **A mandatory signal can never be shadowed.** ``ShadowRegion.__post_init__``
   refuses one. ``policy.py:47`` says AOP may add observation and may never take
   a mandatory signal away; if the shadow could mark ``privilege_change`` blind,
   the whole Stage 1 guarantee would be quietly negotiable from Stage 4.
2. **:meth:`SensorShadow.confidence_penalty` is monotone in the shadow.** Adding
   a region can never lower the penalty. It is a product of per-region survival
   factors, so the bound holds for every region set rather than for the ones a
   test happens to try.
3. **Confidence may never benefit from not having looked** (falsifier F4, the
   most dangerous single failure available to this stage).
   :func:`visibility_adjusted_confidence` is built so that a lost expected
   signal collapses confidence to zero instead of letting a shorter, cleaner
   evidence set look more certain. See that function's docstring for the measured
   reason it is shaped that way.

``MAX_REGION_PENALTY``, ``TRUNCATION_PENALTY`` and the region ordering are
**chosen parameters, not measured ones**, and are declared as such in the
findings document (spec §9.11).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from pocketsec.stage0.contracts.common import (
    ContractError,
    require_finite_unit_interval,
    require_identifier,
)
from pocketsec.stage0.contracts.threat_prediction_v1 import NON_COMMITTAL_VERDICTS, Verdict
from pocketsec.stage1.observation.policy import MANDATORY_SIGNALS, ObservationLevel
from pocketsec.stage1.ssir.transition import SSIRTransitionV1
from pocketsec.stage1.state.potential import BASE_WEIGHTS
from pocketsec.stage1.telemetry.raw_event_v1 import SensorPath
from pocketsec.stage4.visibility.model import (
    VisibilityModel,
    best_visibility,
    signal_dimensions,
    signals_of_transition,
)

__all__ = [
    "ALWAYS_OBSERVED",
    "MAX_REGION_PENALTY",
    "MAX_SHADOW_REGIONS",
    "SHADOW_REASONS",
    "TRUNCATION_PENALTY",
    "SensorShadow",
    "ShadowRegion",
    "consequence_weight",
    "estimate_sensor_shadow",
    "verdict_committal_rank",
    "visibility_adjusted_confidence",
    "visibility_adjusted_verdict",
]

#: Hard bound (spec D4.3, architecture §6). Hitting it sets ``truncated`` and
#: names what was lost; a silent drop is a defect.
MAX_SHADOW_REGIONS: int = 32

#: The four reasons a region may exist. A closed set: an unrecognised reason is
#: refused rather than stored, so nobody can widen the vocabulary by typo.
SHADOW_REASONS: frozenset[str] = frozenset(
    {
        "sensor_path_dropped",
        "below_observation_level",
        "no_visibility_evidence",
        "observation_incomplete",
    }
)

#: Ceiling on one region's contribution to the confidence penalty. A single
#: blind spot must not be able to zero out confidence on its own: that would
#: make the penalty a switch rather than a measure, and would hide the
#: difference between one hole and twelve. Chosen parameter.
MAX_REGION_PENALTY: float = 0.5

#: Additional survival factor applied when the region list was truncated. Losing
#: regions to a bound means the shadow is *understated*, so the penalty must not
#: fall when that happens. Chosen parameter.
TRUNCATION_PENALTY: float = 0.25

#: The measured frequency at which a signal counts as collected at BASELINE.
#: Exactly 1.0, deliberately: ``policy.collects`` guarantees only mandatory
#: signals at BASELINE, so an optional signal earns its way out of the shadow
#: only by having been observed on *every* occurrence in the replay evidence.
ALWAYS_OBSERVED: float = 1.0

_PHI_WEIGHT_TOTAL: float = sum(BASE_WEIGHTS.values())

#: Committal ordering over ``Verdict``. Only used to assert that a verdict never
#: becomes *more* committal as visibility falls; it is not a severity scale and
#: must never be read as one.
_COMMITTAL_RANK: Mapping[str, int] = {
    Verdict.INSUFFICIENT_EVIDENCE.value: 0,
    Verdict.UNIDENTIFIABLE.value: 0,
    Verdict.UNKNOWN.value: 0,
    Verdict.BENIGN.value: 1,
    Verdict.SUSPICIOUS.value: 1,
    Verdict.MALICIOUS.value: 1,
}


def verdict_committal_rank(verdict: Verdict) -> int:
    """0 for a non-committal verdict, 1 for a committal one."""
    return _COMMITTAL_RANK[Verdict(verdict).value]


def consequence_weight(signal: str) -> float:
    """Φ weight of the dimensions ``signal`` could have raised, normalised.

    The weights are Stage 1's own ``BASE_WEIGHTS`` (``potential.py:41``), not new
    constants: the cost of a blind spot is the consequence of the capability it
    could have hidden, and Stage 1 already argued those weights out loud.
    Normalised by the total so the value lands in [0, 1] and can multiply.
    """
    dimensions = signal_dimensions(signal)
    if not dimensions:
        return 0.0
    weight = sum(BASE_WEIGHTS[name] for name in dimensions if name in BASE_WEIGHTS)
    return min(1.0, weight / _PHI_WEIGHT_TOTAL)


@dataclass(frozen=True, slots=True)
class ShadowRegion:
    """One signal that could have carried security evidence and could not be seen."""

    signal: str
    sensors_blind: tuple[SensorPath, ...]
    reason: str
    consequence_weight: float

    def __post_init__(self) -> None:
        require_identifier(self.signal, "ShadowRegion.signal")
        require_finite_unit_interval(self.consequence_weight, "ShadowRegion.consequence_weight")
        if self.reason not in SHADOW_REASONS:
            raise ContractError(
                f"ShadowRegion.reason must be one of {sorted(SHADOW_REASONS)}, got {self.reason!r}"
            )
        if self.signal in MANDATORY_SIGNALS:
            raise ContractError(
                f"refusing to shadow mandatory signal {self.signal!r}: AOP may never "
                "disable it (policy.py:47), so it cannot be unobservable"
            )
        blind = tuple(SensorPath(sensor) for sensor in self.sensors_blind)
        if not blind:
            raise ContractError("ShadowRegion.sensors_blind must name at least one path")
        object.__setattr__(self, "sensors_blind", blind)

    @property
    def penalty_term(self) -> float:
        """This region's contribution, capped by ``MAX_REGION_PENALTY``."""
        return min(MAX_REGION_PENALTY, self.consequence_weight)

    def to_dict(self) -> dict[str, Any]:
        return {
            "signal": self.signal,
            "sensors_blind": [sensor.value for sensor in self.sensors_blind],
            "reason": self.reason,
            "consequence_weight": round(self.consequence_weight, 4),
        }


@dataclass(frozen=True, slots=True)
class SensorShadow:
    """Shadow_t = PotentialSecurityEvidence - ObservableEvidence (§6).

    ``truncated_signals`` is beyond the spec's two fields and has a default, so
    existing keyword construction is unaffected. It exists because the bound rule
    says *a silent drop is a defect*: ``truncated=True`` alone says something was
    lost but not what, which is exactly the shape of record this project has
    already been burned by.
    """

    regions: tuple[ShadowRegion, ...]
    truncated: bool
    truncated_signals: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        regions = tuple(self.regions)
        if len(regions) > MAX_SHADOW_REGIONS:
            raise ContractError(
                f"SensorShadow holds {len(regions)} regions, bound is {MAX_SHADOW_REGIONS}"
            )
        seen: set[tuple[str, str]] = set()
        for region in regions:
            if not isinstance(region, ShadowRegion):
                raise ContractError("SensorShadow.regions must hold ShadowRegion values")
            key = (region.signal, region.reason)
            if key in seen:
                raise ContractError(f"duplicate shadow region for {key!r}")
            seen.add(key)
        object.__setattr__(self, "regions", regions)
        object.__setattr__(self, "truncated", bool(self.truncated))
        object.__setattr__(self, "truncated_signals", tuple(self.truncated_signals))
        if self.truncated_signals and not self.truncated:
            raise ContractError("truncated_signals were recorded but truncated is False")

    def confidence_penalty(self) -> float:
        """Confidence lost to the shadow, in [0, 1].

        Monotone in the region set by construction: the penalty is one minus a
        product of survival factors in (0, 1], so adding a region multiplies the
        survival by at most 1 and the penalty can only rise or stay level.
        """
        survival = 1.0
        for region in self.regions:
            survival *= 1.0 - region.penalty_term
        if self.truncated:
            survival *= 1.0 - TRUNCATION_PENALTY
        return max(0.0, min(1.0, 1.0 - survival))

    def covers(self, signal: str) -> bool:
        return any(region.signal == signal for region in self.regions)

    def blind_signals(self) -> frozenset[str]:
        return frozenset(region.signal for region in self.regions)

    def to_dict(self) -> dict[str, Any]:
        return {
            "regions": [region.to_dict() for region in self.regions],
            "truncated": self.truncated,
            "truncated_signals": list(self.truncated_signals),
            "confidence_penalty": round(self.confidence_penalty(), 4),
        }


def _region_for_expected(model: VisibilityModel, signal: str) -> ShadowRegion | None:
    """The single strongest reason ``signal`` is unobservable, or ``None``.

    Precedence is deliberate and is the order of how little we know: no evidence
    at all beats a dropped path, which beats a collection level that does not
    guarantee the signal. Reporting the weaker reason would understate the gap.
    """
    if signal in MANDATORY_SIGNALS:
        return None
    weight = consequence_weight(signal)
    evidenced = model.evidenced_sensors(signal)
    if not evidenced:
        return ShadowRegion(
            signal=signal,
            sensors_blind=tuple(SensorPath),
            reason="no_visibility_evidence",
            consequence_weight=weight,
        )
    live = model.observable_sensors(signal)
    if not live:
        return ShadowRegion(
            signal=signal,
            sensors_blind=evidenced,
            reason="sensor_path_dropped",
            consequence_weight=weight,
        )
    best = best_visibility(model, signal)
    if model.level is ObservationLevel.BASELINE and (best is None or best < ALWAYS_OBSERVED):
        return ShadowRegion(
            signal=signal,
            sensors_blind=live,
            reason="below_observation_level",
            consequence_weight=weight,
        )
    return None


_SENSOR_VALUES: frozenset[str] = frozenset(path.value for path in SensorPath)


def _sensors_of_transition(transition: SSIRTransitionV1) -> tuple[SensorPath, ...]:
    """Which paths contributed evidence, read off the evidence store names.

    ``RawEventV1.evidence_ref`` sets ``store="raw.<sensor>"``, so the path is
    recoverable from lineage without Stage 4 keeping its own copy of it. An
    unrecognised store name yields every path, which overstates the blindness
    rather than understating it.
    """
    found = {
        ref.store.rsplit(".", 1)[-1]
        for ref in transition.evidence
        if ref.store.rsplit(".", 1)[-1] in _SENSOR_VALUES
    }
    if not found:
        return tuple(SensorPath)
    return tuple(SensorPath(value) for value in sorted(found))


def _incomplete_regions(transitions: Sequence[SSIRTransitionV1]) -> list[ShadowRegion]:
    """Regions from Stage 1's own ``observation_incomplete`` flag.

    Used directly rather than re-derived: Stage 1 already decided that fusion was
    partial or that sensors disagreed, and second-guessing that here would mean
    two subsystems holding different views of the same event.
    """
    regions: list[ShadowRegion] = []
    seen: set[str] = set()
    for transition in transitions:
        if not transition.observation_incomplete:
            continue
        blind = _sensors_of_transition(transition)
        for signal in sorted(signals_of_transition(transition)):
            if signal in MANDATORY_SIGNALS or signal in seen:
                continue
            seen.add(signal)
            regions.append(
                ShadowRegion(
                    signal=signal,
                    sensors_blind=blind,
                    reason="observation_incomplete",
                    consequence_weight=consequence_weight(signal),
                )
            )
    return regions


def estimate_sensor_shadow(
    model: VisibilityModel,
    *,
    expected: Sequence[str],
    transitions: Sequence[SSIRTransitionV1],
) -> SensorShadow:
    """CBF-F06 — the shadow over an incident's expected evidence.

    ``expected`` is the drop-invariant set of signals the incident's worlds
    depend on seeing. Walking it (rather than walking what arrived) is the point:
    a shadow derived from observed evidence could never contain the evidence that
    never arrived.
    """
    candidates: list[ShadowRegion] = []
    seen: set[tuple[str, str]] = set()
    for signal in sorted(dict.fromkeys(expected)):
        region = _region_for_expected(model, signal)
        if region is not None and (region.signal, region.reason) not in seen:
            seen.add((region.signal, region.reason))
            candidates.append(region)
    for region in _incomplete_regions(transitions):
        if (region.signal, region.reason) not in seen:
            seen.add((region.signal, region.reason))
            candidates.append(region)

    # Heaviest consequence first, then alphabetically, so truncation loses the
    # least consequential holes and the result is reproducible run to run.
    candidates.sort(key=lambda r: (-r.consequence_weight, r.signal, r.reason))
    kept = candidates[:MAX_SHADOW_REGIONS]
    lost = candidates[MAX_SHADOW_REGIONS:]
    return SensorShadow(
        regions=tuple(kept),
        truncated=bool(lost),
        truncated_signals=tuple(sorted({region.signal for region in lost})),
    )


def visibility_adjusted_confidence(
    *,
    raw_confidence: float,
    expected: frozenset[str],
    observed: frozenset[str],
    shadow: SensorShadow,
    model: VisibilityModel,
) -> float:
    """Confidence after the shadow, built so it can never rise on a sensor loss.

    Falsifier F4 is the whole reason this function exists. Measured on this
    repository's eval corpus: Stage 1's ``peak_uncertainty`` is a *maximum* over
    the transitions that arrived, so removing a sensor's events removes
    uncertainty contributions and the raw confidence ``1 - peak_uncertainty``
    **rises** under a drop. Any design that passes that number through is unsafe.

    The construction therefore treats an expected signal we did not see, and
    cannot show we would have seen, as disqualifying rather than as absent data:

    * an expected signal missing whose visibility is measured at or above
      ``ALWAYS_OBSERVED`` on a live path is *informative absence* — real evidence,
      and it does not reduce confidence here (the tension engine scores it);
    * any other missing expected signal, and any expected signal the shadow
      covers, is an **unknown hole**, and one unknown hole yields confidence 0.

    Monotone under a drop because dropping a path can only shrink ``observed``
    and only grow the shadow, so the hole set can only grow.
    """
    ceiling = 1.0 - shadow.confidence_penalty()
    holes = _unknown_holes(expected=expected, observed=observed, shadow=shadow, model=model)
    if holes:
        return 0.0
    bounded = max(0.0, min(1.0, float(raw_confidence)))
    return max(0.0, min(bounded, ceiling))


def _unknown_holes(
    *,
    expected: frozenset[str],
    observed: frozenset[str],
    shadow: SensorShadow,
    model: VisibilityModel,
) -> tuple[str, ...]:
    """Expected signals whose absence teaches nothing, plus shadowed expectations."""
    holes: list[str] = []
    for signal in sorted(expected):
        if shadow.covers(signal):
            holes.append(signal)
            continue
        if signal in observed:
            continue
        best = best_visibility(model, signal)
        if best is None or best < ALWAYS_OBSERVED:
            holes.append(signal)
    return tuple(holes)


def visibility_adjusted_verdict(proposed: Verdict, shadow: SensorShadow) -> Verdict:
    """Downgrade a committal verdict the shadow cannot support. Never upgrades.

    A non-committal verdict is returned untouched: the shadow's job is to stop a
    confident answer that the evidence could not have justified, not to invent
    one. ``INSUFFICIENT_EVIDENCE`` is Stage 1's existing vocabulary and Stage 4
    mints no parallel term (ADR-0032).

    The trigger is ``confidence_penalty() > 0`` rather than a chosen threshold,
    and that is not as blunt as it looks: a region over a signal that could have
    raised no lattice dimension carries ``consequence_weight == 0`` and leaves the
    penalty at zero. Consequence is already inside the penalty, so no second
    fabricated constant is needed to decide when a hole matters.
    """
    verdict = Verdict(proposed)
    if verdict in NON_COMMITTAL_VERDICTS:
        return verdict
    if shadow.confidence_penalty() > 0.0:
        return Verdict.INSUFFICIENT_EVIDENCE
    return verdict
