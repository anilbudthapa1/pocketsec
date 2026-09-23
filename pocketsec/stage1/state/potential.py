"""D1.5 — the Security Potential function Φ(S) (spec section 6).

Static per-event severity is insufficient: individually legitimate capabilities
become dangerous *in combination*. Reading a credential file is routine for a
backup job. Reading one as root, from a process that also holds external
reachability, is the shape of exfiltration.

    ΔΦ_t = Φ(S_{t+1}) - Φ(S_t)

Φ is **not** a threat score and must never be treated as one. It is one of three
independent signals (novelty N, potential Φ, confidence U) that the spec
explicitly requires to stay separate.

Every weight here is an explicit, documented monotonic rule, not a tuned
constant. The Stage 1 research question is whether *composition* beats summing
independent event severities — which only means something if the composition is
legible enough to argue about. The calibration report (`calibrate`) measures the
separation these weights actually achieve rather than asserting it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pocketsec.stage1.state.security_state import (
    CredentialExposure,
    Persistence,
    Privilege,
    Reachability,
    SecurityStateV1,
)

__all__ = ["BASE_WEIGHTS", "INTERACTIONS", "PhiBreakdown", "calibrate", "delta_phi", "phi"]


#: Per-dimension base contribution per lattice step. Deliberately modest: the
#: hypothesis under test is that interactions, not base severities, carry the
#: signal. If base weights dominated, Φ would just be a severity sum wearing a
#: different hat.
BASE_WEIGHTS: dict[str, float] = {
    "privilege": 1.0,
    "trust": 0.5,
    "credential": 1.0,
    "reachability": 0.75,
    "persistence": 1.0,
    "execution": 0.5,
    "modification": 0.75,
    "discovery": 0.5,
    "isolation": 1.0,
}


@dataclass(frozen=True, slots=True)
class Interaction:
    """A named combination that is worth more than the sum of its parts."""

    name: str
    weight: float
    rationale: str


#: Interaction terms. Each is a security argument, not a fitted parameter, and
#: each is evaluated by a dedicated predicate below.
INTERACTIONS: tuple[Interaction, ...] = (
    Interaction(
        "exfiltration_triad",
        4.0,
        "credential access + external reachability + elevated privilege: the "
        "capability set required to take secrets off the host",
    ),
    Interaction(
        "privileged_credential_access",
        2.0,
        "root or elevated privilege combined with readable/extracted credentials",
    ),
    Interaction(
        "credential_egress",
        2.5,
        "credential exposure combined with external reachability, regardless of "
        "privilege: an unprivileged process can still exfiltrate what it can read",
    ),
    Interaction(
        "privileged_persistence",
        2.0,
        "elevated privilege plus service/boot persistence: survives reboot with authority",
    ),
    Interaction(
        "boundary_escape",
        2.0,
        "boundary crossing combined with elevated privilege: container or namespace escape",
    ),
    Interaction(
        "discovery_to_credential",
        1.0,
        "system/credential discovery followed by credential access: targeted rather "
        "than incidental",
    ),
)


def _exfiltration_triad(state: SecurityStateV1) -> bool:
    return (
        state.credential >= CredentialExposure.READABLE
        and state.reachability >= Reachability.EXTERNAL
        and state.privilege >= Privilege.ELEVATED
    )


def _privileged_credential_access(state: SecurityStateV1) -> bool:
    return (
        state.privilege >= Privilege.ELEVATED
        and state.credential >= CredentialExposure.READABLE
    )


def _credential_egress(state: SecurityStateV1) -> bool:
    return (
        state.credential >= CredentialExposure.READABLE
        and state.reachability >= Reachability.EXTERNAL
    )


def _privileged_persistence(state: SecurityStateV1) -> bool:
    return state.privilege >= Privilege.ELEVATED and state.persistence >= Persistence.SERVICE


def _boundary_escape(state: SecurityStateV1) -> bool:
    return state.isolation >= 2 and state.privilege >= Privilege.ELEVATED  # noqa: PLR2004


def _discovery_to_credential(state: SecurityStateV1) -> bool:
    return state.discovery >= 2 and state.credential >= CredentialExposure.READABLE  # noqa: PLR2004


_PREDICATES = {
    "exfiltration_triad": _exfiltration_triad,
    "privileged_credential_access": _privileged_credential_access,
    "credential_egress": _credential_egress,
    "privileged_persistence": _privileged_persistence,
    "boundary_escape": _boundary_escape,
    "discovery_to_credential": _discovery_to_credential,
}


@dataclass(frozen=True, slots=True)
class PhiBreakdown:
    """Φ with its reasoning attached.

    Φ is never reported as a bare number. An unexplainable potential score is
    indistinguishable from an arbitrary weight, which the spec forbids.
    """

    total: float
    base: float
    base_terms: dict[str, float]
    active_interactions: tuple[str, ...]
    interaction_total: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "total": round(self.total, 4),
            "base": round(self.base, 4),
            "base_terms": {k: round(v, 4) for k, v in self.base_terms.items()},
            "active_interactions": list(self.active_interactions),
            "interaction_total": round(self.interaction_total, 4),
        }


def phi(state: SecurityStateV1) -> PhiBreakdown:
    """Compute Φ(S) with a full breakdown."""
    base_terms = {
        name: BASE_WEIGHTS[name] * state.level(name)
        for name in BASE_WEIGHTS
        if state.level(name) > 0
    }
    base = sum(base_terms.values())

    active: list[str] = []
    interaction_total = 0.0
    for interaction in INTERACTIONS:
        if _PREDICATES[interaction.name](state):
            active.append(interaction.name)
            interaction_total += interaction.weight

    return PhiBreakdown(
        total=base + interaction_total,
        base=base,
        base_terms=base_terms,
        active_interactions=tuple(active),
        interaction_total=interaction_total,
    )


def delta_phi(previous: SecurityStateV1, current: SecurityStateV1) -> float:
    """ΔΦ — how much the security potential moved."""
    return phi(current).total - phi(previous).total


# --- calibration -------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CalibrationReport:
    """D1.5 calibration: does composition separate better than a severity sum?

    Compares Φ against a *compositionless* control — the same base weights with
    every interaction term removed — over labelled states. Reported as a
    measured separation, never asserted.
    """

    sample_count: int
    benign_mean_phi: float
    malicious_mean_phi: float
    separation: float
    additive_separation: float
    composition_gain: float
    notes: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "sample_count": self.sample_count,
            "benign_mean_phi": round(self.benign_mean_phi, 4),
            "malicious_mean_phi": round(self.malicious_mean_phi, 4),
            "separation": round(self.separation, 4),
            "additive_separation": round(self.additive_separation, 4),
            "composition_gain": round(self.composition_gain, 4),
            "notes": self.notes,
        }


def _additive_only(state: SecurityStateV1) -> float:
    """The control: base weights, no interaction terms."""
    return sum(BASE_WEIGHTS[name] * state.level(name) for name in BASE_WEIGHTS)


def calibrate(labelled: list[tuple[SecurityStateV1, int]]) -> CalibrationReport:
    """Measure Φ's separation against the additive control.

    ``composition_gain`` > 0 means interaction terms widened the gap between
    benign and malicious states beyond what summing severities achieves. A
    value <= 0 is a real result and must be reported as one, not tuned away.
    """
    benign = [state for state, label in labelled if label == 0]
    malicious = [state for state, label in labelled if label == 1]
    if not benign or not malicious:
        return CalibrationReport(
            sample_count=len(labelled),
            benign_mean_phi=0.0,
            malicious_mean_phi=0.0,
            separation=0.0,
            additive_separation=0.0,
            composition_gain=0.0,
            notes="insufficient labels: need both benign and malicious states",
        )

    def mean(values: list[float]) -> float:
        return sum(values) / len(values)

    benign_phi = mean([phi(state).total for state in benign])
    malicious_phi = mean([phi(state).total for state in malicious])
    benign_add = mean([_additive_only(state) for state in benign])
    malicious_add = mean([_additive_only(state) for state in malicious])

    separation = malicious_phi - benign_phi
    additive_separation = malicious_add - benign_add
    return CalibrationReport(
        sample_count=len(labelled),
        benign_mean_phi=benign_phi,
        malicious_mean_phi=malicious_phi,
        separation=separation,
        additive_separation=additive_separation,
        composition_gain=separation - additive_separation,
        notes=(
            "Composition gain is the margin interaction terms add over an "
            "additive severity sum on identical states."
        ),
    )
