"""D4.1 (continued) — ``SecurityWorldV1``: one competing explanation of the host.

This is the atom of Stage 4. A world is a *latent* claim — "the host is in this
security state because this mechanism ran" — together with what that claim makes
observable (``expected_evidence``), what it makes impossible
(``forbidden_evidence``) and what it needs to have been able to see
(``visibility_requirements``). The useful intelligence is in the differences
between worlds, so everything here exists to keep those differences explicit and
comparable.

What this module refuses to do, by construction rather than by convention:

* **It refuses a self-contradicting world.** ``expected_evidence`` and
  ``forbidden_evidence`` may not intersect. A world that both predicts and
  forbids a signal can never be falsified by that signal, which makes it
  unkillable — and an unkillable world is a story, not a hypothesis.
* **It refuses a world that overstates its own consequence.**
  ``LatentSecurityState.consequence`` must equal ``phi(state).total``, and every
  asserted dimension must actually be raised in the state it wraps. That is §21
  (semantic conservation) made mechanical: abstraction is allowed, factual
  amplification is not.
* **It refuses to read a log-odds as a probability.** ``WorldSupport`` carries its
  geometry, and ``as_probability()`` returns ``None`` for every representation
  that does not legitimately normalise (§11).
* **It refuses an authority-named field**, via the local
  :func:`authority_named_fields` audit (trust rule T5, ADR-0003). Stage 4 has its
  own copy because it imports nothing from Stage 3 (spec §2.5).
* **It refuses to grow.** ``state_bytes() <= MAX_WORLD_BYTES`` is checked at
  construction, so "KB-scale per world" (§44) is a property of the type rather
  than a hope about callers.

``mechanism_id`` is a *semantic* descriptor — ``"compromised_admin_session"`` —
never a technique name and never an ATT&CK id. External knowledge constrains and
names behaviour; it does not decide the world (§33).
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, fields as dataclass_fields
from enum import StrEnum
from typing import TYPE_CHECKING, Any, Protocol

from pocketsec.stage0.contracts.common import (
    ContractError,
    EvidenceRef,
    register_schema,
    require_finite_unit_interval,
    require_identifier,
    require_non_negative_int,
)
from pocketsec.stage0.contracts.threat_prediction_v1 import FORBIDDEN_AUTHORITY_FIELDS
from pocketsec.stage1.state.potential import phi
from pocketsec.stage1.state.security_state import DIMENSIONS, SecurityStateV1

if TYPE_CHECKING:  # pragma: no cover - typing only
    from collections.abc import Iterable, Mapping

__all__ = [
    "BeliefGeometry",
    "LatentSecurityState",
    "MAX_EXPECTED_SIGNALS",
    "MAX_FORBIDDEN_SIGNALS",
    "MAX_LOG_ODDS",
    "MAX_WORLD_BYTES",
    "MAX_WORLD_FISSION_DEPTH",
    "SECURITY_WORLD_V1_ID",
    "SECURITY_WORLD_V1_VERSION",
    "SecurityWorldV1",
    "TensionLike",
    "WorldSupport",
    "WorldSupportState",
    "authority_named_fields",
    "canonical_bytes",
]

SECURITY_WORLD_V1_ID = "pocketsec.security_world.v1"
SECURITY_WORLD_V1_VERSION = register_schema(SECURITY_WORLD_V1_ID, "1.0.0")

#: §44, "KB-scale/world, not model-context-scale". Measured as the length of the
#: world's canonical JSON, which is also what the Stage 5 seam will persist, so
#: the bound is on the thing that actually costs bytes.
MAX_WORLD_BYTES: int = 8192

MAX_EXPECTED_SIGNALS: int = 32
MAX_FORBIDDEN_SIGNALS: int = 16

#: §14 caps fission at depth 2. ``worlds/lifecycle.py`` owns ``MAX_FISSION_DEPTH``
#: and importing it here would close a cycle (lifecycle needs this module), so
#: the constructor-side bound lives here under its own name. The two are pinned
#: to each other by a test in ``tests/test_stage4_foundation.py`` as soon as
#: ``lifecycle`` exists, rather than left to agree by coincidence.
MAX_WORLD_FISSION_DEPTH: int = 2

#: Support magnitude bound. At |log-odds| = 32 the implied probability is within
#: 1.3e-14 of 0 or 1, so clamping here costs nothing a float could represent as a
#: decision, while keeping ``combine()`` closed over finite values. An unbounded
#: accumulator is how a flood turns support into ``inf`` and every comparison
#: into ``nan``.
MAX_LOG_ODDS: float = 32.0


class WorldSupportState(StrEnum):
    """§2: worlds may split, merge, crystallize, collapse or remain unresolved."""

    PROVISIONAL = "PROVISIONAL"
    SUPPORTED = "SUPPORTED"
    CRYSTALLIZED = "CRYSTALLIZED"
    COLLAPSING = "COLLAPSING"
    UNRESOLVED = "UNRESOLVED"


class BeliefGeometry(StrEnum):
    """§11: the representation is selected empirically, so it is recorded.

    Whichever geometry is in use travels with the value. Nobody downstream can
    then read a log-odds, an e-value or an interval midpoint as a probability,
    which is the specific mistake §11 exists to prevent.
    """

    LOG_ODDS = "LOG_ODDS"
    CALIBRATED_PROBABILITY = "CALIBRATED_PROBABILITY"
    EVIDENCE_INTERVAL = "EVIDENCE_INTERVAL"
    E_VALUE = "E_VALUE"


#: Geometries whose scalar is a probability. The set is a single-element tuple on
#: purpose: it is the only place in Stage 4 where "this number is a probability"
#: is written down, and it is short enough to audit by eye.
NORMALISING_GEOMETRIES = (BeliefGeometry.CALIBRATED_PROBABILITY,)


def canonical_bytes(payload: Mapping[str, Any]) -> bytes:
    """Deterministic JSON bytes — the substrate of every byte bound and digest."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


class TensionLike(Protocol):
    """The slice of ``tension.evidence_tension.EvidenceTension`` a world needs.

    A structural type rather than an import: ``tension/`` is built by a later
    work package that depends on this one, and a runtime import from foundation
    up into a consumer would be a dependency cycle. The Protocol is the contract
    both sides are held to, and it names only the three members this module
    touches — ``total`` for ordering, ``is_fatal()`` for the death test,
    ``to_dict()`` for the byte bound.
    """

    @property
    def total(self) -> float: ...

    def is_fatal(self) -> bool: ...

    def to_dict(self) -> dict[str, Any]: ...


def authority_named_fields(cls: type) -> tuple[str, ...]:
    """Dataclass fields whose lowered name contains a ``FORBIDDEN_AUTHORITY_FIELDS`` token.

    Trust rule T5 / ADR-0003: no model output carries response authority. Stage 4
    feels this harder than any other stage — the architecture's own §9 writes
    ``do(block privilege transition)`` and both ``block`` and ``privilege`` are
    forbidden tokens — so the audit runs on every world construction instead of
    being left to review.

    **There is no exemption list, deliberately.** The moment one exists, every
    future collision is resolved by appending to it rather than by renaming, and
    the rule stops being a rule. A collision is resolved by choosing a different
    field name (spec §2.4 fixes the renamings).
    """
    cached = _AUTHORITY_CACHE.get(cls)
    if cached is None:
        cached = tuple(
            field.name
            for field in dataclass_fields(cls)
            if any(token in field.name.lower() for token in FORBIDDEN_AUTHORITY_FIELDS)
        )
        _AUTHORITY_CACHE[cls] = cached
    return cached


#: Per-class result of the T5 audit. The audit is a property of the *type*, so
#: computing it once per class keeps it out of the per-world cost while still
#: running before the first instance of any new class exists.
_AUTHORITY_CACHE: dict[type, tuple[str, ...]] = {}


def _refuse_authority_fields(instance: object) -> None:
    offenders = authority_named_fields(type(instance))
    if offenders:
        raise ContractError(
            f"{type(instance).__name__} declares response-authority field names "
            f"{list(offenders)}; Stage 4 output carries no authority (T5, ADR-0003)"
        )


@dataclass(frozen=True, slots=True)
class WorldSupport:
    """Support with its geometry attached — never a bare float.

    ``interval`` is required by ``EVIDENCE_INTERVAL`` and forbidden for every
    other geometry. A half-declared representation (an interval attached to a
    point estimate, or an interval geometry with no interval) is the ambiguity
    §11 warns about, so construction refuses both shapes.
    """

    geometry: BeliefGeometry
    value: float
    interval: tuple[float, float] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.geometry, BeliefGeometry):
            raise ContractError(f"geometry must be a BeliefGeometry, got {self.geometry!r}")
        if not isinstance(self.value, (int, float)) or isinstance(self.value, bool):
            raise ContractError(f"support value must be a number, got {self.value!r}")
        if not math.isfinite(self.value):
            raise ContractError(f"support value must be finite, got {self.value!r}")
        if self.geometry is BeliefGeometry.CALIBRATED_PROBABILITY:
            require_finite_unit_interval(self.value, "WorldSupport.value")
        if self.geometry is BeliefGeometry.E_VALUE and self.value <= 0.0:
            raise ContractError(f"an e-value is strictly positive, got {self.value!r}")
        self._validate_interval()

    def _validate_interval(self) -> None:
        if self.geometry is BeliefGeometry.EVIDENCE_INTERVAL:
            if self.interval is None:
                raise ContractError("EVIDENCE_INTERVAL support must carry its interval")
            low, high = self.interval
            if not (math.isfinite(low) and math.isfinite(high)) or low > high:
                raise ContractError(f"interval must be finite and ordered, got {self.interval!r}")
            if not low <= self.value <= high:
                raise ContractError(
                    f"point estimate {self.value!r} lies outside its interval {self.interval!r}"
                )
        elif self.interval is not None:
            raise ContractError(
                f"{self.geometry.value} support may not carry an interval; an interval "
                "attached to a point geometry is a representation nobody can read back"
            )

    def as_probability(self) -> float | None:
        """The value as a probability, or ``None`` when the geometry is not one.

        ``None`` is the honest answer for a log-odds, an e-value or an interval.
        There is deliberately no logistic conversion here: a model score pushed
        through a sigmoid is still uncalibrated, and Stage 1 already ships
        ``calibration_id=None`` rather than pretend otherwise.
        """
        if self.geometry in NORMALISING_GEOMETRIES:
            return float(self.value)
        return None

    def combine(self, log_likelihood_ratio: float) -> WorldSupport:
        """Fold one evidence update in, staying inside the declared geometry."""
        if not math.isfinite(log_likelihood_ratio):
            raise ContractError(
                f"log-likelihood ratio must be finite, got {log_likelihood_ratio!r}"
            )
        if self.geometry is BeliefGeometry.LOG_ODDS:
            return WorldSupport(self.geometry, _clamp_log_odds(self.value + log_likelihood_ratio))
        if self.geometry is BeliefGeometry.CALIBRATED_PROBABILITY:
            updated = _logit(self.value) + log_likelihood_ratio
            return WorldSupport(self.geometry, _sigmoid(_clamp_log_odds(updated)))
        if self.geometry is BeliefGeometry.E_VALUE:
            factor = math.exp(_clamp_log_odds(log_likelihood_ratio))
            return WorldSupport(self.geometry, min(self.value * factor, math.exp(MAX_LOG_ODDS)))
        low, high = self.interval if self.interval is not None else (self.value, self.value)
        shift = log_likelihood_ratio
        return WorldSupport(
            self.geometry,
            _clamp_log_odds(self.value + shift),
            (_clamp_log_odds(low + shift), _clamp_log_odds(high + shift)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "geometry": self.geometry.value,
            "value": round(float(self.value), 6),
            "interval": None if self.interval is None else [round(v, 6) for v in self.interval],
            "as_probability": self.as_probability(),
        }


def _clamp_log_odds(value: float) -> float:
    return max(-MAX_LOG_ODDS, min(MAX_LOG_ODDS, value))


def _sigmoid(value: float) -> float:
    return 1.0 / (1.0 + math.exp(-value))


def _logit(probability: float) -> float:
    #: Probabilities of exactly 0 or 1 are certainty, which no evidence update
    #: could ever move. Clamping to the representable interior keeps `combine`
    #: total instead of raising on a legitimately saturated support.
    bounded = min(max(probability, 1e-12), 1.0 - 1e-12)
    return math.log(bounded / (1.0 - bounded))


@dataclass(frozen=True, slots=True)
class LatentSecurityState:
    """X_t (§5): what a world asserts is true, distinct from what was observed.

    The separation is the whole point of §5. An observation is evidence; a latent
    state is a claim about the host that the evidence may or may not identify.
    Keeping them in different types is what stops "I did not observe it,
    therefore it did not happen" from being expressible.
    """

    state: SecurityStateV1
    #: DIMENSIONS keys the world commits to. Every one must actually be raised in
    #: ``state``: a world may not assert a capability its own latent state does
    #: not hold (§21).
    asserted_dimensions: frozenset[str]
    #: phi(state).total. Checked, not trusted — see __post_init__.
    consequence: float

    def __post_init__(self) -> None:
        _refuse_authority_fields(self)
        unknown = sorted(set(self.asserted_dimensions) - set(DIMENSIONS))
        if unknown:
            raise ContractError(f"asserted dimensions not in DIMENSIONS: {unknown}")
        unheld = sorted(d for d in self.asserted_dimensions if self.state.level(d) <= 0)
        if unheld:
            raise ContractError(
                f"world asserts {unheld} but its latent state does not hold them; "
                "abstraction is allowed, factual amplification is not (§21)"
            )
        measured = phi(self.state).total
        if abs(float(self.consequence) - measured) > 1e-9:
            raise ContractError(
                f"consequence {self.consequence!r} does not equal phi(state).total "
                f"{measured!r}; a world may not overstate its own consequence"
            )

    @classmethod
    def from_state(
        cls, state: SecurityStateV1, asserted_dimensions: Iterable[str]
    ) -> LatentSecurityState:
        """Build with the consequence measured rather than supplied."""
        return cls(state, frozenset(asserted_dimensions), phi(state).total)

    def raises(self, dimension: str) -> bool:
        return dimension in self.asserted_dimensions

    def to_dict(self) -> dict[str, Any]:
        return {
            "state": self.state.to_dict(),
            "asserted_dimensions": sorted(self.asserted_dimensions),
            "consequence": round(float(self.consequence), 6),
        }


@dataclass(frozen=True, slots=True)
class SecurityWorldV1:
    """W_i(t) — the architecture's §37 ``World`` tuple, as a frozen dataclass."""

    world_id: str
    #: A semantic descriptor ("compromised_admin_session"), never a technique
    #: name and never an ATT&CK id (§33).
    mechanism_id: str
    latent_state: LatentSecurityState
    support: WorldSupport
    support_state: WorldSupportState
    expected_evidence: frozenset[str]
    forbidden_evidence: frozenset[str]
    contradictions: tuple[str, ...]
    tension: TensionLike | None
    uncertainty: float
    #: Signals this world's claims depend on having been able to see. The sensor
    #: shadow is intersected with this, which is how a blind spot becomes a
    #: confidence penalty instead of a silent assumption.
    visibility_requirements: frozenset[str]
    #: CausalNode.signature values — the causal spine this world is a hypothesis
    #: over. Signatures are built from semantics, so a renamed binary does not
    #: change them.
    spine_signatures: tuple[str, ...]
    evidence_refs: tuple[EvidenceRef, ...]
    born_at_sequence: int
    fission_depth: int = 0
    schema_version: str = SECURITY_WORLD_V1_VERSION

    def __post_init__(self) -> None:
        # Order matters and is fixed by the spec: the authority audit runs first,
        # because a world that names authority must be refused before anything
        # else about it is discussed.
        _refuse_authority_fields(self)
        require_identifier(self.world_id, "SecurityWorldV1.world_id")
        require_identifier(self.mechanism_id, "SecurityWorldV1.mechanism_id")
        self._refuse_self_contradiction()
        self._require_latent_state()
        require_finite_unit_interval(self.uncertainty, "SecurityWorldV1.uncertainty")
        self._refuse_oversize_signal_sets()
        require_non_negative_int(self.born_at_sequence, "SecurityWorldV1.born_at_sequence")
        require_non_negative_int(self.fission_depth, "SecurityWorldV1.fission_depth")
        if self.fission_depth > MAX_WORLD_FISSION_DEPTH:
            raise ContractError(
                f"fission_depth {self.fission_depth} exceeds {MAX_WORLD_FISSION_DEPTH}; "
                "unbounded splitting is a denial of service, not adaptive complexity"
            )
        self._refuse_oversize_state()

    def _refuse_self_contradiction(self) -> None:
        overlap = sorted(self.expected_evidence & self.forbidden_evidence)
        if overlap:
            raise ContractError(
                f"world {self.world_id} both predicts and forbids {overlap}; such a "
                "world cannot be falsified by that signal and is therefore unkillable"
            )

    def _require_latent_state(self) -> None:
        """The dimension refusal itself lives in ``LatentSecurityState.__post_init__``.

        What is left to check here is that the field really holds one, because a raw
        ``SecurityStateV1`` would have skipped every §21 conservation check.
        """
        if not isinstance(self.latent_state, LatentSecurityState):
            raise ContractError(
                f"latent_state must be a LatentSecurityState, got "
                f"{type(self.latent_state).__name__}; a bare state skips every §21 check"
            )

    def _refuse_oversize_signal_sets(self) -> None:
        if len(self.expected_evidence) > MAX_EXPECTED_SIGNALS:
            raise ContractError(
                f"expected_evidence holds {len(self.expected_evidence)} signals, "
                f"bound is {MAX_EXPECTED_SIGNALS}"
            )
        if len(self.forbidden_evidence) > MAX_FORBIDDEN_SIGNALS:
            raise ContractError(
                f"forbidden_evidence holds {len(self.forbidden_evidence)} signals, "
                f"bound is {MAX_FORBIDDEN_SIGNALS}"
            )

    def _refuse_oversize_state(self) -> None:
        size = self.state_bytes()
        if size > MAX_WORLD_BYTES:
            raise ContractError(
                f"world {self.world_id} serialises to {size} bytes, bound is "
                f"{MAX_WORLD_BYTES}; §44 requires KB-scale worlds"
            )

    def state_bytes(self) -> int:
        """Canonical serialised size — the quantity §44's bound is actually about."""
        return len(canonical_bytes(self.to_dict()))

    def predicts(self, signal: str) -> bool:
        return signal in self.expected_evidence

    def forbids(self, signal: str) -> bool:
        return signal in self.forbidden_evidence

    def observationally_equivalent(self, other: SecurityWorldV1, *, epsilon: float) -> bool:
        """§14's fusion test: do these two worlds differ in anything observable?

        Support is deliberately **not** part of the comparison. Two worlds with
        the same predictions and the same security consequence are the same
        hypothesis held with different confidence; fusing them is correct, and
        refusing to fuse them because their support differs would keep duplicate
        mechanisms alive forever.

        ``epsilon`` is a *chosen* constant, not a measured one. G4.2's "or an
        equivalent explanation" clause rests on it, which is why the spec
        requires it reported as a parameter rather than as a finding.
        """
        if epsilon < 0.0:
            raise ContractError(f"epsilon must be non-negative, got {epsilon!r}")
        return (
            self.expected_evidence == other.expected_evidence
            and self.forbidden_evidence == other.forbidden_evidence
            and self.visibility_requirements == other.visibility_requirements
            and self.latent_state.asserted_dimensions == other.latent_state.asserted_dimensions
            and abs(self.latent_state.consequence - other.latent_state.consequence) <= epsilon
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "world_id": self.world_id,
            "mechanism_id": self.mechanism_id,
            "latent_state": self.latent_state.to_dict(),
            "support": self.support.to_dict(),
            "support_state": self.support_state.value,
            "expected_evidence": sorted(self.expected_evidence),
            "forbidden_evidence": sorted(self.forbidden_evidence),
            "contradictions": list(self.contradictions),
            "tension": None if self.tension is None else self.tension.to_dict(),
            "uncertainty": round(float(self.uncertainty), 6),
            "visibility_requirements": sorted(self.visibility_requirements),
            "spine_signatures": list(self.spine_signatures),
            "evidence_refs": [ref.to_dict() for ref in self.evidence_refs],
            "born_at_sequence": self.born_at_sequence,
            "fission_depth": self.fission_depth,
            "schema_version": self.schema_version,
        }
