"""D7.5 — epistemic distance: how far a contributor's context is from the receiver's.

Architecture §7: "distance is used for transfer relevance, not truth. A web server should
not strongly redefine a developer workstation's normality simply because many web servers
agree." ECHO splits evidence by context before it sums anything; this module supplies the
split. A large distance lowers how much a contribution *matters here*; it never says the
contribution is false, and a small one never says it is true.

The four terms that are built, each from a field the wire actually carries:

* ``role``           0 if the roles are equal, 0.5 if either is UNKNOWN, else 1.0.
  UNKNOWN is checked first: two unknown roles are not evidence of the same role.
* ``software_epoch`` 0/1 equality of the ``se-`` image class.
* ``visibility``     |level difference| / 2 over LOW=0, PARTIAL=1, FULL=2.
* ``behaviour``      L1 distance of the quantised relation-family profiles / (3 * len).

``total = sum(DISTANCE_WEIGHTS[term] * term)``. ``enabled=False`` is the CONTROL
(ORPH-F05 → role equality): every term is still reported, but ``total`` is the role term
alone, so a firing count can be taken as "decisions that differ from role equality".

Architecture §7's ``policy_distance`` and ``architecture_distance`` are **not built** and
are typed ``None``: no exported field carries them, and exporting a policy digest to feed
them would be new disclosure with no other consumer (lesson 3, ADR-0065). They are
UNMEASURED, and a ``None`` field cannot be mistaken for a measured zero.

:class:`LocalContext` describes the RECEIVING host and is never exported.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.ssir.relations import RelationFamily
from pocketsec.stage7.capsule.knowledge_capsule import (
    FAMILY_PROFILE_LEVELS,
    EpochContext,
    RoleClass,
    SourceContextSketch,
    VisibilityClass,
)

__all__ = [
    "DISTANCE_WEIGHTS",
    "EpistemicDistance",
    "LocalContext",
    "epistemic_distance",
    "relevance",
]

#: §4.23. Chosen, not measured.
DISTANCE_WEIGHTS: Mapping[str, float] = MappingProxyType({
    "role": 1.0,
    "software_epoch": 0.25,
    "visibility": 0.25,
    "behaviour": 0.5,
})

_SOFTWARE_EPOCH = re.compile(r"^se-[0-9a-f]{16}$")
_VISIBILITY_LEVEL: Mapping[VisibilityClass, int] = MappingProxyType({
    VisibilityClass.LOW: 0,
    VisibilityClass.PARTIAL: 1,
    VisibilityClass.FULL: 2,
})
_PROFILE_LEN: int = len(RelationFamily)


def _check_profile(profile: object, field: str) -> tuple[int, ...]:
    if not isinstance(profile, tuple) or len(profile) != _PROFILE_LEN:
        raise ContractError(f"{field} must be a tuple of {_PROFILE_LEN} ints, got {profile!r}")
    for level in profile:
        if isinstance(level, bool) or not isinstance(level, int) or \
                not 0 <= level < FAMILY_PROFILE_LEVELS:
            raise ContractError(f"{field} levels must be ints in [0, {FAMILY_PROFILE_LEVELS}), "
                                f"got {profile!r}")
    return profile


@dataclass(frozen=True, slots=True)
class LocalContext:
    """The receiving host's own context. Never exported; nothing foreign writes it."""

    role: RoleClass
    software_epoch: str
    visibility: VisibilityClass
    family_profile: tuple[int, ...]
    local_keys: frozenset[str]            # antibody keys of LOCAL-origin knowledge (sovereignty)
    observable_relations: frozenset[int]  # relation ids this host's sensors can observe

    def __post_init__(self) -> None:
        if not isinstance(self.role, RoleClass):
            raise ContractError(f"role must be a RoleClass, got {self.role!r}")
        if not isinstance(self.software_epoch, str) or not _SOFTWARE_EPOCH.fullmatch(self.software_epoch):
            raise ContractError(f"software_epoch must be 'se-' + 16 hex, got {self.software_epoch!r}")
        if not isinstance(self.visibility, VisibilityClass):
            raise ContractError(f"visibility must be a VisibilityClass, got {self.visibility!r}")
        _check_profile(self.family_profile, "family_profile")
        if not isinstance(self.local_keys, frozenset) or \
                not all(isinstance(key, str) and key for key in self.local_keys):
            raise ContractError("local_keys must be a frozenset of non-empty strings")
        if not isinstance(self.observable_relations, frozenset) or not all(
                isinstance(r, int) and not isinstance(r, bool) and r >= 0
                for r in self.observable_relations):
            raise ContractError("observable_relations must be a frozenset of non-negative ints")


@dataclass(frozen=True, slots=True)
class EpistemicDistance:
    total: float
    role: float
    software_epoch: float
    visibility: float
    behaviour: float
    policy: None          # UNMEASURED: no exported representation exists (ADR-0065)
    architecture: None    # UNMEASURED: no exported representation exists (ADR-0065)

    def __post_init__(self) -> None:
        if self.policy is not None or self.architecture is not None:
            raise ContractError("policy and architecture distance are not built; they must be None")
        for name in ("role", "software_epoch", "visibility", "behaviour"):
            value = getattr(self, name)
            if not isinstance(value, float) or not 0.0 <= value <= 1.0:
                raise ContractError(f"{name} term must be a float in [0, 1], got {value!r}")
        if not isinstance(self.total, float) or not 0.0 <= self.total <= sum(DISTANCE_WEIGHTS.values()):
            raise ContractError(f"total out of range: {self.total!r}")


def _role_term(theirs: RoleClass, ours: RoleClass) -> float:
    if theirs is RoleClass.UNKNOWN or ours is RoleClass.UNKNOWN:
        return 0.5
    return 0.0 if theirs is ours else 1.0


def epistemic_distance(sketch: SourceContextSketch, epoch: EpochContext, local: LocalContext, *,
                       enabled: bool = True) -> EpistemicDistance:
    """The contributor's context (``sketch``, ``epoch``) measured against the receiver's."""
    if not isinstance(local, LocalContext):
        raise ContractError(f"local must be a LocalContext, got {type(local).__name__}")
    profile = _check_profile(sketch.family_profile, "sketch.family_profile")
    role = _role_term(RoleClass(sketch.role), local.role)
    software = 0.0 if epoch.software_epoch == local.software_epoch else 1.0
    visibility = abs(_VISIBILITY_LEVEL[VisibilityClass(epoch.visibility)]
                     - _VISIBILITY_LEVEL[local.visibility]) / 2.0
    behaviour = sum(abs(a - b) for a, b in zip(profile, local.family_profile, strict=True)) / (
        (FAMILY_PROFILE_LEVELS - 1) * _PROFILE_LEN)
    terms = {"role": role, "software_epoch": software, "visibility": visibility,
             "behaviour": float(behaviour)}
    if enabled:
        total = sum(DISTANCE_WEIGHTS[name] * value for name, value in terms.items())
    else:
        total = DISTANCE_WEIGHTS["role"] * role
    return EpistemicDistance(total=float(total), role=role, software_epoch=software,
                             visibility=visibility, behaviour=float(behaviour),
                             policy=None, architecture=None)


def relevance(distance: EpistemicDistance) -> float:
    """``1 / (1 + total)``: 1.0 for an identical context, never 0."""
    return 1.0 / (1.0 + distance.total)
