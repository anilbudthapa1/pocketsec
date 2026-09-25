"""D4.18 (base corpus) — constructed incident cases with a known ground-truth world.

Architecture §39 asks for *counterfactual* incident data, not attack labels: shared
evidence prefixes with different continuations, the same semantics under renamed
actors, low-and-slow timing, decoy ancestry, non-identifiable worlds. This module
builds the base corpus and four variant families; ``labs/dropped_telemetry.py`` and
``labs/nonidentifiable.py`` build the other two on the same :class:`IncidentCase`.

Everything is layered on ``stage1/labs/ambiguous_corpus.build_ambiguous_corpus`` and
reuses ``Behaviour`` and ``Scenario`` unchanged — Stage 4 defines **no fifth scenario
type**. That corpus is the only non-saturated one in this repository, and its central
property (benign and malicious sessions matched on every aggregate statistic,
differing only in *attribution*) is exactly what a competing-worlds engine must face.

Three traps this module exists to avoid, each of which already cost a published
wrong answer:

1. **Identities must be unique across every corpus replayed on one pipeline.**
   ``Stage1Pipeline`` keys lineage state on boot+pid+start-time and carries it
   forward, so reused identities let capability accumulate between sessions: every
   lineage saturated by the second session, every chain stage at zero ΔΦ, a median
   per-lineage peak of **0.00 for both classes**, and a +0.042 PR-AUC retraction. The
   ambiguous corpus is session-unique *within one call*; stitching corpora together
   reopens the hole, so :func:`identity_namespace` and :func:`reidentify` are the one
   implementation of the fix and every other corpus module uses them.
2. **A corpus can leak through vocabulary.** An operation one class never emits gives
   a bag-of-features model a free perfect score. Every variant preserves the
   operation multiset or draws additions from operations both classes already emit,
   and :func:`operation_share_gap` and :func:`pooled_order_free_scores` exist so a
   test can *measure* that instead of asserting it.
3. **A ground truth written by the mechanism's own author is a confound.** The corpus
   knows which world a case came from; LUCID must not. Nothing under
   ``pocketsec/stage4/engine/`` may accept a :class:`GroundTruthWorld`, and spec §6.1
   records that world-set recall over hand-authored worlds partly measures the
   authoring.

Every ``mechanism_id`` is a semantic descriptor — never a technique name, never an
ATT&CK id (§33). The five world labels are architecture §4's own list.
"""

from __future__ import annotations

import math
import random
import statistics
from collections import Counter
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any

from pocketsec.stage0.contracts.common import ContractError
from pocketsec.stage1.labs.ambiguous_corpus import AMBIGUOUS_VERSION, build_ambiguous_corpus
from pocketsec.stage1.labs.corpus import Behaviour, Scenario
from pocketsec.stage1.pipeline import Stage1Pipeline
from pocketsec.stage1.state.security_state import DIMENSIONS

if TYPE_CHECKING:  # pragma: no cover - typing only
    from collections.abc import Iterable, Mapping, Sequence

__all__ = [
    "EXPECTED_STATES",
    "FAMILY_BANDS",
    "FLOOD_CANDIDATE_LINEAGES",
    "GroundTruthWorld",
    "INCIDENT_CORPUS_VERSION",
    "IncidentCase",
    "MAX_BEHAVIOURS_PER_INCIDENT",
    "MECHANISM_BY_LABEL",
    "RENAME_MAP",
    "SPURIOUS_MECHANISM_ID",
    "WORLD_LABELS",
    "build_decoy_variants",
    "build_incident_corpus",
    "build_low_and_slow_variants",
    "build_rename_variants",
    "build_shared_prefix_pairs",
    "build_world_flood",
    "chain_owner_identity",
    "decoy_cases",
    "identity_keys",
    "identity_namespace",
    "median_peak_delta_phi",
    "operation_counts",
    "operation_share_gap",
    "pooled_order_free_scores",
    "reidentify",
    "replay_cases",
]

#: Carries the version of the corpus it is built on, so one BenchmarkResult's
#: provenance records both (integration plan §5.4).
INCIDENT_CORPUS_VERSION = f"stage4-incident-v0.1.0+{AMBIGUOUS_VERSION}"

#: Corpus-side cap on one case. ``engine/integrator.py`` owns the transition bound
#: ``MAX_TRANSITIONS_PER_INCIDENT``; this bounds what the corpus may *hand* it, under
#: its own name so the two are not two spellings of the same constant.
MAX_BEHAVIOURS_PER_INCIDENT = 4096

# --- the five worlds of architecture §4 --------------------------------------

WORLD_APPROVED_ADMIN = "approved_admin"
WORLD_COMPROMISED_SESSION = "compromised_session"
WORLD_STOLEN_CREDENTIAL = "stolen_credential"
WORLD_LEGITIMATE_AUTOMATION = "legitimate_automation"
WORLD_NOVEL_UNRESOLVED = "novel_unresolved"

WORLD_LABELS = (
    WORLD_APPROVED_ADMIN,
    WORLD_COMPROMISED_SESSION,
    WORLD_STOLEN_CREDENTIAL,
    WORLD_LEGITIMATE_AUTOMATION,
    WORLD_NOVEL_UNRESOLVED,
)

MECHANISM_BY_LABEL = {
    WORLD_APPROVED_ADMIN: "approved_administration",
    WORLD_COMPROMISED_SESSION: "compromised_admin_session",
    WORLD_STOLEN_CREDENTIAL: "stolen_credential_reuse",
    WORLD_LEGITIMATE_AUTOMATION: "scheduled_automation_external_sink",
    WORLD_NOVEL_UNRESOLVED: "unresolved_novel_mechanism",
}

#: What each world asserts, as ``DIMENSIONS`` keys — reading a value out of that
#: mapping is permitted, naming a *field* after one is not (spec §2.4). The UNKNOWN
#: world asserts nothing: novelty is not maliciousness.
_RAISES_BY_LABEL = {
    WORLD_APPROVED_ADMIN: frozenset({"privilege", "modification"}),
    WORLD_COMPROMISED_SESSION: frozenset({"privilege", "credential", "reachability"}),
    WORLD_STOLEN_CREDENTIAL: frozenset({"credential", "reachability", "discovery"}),
    WORLD_LEGITIMATE_AUTOMATION: frozenset({"credential", "reachability"}),
    WORLD_NOVEL_UNRESOLVED: frozenset(),
}

#: The observation that would separate this world from its alternatives. Every value
#: is a ``MANDATORY_SIGNALS`` member, so the discriminator comes from a vocabulary
#: both classes emit: the power is in *which lineage* produced it, never in an
#: operation only one class uses. ``None`` means non-identifiable by construction.
_DISCRIMINATOR_BY_LABEL = {
    WORLD_APPROVED_ADMIN: "authentication",
    WORLD_COMPROMISED_SESSION: "boundary_crossing",
    WORLD_STOLEN_CREDENTIAL: "credential_access",
    WORLD_LEGITIMATE_AUTOMATION: "authentication",
    WORLD_NOVEL_UNRESOLVED: None,
}

_M = MECHANISM_BY_LABEL
_NOVEL = _M[WORLD_NOVEL_UNRESOLVED]
_ALTERNATIVES_BY_LABEL = {
    WORLD_APPROVED_ADMIN: (_M[WORLD_COMPROMISED_SESSION], _NOVEL),
    WORLD_COMPROMISED_SESSION: (_M[WORLD_APPROVED_ADMIN], _M[WORLD_STOLEN_CREDENTIAL], _NOVEL),
    WORLD_STOLEN_CREDENTIAL: (
        _M[WORLD_LEGITIMATE_AUTOMATION],
        _M[WORLD_COMPROMISED_SESSION],
        _NOVEL,
    ),
    WORLD_LEGITIMATE_AUTOMATION: (_M[WORLD_STOLEN_CREDENTIAL], _NOVEL),
    WORLD_NOVEL_UNRESOLVED: tuple(_M[x] for x in WORLD_LABELS if x != WORLD_NOVEL_UNRESOLVED),
}

#: The rival explanation a decoy ancestor suggests. Its purpose is to be *wrong*:
#: G4.6 requires counterfactual stress to identify it as spurious.
SPURIOUS_MECHANISM_ID = "coincident_privileged_maintenance"

#: ``IdentifiabilityState`` member *values*. ``identifiability/resolution.py`` owns the
#: enum and a later work package builds it, so importing it here would invert the
#: dependency. It is a ``StrEnum``, so ``IdentifiabilityState.IDENTIFIED ==
#: "IDENTIFIED"`` and no conversion is needed; a test pins the two sets together as
#: soon as the enum exists rather than leaving them to agree by coincidence.
EXPECTED_STATES = frozenset({"IDENTIFIED", "UNIDENTIFIABLE", "INSUFFICIENT_EVIDENCE", "UNKNOWN"})

# --- identity namespacing ----------------------------------------------------

#: One band per corpus family, so one ``Stage1Pipeline`` can replay the base corpus,
#: the flood and every variant with no lineage state leaking between families. A new
#: family adds a band here; it never borrows one.
FAMILY_BANDS = {
    "base": 1,
    "prefix": 2,
    "rename": 3,
    "slow": 4,
    "decoy": 5,
    "flood": 6,
    "nonidentifiable": 7,
    "resolvable": 8,
}

_BAND_SIZE = 100_000
_MAX_ACTORS_PER_CASE = 100
#: Identity slot reserved for an injected decoy actor, above every real slot.
_DECOY_SLOT = 90


def identity_namespace(family: str, ordinal: int) -> int:
    """A globally unique identity namespace for one case of one family."""
    try:
        band = FAMILY_BANDS[family]
    except KeyError as exc:
        raise ContractError(
            f"unknown corpus family {family!r}; add a band to FAMILY_BANDS"
        ) from exc
    if not 0 <= ordinal < _BAND_SIZE:
        raise ContractError(f"ordinal {ordinal} outside the band size {_BAND_SIZE}")
    return band * _BAND_SIZE + ordinal


def _reidentify(
    scenario: Scenario, *, namespace: int
) -> tuple[Scenario, Mapping[tuple[str, str], tuple[str, str]]]:
    """Rewrite identities into ``namespace``, returning the old-to-new mapping."""
    mapping: dict[tuple[str, str], tuple[str, str]] = {}
    behaviours: list[Behaviour] = []
    for behaviour in scenario.behaviours:
        pid = behaviour.fields.get("pid")
        start = behaviour.fields.get("start_time")
        if pid is None or start is None:
            behaviours.append(behaviour)
            continue
        key = (pid, start)
        if key not in mapping:
            slot = len(mapping)
            if slot >= _DECOY_SLOT:
                raise ContractError(
                    f"{scenario.name} holds {slot + 1} actors; slot {_DECOY_SLOT} up is "
                    "reserved for decoys and the next namespace begins at 100"
                )
            fresh = str(namespace * _MAX_ACTORS_PER_CASE + slot)
            mapping[key] = (fresh, fresh)
        new_pid, new_start = mapping[key]
        behaviours.append(
            Behaviour(
                behaviour.operation, {**behaviour.fields, "pid": new_pid, "start_time": new_start}
            )
        )
    return replace(scenario, behaviours=tuple(behaviours)), mapping


def reidentify(scenario: Scenario, *, namespace: int) -> Scenario:
    """Move every actor identity into ``namespace``, preserving the structure.

    Distinct actors stay distinct; only the identity *values* move. Semantics are
    untouched because Stage 1 excludes pids from ``semantic_key()`` — asserted, not
    assumed.
    """
    return _reidentify(scenario, namespace=namespace)[0]


def identity_keys(case: IncidentCase) -> frozenset[tuple[str, str]]:
    """Every ``(pid, start_time)`` pair the case's behaviours name."""
    return frozenset(
        (behaviour.fields["pid"], behaviour.fields["start_time"])
        for behaviour in case.scenario.behaviours
        if "pid" in behaviour.fields and "start_time" in behaviour.fields
    )


def chain_owner_identity(scenario: Scenario) -> tuple[str, str] | None:
    """The first ``setuid`` performer: who opened the capability chain, or ``None``."""
    for behaviour in scenario.behaviours:
        if behaviour.operation == "setuid":
            pid = behaviour.fields.get("pid")
            start = behaviour.fields.get("start_time")
            if pid is not None and start is not None:
                return (pid, start)
    return None


# --- the case types ----------------------------------------------------------


@dataclass(frozen=True, slots=True)
class GroundTruthWorld:
    """The world a case actually came from. The corpus knows; LUCID must not."""

    world_label: str
    mechanism_id: str
    raises_dimensions: frozenset[str]
    #: ``None`` means the case was constructed to be non-identifiable.
    discriminating_signal: str | None

    def __post_init__(self) -> None:
        if self.world_label not in WORLD_LABELS:
            raise ContractError(f"unknown world label {self.world_label!r}")
        expected = MECHANISM_BY_LABEL[self.world_label]
        if expected != self.mechanism_id:
            raise ContractError(
                f"{self.world_label!r} means {expected!r}, not {self.mechanism_id!r}"
            )
        unknown = sorted(set(self.raises_dimensions) - set(DIMENSIONS))
        if unknown:
            raise ContractError(f"raises_dimensions not in DIMENSIONS: {unknown}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "world_label": self.world_label,
            "mechanism_id": self.mechanism_id,
            "raises_dimensions": sorted(self.raises_dimensions),
            "discriminating_signal": self.discriminating_signal,
        }


@dataclass(frozen=True, slots=True)
class IncidentCase:
    """One constructed incident, with everything the scoring side needs.

    The last four fields are additions to the spec's six, and necessary ones: G4.6
    requires a *predefined* spurious explanation provably off the true chain, and
    G4.3's staged resolution needs to know where a shared prefix ends. All four
    default to "absent", so the spec's construction signature still works.
    """

    incident_id: str
    scenario: Scenario
    truth: GroundTruthWorld
    material_alternatives: tuple[str, ...]
    #: An ``IdentifiabilityState`` member value — see :data:`EXPECTED_STATES`.
    expected_state: str
    #: Signals this case's telemetry does not carry, set by ``labs/dropped_telemetry``.
    visibility_mask: frozenset[str] = frozenset()
    #: The rival mechanism a decoy ancestor suggests, or "" for no decoy.
    spurious_mechanism_id: str = ""
    #: The decoy actor's identity. Refused if it equals ``chain_identity``.
    decoy_identity: tuple[str, str] | None = None
    #: The true chain owner, recorded before any decoy was injected.
    chain_identity: tuple[str, str] | None = None
    #: Behaviour count of a deliberately shared evidence prefix, or 0.
    shared_prefix_length: int = 0

    def __post_init__(self) -> None:
        where = self.incident_id
        if self.expected_state not in EXPECTED_STATES:
            raise ContractError(f"{self.expected_state!r} is not an IdentifiabilityState value")
        if self.truth.mechanism_id in self.material_alternatives:
            raise ContractError(
                f"{where}: the true mechanism is among its own material alternatives, "
                "which makes the alternative set untestable"
            )
        if len(self.scenario.behaviours) > MAX_BEHAVIOURS_PER_INCIDENT:
            raise ContractError(f"{where}: over {MAX_BEHAVIOURS_PER_INCIDENT} behaviours")
        if self.spurious_mechanism_id and self.decoy_identity is None:
            raise ContractError(
                f"{where} names a spurious mechanism but no decoy identity; a spurious "
                "explanation nobody can locate cannot be stress-tested"
            )
        if self.decoy_identity is not None and self.decoy_identity == self.chain_identity:
            raise ContractError(
                f"{where}: the decoy identity IS the chain owner, so 'spurious ancestor "
                "off the true chain' does not hold"
            )
        if self.shared_prefix_length > len(self.scenario.behaviours):
            raise ContractError(f"{where}: prefix longer than the scenario")

    @property
    def label(self) -> int:
        """The scenario's binary label, for per-class corpus statistics."""
        return self.scenario.label

    def to_dict(self) -> dict[str, Any]:
        return {
            "incident_id": self.incident_id,
            "scenario": self.scenario.to_dict(),
            "truth": self.truth.to_dict(),
            "material_alternatives": list(self.material_alternatives),
            "expected_state": self.expected_state,
            "visibility_mask": sorted(self.visibility_mask),
            "spurious_mechanism_id": self.spurious_mechanism_id,
            "decoy_identity": None if self.decoy_identity is None else list(self.decoy_identity),
            "chain_identity": None if self.chain_identity is None else list(self.chain_identity),
            "shared_prefix_length": self.shared_prefix_length,
        }


def _ground_truth(world_label: str, *, discriminator: str | None = "") -> GroundTruthWorld:
    signal = _DISCRIMINATOR_BY_LABEL[world_label] if discriminator == "" else discriminator
    return GroundTruthWorld(
        world_label=world_label,
        mechanism_id=MECHANISM_BY_LABEL[world_label],
        raises_dimensions=_RAISES_BY_LABEL[world_label],
        discriminating_signal=signal,
    )


def _truth(label_index: int, binary_label: int) -> GroundTruthWorld:
    """Map an ambiguous-corpus session onto one of the five §4 worlds.

    That corpus marks ``index % 9 == 0`` malicious sessions *subtle*: a partial chain
    held out as an unseen technique. Those become ``novel_unresolved`` — a chain whose
    later stages never occurred is a mechanism the system cannot name.
    """
    first = (label_index // 3) % 2 == 0
    if binary_label != 1:
        return _ground_truth(WORLD_APPROVED_ADMIN if first else WORLD_LEGITIMATE_AUTOMATION)
    if label_index % 9 == 0:
        return _ground_truth(WORLD_NOVEL_UNRESOLVED)
    return _ground_truth(WORLD_COMPROMISED_SESSION if first else WORLD_STOLEN_CREDENTIAL)


def _expected_state(truth: GroundTruthWorld) -> str:
    return "UNKNOWN" if truth.discriminating_signal is None else "IDENTIFIED"


# --- the decoy ancestor ------------------------------------------------------

#: A high-ΔΦ ancestor **not** on the true chain: privilege, credential and persistence
#: in three operations by an actor that touches nothing else. Every operation is one
#: both classes already emit, so injection leaks no vocabulary.
_DECOY_CHAIN = (
    ("setuid", {"target_uid": "0"}),
    ("read", {"path": "/etc/sudoers"}),
    ("write", {"path": "/etc/systemd/system/maintenance.service"}),
)
_DECOY_CHAIN_ALTERNATE = (
    ("setuid", {"target_uid": "0"}),
    ("read", {"path": "/etc/gshadow"}),
    ("write", {"path": "/etc/cron.daily/maintenance"}),
)

#: Which base-corpus indices carry a decoy. Under the ambiguous corpus's
#: ``index % 3 == 0`` malicious rule these are three benign and two malicious, so the
#: injections skew neither class's operation shares. Five, because G4.6 asserts five.
_DECOY_INDICES = (4, 9, 16, 21, 28)


def _actor(namespace: int, slot: int) -> str:
    return str(namespace * _MAX_ACTORS_PER_CASE + slot)


def _behaviour(operation: str, fields: dict[str, str], actor: str, gap_ns: int) -> Behaviour:
    return Behaviour(
        operation, {**fields, "pid": actor, "start_time": actor, "_gap_ns": str(gap_ns)}
    )


def _inject_decoy(
    scenario: Scenario,
    *,
    namespace: int,
    chain: Sequence[tuple[str, dict[str, str]]],
    rng: random.Random,
) -> tuple[Scenario, tuple[str, str]]:
    """Insert a decoy ancestor performed by a fresh actor, spread through the stream."""
    identity = str(namespace * _MAX_ACTORS_PER_CASE + _DECOY_SLOT)
    behaviours = list(scenario.behaviours)
    stride = max(1, len(behaviours) // (len(chain) + 1))
    start = rng.randrange(1, max(2, stride))
    for offset, (operation, fields) in enumerate(chain):
        at = min(start + offset * stride, len(behaviours))
        behaviours.insert(
            at, _behaviour(operation, fields, identity, rng.randrange(3, 30) * 1_000_000_000)
        )
    return replace(scenario, behaviours=tuple(behaviours)), (identity, identity)


# --- builders ----------------------------------------------------------------


def build_incident_corpus(*, count: int, seed: int) -> tuple[IncidentCase, ...]:
    """The base corpus: ambiguous sessions relabelled onto the five §4 worlds.

    Five cases carry a predefined spurious explanation (G4.6) at ``count >= 29``;
    below that :func:`decoy_cases` reports the truth rather than the intent.
    """
    if count < 1:
        raise ContractError(f"count must be positive, got {count}")
    base = build_ambiguous_corpus(count=count, seed=seed)
    rng = random.Random(seed ^ 0x5A4F)
    cases: list[IncidentCase] = []
    for index, scenario in enumerate(base):
        truth = _truth(index, scenario.label)
        namespace = identity_namespace("base", index)
        renamed = reidentify(scenario, namespace=namespace)
        # Read the chain owner BEFORE injecting, or the decoy's own setuid can be
        # mistaken for the chain's and "off the true chain" becomes unprovable.
        owner = chain_owner_identity(renamed)
        spurious, decoy = "", None
        if index in _DECOY_INDICES:
            renamed, decoy = _inject_decoy(
                renamed, namespace=namespace, chain=_DECOY_CHAIN, rng=rng
            )
            spurious = SPURIOUS_MECHANISM_ID
        cases.append(
            IncidentCase(
                incident_id=f"s4-inc-{seed:04d}-{index:04d}",
                scenario=replace(renamed, name=f"inc-{index:04d}-{truth.world_label}"),
                truth=truth,
                material_alternatives=_ALTERNATIVES_BY_LABEL[truth.world_label],
                expected_state=_expected_state(truth),
                spurious_mechanism_id=spurious,
                decoy_identity=decoy,
                chain_identity=owner,
            )
        )
    return tuple(cases)


def decoy_cases(cases: Iterable[IncidentCase]) -> tuple[IncidentCase, ...]:
    """The cases carrying a predefined spurious explanation. G4.6 reads exactly this."""
    return tuple(case for case in cases if case.spurious_mechanism_id)


# --- §39 row 1: shared prefix, different continuation ------------------------

#: Filler routines, capability-neutral by construction: loopback only, no credential
#: object, no privilege change. The chain must be the *only* source of capability, or
#: a chain stage's marginal ΔΦ is invisible — the 0.00-median defect again.
_LOOPBACK_WEB = {"raddr": "127.0.0.1", "rport": "51001"}
_LOOPBACK_METRICS = {"raddr": "127.0.0.1", "rport": "8125"}
_FILLER_ROUTINES = (
    (("accept", _LOOPBACK_WEB), ("read", {"path": "/var/www/index.html"}),
     ("send", _LOOPBACK_WEB)),
    (("execve", {"path": "/usr/bin/make"}), ("read", {"path": "/home/ci/src/app.c"}),
     ("write", {"path": "/home/ci/build/app.o"})),
    (("read", {"path": "/var/log/syslog"}), ("connect", _LOOPBACK_METRICS),
     ("send", _LOOPBACK_METRICS)),
)

#: The shared prefix: privilege change, then a credential read. Both continuations
#: complete it with the same external egress; only the egress *actor* differs.
_PREFIX_CHAIN = (("setuid", {"target_uid": "0"}), ("read", {"path": "/etc/shadow"}))
_VAULT = {"raddr": "203.0.113.5", "rport": "443"}
_CONTINUATION = (("connect", _VAULT), ("send", _VAULT))


def _prefix_session(
    *, namespace: int, rng: random.Random, single_lineage: bool, length: int
) -> tuple[tuple[Behaviour, ...], int]:
    """One shared-prefix session, returned with its prefix length."""
    owner = _actor(namespace, 0)
    others = [_actor(namespace, slot) for slot in range(1, 1 + len(_FILLER_ROUTINES))]
    stream: list[Behaviour] = []
    for step in range(length):
        routine = _FILLER_ROUTINES[step % len(_FILLER_ROUTINES)]
        operation, fields = routine[step % len(routine)]
        actor = others[step % len(others)]
        stream.append(_behaviour(operation, fields, actor, rng.randrange(2, 90) * 1_000_000_000))
    stride = max(2, length // 3)
    for offset, (operation, fields) in enumerate(_PREFIX_CHAIN):
        stream.insert(
            min(1 + offset * stride, len(stream)),
            _behaviour(operation, fields, owner, rng.randrange(5, 40) * 60_000_000_000),
        )
    prefix_length = len(stream)
    egress = owner if single_lineage else others[0]
    for operation, fields in _CONTINUATION:
        stream.append(_behaviour(operation, fields, egress, rng.randrange(5, 40) * 60_000_000_000))
    return tuple(stream), prefix_length


def build_shared_prefix_pairs(
    *, count: int, seed: int
) -> tuple[tuple[IncidentCase, IncidentCase], ...]:
    """§39 row 1: pairs whose evidence prefix is identical and whose outcome is not.

    Both members hold the same operations in the same order with the same timing
    draws; only the lineage performing the external egress differs. Their identities
    differ, which does **not** make the evidence differ, and a test asserts the
    prefixes compile to identical semantics rather than trusting the construction.
    """
    pairs: list[tuple[IncidentCase, IncidentCase]] = []
    for ordinal in range(count):
        length = 24 + (ordinal % 7)
        # One seed for both members, so every filler and timing draw matches and the
        # pair differs in attribution alone.
        streams = {
            single: _prefix_session(
                namespace=identity_namespace("prefix", 2 * ordinal + int(not single)),
                rng=random.Random(seed * 7919 + ordinal),
                single_lineage=single,
                length=length,
            )
            for single in (True, False)
        }
        pairs.append(
            (
                _prefix_case(ordinal, seed, *streams[True], WORLD_COMPROMISED_SESSION, 1),
                _prefix_case(ordinal, seed, *streams[False], WORLD_LEGITIMATE_AUTOMATION, 0),
            )
        )
    return tuple(pairs)


def _prefix_case(
    ordinal: int,
    seed: int,
    stream: tuple[Behaviour, ...],
    prefix_length: int,
    world_label: str,
    binary_label: int,
) -> IncidentCase:
    # Both members are separated by *who* crossed the boundary, so both name the same
    # discriminating signal. That is the point of the pair.
    return IncidentCase(
        incident_id=f"s4-pfx-{seed:04d}-{ordinal:04d}-{binary_label}",
        scenario=Scenario(
            f"pfx-{ordinal:04d}-{world_label}",
            stream,
            binary_label,
            technique="shared-prefix" if binary_label else None,
        ),
        truth=_ground_truth(world_label, discriminator="boundary_crossing"),
        material_alternatives=_ALTERNATIVES_BY_LABEL[world_label],
        # The full case is identifiable; a consumer replaying only
        # ``shared_prefix_length`` behaviours should expect INSUFFICIENT_EVIDENCE.
        expected_state="IDENTIFIED",
        chain_identity=chain_owner_identity(Scenario("probe", stream, binary_label)),
        shared_prefix_length=prefix_length,
    )


# --- §39 rows 2-4: rename, low-and-slow, decoy variants ----------------------

#: Semantics-preserving renamings: every pair maps an object onto another of the
#: **same** class under Stage 1's host-metadata tables. A test checks class
#: preservation against ``stage1/compiler/entity_registry``'s own tables and then the
#: far stronger property, identical SSIR semantic keys after replay.
RENAME_MAP = {
    "/etc/shadow": "/etc/gshadow",
    "/root/.ssh/id_rsa": "/home/ops/.ssh/id_ed25519",
    "/backup/keys.tar": "/srv/archive/secrets.tar",
    "/etc/cron.d/sysupdate": "/etc/cron.daily/patchrun",
    "/usr/bin/apt": "/usr/sbin/aptitude",
    "/usr/bin/make": "/usr/bin/ninja",
    "/usr/bin/perl": "/usr/bin/python3",
    "/var/www/index.html": "/srv/http/home.html",
    "/var/www/static/app.js": "/srv/http/assets/app.js",
    "/home/ci/src/app.c": "/opt/ci/src/app.c",
    "/home/ci/build/app.o": "/opt/ci/build/app.o",
    "/var/log/syslog": "/var/log/messages",
    "/var/lib/db/shard-1.dat": "/srv/db/shard-7.dat",
    "/var/lib/db/wal.log": "/srv/db/journal.log",
    "/var/log/dpkg.log": "/var/log/apt/history.log",
    "/var/cache/apt/state": "/var/cache/apt/pkgcache",
    "/var/lib/cache/dump.rdb": "/srv/cache/snapshot.rdb",
    "/var/spool/cron/jobs": "/var/spool/atjobs/list",
    "/var/spool/cron/state": "/var/spool/atjobs/state",
    "/var/mail/queue/00001": "/var/spool/mail/queue/00002",
    "203.0.113.5": "198.51.100.210",
    "203.0.113.6": "198.51.100.211",
    "198.51.100.77": "203.0.113.77",
    "198.51.100.91": "203.0.113.91",
}


def _rename_fields(fields: dict[str, str]) -> dict[str, str]:
    renamed = dict(fields)
    for key in ("path", "raddr"):
        value = renamed.get(key)
        if value is not None and value in RENAME_MAP:
            renamed[key] = RENAME_MAP[value]
    return renamed


def _rebanded(
    case: IncidentCase,
    *,
    family: str,
    ordinal: int,
    suffix: str,
    behaviours: tuple[Behaviour, ...],
) -> IncidentCase:
    """Rebuild a case in a fresh identity band, carrying both marked identities across.

    Both identities travel through the remapping. Recomputing the decoy from the new
    scenario points it at the chain owner, which ``IncidentCase`` refuses — which is
    how that bug was caught rather than shipped.
    """
    scenario, mapping = _reidentify(
        replace(case.scenario, name=f"{case.scenario.name}{suffix}", behaviours=behaviours),
        namespace=identity_namespace(family, ordinal),
    )
    return replace(
        case,
        incident_id=f"{case.incident_id}{suffix}",
        scenario=scenario,
        decoy_identity=None if case.decoy_identity is None else mapping.get(case.decoy_identity),
        chain_identity=None if case.chain_identity is None else mapping.get(case.chain_identity),
    )


def build_rename_variants(case: IncidentCase, *, seed: int) -> tuple[IncidentCase, ...]:
    """§39 row 2: same semantics, renamed actors, paths and destinations. A conclusion
    that moves under this rests on a name, which ADR-0006 already forbids.
    """
    return (
        _rebanded(
            case,
            family="rename",
            ordinal=_ordinal_of(case, seed),
            suffix="-rn",
            behaviours=tuple(
                Behaviour(b.operation, _rename_fields(b.fields)) for b in case.scenario.behaviours
            ),
        ),
    )


def build_low_and_slow_variants(case: IncidentCase, *, seed: int) -> tuple[IncidentCase, ...]:
    """§39 row 5: the same chain, stretched so no fixed window spans two stages."""
    ordinal = _ordinal_of(case, seed)
    return tuple(
        _rebanded(
            case,
            family="slow",
            ordinal=(ordinal * 2 + slot) % _BAND_SIZE,
            suffix=f"-sl{factor}",
            behaviours=tuple(_slow(b, factor) for b in case.scenario.behaviours),
        )
        for slot, factor in enumerate((60, 1440))
    )


def _slow(behaviour: Behaviour, factor: int) -> Behaviour:
    gap = int(behaviour.fields.get("_gap_ns", "1000000"))
    return Behaviour(behaviour.operation, {**behaviour.fields, "_gap_ns": str(gap * factor)})


def build_decoy_variants(case: IncidentCase, *, seed: int) -> tuple[IncidentCase, ...]:
    """§39 row 6: two variants, two decoy shapes, each a high-ΔΦ ancestor off the true
    chain suggesting :data:`SPURIOUS_MECHANISM_ID`, performed by an actor that appears
    nowhere else in the session.
    """
    ordinal = _ordinal_of(case, seed)
    variants: list[IncidentCase] = []
    for slot, chain in enumerate((_DECOY_CHAIN, _DECOY_CHAIN_ALTERNATE)):
        rebanded = _rebanded(
            case,
            family="decoy",
            ordinal=(ordinal * 2 + slot) % _BAND_SIZE,
            suffix=f"-dc{slot}",
            behaviours=case.scenario.behaviours,
        )
        owner = rebanded.chain_identity or chain_owner_identity(rebanded.scenario)
        scenario, decoy = _inject_decoy(
            rebanded.scenario,
            namespace=identity_namespace("decoy", (ordinal * 2 + slot) % _BAND_SIZE),
            chain=chain,
            rng=random.Random(seed * 104729 + ordinal * 7 + slot),
        )
        variants.append(
            replace(
                rebanded,
                scenario=scenario,
                spurious_mechanism_id=SPURIOUS_MECHANISM_ID,
                decoy_identity=decoy,
                chain_identity=owner,
            )
        )
    return tuple(variants)


def _ordinal_of(case: IncidentCase, seed: int) -> int:
    """A stable per-case ordinal inside a variant band, derived from its id.

    Arithmetic over the id's characters, not ``hash()``: ``hash`` is salted per process
    so a corpus keyed on it is irreproducible, and ``PYTHONHASHSEED=0`` hides that.
    """
    accumulator = seed % _BAND_SIZE
    for character in case.incident_id:
        accumulator = (accumulator * 131 + ord(character)) % _BAND_SIZE
    return accumulator // 4


# --- the adversarial world flood ---------------------------------------------

#: Each is enough to *suggest* a capability chain without completing one, so every
#: actor holding one is a candidate world. Flooding the field with candidates is the
#: denial of service an attacker would attempt.
_EGRESS = {"raddr": "203.0.113.9", "rport": "443"}
_PARTIAL_CHAINS = (
    (("setuid", {"target_uid": "0"}), ("read", {"path": "/etc/passwd"})),
    (("read", {"path": "/etc/shadow"}), ("write", {"path": "/srv/archive/dump.tar"})),
    (("connect", _EGRESS), ("send", _EGRESS)),
    (("setuid", {"target_uid": "0"}), ("write", {"path": "/etc/cron.daily/refresh"})),
    (("read", {"path": "/home/ops/.ssh/id_ed25519"}), ("read", {"path": "/etc/group"})),
)

#: Candidate lineages per flood session. Strictly above ``MAX_WORLDS`` (8), because a
#: flood that cannot push the field past its own cap demonstrates nothing about the cap.
#: Two actors may draw the same partial shape, which also exercises the fusion path.
FLOOD_CANDIDATE_LINEAGES = 12

#: The one complete chain in a flood session: the ground truth. A flood whose true
#: world cannot be recovered tests nothing, so recoverability is asserted too.
_SINK = {"raddr": "203.0.113.42", "rport": "443"}
_FLOOD_TRUE_CHAIN = (
    ("setuid", {"target_uid": "0"}), ("read", {"path": "/etc/shadow"}),
    ("connect", _SINK), ("send", _SINK),
)


def build_world_flood(*, count: int, seed: int) -> tuple[IncidentCase, ...]:
    """Sessions engineered to make the belief field branch, each with one true world.

    Several actors get a *partial* capability chain and exactly one gets the complete
    chain. Every partial chain is a legitimate residual, so a birth rule that spawns
    on residuals alone exceeds ``MAX_WORLDS`` at once — the load G4.9 needs.
    """
    if count < 1:
        raise ContractError(f"count must be positive, got {count}")
    cases: list[IncidentCase] = []
    for ordinal in range(count):
        rng = random.Random(seed * 31337 + ordinal)
        namespace = identity_namespace("flood", ordinal)
        owner = _actor(namespace, 0)
        stream: list[Behaviour] = []
        for slot in range(1, FLOOD_CANDIDATE_LINEAGES + 1):
            actor = _actor(namespace, slot)
            for operation, fields in _PARTIAL_CHAINS[slot % len(_PARTIAL_CHAINS)]:
                stream.append(
                    _behaviour(operation, fields, actor, rng.randrange(2, 40) * 1_000_000_000)
                )
        for operation, fields in _FLOOD_TRUE_CHAIN:
            stream.insert(
                rng.randrange(0, len(stream) + 1),
                _behaviour(operation, fields, owner, rng.randrange(5, 30) * 60_000_000_000),
            )
        cases.append(
            IncidentCase(
                incident_id=f"s4-fld-{seed:04d}-{ordinal:04d}",
                scenario=Scenario(
                    f"flood-{ordinal:04d}", tuple(stream), 1, technique="world-flood"
                ),
                truth=_ground_truth(WORLD_COMPROMISED_SESSION, discriminator="boundary_crossing"),
                material_alternatives=_ALTERNATIVES_BY_LABEL[WORLD_COMPROMISED_SESSION],
                expected_state="IDENTIFIED",
                chain_identity=(owner, owner),
            )
        )
    return tuple(cases)


# --- corpus statistics -------------------------------------------------------


def replay_cases(
    cases: Sequence[IncidentCase], *, pipeline: Stage1Pipeline | None = None
) -> dict[str, tuple[float, ...]]:
    """Replay every case through ONE pipeline, returning per-transition ΔΦ traces.
    One pipeline is how a host sees the corpus, and the reason identities must be
    unique: a fresh pipeline per case hides a collision a real replay would suffer.
    """
    driver = pipeline if pipeline is not None else Stage1Pipeline()
    return {
        case.incident_id: tuple(
            transition.delta_phi
            for transition in driver.run_scenario(case.scenario, offset=offset).transitions
        )
        for offset, case in enumerate(cases)
    }


def median_peak_delta_phi(cases: Sequence[IncidentCase]) -> dict[int, float]:
    """Median per-case peak ΔΦ per label. Asserted non-zero for **both** classes before
    any mechanism is measured here: 0.00 is the identity-reuse defect's signature.
    """
    traces = replay_cases(cases)
    peaks: dict[int, list[float]] = {}
    for case in cases:
        peaks.setdefault(case.label, []).append(max(traces[case.incident_id], default=0.0))
    return {label: statistics.median(values) for label, values in sorted(peaks.items())}


def operation_counts(cases: Sequence[IncidentCase]) -> dict[int, Counter[str]]:
    """Operation counts per binary label — the vocabulary a counting model would see."""
    counts: dict[int, Counter[str]] = {}
    for case in cases:
        counter = counts.setdefault(case.label, Counter())
        for behaviour in case.scenario.behaviours:
            counter[behaviour.operation] += 1
    return counts


def operation_share_gap(cases: Sequence[IncidentCase]) -> float:
    """Largest per-operation share difference between the classes — the structural
    half of the vocabulary guard. An operation one class never emits produces a gap
    equal to the other's share, which is the free-perfect-score leak (MEMORY trap 4).
    """
    counts = operation_counts(cases)
    if len(counts) < 2:
        return 0.0
    totals = {label: sum(counter.values()) for label, counter in counts.items()}
    labels = sorted(counts)
    gap = 0.0
    for operation in {op for counter in counts.values() for op in counter}:
        shares = [
            (counts[label][operation] / totals[label]) if totals[label] else 0.0
            for label in labels
        ]
        gap = max(gap, abs(shares[0] - shares[1]))
    return gap


def pooled_order_free_scores(cases: Sequence[IncidentCase]) -> list[float]:
    """Scores from an order-free bag-of-operations model, in corpus order.

    A multinomial naive Bayes over per-case operation counts, fitted **leave-one-out**
    and normalised per event. Order-free by construction, so if it beats the base rate
    the label is readable from the operation histogram and no order-sensitive Stage 4
    result measured on this corpus would mean anything.

    Leave-one-out rather than in-sample, for a measured reason: Stage 3's in-sample
    version (``stage3/labs/crystal_corpus.pooled_order_free_scores``) reaches
    **0.5679** average precision against a base rate of **0.3333** on the *unmodified*
    ``build_ambiguous_corpus(count=60, seed=11)``, whose per-operation shares differ by
    at most **0.0074**. An in-sample fit of an eight-operation multinomial to 60
    sessions memorises count noise, so it cannot tell overfitting from leakage, and a
    guard a clean corpus fails is not a guard. Both figures were measured by running
    those functions in the session that wrote this. Per-event normalisation removes
    length as a confound; length alone scores **0.2639**, below the base rate.
    """
    labels = [case.label for case in cases]
    histograms = [Counter(b.operation for b in case.scenario.behaviours) for case in cases]
    vocabulary = sorted({operation for histogram in histograms for operation in histogram})
    if not vocabulary or len(set(labels)) < 2:
        return [0.0 for _ in cases]

    pooled: dict[int, Counter[str]] = {}
    for label, histogram in zip(labels, histograms, strict=True):
        pooled.setdefault(label, Counter()).update(histogram)

    scores: list[float] = []
    for label, histogram in zip(labels, histograms, strict=True):
        held_out = {key: Counter(value) for key, value in pooled.items()}
        held_out[label].subtract(histogram)
        log_p = {
            key: _log_likelihoods(counter, vocabulary) for key, counter in held_out.items()
        }
        positive, negative = log_p.get(1), log_p.get(0)
        if positive is None or negative is None:  # pragma: no cover - guarded above
            scores.append(0.0)
            continue
        scores.append(
            math.fsum(
                count * (positive[operation] - negative[operation])
                for operation, count in histogram.items()
            )
            / (sum(histogram.values()) or 1)
        )
    return scores


def _log_likelihoods(counter: Counter[str], vocabulary: Sequence[str]) -> dict[str, float]:
    total = sum(max(0, value) for value in counter.values())
    denominator = total + len(vocabulary)
    return {
        operation: math.log((max(0, counter[operation]) + 1.0) / denominator)
        for operation in vocabulary
    }
