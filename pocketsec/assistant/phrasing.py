"""Plain-English names for PocketSec's recorded values. Tables, not a language model.

What this module is FOR: turning ``READ FILE /root/.ssh/id_rsa`` into "read the file
/root/.ssh/id_rsa", and ``CREDENTIAL`` into "credential material", for a reader who
does not know Stage 1's vocabulary. Every phrase is a fixed string or a fixed pattern
around a recorded value; nothing is paraphrased.

Two constraints shape the wording, both enforced by ``guard.py``:

* a security-dimension word (``privilege``, ``credential``, ``reachability``, ...) may
  appear only when the cited fact holds it — so each phrase keeps the recorded
  dimension name inside it ("credential exposure", "network reachability");
* the strongest reading of an object class is Stage 4's own ``AMPLIFICATION_RULES``
  value ("possible credential access"), never a completed-compromise verb.

Level names are shown lower-cased ("readable", "user files"). A raised level is never
the lattice floor, so "none" is never printed as a level — it would read as a denial.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from types import MappingProxyType

from pocketsec.stage4.claims.compiler import AMPLIFICATION_RULES

__all__ = [
    "NOVEL_PREFIX",
    "RELATION_VERBS",
    "capability_phrase",
    "class_phrase",
    "decision_phrase",
    "dimension_phrase",
    "horizon_phrase",
    "identifiability_phrase",
    "join_phrases",
    "level_phrase",
    "mechanism_phrase",
    "mechanisms_phrase",
    "object_phrase",
    "outcome_phrase",
    "permitted_reading",
    "relation_phrase",
    "relation_verb",
    "shadow_phrase",
    "truncation_phrase",
]

#: Stage 4's family name for activity matching no known mechanism.
NOVEL_PREFIX = "unresolved_novel"

_DIMENSIONS: Mapping[str, str] = MappingProxyType(
    {
        "privilege": "privilege level",
        "trust": "trust",
        "credential": "credential exposure",
        "reachability": "network reachability",
        "persistence": "persistence",
        "execution": "execution control",
        "modification": "modification capability",
        "discovery": "discovery",
        "isolation": "isolation",
    }
)

_OBJECT_CLASSES: Mapping[str, str] = MappingProxyType(
    {
        "CREDENTIAL": "credential material",
        "AUTHORIZATION_DATA": "authorization data",
        "PERSISTENCE": "a persistence location (something placed there can run again later)",
        "ROOT_OWNED": "owned by root",
        "USER_WRITABLE": "writable by ordinary users",
        "SYSTEM_BINARY": "a system program",
        "TEMP_LOCATION": "a temporary location",
        "EXTERNAL_ENDPOINT": "an external network address",
        "INTERPRETER": "a script interpreter",
    }
)

_CAPABILITIES: Mapping[str, str] = MappingProxyType(
    {
        "INTERPRETER": "runs scripts",
        "NETWORK_CAPABLE": "uses the network",
        "NETWORK_CLIENT": "makes outgoing network connections",
        "NETWORK_SERVER": "accepts incoming network connections",
        "PROCESS_SPAWNER": "starts other processes",
        "CREDENTIAL_READER": "reads credential material",
        "PRIVILEGE_CHANGER": "changes its privilege level",
        "PERSISTENCE_WRITER": "writes persistence locations",
    }
)

#: Verb patterns per Stage 1 relation. ``{o}`` is the object with its noun ("the file
#: /etc/x"); ``{n}`` is the bare recorded name, for verbs that already say what it is.
_RELATIONS: Mapping[str, str] = MappingProxyType(
    {
        "SPAWN": "started a new process",
        "EXECUTE": "ran the program {n}",
        "READ": "read {o}",
        "WRITE": "wrote to {o}",
        "CREATE": "created {o}",
        "DELETE": "deleted {o}",
        "RENAME": "renamed {o}",
        "CONNECT": "connected to {o}",
        "ACCEPT": "accepted a network connection involving {n}",
        "LISTEN": "listened for connections on {o}",
        "SEND": "sent data to {o}",
        "RECEIVE": "received data from {o}",
        "AUTHENTICATE": "authenticated as {o}",
        "IMPERSONATE": "switched to the user identity {o}",
        "GRANT": "granted access involving {o}",
        "REVOKE": "revoked access involving {o}",
        "LOAD": "loaded {o}",
        "MAP": "mapped {o} into memory",
        "MOUNT": "mounted {o}",
        "SIGNAL": "sent a signal to {o}",
        "CONTROL": "took control of {o}",
        "INSTALL": "installed {o}",
        "REMOVE": "removed {o}",
        "CHANGE": "changed {o}",
    }
)

#: The first word of each relation's phrase: the verb a sentence about that event uses.
#: The guard reads this to refuse a sentence that describes an event with another
#: relation's verb ("deleted" for a READ). Derived from the table, not restated.
RELATION_VERBS: frozenset[str] = frozenset(pattern.split()[0] for pattern in _RELATIONS.values())

_OBJECT_NOUNS: Mapping[str, str] = MappingProxyType(
    {
        "FILE": "the file",
        "DIRECTORY": "the directory",
        "ENDPOINT": "the network address",
        "USER": "",
        "PROCESS": "a process",
        "PACKAGE": "the package",
        "SERVICE": "the service",
    }
)

_HORIZONS: Mapping[str, str] = MappingProxyType(
    {
        "RESOLVED": "it considered the incident resolved",
        "ESCALATE_TO_ANALYST": "it asked for a human analyst to look at the incident",
        "PRESERVE_UNRESOLVED": "it kept the incident open and unresolved",
        "REQUEST_HIGHER_OBSERVATION_TIER": "it asked for more detailed monitoring before deciding",
    }
)

_IDENTIFIABILITY: Mapping[str, str] = MappingProxyType(
    {
        "IDENTIFIED": "it singled out one leading explanation",
        "UNIDENTIFIABLE": (
            "on the recorded evidence, every observation it can afford would leave the "
            "leading explanations indistinguishable"
        ),
        "INSUFFICIENT_EVIDENCE": (
            "the explanations could be told apart, but the evidence to do so is not yet recorded"
        ),
        # Stage 4 records UNKNOWN for an empty field, an all-novel field, and a field a
        # novel world merely leads (``resolution._novel_leader_verdict``). The one thing
        # true of all three is that no explanation was identified; anything about what
        # the explanations *are* comes from the hypotheses, not from this enum.
        "UNKNOWN": "it could not single out one leading explanation",
    }
)

#: Stage 4's four shadow reasons (``sensor_shadow.SHADOW_REASONS``), each worded for
#: what it actually says. ``{s}`` is the blind sensors, ``{g}`` the signal.
_SHADOW_REASONS: Mapping[str, str] = MappingProxyType(
    {
        "no_visibility_evidence": (
            "PocketSec's sensor-visibility model has no evidence that {s} can observe the "
            "{g} signal"
        ),
        "sensor_path_dropped": (
            "PocketSec's sensor-visibility model records that the {s} path for the {g} "
            "signal was dropped"
        ),
        "below_observation_level": (
            "PocketSec's current collection level is below the one that would guarantee "
            "{s} report the {g} signal"
        ),
        "observation_incomplete": (
            "PocketSec's collector marked its own observation of the {g} signal from {s} "
            "as incomplete"
        ),
    }
)

#: ``max_<thing>:<N>`` truncation reasons: what ``<thing>`` counts, in words.
_CAPPED_THINGS: Mapping[str, str] = MappingProxyType(
    {
        "field_evidence_refs": "evidence references",
        "receipts": "receipts",
        "residuals": "residual entries",
        "denials": "denials",
    }
)
_CAP_RE = re.compile(r"max_([a-z_]+):(\d+)")

_DECISIONS: Mapping[str, str] = MappingProxyType(
    {
        "ACT": "act on the host",
        "OBSERVE": "only observe and preserve evidence",
        "DEFER": "wait before deciding",
        "ESCALATE": "hand the decision to a human",
        "NO_ACTION": "take no action",
        "ROLLBACK": "roll back an earlier change",
    }
)

_OUTCOMES: Mapping[str, str] = MappingProxyType(
    {
        "COMMITTED_VERIFIED": "it was carried out and its checks confirmed the effect",
        "COMMITTED_UNVERIFIED": "it was carried out but its effect was not confirmed",
        "ROLLED_BACK": "it was carried out and then reversed",
        "ROLLBACK_FAILED": "it was carried out and an attempt to reverse it failed",
        "REFUSED_SENTINEL": "SENTINEL refused it before it reached the host",
        "REFUSED_EVIDENCE": "the evidence-preservation gate refused it before it reached the host",
        "REFUSED_IDENTITY": "it was refused because the target's identity had changed",
        "REFUSED_TOKEN": "it was refused because its authorisation token was not valid",
        "REFUSED_JOURNAL_FULL": "it was refused because the rollback journal was full",
        "ESCALATED": "it was passed to a human instead of being carried out",
    }
)


def _lookup(table: Mapping[str, str], key: str) -> str:
    return table.get(key, key.replace("_", " ").lower())


def dimension_phrase(dimension: str) -> str:
    return _lookup(_DIMENSIONS, dimension)


def level_phrase(level: str) -> str:
    return level.replace("_", " ").lower()


def class_phrase(name: str) -> str:
    return _lookup(_OBJECT_CLASSES, name)


def capability_phrase(name: str) -> str:
    return _lookup(_CAPABILITIES, name)


def horizon_phrase(horizon: str) -> str:
    return _lookup(_HORIZONS, horizon)


def identifiability_phrase(state: str) -> str:
    return _lookup(_IDENTIFIABILITY, state)


def decision_phrase(decision: str) -> str:
    return _lookup(_DECISIONS, decision)


def outcome_phrase(outcome: str) -> str:
    return _lookup(_OUTCOMES, outcome)


def object_phrase(kind: str, name: str) -> str:
    noun = _OBJECT_NOUNS.get(kind, "")
    if not name:
        return noun or "an unnamed object"
    return f"{noun} {name}".strip()


def relation_phrase(relation: str, kind: str, name: str) -> str:
    """``READ``, ``FILE``, ``/etc/x`` -> ``read the file /etc/x``."""
    pattern = _RELATIONS.get(relation, relation.lower() + " {o}")
    return pattern.format(o=object_phrase(kind, name), n=name or object_phrase(kind, name))


def permitted_reading(object_classes: Iterable[str]) -> str | None:
    """Stage 4's strongest permitted phrase for these classes, e.g. "possible credential access"."""
    for name in object_classes:
        allowed = AMPLIFICATION_RULES.get(name)
        if allowed:
            return sorted(allowed)[0].replace("_", " ")
    return None


def mechanism_phrase(mechanism_id: str) -> str:
    """``unresolved_novel_mechanism.083c28`` -> ``unresolved novel mechanism``.

    The variant suffix is a hash, meaningless to a reader; it stays in ``--json`` and
    the source list. Variants are counted instead (``mechanisms_phrase``).
    """
    return mechanism_id.partition(".")[0].replace("_", " ")


def mechanisms_phrase(entries: Iterable[tuple[str, str]]) -> str:
    """Group (mechanism_id, weight text) pairs: repeats become "name, N variants (w each)"."""
    groups: dict[tuple[str, str], int] = {}
    for mechanism_id, weight in entries:
        key = (mechanism_phrase(mechanism_id), weight)
        groups[key] = groups.get(key, 0) + 1
    parts = []
    for (name, weight), count in groups.items():
        tail = f" ({weight})" if weight else ""
        if count > 1:
            tail = f", {count} variants" + (f" ({weight} each)" if weight else "")
        parts.append(name + tail)
    return join_phrases(parts)


def relation_verb(relation: str) -> str:
    """The verb a sentence about a ``relation`` event uses (``READ`` -> ``read``)."""
    return _RELATIONS.get(relation, relation.lower()).split()[0]


def shadow_phrase(reason: str | None, sensors: str, signal: str) -> str:
    """What one shadow region says, worded for its recorded reason."""
    pattern = _SHADOW_REASONS.get(reason or "")
    if pattern is None:
        return f"PocketSec's sensor-visibility model places the {signal} signal in a sensor shadow"
    return pattern.format(s=sensors, g=signal)


def truncation_phrase(reason: str) -> str | None:
    """``max_field_evidence_refs:64`` -> ``keeps at most 64 evidence references``, else None."""
    match = _CAP_RE.fullmatch(reason)
    if match is None:
        return None
    thing = _CAPPED_THINGS.get(match.group(1), match.group(1).replace("_", " "))
    return f"keeps at most {match.group(2)} {thing}"


def join_phrases(items: Iterable[str]) -> str:
    listed = [item for item in items if item]
    if len(listed) <= 1:
        return "".join(listed)
    return ", ".join(listed[:-1]) + " and " + listed[-1]
