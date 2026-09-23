"""D1.3 (part) — the security relation algebra (spec section 9).

A deliberately small vocabulary of low-level *machine operations*. These are not
ATT&CK techniques and must not become them: the Stage 1 non-goals forbid
encoding a threat taxonomy as the fundamental event language, precisely so the
representation survives taxonomy churn.

24 relations fit in a ``uint8`` with room to grow, which the SSIR binary layout
depends on.
"""

from __future__ import annotations

from enum import IntEnum

__all__ = ["Relation", "RELATION_FAMILIES", "RelationFamily", "family_of"]


class Relation(IntEnum):
    """Fundamental machine operations."""

    # Execution
    SPAWN = 0
    EXECUTE = 1
    # Filesystem
    READ = 2
    WRITE = 3
    CREATE = 4
    DELETE = 5
    RENAME = 6
    # Network
    CONNECT = 7
    ACCEPT = 8
    LISTEN = 9
    SEND = 10
    RECEIVE = 11
    # Identity
    AUTHENTICATE = 12
    IMPERSONATE = 13
    # Authorisation
    GRANT = 14
    REVOKE = 15
    # Loading
    LOAD = 16
    MAP = 17
    MOUNT = 18
    # Control
    SIGNAL = 19
    CONTROL = 20
    # Packaging
    INSTALL = 21
    REMOVE = 22
    CHANGE = 23


class RelationFamily(IntEnum):
    EXECUTION = 0
    FILESYSTEM = 1
    NETWORK = 2
    IDENTITY = 3
    AUTHORIZATION = 4
    LOADING = 5
    CONTROL = 6
    PACKAGING = 7


RELATION_FAMILIES: dict[Relation, RelationFamily] = {
    Relation.SPAWN: RelationFamily.EXECUTION,
    Relation.EXECUTE: RelationFamily.EXECUTION,
    Relation.READ: RelationFamily.FILESYSTEM,
    Relation.WRITE: RelationFamily.FILESYSTEM,
    Relation.CREATE: RelationFamily.FILESYSTEM,
    Relation.DELETE: RelationFamily.FILESYSTEM,
    Relation.RENAME: RelationFamily.FILESYSTEM,
    Relation.CONNECT: RelationFamily.NETWORK,
    Relation.ACCEPT: RelationFamily.NETWORK,
    Relation.LISTEN: RelationFamily.NETWORK,
    Relation.SEND: RelationFamily.NETWORK,
    Relation.RECEIVE: RelationFamily.NETWORK,
    Relation.AUTHENTICATE: RelationFamily.IDENTITY,
    Relation.IMPERSONATE: RelationFamily.IDENTITY,
    Relation.GRANT: RelationFamily.AUTHORIZATION,
    Relation.REVOKE: RelationFamily.AUTHORIZATION,
    Relation.LOAD: RelationFamily.LOADING,
    Relation.MAP: RelationFamily.LOADING,
    Relation.MOUNT: RelationFamily.LOADING,
    Relation.SIGNAL: RelationFamily.CONTROL,
    Relation.CONTROL: RelationFamily.CONTROL,
    Relation.INSTALL: RelationFamily.PACKAGING,
    Relation.REMOVE: RelationFamily.PACKAGING,
    Relation.CHANGE: RelationFamily.PACKAGING,
}


def family_of(relation: Relation) -> RelationFamily:
    return RELATION_FAMILIES[relation]


assert len(RELATION_FAMILIES) == len(Relation), "every relation needs a family"
assert max(Relation) < 256, "relations must fit in a uint8 for the SSIR layout"
