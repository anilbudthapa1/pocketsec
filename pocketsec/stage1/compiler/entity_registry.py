"""D1.3 (part) — the bounded entity registry.

Resolves the actor and object of an operation into :class:`Entity` values,
carrying semantics forward across transitions so that a process which connected
to the network five events ago is still ``NETWORK_CLIENT`` now.

Two properties this module is responsible for:

* **Identity is not the name.** A process key is boot+pid+start-time, because
  pids are reused; a file key is inode-aware. Display names are retained for
  investigation and excluded from the model-facing encoding.
* **Object properties come from host metadata, not behaviour.** Whether
  ``/etc/shadow`` is a CREDENTIAL is a fact about the host's filesystem, so it
  is assigned from path metadata. Whether a *process* is a CREDENTIAL_READER is
  a fact about its behaviour, so it is only ever earned by reading one.

The registry is bounded. Under entity churn it evicts least-recently-used
entries and counts the evictions, rather than growing.
"""

from __future__ import annotations

from collections import OrderedDict
from typing import Any

from pocketsec.stage1.compiler.rules import OperationRule
from pocketsec.stage1.ssir.entities import (
    Entity,
    EntityKind,
    SemanticBelief,
    SemanticProperty,
)
from pocketsec.stage1.telemetry.raw_event_v1 import EvidenceEvent

__all__ = ["CREDENTIAL_PATHS", "EntityRegistry", "PERSISTENCE_PATHS"]

#: Host metadata: paths whose contents are credentials. A fact about the
#: filesystem layout, independent of who touches them.
CREDENTIAL_PATHS = (
    "/etc/shadow",
    "/etc/gshadow",
    "/etc/sudoers",
    ".ssh/id_",
    ".aws/credentials",
    ".kube/config",
    "/proc/self/environ",
)

#: Paths whose modification survives a reboot.
PERSISTENCE_PATHS = (
    "/etc/systemd/",
    "/lib/systemd/",
    "/etc/cron",
    "/etc/init.d/",
    "/etc/rc.local",
    ".bashrc",
    ".profile",
    "/etc/ld.so.preload",
)

#: Paths that are authorisation data without being secrets themselves.
AUTHORIZATION_PATHS = ("/etc/passwd", "/etc/group", "authorized_keys", "/etc/pam.d/")

#: Interpreters, by basename. Used only for the *object* of an EXECUTE, which
#: is host metadata about the binary, never to grant an actor capability.
INTERPRETER_NAMES = frozenset(
    {"sh", "bash", "dash", "zsh", "python", "python3", "perl", "ruby", "node", "php"}
)

_SYSTEM_PREFIXES = ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/")
_TEMP_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/")

#: Loopback and RFC1918 prefixes count as local/LAN; everything else external.
_LOCAL_ADDRESS_PREFIXES = ("127.", "::1", "localhost", "unix:")
_LAN_ADDRESS_PREFIXES = ("10.", "192.168.", "172.16.", "172.17.", "169.254.", "fe80:")


class EntityRegistry:
    """Bounded store of entity identity and accumulated semantics."""

    def __init__(self, *, capacity: int = 2048) -> None:
        if capacity < 1:
            raise ValueError("capacity must be >= 1")
        self.capacity = capacity
        self._entities: OrderedDict[str, Entity] = OrderedDict()
        self._evictions = 0

    @property
    def evictions(self) -> int:
        return self._evictions

    def __len__(self) -> int:
        return len(self._entities)

    def get(self, identity: str) -> Entity | None:
        entity = self._entities.get(identity)
        if entity is not None:
            self._entities.move_to_end(identity)
        return entity

    def update(self, entity: Entity) -> Entity:
        self._entities[entity.identity] = entity
        self._entities.move_to_end(entity.identity)
        while len(self._entities) > self.capacity:
            self._entities.popitem(last=False)
            self._evictions += 1
        return entity

    # --- resolution -----------------------------------------------------

    def resolve_actor(self, event: EvidenceEvent, fields: dict[str, str]) -> Entity:
        """Resolve the acting process, preserving earned semantics."""
        identity = self._process_identity(event, fields)
        existing = self.get(identity)
        if existing is not None:
            return existing

        entity = Entity(
            identity=identity,
            semantics=SemanticBelief(kind=EntityKind.PROCESS),
            evidence=event.evidence_refs[:1],
            display_name=fields.get("exe", fields.get("comm", "")),
        )
        return self.update(entity)

    def resolve_object(
        self, event: EvidenceEvent, rule: OperationRule, fields: dict[str, str]
    ) -> Entity:
        """Resolve the object, assigning host-metadata semantics."""
        identity, display = self._object_identity(rule, fields)
        existing = self.get(identity)
        if existing is not None:
            return existing

        present = frozenset(self._metadata_properties(rule, display))
        belief = SemanticBelief(kind=rule.object_kind).classify(
            present=present, evaluated=self._evaluable_properties(rule)
        )

        entity = Entity(
            identity=identity,
            semantics=belief,
            evidence=event.evidence_refs[:1],
            display_name=display,
        )
        return self.update(entity)

    # --- identity -------------------------------------------------------

    @staticmethod
    def _process_identity(event: EvidenceEvent, fields: dict[str, str]) -> str:
        """boot + pid + start-time. pid alone is reused and would merge lineages."""
        pid = fields.get("pid", "0")
        start = fields.get("start_time", fields.get("proc_start", "0"))
        return f"proc:{event.boot_id}:{pid}:{start}"

    @staticmethod
    def _object_identity(rule: OperationRule, fields: dict[str, str]) -> tuple[str, str]:
        kind = rule.object_kind
        if kind is EntityKind.ENDPOINT:
            address = fields.get("raddr", fields.get("addr", "unknown"))
            port = fields.get("rport", fields.get("port", "0"))
            return f"endpoint:{address}:{port}", f"{address}:{port}"
        if kind in (EntityKind.FILE, EntityKind.DIRECTORY):
            path = fields.get("path", fields.get("name", "unknown"))
            inode = fields.get("inode", "")
            # Inode-aware: two paths hardlinked to one inode are one object.
            return (f"file:{inode}" if inode else f"file:{path}"), path
        if kind is EntityKind.PROCESS:
            return f"proc:{fields.get('target_pid', fields.get('cpid', '0'))}", fields.get(
                "target_comm", ""
            )
        if kind is EntityKind.USER:
            uid = fields.get("target_uid", fields.get("uid", "0"))
            return f"user:{uid}", f"uid={uid}"
        label = fields.get("path", fields.get("name", "unknown"))
        return f"{kind.name.lower()}:{label}", label

    @staticmethod
    def _evaluable_properties(rule: OperationRule) -> frozenset[SemanticProperty]:
        """Properties the metadata classifier can decide for this object kind.

        Declaring this explicitly is what makes a negative result meaningful:
        the classifier states what it looked for, so "not found" is evidence
        rather than silence.
        """
        if rule.object_kind is EntityKind.ENDPOINT:
            return frozenset({SemanticProperty.EXTERNAL_ENDPOINT})
        if rule.object_kind in (EntityKind.FILE, EntityKind.DIRECTORY):
            return frozenset(
                {
                    SemanticProperty.CREDENTIAL,
                    SemanticProperty.PERSISTENCE,
                    SemanticProperty.AUTHORIZATION_DATA,
                    SemanticProperty.SYSTEM_BINARY,
                    SemanticProperty.ROOT_OWNED,
                    SemanticProperty.TEMP_LOCATION,
                    SemanticProperty.USER_WRITABLE,
                    SemanticProperty.INTERPRETER,
                }
            )
        return frozenset()

    @staticmethod
    def _metadata_properties(
        rule: OperationRule, display: str
    ) -> tuple[SemanticProperty, ...]:
        """Assign properties that are facts about the host, not behaviour."""
        kind = rule.object_kind
        props: list[SemanticProperty] = []

        if kind is EntityKind.ENDPOINT:
            lowered = display.lower()
            is_local = any(lowered.startswith(p) for p in _LOCAL_ADDRESS_PREFIXES)
            is_lan = any(lowered.startswith(p) for p in _LAN_ADDRESS_PREFIXES)
            if not is_local and not is_lan and display not in ("", "unknown:0"):
                props.append(SemanticProperty.EXTERNAL_ENDPOINT)
            return tuple(props)

        if kind not in (EntityKind.FILE, EntityKind.DIRECTORY):
            return ()

        if any(marker in display for marker in CREDENTIAL_PATHS):
            props.append(SemanticProperty.CREDENTIAL)
        if any(marker in display for marker in PERSISTENCE_PATHS):
            props.append(SemanticProperty.PERSISTENCE)
        if any(marker in display for marker in AUTHORIZATION_PATHS):
            props.append(SemanticProperty.AUTHORIZATION_DATA)
        if display.startswith(_SYSTEM_PREFIXES):
            props.append(SemanticProperty.SYSTEM_BINARY)
            props.append(SemanticProperty.ROOT_OWNED)
        if display.startswith(_TEMP_PREFIXES):
            props.append(SemanticProperty.TEMP_LOCATION)
            props.append(SemanticProperty.USER_WRITABLE)
        if display.rsplit("/", 1)[-1] in INTERPRETER_NAMES:
            props.append(SemanticProperty.INTERPRETER)
        return tuple(props)

    def to_dict(self) -> dict[str, Any]:
        return {
            "capacity": self.capacity,
            "live_entities": len(self._entities),
            "evictions": self._evictions,
        }
