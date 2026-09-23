"""D1.3 (part) — operation classification and state operators.

The deterministic layer of the semantic compiler. Stage 0's principle applies
directly: *do not learn what can be represented exactly by deterministic code*.
Mapping ``syscall=connect`` to ``Relation.CONNECT`` is exact; no model should
spend a parameter on it.

Each rule says three things: which machine relation this is, which capabilities
the actor demonstrates by doing it, and which state lattices it raises. The
conditional raises are where object semantics matter — reading a file raises
credential exposure only if the object is actually a credential.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum

from pocketsec.stage1.ssir.entities import EntityKind, SemanticProperty
from pocketsec.stage1.ssir.relations import Relation
from pocketsec.stage1.state.security_state import (
    CredentialExposure,
    Discovery,
    ExecutionControl,
    Isolation,
    ModificationCapability,
    Persistence,
    Privilege,
    Reachability,
)
from pocketsec.stage1.telemetry.raw_event_v1 import EvidenceEvent

__all__ = ["OPERATION_RULES", "OperationRule", "classify_operation"]


@dataclass(frozen=True, slots=True)
class OperationRule:
    """How one machine operation maps into SSIR and the state calculus."""

    relation: Relation
    #: Canonical operation tokens, normalised across sensors. This is where
    #: source-independence is actually implemented: auditd's ``SYSCALL/connect``
    #: and eBPF's ``sys_connect`` both normalise to ``connect``.
    tokens: frozenset[str]
    object_kind: EntityKind = EntityKind.UNKNOWN
    #: Capabilities the actor demonstrates by performing this operation.
    actor_properties: tuple[SemanticProperty, ...] = ()
    #: Unconditional lattice raises.
    raises: tuple[tuple[str, IntEnum], ...] = ()
    #: Raises that apply only when the object holds a given property.
    conditional_raises: tuple[tuple[SemanticProperty, str, IntEnum], ...] = ()
    property_support: float = 0.6


OPERATION_RULES: tuple[OperationRule, ...] = (
    OperationRule(
        relation=Relation.SPAWN,
        tokens=frozenset({"fork", "clone", "vfork", "spawn"}),
        object_kind=EntityKind.PROCESS,
        actor_properties=(SemanticProperty.PROCESS_SPAWNER,),
    ),
    OperationRule(
        relation=Relation.EXECUTE,
        tokens=frozenset({"execve", "execveat", "exec"}),
        object_kind=EntityKind.FILE,
        actor_properties=(SemanticProperty.PROCESS_SPAWNER,),
        conditional_raises=(
            (SemanticProperty.INTERPRETER, "execution", ExecutionControl.INTERPRETER),
            (SemanticProperty.USER_WRITABLE, "trust", 1),  # Trust.UNCERTAIN
        ),
    ),
    OperationRule(
        relation=Relation.READ,
        tokens=frozenset({"read", "openat_read", "pread64", "readv", "open_rdonly"}),
        object_kind=EntityKind.FILE,
        conditional_raises=(
            (SemanticProperty.CREDENTIAL, "credential", CredentialExposure.READABLE),
            (
                SemanticProperty.AUTHORIZATION_DATA,
                "credential",
                CredentialExposure.METADATA,
            ),
        ),
    ),
    OperationRule(
        relation=Relation.WRITE,
        tokens=frozenset({"write", "pwrite64", "writev", "open_wronly"}),
        object_kind=EntityKind.FILE,
        conditional_raises=(
            (SemanticProperty.PERSISTENCE, "persistence", Persistence.SERVICE),
            (SemanticProperty.ROOT_OWNED, "modification", ModificationCapability.SYSTEM),
            (
                SemanticProperty.AUTHORIZATION_DATA,
                "modification",
                ModificationCapability.CONFIG,
            ),
        ),
        raises=(("modification", ModificationCapability.USER_FILES),),
    ),
    OperationRule(
        relation=Relation.CREATE,
        tokens=frozenset({"creat", "mkdir", "mknod", "create"}),
        object_kind=EntityKind.FILE,
        conditional_raises=((SemanticProperty.PERSISTENCE, "persistence", Persistence.USER),),
    ),
    OperationRule(
        relation=Relation.DELETE,
        tokens=frozenset({"unlink", "unlinkat", "rmdir", "delete"}),
        object_kind=EntityKind.FILE,
        conditional_raises=(
            (SemanticProperty.ROOT_OWNED, "modification", ModificationCapability.SYSTEM),
        ),
    ),
    OperationRule(
        relation=Relation.RENAME,
        tokens=frozenset({"rename", "renameat", "renameat2"}),
        object_kind=EntityKind.FILE,
    ),
    OperationRule(
        relation=Relation.CONNECT,
        tokens=frozenset({"connect", "sys_connect", "tcp_connect"}),
        object_kind=EntityKind.ENDPOINT,
        actor_properties=(
            SemanticProperty.NETWORK_CAPABLE,
            SemanticProperty.NETWORK_CLIENT,
        ),
        raises=(("reachability", Reachability.LOCAL),),
        conditional_raises=(
            (SemanticProperty.EXTERNAL_ENDPOINT, "reachability", Reachability.EXTERNAL),
        ),
    ),
    OperationRule(
        relation=Relation.ACCEPT,
        tokens=frozenset({"accept", "accept4"}),
        object_kind=EntityKind.ENDPOINT,
        actor_properties=(
            SemanticProperty.NETWORK_CAPABLE,
            SemanticProperty.NETWORK_SERVER,
        ),
        raises=(("reachability", Reachability.LOCAL),),
    ),
    OperationRule(
        relation=Relation.LISTEN,
        tokens=frozenset({"listen", "bind"}),
        object_kind=EntityKind.SOCKET,
        actor_properties=(
            SemanticProperty.NETWORK_CAPABLE,
            SemanticProperty.NETWORK_SERVER,
        ),
        raises=(("reachability", Reachability.LOCAL),),
    ),
    OperationRule(
        relation=Relation.SEND,
        tokens=frozenset({"send", "sendto", "sendmsg", "write_socket"}),
        object_kind=EntityKind.ENDPOINT,
        actor_properties=(SemanticProperty.NETWORK_CAPABLE,),
        conditional_raises=(
            (SemanticProperty.EXTERNAL_ENDPOINT, "reachability", Reachability.EXTERNAL),
        ),
    ),
    OperationRule(
        relation=Relation.RECEIVE,
        tokens=frozenset({"recv", "recvfrom", "recvmsg"}),
        object_kind=EntityKind.ENDPOINT,
        actor_properties=(SemanticProperty.NETWORK_CAPABLE,),
    ),
    OperationRule(
        relation=Relation.AUTHENTICATE,
        tokens=frozenset({"pam_authenticate", "authenticate", "login"}),
        object_kind=EntityKind.USER,
    ),
    OperationRule(
        relation=Relation.IMPERSONATE,
        tokens=frozenset({"setuid", "setgid", "setresuid", "seteuid", "sudo"}),
        object_kind=EntityKind.USER,
        actor_properties=(SemanticProperty.PRIVILEGE_CHANGER,),
        raises=(("privilege", Privilege.ELEVATED),),
    ),
    OperationRule(
        relation=Relation.GRANT,
        tokens=frozenset({"chmod", "fchmod", "setcap", "chown", "grant"}),
        object_kind=EntityKind.FILE,
        raises=(("modification", ModificationCapability.CONFIG),),
        conditional_raises=(
            (SemanticProperty.ROOT_OWNED, "privilege", Privilege.ROOT),
        ),
    ),
    OperationRule(
        relation=Relation.REVOKE,
        tokens=frozenset({"revoke", "removexattr"}),
        object_kind=EntityKind.FILE,
    ),
    OperationRule(
        relation=Relation.LOAD,
        tokens=frozenset({"init_module", "finit_module", "load_module", "dlopen"}),
        object_kind=EntityKind.KERNEL_OBJECT,
        raises=(
            ("persistence", Persistence.BOOT_KERNEL),
            ("execution", ExecutionControl.PRIVILEGED),
        ),
    ),
    OperationRule(
        relation=Relation.MAP,
        tokens=frozenset({"mmap", "mprotect"}),
        object_kind=EntityKind.KERNEL_OBJECT,
    ),
    OperationRule(
        relation=Relation.MOUNT,
        tokens=frozenset({"mount", "umount", "pivot_root", "setns", "unshare"}),
        object_kind=EntityKind.NAMESPACE,
        raises=(("isolation", Isolation.BOUNDARY_CROSSED),),
    ),
    OperationRule(
        relation=Relation.SIGNAL,
        tokens=frozenset({"kill", "tgkill", "signal"}),
        object_kind=EntityKind.PROCESS,
    ),
    OperationRule(
        relation=Relation.CONTROL,
        tokens=frozenset({"ptrace", "process_vm_readv", "prctl"}),
        object_kind=EntityKind.PROCESS,
        actor_properties=(SemanticProperty.CREDENTIAL_READER,),
        raises=(
            ("discovery", Discovery.CREDENTIAL_SYSTEM),
            ("credential", CredentialExposure.READABLE),
        ),
    ),
    OperationRule(
        relation=Relation.INSTALL,
        tokens=frozenset({"install", "dpkg_install", "rpm_install"}),
        object_kind=EntityKind.PACKAGE,
        raises=(("persistence", Persistence.SERVICE),),
    ),
    OperationRule(
        relation=Relation.REMOVE,
        tokens=frozenset({"uninstall", "dpkg_remove", "rpm_erase"}),
        object_kind=EntityKind.PACKAGE,
    ),
    OperationRule(
        relation=Relation.CHANGE,
        tokens=frozenset({"systemctl", "service_change", "config_change"}),
        object_kind=EntityKind.SERVICE,
        raises=(("persistence", Persistence.SERVICE),),
    ),
)

#: Token -> rule. Built once; a duplicate token across rules is a definition
#: bug and fails at import rather than silently shadowing.
_TOKEN_INDEX: dict[str, OperationRule] = {}
for _rule in OPERATION_RULES:
    for _token in _rule.tokens:
        if _token in _TOKEN_INDEX:
            raise RuntimeError(f"duplicate operation token {_token!r} in OPERATION_RULES")
        _TOKEN_INDEX[_token] = _rule


#: Discovery operations, recognised by what is read rather than by syscall.
_DISCOVERY_PATH_MARKERS = ("/etc/passwd", "/etc/shadow", "/proc/self/environ")


def normalise_token(raw: str) -> str:
    """Normalise a sensor's operation token to the canonical vocabulary.

    Source-independence starts here: strip the ``sys_``/``SYS_`` prefixes and
    case differences that distinguish eBPF probe names from audit syscall names
    but carry no semantic content.
    """
    token = raw.strip().lower()
    for prefix in ("sys_", "syscall_", "do_", "__x64_sys_"):
        if token.startswith(prefix):
            token = token[len(prefix) :]
    return token


def classify_operation(event: EvidenceEvent) -> OperationRule | None:
    """Identify the machine operation a fused event describes.

    Returns ``None`` when no rule matches. The compiler treats that as missing
    information rather than inventing a relation.
    """
    fields = event.merged_fields()
    for key in ("operation", "syscall", "probe", "record_op"):
        raw = fields.get(key)
        if not raw:
            continue
        rule = _TOKEN_INDEX.get(normalise_token(raw))
        if rule is not None:
            return rule

    for record in event.records:
        rule = _TOKEN_INDEX.get(normalise_token(record.record_type))
        if rule is not None:
            return rule
    return None


assert len({rule.relation for rule in OPERATION_RULES}) == len(OPERATION_RULES), (
    "each relation should have exactly one rule at Stage 1"
)
assert field  # dataclasses.field retained for future rule extensions
